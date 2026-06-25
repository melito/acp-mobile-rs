//! WebSocket <-> unix-socket bridge.
//!
//! A browser opens `/ws?sock=<pid>`; we dial that session's unix socket, replay
//! its cached history to the browser, then bidirectionally bridge live traffic:
//!   browser frame  -> ndjson line on the socket (append '\n')
//!   socket line    -> browser frame  (UNLESS it's an fs reverse-call we answer
//!                                      locally on the server's filesystem)
//!
//! Faithful port of the Go `bridgeWebSocket` + `handleReverseCall`. The replay
//! burst has no end marker, so we detect "burst done" via a short idle timeout
//! (150ms with no new bytes), exactly like Go's `SetDeadline`.

use std::time::Duration;

use axum::extract::ws::{Message as WsMessage, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, value::RawValue, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

type WsSink = futures_util::stream::SplitSink<WebSocket, WsMessage>;

/// Idle gap that marks the end of the replay burst (Go: 150ms SetDeadline).
const REPLAY_IDLE: Duration = Duration::from_millis(150);

/// Bridge a connected browser WebSocket to the session socket at `sock_path`.
/// Runs until either side closes. `read_file`/`write_file` are injected so the
/// security layer (task 11) can wrap fs access with path checks; the default
/// impls mirror Go's unconstrained behavior.
pub async fn bridge(ws: WebSocket, sock_path: std::path::PathBuf) {
    // Split BOTH streams into disjoint halves so the two directions can run
    // concurrently without overlapping mutable borrows: b2s owns (ws_rx,
    // sock_wr); s2b owns (ws_tx, sock_rd).
    let (mut ws_tx, mut ws_rx) = ws.split();

    let conn = match UnixStream::connect(&sock_path).await {
        Ok(c) => c,
        Err(e) => {
            let err = json!({
                "jsonrpc":"2.0","id":null,
                "error":{"code":-32000,"message":"Connection failed",
                         "data":{"details":e.to_string()}}
            });
            let _ = ws_tx.send(WsMessage::Text(err.to_string().into())).await;
            let _ = ws_tx.send(WsMessage::Close(None)).await;
            return;
        }
    };

    let (mut sock_rd, mut sock_wr) = conn.into_split();

    // One task owns the socket write half; both directions queue lines to it via
    // `sock_tx` (each item already includes its trailing '\n'). This serializes
    // socket writes — no interleaved partial lines — and lets browser->socket
    // forwarding and fs-reply writes coexist without sharing the write half.
    let (sock_tx, mut sock_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let writer_task = tokio::spawn(async move {
        while let Some(buf) = sock_rx.recv().await {
            if sock_wr.write_all(&buf).await.is_err() {
                break;
            }
        }
    });

    // --- Phase 1: drain the replay burst into memory (idle-timeout bounded) ---
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut tmp = vec![0u8; 256 * 1024];
    let mut responses: Vec<Vec<u8>> = Vec::new();
    let mut notifications: Vec<Vec<u8>> = Vec::new();

    loop {
        match timeout(REPLAY_IDLE, sock_rd.read(&mut tmp)).await {
            Ok(Ok(0)) => break,        // EOF: replay done (and socket closed)
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                drain_lines(&mut buf, |line| {
                    // Classify: a result/error line is a "response", else a
                    // notification. (Go uses a substring check; we match it.)
                    if contains(line, b"\"result\"") || contains(line, b"\"error\"") {
                        responses.push(line.to_vec());
                    } else {
                        notifications.push(line.to_vec());
                    }
                });
            }
            Ok(Err(_)) => break,       // read error
            Err(_) => break,           // idle timeout: replay burst is done
        }
    }

    // Send replay: all responses first, then all notifications (Go order).
    for line in responses.iter().chain(notifications.iter()) {
        if ws_tx
            .send(WsMessage::Text(String::from_utf8_lossy(line).into_owned().into()))
            .await
            .is_err()
        {
            return;
        }
    }

    // --- Phase 2: live bridge, both directions, until either side closes -----
    // browser -> socket (queue each frame as a line on the writer task)
    let b2s_tx = sock_tx.clone();
    let b2s = async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                WsMessage::Text(t) => {
                    let mut line = t.as_bytes().to_vec();
                    line.push(b'\n');
                    if b2s_tx.send(line).is_err() {
                        break;
                    }
                }
                WsMessage::Close(_) => break,
                _ => {}
            }
        }
    };

    // socket -> browser (with local fs reverse-call handling; fs replies are
    // queued back to the writer task via sock_tx).
    let s2b = async {
        // Flush any leftover bytes captured during the replay read first.
        let mut pending = std::mem::take(&mut buf);
        {
            let mut consumed = Vec::new();
            drain_lines(&mut pending, |line| consumed.push(line.to_vec()));
            for line in consumed {
                if !forward_or_handle(&line, &mut ws_tx, &sock_tx).await {
                    return;
                }
            }
        }

        let mut tmp = vec![0u8; 256 * 1024];
        loop {
            match sock_rd.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    pending.extend_from_slice(&tmp[..n]);
                    let mut consumed = Vec::new();
                    drain_lines(&mut pending, |line| consumed.push(line.to_vec()));
                    for line in consumed {
                        if !forward_or_handle(&line, &mut ws_tx, &sock_tx).await {
                            return;
                        }
                    }
                }
            }
        }
    };

    // Either direction ending tears down the bridge.
    tokio::select! {
        _ = b2s => {},
        _ = s2b => {},
    }
    // Drop the senders so the writer task drains and exits, then reap it.
    drop(sock_tx);
    writer_task.abort();
}

/// Forward one socket line to the browser, UNLESS it's an fs reverse-call we
/// answer locally (queuing the response back to the socket writer task).
/// Returns false if the WS send failed (bridge should stop).
async fn forward_or_handle(
    line: &[u8],
    ws_tx: &mut WsSink,
    sock_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> bool {
    if let Some(mut resp) = handle_reverse_call(line) {
        resp.push(b'\n');
        let _ = sock_tx.send(resp);
        return true;
    }
    ws_tx
        .send(WsMessage::Text(String::from_utf8_lossy(line).into_owned().into()))
        .await
        .is_ok()
}

/// If `line` is an fs reverse-call from the agent, handle it on the server's
/// filesystem and return the JSON-RPC response bytes. Else `None` (forward to
/// browser). Mirrors Go `handleReverseCall`.
fn handle_reverse_call(line: &[u8]) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let method = v.get("method")?.as_str()?;
    let id = v.get("id")?;
    if id.is_null() {
        return None;
    }
    let params = v.get("params");
    match method {
        "fs/read_text_file" => Some(handle_fs_read(id, params)),
        "fs/write_text_file" => Some(handle_fs_write(id, params)),
        _ => None,
    }
}

fn rpc_result(id: &Value, result: Value) -> Vec<u8> {
    json!({"jsonrpc":"2.0","id":id,"result":result})
        .to_string()
        .into_bytes()
}
fn rpc_error(id: &Value, code: i64, message: &str) -> Vec<u8> {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
        .to_string()
        .into_bytes()
}

fn handle_fs_read(id: &Value, params: Option<&Value>) -> Vec<u8> {
    let p = match params {
        Some(p) => p,
        None => return rpc_error(id, -32602, "invalid params"),
    };
    let path = match p.get("path").and_then(|p| p.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return rpc_error(id, -32602, "invalid params"),
    };
    // SECURITY (task 11): unconstrained read — must be path-guarded before
    // the server is exposed. Faithful to Go for now; flagged.
    let mut content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return rpc_error(id, -32000, &e.to_string()),
    };
    // Optional 1-based line offset + limit.
    let line = p.get("line").and_then(|l| l.as_i64());
    let limit = p.get("limit").and_then(|l| l.as_i64());
    if line.is_some() || limit.is_some() {
        let lines: Vec<&str> = content.split('\n').collect();
        let start = line.filter(|l| *l > 1).map(|l| (l - 1) as usize).unwrap_or(0);
        let start = start.min(lines.len());
        let mut slice = &lines[start..];
        if let Some(lim) = limit {
            let lim = (lim as usize).min(slice.len());
            slice = &slice[..lim];
        }
        content = slice.join("\n");
    }
    rpc_result(id, json!({"content": content}))
}

fn handle_fs_write(id: &Value, params: Option<&Value>) -> Vec<u8> {
    let p = match params {
        Some(p) => p,
        None => return rpc_error(id, -32602, "invalid params"),
    };
    let path = match p.get("path").and_then(|p| p.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return rpc_error(id, -32602, "invalid params"),
    };
    let content = p.get("content").and_then(|c| c.as_str()).unwrap_or("");
    // SECURITY (task 11): unconstrained write to ANY path the agent names —
    // must be path-guarded before exposure. Faithful to Go for now; flagged.
    match std::fs::write(path, content) {
        Ok(()) => rpc_result(id, json!({})),
        Err(e) => rpc_error(id, -32000, &e.to_string()),
    }
}

// --- ndjson helpers --------------------------------------------------------

/// Pull every complete `\n`-terminated line out of `buf`, calling `f` on each
/// (without the newline), leaving any trailing partial line in `buf`.
fn drain_lines(buf: &mut Vec<u8>, mut f: impl FnMut(&[u8])) {
    let mut start = 0;
    while let Some(rel) = memchr(b'\n', &buf[start..]) {
        let end = start + rel;
        let line = &buf[start..end];
        if !line.is_empty() {
            f(line);
        }
        start = end + 1;
    }
    if start > 0 {
        buf.drain(..start);
    }
}

fn memchr(needle: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|&b| b == needle)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// Keep RawValue referenced so the json feature stays exercised (avoids a
// spurious unused warning during incremental builds of this module).
#[allow(dead_code)]
fn _raw(_: &RawValue) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_lines_splits_and_keeps_partial() {
        let mut buf = b"a\nbb\nccc".to_vec();
        let mut got = Vec::new();
        drain_lines(&mut buf, |l| got.push(String::from_utf8_lossy(l).into_owned()));
        assert_eq!(got, vec!["a", "bb"]);
        assert_eq!(buf, b"ccc"); // partial remainder kept
    }

    #[test]
    fn reverse_call_ignores_non_fs() {
        let line = br#"{"jsonrpc":"2.0","method":"session/update","params":{}}"#;
        assert!(handle_reverse_call(line).is_none());
        // a response (no method) is not a reverse call
        let resp = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert!(handle_reverse_call(resp).is_none());
    }

    #[test]
    fn fs_read_roundtrips_a_temp_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("acp-mobile-fs-read-test.txt");
        std::fs::write(&path, "line1\nline2\nline3\n").unwrap();
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"fs/read_text_file","params":{{"path":"{}"}}}}"#,
            path.display()
        );
        let resp = handle_reverse_call(line.as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["id"], 7);
        assert!(v["result"]["content"].as_str().unwrap().contains("line2"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fs_read_with_line_and_limit() {
        let dir = std::env::temp_dir();
        let path = dir.join("acp-mobile-fs-read-limit.txt");
        std::fs::write(&path, "a\nb\nc\nd\ne\n").unwrap();
        // line 2, limit 2 -> "b\nc"
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{{"path":"{}","line":2,"limit":2}}}}"#,
            path.display()
        );
        let resp = handle_reverse_call(line.as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["result"]["content"], "b\nc");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fs_read_missing_path_is_error() {
        let line = br#"{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{}}"#;
        let resp = handle_reverse_call(line).unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32602);
    }

    #[test]
    fn fs_write_creates_file_and_acks() {
        let path = std::env::temp_dir().join("acp-mobile-fs-write-test.txt");
        let _ = std::fs::remove_file(&path);
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"fs/write_text_file","params":{{"path":"{}","content":"hello bridge"}}}}"#,
            path.display()
        );
        let resp = handle_reverse_call(line.as_bytes()).unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["id"], 3);
        assert!(v["result"].is_object(), "write acks with a result");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello bridge");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fs_write_missing_path_is_error() {
        let line = br#"{"jsonrpc":"2.0","id":1,"method":"fs/write_text_file","params":{"content":"x"}}"#;
        let resp = handle_reverse_call(line).unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32602);
    }

    /// Replay classification: a response (has "result") sorts before a
    /// notification. We test the predicate the bridge uses to split the burst.
    #[test]
    fn replay_classifies_responses_vs_notifications() {
        let response = br#"{"jsonrpc":"2.0","id":0,"result":{"x":1}}"#;
        let error_resp = br#"{"jsonrpc":"2.0","id":0,"error":{"code":-1}}"#;
        let notification = br#"{"jsonrpc":"2.0","method":"session/update","params":{}}"#;
        assert!(contains(response, b"\"result\""));
        assert!(contains(error_resp, b"\"error\""));
        assert!(!contains(notification, b"\"result\"") && !contains(notification, b"\"error\""));
    }
}
