//! Session discovery + probe.
//!
//! Finds live acp-multiplex sockets (this server discovers sessions from ANY
//! proxy, not ones it spawned), then PROBES each by connecting and reading its
//! replay burst to extract a human-facing session summary: the buffer name
//! (`acp-multiplex/meta`), agent title (`initialize` response), session id, and
//! project (basename of the proxy process's cwd).
//!
//! The socket layout is the shared wire contract with acp-multiplex (documented
//! in docs/acp-protocol-spec.org). We copy — not link — the proxy's discovery
//! primitives so the two repos stay decoupled; the protocol is the interface.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::time::timeout;

/// Socket directory: `$XDG_RUNTIME_DIR/acp-multiplex/` (fallback `$TMPDIR`).
pub fn socket_dir() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("acp-multiplex")
}

/// Resolve a pid string to its socket path (new layout, then legacy). Used by
/// the WS bridge: the browser passes `?sock=<pid>`. Returns `None` if neither
/// exists. Mirrors Go `findSocket`.
pub fn find_socket(pid: &str) -> Option<PathBuf> {
    let primary = socket_dir().join(format!("{pid}.sock"));
    if primary.exists() {
        return Some(primary);
    }
    // Legacy layout some older proxies used.
    let legacy = std::env::temp_dir().join(format!("acp-multiplex-{pid}.sock"));
    if legacy.exists() {
        return Some(legacy);
    }
    None
}

fn pid_of(name: &str) -> Option<i32> {
    name.strip_suffix(".sock")?.parse::<i32>().ok()
}

fn pid_alive(pid: i32) -> bool {
    // SAFETY: kill(pid, 0) only probes existence/permission, sends no signal.
    unsafe { kill(pid, 0) == 0 }
}

extern "C" {
    #[link_name = "kill"]
    fn kill(pid: i32, sig: i32) -> i32;
}

/// A live session socket and the pid that owns it.
#[derive(Debug, Clone)]
pub struct LiveSocket {
    pub pid: i32,
    pub path: PathBuf,
}

/// List live proxy sockets, removing dead ones as a side effect. Scans the new
/// layout plus the legacy `$TMPDIR/acp-multiplex-<pid>.sock` (Go-compat).
pub fn list_sockets() -> Vec<LiveSocket> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // New layout.
    if let Ok(entries) = std::fs::read_dir(socket_dir()) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if let Some(pid) = pid_of(&name) {
                if pid_alive(pid) {
                    seen.insert(pid);
                    out.push(LiveSocket { pid, path: e.path() });
                } else {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
    // Legacy layout in $TMPDIR.
    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name
                .strip_prefix("acp-multiplex-")
                .and_then(|s| s.strip_suffix(".sock"))
            {
                if let Ok(pid) = rest.parse::<i32>() {
                    if seen.contains(&pid) {
                        continue;
                    }
                    if pid_alive(pid) {
                        out.push(LiveSocket { pid, path: e.path() });
                    } else {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }
    }
    out
}

/// A probed session, ready to serialize into `/api/sessions`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SessionInfo {
    pub pid: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub buffer_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cwd: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub project: String,
}

/// The proxy process's cwd: `lsof` on macOS (no `/proc`). Mirrors Go
/// `processCwd`. Empty string if it can't be determined.
fn process_cwd(pid: i32) -> String {
    // Linux fast path: /proc/<pid>/cwd.
    if let Ok(target) = std::fs::read_link(format!("/proc/{pid}/cwd")) {
        return target.to_string_lossy().into_owned();
    }
    // macOS: lsof -a -d cwd -p <pid> -Fn ; the cwd line starts with "n/".
    let out = std::process::Command::new("lsof")
        .args(["-a", "-d", "cwd", "-p", &pid.to_string(), "-Fn"])
        .output();
    if let Ok(out) = out {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(path) = line.strip_prefix("n/") {
                return format!("/{path}");
            }
        }
    }
    String::new()
}

/// Connect to a socket and read its replay burst, pulling out the session
/// summary. Bounded by a short timeout so a misbehaving socket can't hang the
/// listing. Mirrors Go `probeSocket`.
pub async fn probe(sock: &LiveSocket) -> SessionInfo {
    let mut info = SessionInfo {
        pid: sock.pid,
        ..Default::default()
    };
    info.cwd = process_cwd(sock.pid);
    if !info.cwd.is_empty() {
        info.project = Path::new(&info.cwd)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
    }

    let stream = match timeout(Duration::from_millis(500), UnixStream::connect(&sock.path)).await {
        Ok(Ok(s)) => s,
        _ => return info,
    };
    // Read whatever the replay sends within the window, then parse lines.
    let mut buf = Vec::new();
    let _ = timeout(Duration::from_millis(500), read_some(stream, &mut buf)).await;

    for line in buf.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // acp-multiplex/meta -> buffer name.
        if v.get("method").and_then(|m| m.as_str()) == Some("acp-multiplex/meta") {
            if let Some(name) = v.pointer("/params/name").and_then(|n| n.as_str()) {
                info.buffer_name = name.to_string();
            }
            continue;
        }
        // result-bearing lines -> agentInfo.title, sessionId, cwd.
        if let Some(result) = v.get("result") {
            if let Some(t) = result.pointer("/agentInfo/title").and_then(|t| t.as_str()) {
                info.title = t.to_string();
            } else if let Some(n) = result.pointer("/agentInfo/name").and_then(|n| n.as_str()) {
                if info.title.is_empty() {
                    info.title = n.to_string();
                }
            }
            if let Some(sid) = result.get("sessionId").and_then(|s| s.as_str()) {
                info.session_id = sid.to_string();
            }
            if let Some(c) = result.get("cwd").and_then(|c| c.as_str()) {
                info.cwd = c.to_string();
                info.project = Path::new(c)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
            }
        }
    }
    info
}

/// Read until the stream goes idle/EOF or the buffer is reasonably full.
async fn read_some(mut stream: UnixStream, buf: &mut Vec<u8>) {
    let mut tmp = [0u8; 64 * 1024];
    loop {
        match stream.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 1024 * 1024 {
                    break; // enough for a summary
                }
            }
            Err(_) => break,
        }
    }
}

/// Discover and probe all live sessions, concurrently.
pub async fn discover_sessions() -> Vec<SessionInfo> {
    let socks = list_sockets();
    let mut handles = Vec::new();
    for s in socks {
        handles.push(tokio::spawn(async move { probe(&s).await }));
    }
    let mut out = Vec::new();
    for h in handles {
        if let Ok(info) = h.await {
            out.push(info);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_parsing() {
        assert_eq!(pid_of("12345.sock"), Some(12345));
        assert_eq!(pid_of("nope.sock"), None);
    }

    #[test]
    fn current_pid_alive_improbable_dead() {
        assert!(pid_alive(std::process::id() as i32));
        assert!(!pid_alive(1 << 30));
    }

    #[test]
    fn find_socket_resolves_a_created_socket() {
        let pid = std::process::id();
        let dir = socket_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{pid}.sock"));
        let _ = std::fs::remove_file(&path);
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(find_socket(&pid.to_string()), Some(path.clone()));
        let _ = std::fs::remove_file(&path);
    }

    /// Live smoke test: discover + probe whatever real proxy sessions exist.
    /// Ignored by default (needs a running `acp-multiplex`); run explicitly with
    /// `cargo test discover_live -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn discover_live() {
        let sessions = discover_sessions().await;
        eprintln!("discovered {} live session(s):", sessions.len());
        for s in &sessions {
            eprintln!("  {}", serde_json::to_string(s).unwrap());
        }
        assert!(!sessions.is_empty(), "expected at least one live proxy session");
    }

    /// Probe parsing against a synthetic replay (no real proxy needed): a meta
    /// notification + an initialize result + a session/new result.
    #[tokio::test]
    async fn probe_extracts_summary_from_replay() {
        // Spin a one-shot unix server that emits a canned replay and closes.
        let pid = std::process::id() as i32;
        let dir = socket_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("probe-test-{pid}.sock"));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        let server_path = path.clone();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let replay = concat!(
                    r#"{"jsonrpc":"2.0","method":"acp-multiplex/meta","params":{"name":"claude @ proj"}}"#, "\n",
                    r#"{"jsonrpc":"2.0","id":0,"result":{"agentInfo":{"title":"Claude Agent"}}}"#, "\n",
                    r#"{"jsonrpc":"2.0","id":0,"result":{"sessionId":"sess-123","cwd":"/Users/me/code/myproj"}}"#, "\n",
                );
                let _ = conn.write_all(replay.as_bytes()).await;
                let _ = conn.flush().await;
            }
            let _ = std::fs::remove_file(&server_path);
        });

        let info = probe(&LiveSocket { pid, path: path.clone() }).await;
        assert_eq!(info.buffer_name, "claude @ proj");
        assert_eq!(info.title, "Claude Agent");
        assert_eq!(info.session_id, "sess-123");
        assert_eq!(info.project, "myproj");
        let _ = std::fs::remove_file(&path);
    }
}
