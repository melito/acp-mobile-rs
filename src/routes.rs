//! HTTP + WebSocket routes, wired through stonehm so the JSON API gets OpenAPI
//! docs for free (`/openapi.json`, `/openapi.yaml`). The route set matches what
//! the reused `index.html` calls (verified against the file):
//!   GET  /                index.html with a per-request CSP nonce
//!   GET  /ws?sock=<pid>   WebSocket bridge to a session's unix socket
//!   POST /api/sessions    discover + probe live proxy sessions
//!   POST /files/list      list a directory (path-guarded in task 11)
//!   POST /files/read      read a file (path-guarded in task 11)
//!   GET  /openapi.json|yaml  (added by stonehm)
//!
//! Security (auth, CSRF, DNS-rebind, CSP nonce, path guards) is layered OVER
//! this as middleware in task 11; these handlers are the inner app.

use axum::{
    extract::{Query, WebSocketUpgrade},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use stonehm::api_router;
use stonehm_macros::{api_error, api_handler, StonehmSchema};

use crate::bridge::bridge;
use crate::discovery::{discover_sessions, find_socket, SessionInfo};

/// The reused mobile UI. Embedded at build time; `__CSP_NONCE__` is replaced
/// per request once the security layer supplies a nonce (task 11). For now we
/// strip the placeholder so the page renders standalone during development.
const INDEX_HTML: &str = include_str!("../static/index.html");

// --- error type shared by the JSON API ------------------------------------

// NB: `#[api_error]` (stonehm 0.2.2) generates `IntoResponse` + `StonehmSchema`
// but NOT `Serialize` (the README overstates this), and its IntoResponse body
// serializes the enum — so we derive Serialize ourselves.
// BadRequest/Internal are part of the API surface (request validation +
// failures in the security/validation layer, task 11) but not constructed yet.
#[allow(dead_code)]
#[derive(Serialize)]
#[api_error]
pub enum ApiError {
    /// 400: Bad request
    BadRequest,
    /// 404: Session or socket not found
    NotFound,
    /// 500: Internal server error
    Internal,
}

// --- /api/sessions ---------------------------------------------------------

/// `SessionInfo` reused from discovery; re-derive the schema marker here so
/// stonehm can document it. (discovery::SessionInfo already derives Serialize.)
#[derive(Debug, Serialize, StonehmSchema)]
pub struct SessionList {
    pub sessions: Vec<SessionRow>,
}

/// A flattened session row for the API (mirrors discovery::SessionInfo fields).
///
/// `camelCase` on the wire: the reused `index.html` (written against the Go
/// server) reads `.bufferName`/`.sessionId`, so we must emit the Go server's
/// JSON shape, NOT Rust-idiomatic snake_case. When you reuse a frontend, ITS
/// expectations are the wire contract.
#[derive(Debug, Serialize, StonehmSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionRow {
    pub pid: i32,
    pub buffer_name: String,
    pub title: String,
    pub session_id: String,
    pub cwd: String,
    pub project: String,
}

impl From<SessionInfo> for SessionRow {
    fn from(s: SessionInfo) -> Self {
        SessionRow {
            pid: s.pid,
            buffer_name: s.buffer_name,
            title: s.title,
            session_id: s.session_id,
            cwd: s.cwd,
            project: s.project,
        }
    }
}

/// List live agent sessions.
///
/// Discovers all running acp-multiplex sockets, probes each for its session
/// summary (name, agent title, session id, project), and returns them.
#[api_handler]
async fn list_sessions() -> Result<Json<SessionList>, ApiError> {
    let sessions = discover_sessions()
        .await
        .into_iter()
        .map(SessionRow::from)
        .collect();
    Ok(Json(SessionList { sessions }))
}

// --- /files/list, /files/read ----------------------------------------------

/// `/files/read` request, and the base of `/files/list` (which adds showHidden).
#[derive(Debug, Deserialize, StonehmSchema)]
pub struct PathRequest {
    /// Absolute filesystem path.
    pub path: String,
}

/// `/files/list` request: a path plus whether to include dotfiles. Matches the
/// `{path, showHidden}` body index.html sends.
#[derive(Debug, Deserialize, StonehmSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListRequest {
    pub path: String,
    #[serde(default)]
    pub show_hidden: bool,
}

/// One directory entry. `camelCase` to match index.html's `f.isDir`/`f.size`.
#[derive(Debug, Serialize, StonehmSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

/// `/files/list` response: the resolved path + its files. index.html reads
/// `data.path` and `data.files` (NOT `entries`).
#[derive(Debug, Serialize, StonehmSchema)]
pub struct DirListing {
    pub path: String,
    pub files: Vec<FileEntry>,
}

/// List a directory.
///
/// Returns `path` and its `files` (each with name/isDir/size). Dotfiles are
/// included only when `showHidden` is set. (Restricted to session working
/// directories by the security layer; unrestricted here.)
#[api_handler]
async fn files_list(Json(req): Json<ListRequest>) -> Result<Json<DirListing>, ApiError> {
    let mut files = Vec::new();
    let mut rd = tokio::fs::read_dir(&req.path)
        .await
        .map_err(|_| ApiError::NotFound)?;
    while let Ok(Some(e)) = rd.next_entry().await {
        let name = e.file_name().to_string_lossy().into_owned();
        if !req.show_hidden && name.starts_with('.') {
            continue;
        }
        let meta = e.metadata().await.ok();
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        files.push(FileEntry { name, is_dir, size });
    }
    // Directories first, then alphabetical (matches a typical file browser).
    files.sort_by(|a, b| (b.is_dir, &a.name).cmp(&(a.is_dir, &b.name)));
    Ok(Json(DirListing {
        path: req.path,
        files,
    }))
}

#[derive(Debug, Serialize, StonehmSchema)]
pub struct FileContent {
    pub content: String,
}

/// Read a file.
///
/// Returns the UTF-8 contents of `path`. (Restricted to session working
/// directories by the security layer; unrestricted here.)
#[api_handler]
async fn files_read(Json(req): Json<PathRequest>) -> Result<Json<FileContent>, ApiError> {
    let content = tokio::fs::read_to_string(&req.path)
        .await
        .map_err(|_| ApiError::NotFound)?;
    Ok(Json(FileContent { content }))
}

// --- / (index) and /ws (websocket) -----------------------------------------

/// Serve the mobile UI. The CSP nonce is injected by the security middleware;
/// here we just substitute an empty token so the page is self-contained in dev.
async fn index() -> Html<String> {
    Html(INDEX_HTML.replace("__CSP_NONCE__", ""))
}

#[derive(Debug, Deserialize)]
struct WsQuery {
    sock: Option<String>,
}

/// Upgrade to a WebSocket and bridge it to the session socket named by `?sock`.
async fn ws_handler(ws: WebSocketUpgrade, Query(q): Query<WsQuery>) -> Response {
    let pid = match q.sock {
        Some(p) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => p,
        _ => return (axum::http::StatusCode::BAD_REQUEST, "missing/invalid sock").into_response(),
    };
    let sock_path = match find_socket(&pid) {
        Some(p) => p,
        None => return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response(),
    };
    ws.on_upgrade(move |socket| bridge(socket, sock_path))
}

/// Build the inner application router (no security middleware yet — that wraps
/// this in task 11). stonehm gives the JSON API its OpenAPI docs.
pub fn app() -> Router {
    api_router!("acp-mobile", env!("CARGO_PKG_VERSION"))
        .post("/api/sessions", list_sessions)
        .post("/files/list", files_list)
        .post("/files/read", files_read)
        .with_openapi_routes()
        .into_router()
        // Non-documented routes (HTML + WS) added directly.
        .route("/", get(index))
        .route("/ws", get(ws_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for oneshot

    #[tokio::test]
    async fn index_serves_html_without_nonce_placeholder() {
        let app = app();
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("<!"), "looks like html");
        assert!(!html.contains("__CSP_NONCE__"), "placeholder substituted");
    }

    #[tokio::test]
    async fn openapi_json_is_served() {
        let app = app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // NOTE: we only assert the route EXISTS and serves JSON here. We do NOT
        // assert spec *contents* in a unit test, because stonehm registers route
        // metadata via the `inventory` crate, whose link-section statics the test
        // harness's linker can dead-strip (a known `inventory` limitation) — so
        // `paths` is unreliably empty under `cargo test` even though the real
        // BINARY serves the full spec (verified by curl in the task-12 smoke
        // test). Content correctness is asserted against the running binary, not
        // here.
        //
        // Separately: stonehm 0.2.2 double-encodes this body (serves a JSON
        // *string* containing the JSON, not a JSON object). Tracked as an
        // upstream fix in ~/code/keystone; harmless for now (the spec is valid
        // after one extra parse). So we just confirm a 200 + non-empty body.
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty());
        // It should at least be valid JSON (string or object).
        let _: serde_json::Value = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    async fn ws_rejects_missing_sock() {
        let app = app();
        let resp = app
            .oneshot(Request::builder().uri("/ws").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // No upgrade headers + missing sock -> not a successful upgrade.
        assert_ne!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    }

    #[tokio::test]
    async fn files_read_missing_is_404() {
        let app = app();
        let req = Request::builder()
            .uri("/files/read")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"path":"/no/such/file/xyz"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn files_list_filters_hidden_and_sorts_dirs_first() {
        // Build a temp dir with a dotfile, a regular file, and a subdir.
        let base = std::env::temp_dir().join(format!("acp-mobile-list-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("visible.txt"), "x").unwrap();
        std::fs::write(base.join(".hidden"), "x").unwrap();
        std::fs::create_dir(base.join("subdir")).unwrap();

        let call = |show_hidden: bool| {
            let app = app();
            let body = format!(
                r#"{{"path":"{}","showHidden":{}}}"#,
                base.display(),
                show_hidden
            );
            async move {
                let resp = app
                    .oneshot(
                        Request::builder()
                            .uri("/files/list")
                            .method("POST")
                            .header("content-type", "application/json")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }
        };

        // Hidden excluded by default: subdir + visible.txt only, dir first.
        let v = call(false).await;
        let names: Vec<&str> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["subdir", "visible.txt"], "dirs first, no dotfile");
        assert_eq!(v["files"][0]["isDir"], true);
        assert_eq!(v["path"], base.to_string_lossy().as_ref());

        // showHidden=true includes the dotfile.
        let v = call(true).await;
        let names: Vec<&str> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&".hidden"), "showHidden includes dotfiles: {names:?}");

        std::fs::remove_dir_all(&base).ok();
    }

    /// Wire-contract guard: index.html (from the Go server) reads camelCase
    /// fields. This regression was caught by the e2e test; pin it so it can't
    /// silently return. We serialize the structs directly and check key names.
    #[test]
    fn session_and_file_json_use_camelcase() {
        let row = SessionRow {
            pid: 1,
            buffer_name: "b".into(),
            title: "t".into(),
            session_id: "s".into(),
            cwd: "c".into(),
            project: "p".into(),
        };
        let v = serde_json::to_value(&row).unwrap();
        assert!(v.get("bufferName").is_some(), "must be bufferName, not buffer_name");
        assert!(v.get("sessionId").is_some(), "must be sessionId, not session_id");
        assert!(v.get("buffer_name").is_none());

        let listing = DirListing {
            path: "/x".into(),
            files: vec![FileEntry { name: "a".into(), is_dir: true, size: 0 }],
        };
        let v = serde_json::to_value(&listing).unwrap();
        // index.html reads data.path + data.files (NOT entries) and f.isDir.
        assert!(v.get("path").is_some());
        assert!(v.get("files").is_some());
        assert!(v["files"][0].get("isDir").is_some(), "must be isDir, not is_dir");
    }
}


