//! acp-mobile: a hardened mobile web UI for ACP sessions running through
//! acp-multiplex. Discovers live proxy sockets, serves the (reused) index.html,
//! and bridges the browser's WebSocket to a session's Unix socket.
//!
//! Security posture (see docs/acp-protocol-spec.org §"Hardening checklist"):
//! localhost-bound, authkey-gated, CSRF + DNS-rebind protected. With cloudflared
//! (not Tailscale) the app-layer auth is the WHOLE perimeter — keep ALL of it.
//! (Security middleware lands in task 11; this serves the inner app.)

mod bridge;
mod discovery;
mod routes;

use clap::Parser;

/// Mobile web UI for ACP sessions running through acp-multiplex.
///
/// SECURITY: binds 127.0.0.1 by default and currently has NO auth layer (task
/// 11). Do not bind to a non-loopback address or expose via a tunnel until the
/// hardening layer lands.
#[derive(Parser, Debug)]
#[command(name = "acp-mobile", version, about)]
struct Cli {
    /// TCP port to listen on.
    #[arg(short, long, default_value_t = 8090)]
    port: u16,

    /// Address to bind. Defaults to loopback. Overriding this exposes the
    /// (currently unauthenticated) server beyond localhost — don't, until the
    /// security layer exists.
    #[arg(long, default_value = "127.0.0.1")]
    bind: std::net::IpAddr,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let app = routes::app();
    let addr = std::net::SocketAddr::new(cli.bind, cli.port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    eprintln!("acp-mobile: http://{addr}");
    if !cli.bind.is_loopback() {
        eprintln!(
            "acp-mobile: WARNING — bound to non-loopback {} with NO auth layer yet. \
             This exposes unauthenticated agent control. Stop unless you know why.",
            cli.bind
        );
    }
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("acp-mobile").chain(args.iter().copied()))
    }

    #[test]
    fn defaults_to_loopback_8090() {
        let cli = parse(&[]).unwrap();
        assert_eq!(cli.port, 8090);
        assert!(cli.bind.is_loopback());
    }

    #[test]
    fn port_and_bind_flags_parse() {
        let cli = parse(&["--port", "9000", "--bind", "0.0.0.0"]).unwrap();
        assert_eq!(cli.port, 9000);
        assert!(!cli.bind.is_loopback());
        // short -p too
        assert_eq!(parse(&["-p", "1234"]).unwrap().port, 1234);
    }

    #[test]
    fn rejects_bad_port_and_bad_ip() {
        assert!(parse(&["--port", "notaport"]).is_err());
        assert!(parse(&["--bind", "not-an-ip"]).is_err());
        assert!(parse(&["--port", "99999"]).is_err()); // > u16::MAX
    }
}
