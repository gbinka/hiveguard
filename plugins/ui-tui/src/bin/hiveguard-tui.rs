//! Standalone `hiveguard-tui` binary.
//!
//! Connect to a remote daemon over REST + WebSocket and present the same
//! UI as the embedded plugin form. Built from the same `hiveguard-ui`
//! crate so any state-change goes through `update(model, msg)`.

use clap::Parser;
use hiveguard_plugin_ui_tui::app;

#[derive(Parser, Debug)]
#[command(name = "hiveguard-tui", version, about = "HiveGuard terminal UI")]
struct Cli {
    /// Daemon base URL — e.g. `http://localhost:8443`. WebSocket and REST
    /// endpoints are derived from this.
    #[arg(long, default_value = "http://localhost:8443")]
    server: String,

    /// Bearer token for the daemon. Reads the `HIVEGUARD_TOKEN` env var
    /// when not provided on the command line.
    #[arg(long, env = "HIVEGUARD_TOKEN")]
    token: Option<String>,

    /// Skip TLS certificate verification. Useful for dev / self-signed
    /// certs; never use this in production.
    #[arg(long)]
    insecure: bool,

    /// REST polling interval (seconds). The WS push is the primary data
    /// source; polling is a fallback for when WS isn't available.
    #[arg(long, default_value = "5")]
    poll_secs: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let cfg = app::Config {
        server: cli.server,
        token: cli.token,
        insecure: cli.insecure,
        poll_secs: cli.poll_secs,
    };

    app::run(cfg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parses_defaults() {
        let cli = Cli::parse_from(["hiveguard-tui"]);
        assert_eq!(cli.server, "http://localhost:8443");
        assert!(cli.token.is_none());
        assert!(!cli.insecure);
        assert_eq!(cli.poll_secs, 5);
    }

    #[test]
    fn cli_accepts_overrides() {
        let cli = Cli::parse_from([
            "hiveguard-tui",
            "--server",
            "https://node.example.com",
            "--token",
            "abc",
            "--insecure",
            "--poll-secs",
            "10",
        ]);
        assert_eq!(cli.server, "https://node.example.com");
        assert_eq!(cli.token.as_deref(), Some("abc"));
        assert!(cli.insecure);
        assert_eq!(cli.poll_secs, 10);
    }
}
