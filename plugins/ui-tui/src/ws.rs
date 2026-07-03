//! WebSocket client for the daemon's `/api/stream` endpoint.
//!
//! Mirrors the `ui-web` design: connect, parse each frame as `Msg`, dispatch
//! into the main loop. Reconnect with bounded exponential backoff.

use std::time::Duration;

use anyhow::Context as _;
use futures_util::StreamExt;
use hiveguard_ui::Msg;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tokio_util::sync::CancellationToken;

/// Convert a HTTP base URL into a WS URL pointing at `/api/stream`.
pub fn stream_url(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    let ws = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{}", rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{}", rest)
    } else {
        // Assume bare host:port → ws.
        format!("ws://{}", trimmed)
    };
    format!("{ws}/api/stream")
}

/// Run the connect-loop until `shutdown` fires. Each parsed frame is sent
/// through `tx`; lifecycle events (`Connecting` / `ConnectionFailed`) are
/// also emitted so the UI can reflect them.
pub async fn connect_loop(
    url: String,
    token: Option<String>,
    tx: mpsc::Sender<Msg>,
    shutdown: CancellationToken,
) {
    let mut backoff = Duration::from_millis(500);
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        let _ = tx.send(Msg::Connecting).await;

        // tokio-tungstenite picks up the bearer token via the request builder.
        let request = build_request(&url, token.as_deref());

        match request {
            Err(e) => {
                let _ = tx
                    .send(Msg::ConnectionFailed(format!("bad ws url: {e}")))
                    .await;
            }
            Ok(req) => {
                match connect_async(req).await {
                    Ok((ws, _)) => {
                        backoff = Duration::from_millis(500); // reset on success
                        run_session(ws, &tx, &shutdown).await;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Msg::ConnectionFailed(format!("connect: {e}")))
                            .await;
                    }
                }
            }
        }

        // Backoff then retry — or exit on shutdown.
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown.cancelled() => return,
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

fn build_request(
    url: &str,
    token: Option<&str>,
) -> anyhow::Result<tokio_tungstenite::tungstenite::http::Request<()>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut req = url.into_client_request().context("parse ws url")?;
    if let Some(t) = token {
        req.headers_mut()
            .insert("Authorization", format!("Bearer {t}").parse().unwrap());
    }
    Ok(req)
}

async fn run_session<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    tx: &mpsc::Sender<Msg>,
    shutdown: &CancellationToken,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (_sink, mut stream) = ws.split();
    let mut first_frame = true;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            frame = stream.next() => {
                match frame {
                    Some(Ok(WsMessage::Text(text))) => {
                        match serde_json::from_str::<Msg>(&text) {
                            Ok(parsed) => {
                                let _ = tx.send(parsed).await;
                            }
                            Err(e) => {
                                if first_frame {
                                    // Synthesise Connected so the UI doesn't stick on "Connecting".
                                    let _ = tx
                                        .send(Msg::Connected {
                                            node_name: "unknown".into(),
                                            version: "unknown".into(),
                                        })
                                        .await;
                                } else {
                                    eprintln!("ui-tui: dropped malformed frame: {e}");
                                }
                            }
                        }
                        first_frame = false;
                    }
                    Some(Ok(WsMessage::Binary(_))) => {
                        // Ignore for now — protocol is JSON.
                    }
                    Some(Ok(WsMessage::Close(_))) | None => {
                        let _ = tx
                            .send(Msg::ConnectionFailed("socket closed".into()))
                            .await;
                        return;
                    }
                    Some(Ok(_)) => {} // ping / pong handled by tungstenite
                    Some(Err(e)) => {
                        let _ = tx
                            .send(Msg::ConnectionFailed(format!("ws error: {e}")))
                            .await;
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_url_promotes_http_to_ws() {
        assert_eq!(
            stream_url("http://localhost:8443"),
            "ws://localhost:8443/api/stream"
        );
        assert_eq!(
            stream_url("https://node.example.com/"),
            "wss://node.example.com/api/stream"
        );
        assert_eq!(stream_url("h:9"), "ws://h:9/api/stream");
    }
}
