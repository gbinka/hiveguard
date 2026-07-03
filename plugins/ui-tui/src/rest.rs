//! REST client for the HiveGuard daemon.
//!
//! Used as a fallback when the WS stream is unavailable, and to bootstrap
//! the initial snapshot (so the user sees data before the WS pushes its
//! first frame). All endpoints return `Vec<...>` shaped JSON.
//!
//! The shape of the daemon-side responses is *not* required to be
//! identical to `hiveguard_ui::BanRow` etc. — we deserialise into the UI
//! types directly for now, but if the daemon's schema diverges, add a
//! `From<…>` adapter here.

use anyhow::{Context, Result};
use hiveguard_ui::model::{BanRow, PluginStatus, ThreatRow};
use reqwest::Client;
use serde::Deserialize;

/// REST client targeting one daemon.
#[derive(Clone)]
pub struct RestClient {
    base: String,
    token: Option<String>,
    http: Client,
}

#[derive(Debug, Deserialize)]
struct BanList {
    #[serde(default)]
    bans: Vec<BanRow>,
}

#[derive(Debug, Deserialize)]
struct ThreatList {
    #[serde(default)]
    threats: Vec<ThreatRow>,
}

#[derive(Debug, Deserialize)]
struct PluginList {
    #[serde(default)]
    plugins: Vec<PluginStatus>,
}

#[derive(Debug, Deserialize)]
pub struct DaemonInfo {
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub version: String,
}

impl RestClient {
    /// Build a client. `insecure=true` skips TLS verification (useful for
    /// self-signed dev certs).
    pub fn new(base: &str, token: Option<String>, insecure: bool) -> Result<Self> {
        let http = Client::builder()
            .danger_accept_invalid_certs(insecure)
            .user_agent(concat!("hiveguard-tui/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("reqwest client build")?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            http,
        })
    }

    fn req(&self, path: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.get(format!("{}{}", self.base, path));
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        req
    }

    /// `GET /api/info` — node name + version.
    pub async fn info(&self) -> Result<DaemonInfo> {
        let resp = self.req("/api/info").send().await.context("info GET")?;
        if !resp.status().is_success() {
            anyhow::bail!("info: HTTP {}", resp.status());
        }
        resp.json::<DaemonInfo>().await.context("info parse")
    }

    /// `GET /api/bans`. Accepts both `{"bans": [...]}` and a bare array.
    pub async fn bans(&self) -> Result<Vec<BanRow>> {
        decode_list::<BanList, BanRow>(self.req("/api/bans"), |x| x.bans).await
    }

    /// `GET /api/threats`.
    pub async fn threats(&self) -> Result<Vec<ThreatRow>> {
        decode_list::<ThreatList, ThreatRow>(self.req("/api/threats"), |x| x.threats).await
    }

    /// `GET /api/plugins`.
    pub async fn plugins(&self) -> Result<Vec<PluginStatus>> {
        decode_list::<PluginList, PluginStatus>(self.req("/api/plugins"), |x| x.plugins).await
    }

    /// `DELETE /api/bans/{subject}`.
    pub async fn unban(&self, subject: &str) -> Result<()> {
        let mut req = self
            .http
            .delete(format!("{}/api/bans/{}", self.base, subject));
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.context("unban DELETE")?;
        if !resp.status().is_success() {
            anyhow::bail!("unban: HTTP {}", resp.status());
        }
        Ok(())
    }
}

/// Accept either a bare array or an object with a single list field.
async fn decode_list<W, T>(req: reqwest::RequestBuilder, extract: fn(W) -> Vec<T>) -> Result<Vec<T>>
where
    W: serde::de::DeserializeOwned,
    T: serde::de::DeserializeOwned,
{
    let resp = req.send().await.context("GET")?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }
    let body = resp.text().await.context("read body")?;
    if let Ok(list) = serde_json::from_str::<Vec<T>>(&body) {
        return Ok(list);
    }
    let wrapped: W = serde_json::from_str(&body).context("parse list response")?;
    Ok(extract(wrapped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_client_builds_with_token() {
        let c = RestClient::new("http://localhost:8443/", Some("abc".into()), false).unwrap();
        assert_eq!(c.base, "http://localhost:8443");
        assert_eq!(c.token.as_deref(), Some("abc"));
    }

    #[test]
    fn rest_client_strips_trailing_slash() {
        let c = RestClient::new("http://h/", None, true).unwrap();
        assert_eq!(c.base, "http://h");
    }
}
