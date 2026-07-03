use std::net::SocketAddr;

use async_trait::async_trait;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use hiveguard_core::models::GeoIpInfo;

use crate::error::PluginResult;
use crate::traits::Plugin;

/// Categorical alert type — used by destinations to opt in / out of specific
/// classes of events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertKind {
    IpBanned,
    SubnetBanned,
    HighThreatDetected,
    HoneypotHit,
    PeerDown,
    PeerQuarantined,
    BanRateAnomaly,
}

/// Payload delivered to a notifier.
///
/// This mirrors the variants previously baked into the daemon's
/// `alert_manager::AlertEvent`, but lifted into the plugin API so it can be
/// shared by every notifier crate without depending on the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertEvent {
    IpBanned {
        ip: IpNet,
        severity: u8,
        reason: String,
        geo: Option<GeoIpInfo>,
    },
    SubnetBanned {
        subnet: IpNet,
        ip_count: u32,
        reason: String,
    },
    PeerDown {
        node_id: String,
        address: SocketAddr,
    },
    PeerQuarantined {
        node_id: String,
        reason: String,
    },
    HighThreatDetected {
        ip: String,
        score: f64,
        top_detectors: Vec<String>,
    },
    HoneypotHit {
        ip: String,
        path: String,
    },
    BanRateAnomaly {
        bans_per_minute: u32,
        threshold: u32,
    },
}

impl AlertEvent {
    pub fn kind(&self) -> AlertKind {
        match self {
            AlertEvent::IpBanned { .. } => AlertKind::IpBanned,
            AlertEvent::SubnetBanned { .. } => AlertKind::SubnetBanned,
            AlertEvent::HighThreatDetected { .. } => AlertKind::HighThreatDetected,
            AlertEvent::HoneypotHit { .. } => AlertKind::HoneypotHit,
            AlertEvent::PeerDown { .. } => AlertKind::PeerDown,
            AlertEvent::PeerQuarantined { .. } => AlertKind::PeerQuarantined,
            AlertEvent::BanRateAnomaly { .. } => AlertKind::BanRateAnomaly,
        }
    }
}

/// Push notifier — Slack, Teams, PagerDuty, Discord, webhook, email, …
///
/// Notifiers are stateless from the host's perspective: each call to
/// `notify` is independent. Deduplication and rate-limiting live in the
/// alert dispatcher inside `hiveguard-host`, not in individual plugins.
#[async_trait]
pub trait NotifierPlugin: Plugin {
    /// Deliver one alert. Errors are logged and counted but do not stop the
    /// dispatcher; the dispatcher decides retry policy.
    async fn notify(&self, event: &AlertEvent) -> PluginResult<()>;

    /// Does this notifier care about events of `kind`? Default impl accepts
    /// every kind — override to declare a narrower filter.
    fn supports(&self, _kind: AlertKind) -> bool {
        true
    }
}
