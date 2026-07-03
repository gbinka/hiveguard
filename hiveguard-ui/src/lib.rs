//! # hiveguard-ui
//!
//! Render-agnostic UI library for HiveGuard. Implements the Elm Architecture
//! / TEA pattern: `AppModel` + `Msg` + `update(model, msg) -> (model, cmds)` +
//! `view(model) -> ViewTree`. The `ViewTree` is a serialisable IR that any
//! renderer can interpret — `plugins/ui-tui` does this with ratatui,
//! `plugins/ui-web` with Leptos (WASM).
//!
//! ## Design
//!
//! - **No async, no tokio** — this library compiles to WASM. All IO happens
//!   in `Cmd` values that the renderer dispatches.
//! - **No platform deps** — no `std::fs`, no `tokio::net`, no `reqwest`. The
//!   `ApiClient` trait is defined here but its implementations live in the
//!   renderer crates.
//! - **Serialisable everywhere** — `AppModel`, `Msg`, `ViewTree` all derive
//!   `Serialize` / `Deserialize` so they can flow over WebSocket between
//!   `ui-rest` (server) and `ui-web` (browser).
//!
//! ## Status — Phase 5
//!
//! Phase 5 fleshes out `AppModel` with `bans`, `threats`, `plugins_status`,
//! and `filters`. `Msg` gains snapshot variants (`BansLoaded`, ...), user
//! actions (`BanRequested`, `UnbanRequested`), and filter mutators. The
//! `ViewTree` IR is intentionally *not* expanded — renderers are free to
//! read the model directly (the IR is a convenience for trivial views).

pub mod client;
pub mod intent;
pub mod model;
pub mod view;

pub use client::{ApiClient, ApiError};
pub use intent::Msg;
pub use model::{
    AppModel, BanRow, ConnectionStatus, FilterState, PluginStatus, ThreatRow, ViewKind,
};
pub use view::ViewTree;

/// Pure state transition function — the Elm-style `update`.
///
/// Takes the current [`AppModel`] and a [`Msg`] (user intent or API event)
/// and returns the next model. No side effects, no IO — all transport /
/// timer effects are dispatched by the renderer after the state mutation.
///
/// Renderers call this from their event loop:
///
/// ```ignore
/// // Leptos (ui-web):
/// signal.update(|m| *m = hiveguard_ui::update(m.clone(), Msg::Connecting));
/// ```
pub fn update(mut model: AppModel, msg: Msg) -> AppModel {
    match msg {
        Msg::NavigateTo(view) => {
            model.view = view;
        }
        Msg::Connecting => {
            model.status = ConnectionStatus::Connecting;
        }
        Msg::Connected { node_name, version } => {
            model.status = ConnectionStatus::Connected;
            model.node_name = node_name;
            model.daemon_version = version;
        }
        Msg::ConnectionFailed(reason) => {
            model.status = ConnectionStatus::Failed(reason);
        }
        Msg::Tick => {
            // Phase 6: refresh counters, expire bans, etc.
        }

        // --- Snapshots ---
        Msg::BansLoaded(rows) => {
            model.bans = rows;
        }
        Msg::ThreatsLoaded(rows) => {
            model.threats = rows;
        }
        Msg::PluginsLoaded(rows) => {
            model.plugins_status = rows;
        }

        // --- User actions ---
        //
        // The `update` function is pure: it does not call the daemon. The
        // renderer's dispatch layer is expected to forward these intents
        // over the WebSocket / REST. We optimistically remove the matching
        // ban so the table updates immediately; if the daemon rejects the
        // unban the next `BansLoaded` snapshot will repair the model.
        Msg::UnbanRequested(subject) => {
            model.bans.retain(|b| b.subject != subject);
        }
        Msg::BanRequested { .. } => {
            // No optimistic insert — we don't have a canonical timestamp
            // until the daemon emits one. The next `BansLoaded` snapshot
            // will surface the new ban.
        }

        // --- Filters ---
        Msg::FilterBansSeverity(v) => {
            model.filters.bans_severity_min = v;
        }
        Msg::FilterBansSearch(s) => {
            model.filters.bans_search = s;
        }
        Msg::FilterThreatsDetector(d) => {
            model.filters.threats_detector = d;
        }
        Msg::FilterThreatsSeverity(v) => {
            model.filters.threats_severity_min = v;
        }

        // --- Dev convenience ---
        Msg::LoadSampleData => {
            model = load_sample_data(model);
        }
    }
    model
}

/// Populate the model with deterministic fake data so the web UI is
/// exercisable without a live daemon. Pure function — fully replaces the
/// `bans`, `threats`, `plugins_status` fields. Idempotent.
fn load_sample_data(mut model: AppModel) -> AppModel {
    model.bans = vec![
        BanRow {
            subject: "192.0.2.10/32".into(),
            severity: 200,
            reason: "Repeated SSH bruteforce".into(),
            expires_at: Some("2026-05-23T18:00:00Z".into()),
            source: "Detector:ssh-bruteforce".into(),
        },
        BanRow {
            subject: "198.51.100.0/24".into(),
            severity: 240,
            reason: "Coordinated scan from netblock".into(),
            expires_at: None,
            source: "ManualAdmin".into(),
        },
        BanRow {
            subject: "203.0.113.42/32".into(),
            severity: 120,
            reason: "Web app probing".into(),
            expires_at: Some("2026-05-23T20:30:00Z".into()),
            source: "ClusterPeer:node-2".into(),
        },
        BanRow {
            subject: "2001:db8::dead/128".into(),
            severity: 80,
            reason: "Sigma rule: WAF anomaly".into(),
            expires_at: Some("2026-05-23T16:00:00Z".into()),
            source: "Detector:sigma".into(),
        },
    ];
    model.threats = vec![
        ThreatRow {
            ip: "192.0.2.10".into(),
            severity: 220,
            confidence: 95,
            detector: "ssh-bruteforce".into(),
            reason: "12 failed logins in 60s".into(),
            timestamp: "2026-05-23T14:21:03Z".into(),
        },
        ThreatRow {
            ip: "203.0.113.42".into(),
            severity: 140,
            confidence: 78,
            detector: "sigma".into(),
            reason: "Suspicious User-Agent: sqlmap".into(),
            timestamp: "2026-05-23T14:18:55Z".into(),
        },
        ThreatRow {
            ip: "198.51.100.7".into(),
            severity: 80,
            confidence: 60,
            detector: "cti".into(),
            reason: "Listed on AbuseIPDB (score 70)".into(),
            timestamp: "2026-05-23T14:15:10Z".into(),
        },
        ThreatRow {
            ip: "192.0.2.99".into(),
            severity: 180,
            confidence: 85,
            detector: "port-scan".into(),
            reason: "SYN scan across 1024 ports".into(),
            timestamp: "2026-05-23T14:11:22Z".into(),
        },
    ];
    model.plugins_status = vec![
        PluginStatus {
            id: "ingest.journald".into(),
            kind: "Source".into(),
            health: "Healthy".into(),
            version: "0.2.0".into(),
        },
        PluginStatus {
            id: "ingest.syslog".into(),
            kind: "Source".into(),
            health: "Healthy".into(),
            version: "0.2.0".into(),
        },
        PluginStatus {
            id: "detect.ssh-bruteforce".into(),
            kind: "Detector".into(),
            health: "Healthy".into(),
            version: "0.2.0".into(),
        },
        PluginStatus {
            id: "detect.sigma".into(),
            kind: "Detector".into(),
            health: "Degraded".into(),
            version: "0.2.0".into(),
        },
        PluginStatus {
            id: "enforce.iptables".into(),
            kind: "Enforcer".into(),
            health: "Healthy".into(),
            version: "0.2.0".into(),
        },
        PluginStatus {
            id: "notify.slack".into(),
            kind: "Notifier".into(),
            health: "Healthy".into(),
            version: "0.2.0".into(),
        },
        PluginStatus {
            id: "siem.splunk".into(),
            kind: "SiemSink".into(),
            health: "Failed".into(),
            version: "0.1.0".into(),
        },
        PluginStatus {
            id: "cti.abuseipdb".into(),
            kind: "Cti".into(),
            health: "Healthy".into(),
            version: "0.2.0".into(),
        },
        PluginStatus {
            id: "score.bayesian".into(),
            kind: "ScoringEngine".into(),
            health: "Healthy".into(),
            version: "0.2.0".into(),
        },
        PluginStatus {
            id: "ui.web".into(),
            kind: "UiServer".into(),
            health: "Healthy".into(),
            version: "0.1.0".into(),
        },
    ];
    if model.node_name.is_empty() {
        model.node_name = "demo-node".into();
    }
    if model.daemon_version.is_empty() {
        model.daemon_version = "0.2.0".into();
    }
    model
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_navigates_between_views() {
        let m = AppModel::default();
        let m = update(m, Msg::NavigateTo(ViewKind::Bans));
        assert_eq!(m.view, ViewKind::Bans);
    }

    #[test]
    fn update_tracks_connection_lifecycle() {
        let m = AppModel::default();
        let m = update(m, Msg::Connecting);
        assert_eq!(m.status, ConnectionStatus::Connecting);
        let m = update(
            m,
            Msg::Connected {
                node_name: "node-1".into(),
                version: "0.2.0".into(),
            },
        );
        assert_eq!(m.status, ConnectionStatus::Connected);
        assert_eq!(m.node_name, "node-1");
        assert_eq!(m.daemon_version, "0.2.0");
        let m = update(m, Msg::ConnectionFailed("dropped".into()));
        assert_eq!(m.status, ConnectionStatus::Failed("dropped".into()));
    }

    #[test]
    fn update_bans_loaded_replaces_snapshot() {
        let m = AppModel::default();
        let rows = vec![BanRow {
            subject: "10.0.0.1/32".into(),
            severity: 200,
            reason: "scan".into(),
            expires_at: None,
            source: "Detector:x".into(),
        }];
        let m = update(m, Msg::BansLoaded(rows.clone()));
        assert_eq!(m.bans, rows);

        // Subsequent snapshot fully replaces — no append.
        let m = update(m, Msg::BansLoaded(vec![]));
        assert!(m.bans.is_empty());
    }

    #[test]
    fn update_threats_and_plugins_loaded() {
        let m = AppModel::default();
        let t = vec![ThreatRow {
            ip: "1.2.3.4".into(),
            severity: 100,
            confidence: 90,
            detector: "d".into(),
            reason: "r".into(),
            timestamp: "2026-05-23T00:00:00Z".into(),
        }];
        let m = update(m, Msg::ThreatsLoaded(t.clone()));
        assert_eq!(m.threats, t);

        let p = vec![PluginStatus {
            id: "ui.web".into(),
            kind: "UiServer".into(),
            health: "Healthy".into(),
            version: "0.1.0".into(),
        }];
        let m = update(m, Msg::PluginsLoaded(p.clone()));
        assert_eq!(m.plugins_status, p);
    }

    #[test]
    fn update_unban_removes_matching_row() {
        let mut m = AppModel::default();
        m.bans = vec![
            BanRow {
                subject: "10.0.0.1/32".into(),
                ..Default::default()
            },
            BanRow {
                subject: "10.0.0.2/32".into(),
                ..Default::default()
            },
        ];
        let m = update(m, Msg::UnbanRequested("10.0.0.1/32".into()));
        assert_eq!(m.bans.len(), 1);
        assert_eq!(m.bans[0].subject, "10.0.0.2/32");

        // Unban of a non-existent subject is a no-op.
        let m = update(m, Msg::UnbanRequested("198.51.100.1/32".into()));
        assert_eq!(m.bans.len(), 1);
    }

    #[test]
    fn update_ban_requested_does_not_optimistically_insert() {
        // BanRequested is forwarded to the daemon; the optimistic strategy
        // would race with the daemon's authoritative snapshot. Verify no
        // local mutation happens.
        let m = AppModel::default();
        let m = update(
            m,
            Msg::BanRequested {
                subject: "10.0.0.5/32".into(),
                duration_secs: 3600,
                reason: "test".into(),
            },
        );
        assert!(m.bans.is_empty());
    }

    #[test]
    fn update_filters_mutate_only_their_slot() {
        let m = AppModel::default();
        let m = update(m, Msg::FilterBansSeverity(100));
        assert_eq!(m.filters.bans_severity_min, 100);
        assert!(m.filters.bans_search.is_empty());

        let m = update(m, Msg::FilterBansSearch("ssh".into()));
        assert_eq!(m.filters.bans_search, "ssh");
        assert_eq!(m.filters.bans_severity_min, 100);

        let m = update(m, Msg::FilterThreatsDetector("sigma".into()));
        assert_eq!(m.filters.threats_detector, "sigma");

        let m = update(m, Msg::FilterThreatsSeverity(50));
        assert_eq!(m.filters.threats_severity_min, 50);
    }

    #[test]
    fn load_sample_data_populates_all_views() {
        let m = AppModel::default();
        let m = update(m, Msg::LoadSampleData);
        assert!(!m.bans.is_empty(), "bans populated");
        assert!(!m.threats.is_empty(), "threats populated");
        assert!(!m.plugins_status.is_empty(), "plugins populated");
        assert_eq!(m.node_name, "demo-node");
        assert_eq!(m.daemon_version, "0.2.0");
    }

    #[test]
    fn msg_serialises_via_serde_json() {
        // The ws.rs envelope decoding relies on serde round-tripping every
        // Msg variant. Pin a couple of representatives so a stray rename
        // doesn't silently break the wire format.
        let m = Msg::BansLoaded(vec![BanRow {
            subject: "10.0.0.1/32".into(),
            severity: 200,
            reason: "x".into(),
            expires_at: None,
            source: "y".into(),
        }]);
        let s = serde_json::to_string(&m).unwrap();
        let _: Msg = serde_json::from_str(&s).unwrap();

        let m = Msg::FilterBansSearch("hello".into());
        let s = serde_json::to_string(&m).unwrap();
        let _: Msg = serde_json::from_str(&s).unwrap();
    }
}
