// Stage 3 of INT: `alert_manager` removed — see `hiveguard_host::AlertDispatcher`.
pub mod cli;
#[cfg(feature = "cluster")]
pub mod cluster;
pub mod fail2ban_import;
pub mod metrics;
pub mod pipeline;
pub mod plugin_bridge;
pub mod plugin_supervisor;
pub mod siem_buffer;
pub mod siem_exporter;
pub mod socket_server;
pub mod ui_api;

pub use metrics::{create_metrics, Metrics, SharedMetrics, SourceLabels, DetectorLabels, OperationLabels};
pub use pipeline::Pipeline;
pub use socket_server::SocketServer;
