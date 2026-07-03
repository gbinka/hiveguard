pub mod custom_parser;
pub mod file_watcher;
pub mod netdev_parser;
pub mod nginx_parser;
pub mod postfix_parser;
pub mod source;
pub mod ssh_parser;
// Phase 5.1 — Network syslog ingestion (RFC 5424 / RFC 3164 / RFC 6587 / RFC 5425)
pub mod syslog_parser;
pub mod syslog_router;
pub mod syslog_source;

pub use custom_parser::CustomLogSource;
pub use file_watcher::FileWatcher;
pub use netdev_parser::{parse_cisco_asa_line, parse_iptables_line, parse_pf_line, NetdevEvent};
pub use nginx_parser::NginxLogSource;
pub use postfix_parser::PostfixLogSource;
pub use source::LogSource;
pub use ssh_parser::SshLogSource;
pub use syslog_router::SyslogRouter;
pub use syslog_source::{SyslogTcpSource, SyslogTlsSource, SyslogUdpSource};
