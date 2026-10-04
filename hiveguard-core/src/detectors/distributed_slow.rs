use std::time::Duration;

use crate::detector::Detector;
use crate::models::{DetectionSignal, NormalizedEvent};

/// Compatibility shell for the retired subnet-count heuristic.
///
/// Distinct clients in a /24 or /48 are not evidence of coordinated abuse.
/// Until an independently validated abuse correlation is available, this
/// detector must not emit signals (even Warn signals feed the scoring engine).
/// Existing configuration remains loadable, but cannot produce collective bans.
pub struct DistributedSlowDetector;

impl DistributedSlowDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn with_config(_window: Duration, _ip_threshold: usize, _ban_duration: Duration) -> Self {
        Self
    }
}

impl Default for DistributedSlowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DistributedSlowDetector {
    fn name(&self) -> &str {
        "distributed_slow"
    }

    fn process(&self, _event: &NormalizedEvent) -> Option<DetectionSignal> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventType;
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn ordinary_and_4xx_clients_never_ban_their_shared_network() {
        // Even the smallest configured threshold cannot turn ordinary traffic
        // or unrelated 4xx responses into evidence against an entire subnet.
        for detector in [
            DistributedSlowDetector::new(),
            DistributedSlowDetector::with_config(
                Duration::from_secs(600),
                1,
                Duration::from_secs(43200),
            ),
        ] {
            for event_type in [EventType::HttpRequest, EventType::Http4xx] {
                for host in 1..=254 {
                    for ip in [format!("11.22.33.{host}"), format!("2001:db8:1::{host:x}")] {
                        let event = NormalizedEvent {
                            timestamp: Utc::now(),
                            source_ip: ip.parse().unwrap(),
                            event_type: event_type.clone(),
                            source_name: "web".into(),
                            raw_line: "GET /".into(),
                            metadata: HashMap::new(),
                        };
                        assert!(detector.process(&event).is_none());
                    }
                }
            }
        }
    }
}
