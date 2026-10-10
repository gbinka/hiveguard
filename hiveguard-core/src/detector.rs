use crate::models::{DetectionSignal, NormalizedEvent};

/// Trait for threat detectors that process normalized events
/// and optionally produce detection signals.
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal>;

    /// Like [`Detector::process`] but may return several signals for one
    /// event, possibly for *other* source IPs than `event.source_ip` (e.g. a
    /// cross-IP campaign detector banning every participant it has seen).
    /// The pipeline calls this method; the default wraps `process`.
    fn process_multi(&self, event: &NormalizedEvent) -> Vec<DetectionSignal> {
        self.process(event).into_iter().collect()
    }
}
