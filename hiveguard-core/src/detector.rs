use crate::models::{DetectionSignal, NormalizedEvent};

/// Trait for threat detectors that process normalized events
/// and optionally produce detection signals.
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal>;
}
