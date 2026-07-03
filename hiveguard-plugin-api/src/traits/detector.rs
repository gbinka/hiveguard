use hiveguard_core::models::{DetectionSignal, NormalizedEvent};

use crate::traits::Plugin;

/// Threat detector — inspects normalized events, emits detection signals.
///
/// **Note:** unlike the legacy [`hiveguard_core::Detector`] trait, this trait
/// uses `&self` instead of `&mut self`. Detector implementations that need
/// internal state must use interior mutability (`RwLock`, `DashMap`, …).
///
/// This is the refactor's only intentional API break — it lets the host
/// schedule detectors in parallel across events and is required for any
/// future out-of-process or sandboxed detector execution.
pub trait DetectorPlugin: Plugin {
    /// Inspect `event`. Return `Some(DetectionSignal)` when it crosses the
    /// detector's threshold, otherwise `None`.
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal>;
}
