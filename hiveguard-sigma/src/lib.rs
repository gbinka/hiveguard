//! Sigma rule parser and evaluator for HiveGuard.
//!
//! This crate implements Phases 4.1 and 4.2 of the HiveGuard roadmap:
//!
//! - [`rule`] — Sigma rule data structures and YAML parsing (Task 4.1.1)
//! - [`condition`] — Recursive-descent condition expression parser and evaluator (Task 4.1.2)
//! - [`fieldmap`] — Field name mapping layer: Sigma fields → `NormalizedEvent` (Task 4.1.3)
//! - [`selection`] — Selection parsing and per-event matching
//! - [`detector`] — `SigmaDetector` implementing the `Detector` trait (Task 4.2.1)
//! - [`loader`] — Directory loader and hot-reload watcher (Task 4.2.2)
//! - [`error`] — Error types

pub mod condition;
pub mod detector;
pub mod error;
pub mod fieldmap;
pub mod loader;
pub mod rule;
pub mod selection;

pub use condition::{evaluate_condition, evaluate_detection, parse_condition, ConditionExpr};
pub use detector::{SharedSigmaRules, SharedSigmaStats, SigmaDetector};
pub use error::{Result, SigmaError};
pub use fieldmap::FieldMapper;
pub use loader::{load_rules_from_dir, spawn_hot_reload_watcher};
pub use rule::{SigmaDetection, SigmaLevel, SigmaLogSource, SigmaRule, SigmaStatus};
pub use selection::{FieldCondition, FieldModifier, SigmaSelection, SigmaValue};
