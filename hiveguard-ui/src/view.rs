//! Renderer-agnostic view IR — a JSON-serialisable tree that any renderer
//! (ratatui, WASM-DOM, gRPC) can interpret without knowing about UI state.
//!
//! Phase 5 expands this with Table, Form, Chart, Layout primitives.

use serde::{Deserialize, Serialize};

/// IR for one render frame. Renderers receive this from `view(model)` and
/// translate to their native widget tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViewTree {
    /// Vertical stack of children.
    Column(Vec<ViewTree>),
    /// Horizontal stack of children.
    Row(Vec<ViewTree>),
    /// Plain text node.
    Text(String),
    /// Header / title text.
    Heading(String),
    /// Status badge with severity colour hint.
    Badge { text: String, severity: Severity },
    /// Placeholder for Phase 5 widgets.
    Placeholder(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Danger,
    Success,
}
