//! Config view — read-only summary.

use hiveguard_ui::AppModel;
use ratatui::{
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, area: Rect, model: &AppModel) {
    let lines = vec![
        Line::from(Span::raw("Daemon")),
        Line::from(format!("  node_name:      {}", model.node_name)),
        Line::from(format!("  daemon_version: {}", model.daemon_version)),
        Line::from(""),
        Line::from(Span::raw("Filters (current session)")),
        Line::from(format!(
            "  bans.severity_min:    {}",
            model.filters.bans_severity_min
        )),
        Line::from(format!(
            "  bans.search:          \"{}\"",
            model.filters.bans_search
        )),
        Line::from(format!(
            "  threats.detector:     \"{}\"",
            model.filters.threats_detector
        )),
        Line::from(format!(
            "  threats.severity_min: {}",
            model.filters.threats_severity_min
        )),
        Line::from(""),
        Line::from(Span::raw("(config is read-only here — edit /etc/hiveguard/config.yaml)")),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" config ")),
        area,
    );
}
