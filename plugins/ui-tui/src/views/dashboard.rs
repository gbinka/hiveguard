//! Dashboard view — summary cards + key-binding hint.

use hiveguard_ui::AppModel;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render(frame: &mut Frame, area: Rect, model: &AppModel) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // cards
            Constraint::Min(3),    // hints
        ])
        .split(area);

    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
            Constraint::Percentage(34),
        ])
        .split(rows[0]);

    card(frame, cards[0], "Active bans", &model.bans.len().to_string(), Color::Red);
    card(
        frame,
        cards[1],
        "Threats (recent)",
        &model.threats.len().to_string(),
        Color::Yellow,
    );
    let healthy = model
        .plugins_status
        .iter()
        .filter(|p| p.health.eq_ignore_ascii_case("ok") || p.health.eq_ignore_ascii_case("healthy"))
        .count();
    card(
        frame,
        cards[2],
        "Plugins healthy",
        &format!("{healthy} / {}", model.plugins_status.len()),
        Color::Green,
    );

    let hints = vec![
        Line::from(Span::styled(
            "Welcome to HiveGuard TUI",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "Node: {}    Daemon: {}",
            if model.node_name.is_empty() {
                "—"
            } else {
                &model.node_name
            },
            if model.daemon_version.is_empty() {
                "—"
            } else {
                &model.daemon_version
            },
        )),
        Line::from(""),
        Line::from("Switch views with 1-5. Press ? for the full key map."),
    ];
    frame.render_widget(
        Paragraph::new(hints).block(Block::default().borders(Borders::ALL).title(" overview ")),
        rows[1],
    );
}

fn card(frame: &mut Frame, area: Rect, title: &str, value: &str, accent: Color) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(accent),
        ));
    let body = Paragraph::new(Line::from(Span::styled(
        value.to_string(),
        Style::default()
            .fg(accent)
            .add_modifier(Modifier::BOLD),
    )))
    .block(block);
    frame.render_widget(body, area);
}
