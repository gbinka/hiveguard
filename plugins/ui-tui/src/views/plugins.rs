//! Plugins view — health table.

use hiveguard_ui::AppModel;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use super::UiState;

pub fn render(frame: &mut Frame, area: Rect, model: &AppModel, ui: &UiState) {
    let header = Row::new(["Plugin", "Kind", "Health", "Version"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = model
        .plugins_status
        .iter()
        .map(|p| {
            let colour = match p.health.to_lowercase().as_str() {
                "ok" | "healthy" => Color::Green,
                "degraded" | "warn" | "warning" => Color::Yellow,
                "failed" | "down" | "error" => Color::Red,
                _ => Color::Gray,
            };
            Row::new(vec![
                Cell::from(p.id.clone()),
                Cell::from(p.kind.clone()),
                Cell::from(p.health.clone()).style(Style::default().fg(colour)),
                Cell::from(p.version.clone()),
            ])
        })
        .collect();

    let title = format!(" plugins ({}) ", rows.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(28),
            Constraint::Length(16),
            Constraint::Length(12),
            Constraint::Min(8),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    let mut state = TableState::default();
    state.select(Some(
        ui.plugins_selected
            .min(model.plugins_status.len().saturating_sub(1)),
    ));
    frame.render_stateful_widget(table, area, &mut state);
}
