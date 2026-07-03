//! Threats view — scrollable table, filter by detector.

use hiveguard_ui::AppModel;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use super::{severity_colour, UiState};

pub fn render(frame: &mut Frame, area: Rect, model: &AppModel, ui: &UiState) {
    let header = Row::new(["When", "IP", "Sev", "Conf", "Detector", "Reason"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let detector_needle = model.filters.threats_detector.to_lowercase();
    let sev_min = model.filters.threats_severity_min;

    let rows: Vec<Row> = model
        .threats
        .iter()
        .filter(|t| t.severity >= sev_min)
        .filter(|t| {
            detector_needle.is_empty() || t.detector.to_lowercase().contains(&detector_needle)
        })
        .map(|t| {
            Row::new(vec![
                Cell::from(t.timestamp.clone()),
                Cell::from(t.ip.clone()),
                Cell::from(t.severity.to_string())
                    .style(Style::default().fg(severity_colour(t.severity))),
                Cell::from(format!("{}%", t.confidence)),
                Cell::from(t.detector.clone()),
                Cell::from(t.reason.clone()),
            ])
        })
        .collect();

    let title = format!(" threats ({}) ", rows.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(16),
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(20),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .highlight_style(
        Style::default()
            .bg(ratatui::style::Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    let mut state = TableState::default();
    state.select(Some(
        ui.threats_selected.min(model.threats.len().saturating_sub(1)),
    ));
    frame.render_stateful_widget(table, area, &mut state);
}
