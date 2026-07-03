//! Bans view — scrollable table with severity colouring.

use hiveguard_ui::AppModel;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use super::{severity_colour, UiState};

pub fn render(frame: &mut Frame, area: Rect, model: &AppModel, ui: &UiState) {
    let header = Row::new(["Subject", "Sev", "Source", "Expires", "Reason"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let filter_min = model.filters.bans_severity_min;
    let needle = model.filters.bans_search.to_lowercase();
    let rows: Vec<Row> = model
        .bans
        .iter()
        .filter(|b| b.severity >= filter_min)
        .filter(|b| {
            needle.is_empty()
                || b.subject.to_lowercase().contains(&needle)
                || b.reason.to_lowercase().contains(&needle)
        })
        .map(|b| {
            Row::new(vec![
                Cell::from(b.subject.clone()),
                Cell::from(b.severity.to_string())
                    .style(Style::default().fg(severity_colour(b.severity))),
                Cell::from(b.source.clone()),
                Cell::from(b.expires_at.clone().unwrap_or_else(|| "permanent".into())),
                Cell::from(b.reason.clone()),
            ])
        })
        .collect();

    let title = format!(" bans ({}) — d unban · n new ", rows.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(22),
            Constraint::Length(4),
            Constraint::Length(16),
            Constraint::Length(22),
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
    state.select(Some(ui.bans_selected.min(model.bans.len().saturating_sub(1))));
    frame.render_stateful_widget(table, area, &mut state);
}
