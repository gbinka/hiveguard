//! Per-view ratatui renderers.
//!
//! Each submodule exposes `render(model, area, frame, ui_state)` that draws
//! the view from the read-only `AppModel`. State that is purely local to the
//! TUI (selected row index, help overlay flag, scroll position) lives in
//! [`UiState`].

use hiveguard_ui::{AppModel, ViewKind};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
    Frame,
};

pub mod bans;
pub mod config;
pub mod dashboard;
pub mod plugins;
pub mod threats;

/// TUI-local state — not part of `AppModel` (it's renderer-specific).
#[derive(Debug, Clone, Default)]
pub struct UiState {
    pub bans_selected: usize,
    pub threats_selected: usize,
    pub plugins_selected: usize,
    pub help_visible: bool,
}

impl UiState {
    /// Move the selected row in the currently active view.
    pub fn move_selection(&mut self, view: ViewKind, delta: i32, max: usize) {
        let cursor = match view {
            ViewKind::Bans => &mut self.bans_selected,
            ViewKind::Threats => &mut self.threats_selected,
            ViewKind::Plugins => &mut self.plugins_selected,
            _ => return,
        };
        if max == 0 {
            *cursor = 0;
            return;
        }
        let next = (*cursor as i32 + delta).clamp(0, max as i32 - 1);
        *cursor = next as usize;
    }

    /// Subject of the currently selected ban, if any.
    pub fn selected_ban_subject<'a>(&self, model: &'a AppModel) -> Option<&'a str> {
        model
            .bans
            .get(self.bans_selected)
            .map(|b| b.subject.as_str())
    }
}

/// Top-level draw entry point.
pub fn draw(frame: &mut Frame, model: &AppModel, ui: &UiState) {
    let area = frame.area();

    // [tabs | content | status]
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    draw_tabs(frame, chunks[0], model);
    match model.view {
        ViewKind::Dashboard => dashboard::render(frame, chunks[1], model),
        ViewKind::Bans => bans::render(frame, chunks[1], model, ui),
        ViewKind::Threats => threats::render(frame, chunks[1], model, ui),
        ViewKind::Plugins => plugins::render(frame, chunks[1], model, ui),
        ViewKind::Config => config::render(frame, chunks[1], model),
    }
    draw_status(frame, chunks[2], model);

    if ui.help_visible {
        draw_help_overlay(frame, area);
    }
}

fn draw_tabs(frame: &mut Frame, area: Rect, model: &AppModel) {
    let titles = ["1·Dashboard", "2·Bans", "3·Threats", "4·Plugins", "5·Config"];
    let selected = view_index(model.view);
    let tabs = Tabs::new(
        titles
            .iter()
            .map(|t| Line::from(Span::raw(*t)))
            .collect::<Vec<_>>(),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" HiveGuard TUI "),
    )
    .select(selected)
    .style(Style::default().fg(Color::Gray))
    .highlight_style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(tabs, area);
}

fn draw_status(frame: &mut Frame, area: Rect, model: &AppModel) {
    use hiveguard_ui::ConnectionStatus::*;
    let (label, colour) = match &model.status {
        Disconnected => ("disconnected", Color::DarkGray),
        Connecting => ("connecting…", Color::Yellow),
        Connected => ("connected", Color::Green),
        Failed(r) => return draw_failed(frame, area, r),
    };
    let line = Line::from(vec![
        Span::styled(format!(" {label} "), Style::default().fg(colour)),
        Span::raw(" | "),
        Span::raw(format!("node={}", model.node_name)),
        Span::raw(" | "),
        Span::raw(format!("v={}", model.daemon_version)),
        Span::raw(" | q quit · ? help · r refresh"),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_failed(frame: &mut Frame, area: Rect, reason: &str) {
    let line = Line::from(vec![
        Span::styled(" failed ", Style::default().fg(Color::Red)),
        Span::raw(" | "),
        Span::raw(reason),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_help_overlay(frame: &mut Frame, area: Rect) {
    // Centre a 60x14 box.
    let w = area.width.min(60);
    let h = area.height.min(14);
    let x = (area.width.saturating_sub(w)) / 2 + area.x;
    let y = (area.height.saturating_sub(h)) / 2 + area.y;
    let popup = Rect {
        x,
        y,
        width: w,
        height: h,
    };

    let body = vec![
        Line::from(""),
        Line::from(" 1..5  switch view  (Dashboard / Bans / Threats / Plugins / Config)"),
        Line::from(" ↑ ↓   move selection           PgUp/PgDn  page selection"),
        Line::from(" r     refresh from daemon       Enter  activate / submit"),
        Line::from(" d     unban selected (Bans)     ?     toggle this help"),
        Line::from(" q     quit                      Ctrl-C   quit"),
        Line::from(""),
        Line::from(" Press ? to close"),
    ];
    frame.render_widget(
        Paragraph::new(body).block(Block::default().borders(Borders::ALL).title(" help ")),
        popup,
    );
}

fn view_index(v: ViewKind) -> usize {
    match v {
        ViewKind::Dashboard => 0,
        ViewKind::Bans => 1,
        ViewKind::Threats => 2,
        ViewKind::Plugins => 3,
        ViewKind::Config => 4,
    }
}

/// Severity → colour for tables.
pub(crate) fn severity_colour(sev: u8) -> Color {
    match sev {
        0..=2 => Color::Green,
        3..=5 => Color::Yellow,
        6..=8 => Color::LightRed,
        _ => Color::Red,
    }
}
