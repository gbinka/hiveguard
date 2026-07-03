//! Keyboard → `Msg` translation.
//!
//! Pure functions only. Tests live alongside so the binding table can be
//! exercised without spinning up a terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use hiveguard_ui::{Msg, ViewKind};

/// Result of feeding a `KeyEvent` to the input router.
///
/// `Msg` is dispatched through `hiveguard_ui::update`; the other variants
/// are local-only (no state mutation) and don't flow through the model.
#[derive(Debug, Clone)]
pub enum KeyAction {
    /// Apply this `Msg` through `hiveguard_ui::update`.
    Dispatch(Msg),
    /// User-initiated refresh — the binary will trigger BansLoaded etc.
    Refresh,
    /// User selected a row in the current view (delta = +1 / -1).
    Move(i32),
    /// Submit the form / activate the focused control.
    Activate,
    /// Toggle the `?` help overlay.
    ToggleHelp,
    /// Quit the program cleanly.
    Quit,
    /// Nothing to do — keystroke wasn't bound.
    Ignore,
}

/// Map a key event to a `KeyAction`. The `view` argument lets us bind
/// the same key (e.g. `d`) to different actions in different views.
///
/// Global bindings (Quit, Navigate, Refresh, Help) take precedence — they
/// fire regardless of view.
pub fn route_key(key: KeyEvent, view: ViewKind, selected: Option<&str>) -> KeyAction {
    // Ctrl-C always quits, no matter what view we're in.
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return KeyAction::Quit;
    }

    match key.code {
        // --- Global ---
        KeyCode::Char('q') => KeyAction::Quit,
        KeyCode::Char('?') => KeyAction::ToggleHelp,
        KeyCode::Char('r') => KeyAction::Refresh,
        KeyCode::Char('1') => KeyAction::Dispatch(Msg::NavigateTo(ViewKind::Dashboard)),
        KeyCode::Char('2') => KeyAction::Dispatch(Msg::NavigateTo(ViewKind::Bans)),
        KeyCode::Char('3') => KeyAction::Dispatch(Msg::NavigateTo(ViewKind::Threats)),
        KeyCode::Char('4') => KeyAction::Dispatch(Msg::NavigateTo(ViewKind::Plugins)),
        KeyCode::Char('5') => KeyAction::Dispatch(Msg::NavigateTo(ViewKind::Config)),

        // --- Selection ---
        KeyCode::Up => KeyAction::Move(-1),
        KeyCode::Down => KeyAction::Move(1),
        KeyCode::PageUp => KeyAction::Move(-10),
        KeyCode::PageDown => KeyAction::Move(10),
        KeyCode::Enter => KeyAction::Activate,

        // --- View-specific ---
        KeyCode::Char('d') if view == ViewKind::Bans => match selected {
            Some(subject) => KeyAction::Dispatch(Msg::UnbanRequested(subject.to_string())),
            None => KeyAction::Ignore,
        },

        _ => KeyAction::Ignore,
    }
}

/// Format a `BanRow` for compact one-line display.
///
/// Used by the bans table renderer and exposed as a public function so it
/// can be unit-tested without instantiating ratatui.
pub fn format_ban_row(row: &hiveguard_ui::model::BanRow) -> String {
    let expires = row.expires_at.as_deref().unwrap_or("permanent");
    format!(
        "{:<20} sev={:<2} src={:<12} until={:<20} — {}",
        row.subject, row.severity, row.source, expires, row.reason,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn quit_on_ctrl_c() {
        let k = KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        };
        assert!(matches!(
            route_key(k, ViewKind::Dashboard, None),
            KeyAction::Quit
        ));
    }

    #[test]
    fn number_keys_navigate() {
        let cases = [
            ('1', ViewKind::Dashboard),
            ('2', ViewKind::Bans),
            ('3', ViewKind::Threats),
            ('4', ViewKind::Plugins),
            ('5', ViewKind::Config),
        ];
        for (ch, expected) in cases {
            match route_key(key(KeyCode::Char(ch)), ViewKind::Dashboard, None) {
                KeyAction::Dispatch(Msg::NavigateTo(v)) => assert_eq!(v, expected),
                other => panic!("expected NavigateTo({expected:?}), got {other:?}"),
            }
        }
    }

    #[test]
    fn d_unbans_in_bans_view_only() {
        // In Bans view with a selection: emits UnbanRequested.
        match route_key(
            key(KeyCode::Char('d')),
            ViewKind::Bans,
            Some("10.0.0.1/32"),
        ) {
            KeyAction::Dispatch(Msg::UnbanRequested(s)) => assert_eq!(s, "10.0.0.1/32"),
            other => panic!("expected UnbanRequested, got {other:?}"),
        }
        // In Dashboard view, 'd' is ignored.
        assert!(matches!(
            route_key(
                key(KeyCode::Char('d')),
                ViewKind::Dashboard,
                Some("10.0.0.1/32")
            ),
            KeyAction::Ignore
        ));
        // In Bans view without selection: ignored.
        assert!(matches!(
            route_key(key(KeyCode::Char('d')), ViewKind::Bans, None),
            KeyAction::Ignore
        ));
    }

    #[test]
    fn arrow_keys_move_selection() {
        assert!(matches!(
            route_key(key(KeyCode::Up), ViewKind::Bans, None),
            KeyAction::Move(-1)
        ));
        assert!(matches!(
            route_key(key(KeyCode::Down), ViewKind::Bans, None),
            KeyAction::Move(1)
        ));
        assert!(matches!(
            route_key(key(KeyCode::PageDown), ViewKind::Bans, None),
            KeyAction::Move(10)
        ));
    }

    #[test]
    fn format_ban_row_includes_subject_and_reason() {
        let row = hiveguard_ui::model::BanRow {
            subject: "10.0.0.1/32".into(),
            severity: 7,
            reason: "ssh bruteforce".into(),
            expires_at: Some("2026-01-01T00:00:00Z".into()),
            source: "detector.ssh".into(),
        };
        let s = format_ban_row(&row);
        assert!(s.contains("10.0.0.1/32"));
        assert!(s.contains("ssh bruteforce"));
        assert!(s.contains("sev=7"));
    }

    #[test]
    fn format_ban_row_marks_permanent() {
        let row = hiveguard_ui::model::BanRow {
            subject: "1.2.3.4/32".into(),
            severity: 10,
            reason: "honeypot".into(),
            expires_at: None,
            source: "manual".into(),
        };
        assert!(format_ban_row(&row).contains("permanent"));
    }
}
