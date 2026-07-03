//! Main loop glue for the standalone TUI binary.
//!
//! Owns the `AppModel`, the renderer-local `UiState`, the WS task handle,
//! the REST client, and the channel that feeds `Msg` into
//! `hiveguard_ui::update`. Crossterm key events are routed by
//! [`crate::event`] and translated into `Msg` (state-changing) or
//! `KeyAction` (renderer-local).

use std::io;
use std::time::Duration;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures_util::StreamExt;
use hiveguard_ui::{update, AppModel, Msg};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::event::{route_key, KeyAction};
use crate::rest::RestClient;
use crate::views::{self, UiState};

/// CLI-derived runtime configuration.
pub struct Config {
    pub server: String,
    pub token: Option<String>,
    pub insecure: bool,
    pub poll_secs: u64,
}

/// Drive the TUI to completion. Returns when the user quits or the
/// shutdown token fires.
pub async fn run(cfg: Config) -> anyhow::Result<()> {
    // Terminal setup with a panic hook so a panic doesn't leave the user's
    // shell in raw mode.
    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run_inner(&mut terminal, cfg).await;

    // Always restore the terminal — even on Err.
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    result
}

async fn run_inner<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    cfg: Config,
) -> anyhow::Result<()> {
    let rest = RestClient::new(&cfg.server, cfg.token.clone(), cfg.insecure)?;
    let (tx, mut rx) = mpsc::channel::<Msg>(128);
    let shutdown = CancellationToken::new();

    // Spawn WS task.
    {
        let url = crate::ws::stream_url(&cfg.server);
        let token = cfg.token.clone();
        let tx = tx.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { crate::ws::connect_loop(url, token, tx, shutdown).await });
    }

    // Spawn REST poll task as a fallback / bootstrap source.
    {
        let rest = rest.clone();
        let tx = tx.clone();
        let shutdown = shutdown.clone();
        let interval = Duration::from_secs(cfg.poll_secs.max(1));
        tokio::spawn(async move { poll_loop(rest, tx, shutdown, interval).await });
    }

    let mut model = AppModel::default();
    let mut ui = UiState::default();
    let mut events = EventStream::new();

    // Initial paint.
    terminal.draw(|f| views::draw(f, &model, &ui))?;

    loop {
        tokio::select! {
            // Inbound `Msg` from WS / REST / spawned actions.
            maybe = rx.recv() => {
                match maybe {
                    Some(msg) => {
                        model = update(model, msg);
                        terminal.draw(|f| views::draw(f, &model, &ui))?;
                    }
                    None => break, // all senders dropped
                }
            }

            // Inbound terminal event.
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) => {
                        let selected = ui.selected_ban_subject(&model).map(|s| s.to_string());
                        match route_key(key, model.view, selected.as_deref()) {
                            KeyAction::Quit => break,
                            KeyAction::ToggleHelp => {
                                ui.help_visible = !ui.help_visible;
                            }
                            KeyAction::Move(delta) => {
                                let max = current_list_len(&model);
                                ui.move_selection(model.view, delta, max);
                            }
                            KeyAction::Refresh => {
                                trigger_refresh(rest.clone(), tx.clone()).await;
                            }
                            KeyAction::Activate => {
                                // Reserved for future form mode (n = new ban).
                            }
                            KeyAction::Dispatch(Msg::UnbanRequested(subject)) => {
                                // Side-effect: ask the daemon, then update model
                                // optimistically by removing the row.
                                let rest = rest.clone();
                                let tx = tx.clone();
                                let subject_clone = subject.clone();
                                tokio::spawn(async move {
                                    match rest.unban(&subject_clone).await {
                                        Ok(()) => {
                                            if let Ok(b) = rest.bans().await {
                                                let _ = tx.send(Msg::BansLoaded(b)).await;
                                            }
                                        }
                                        Err(e) => {
                                            let _ = tx
                                                .send(Msg::ConnectionFailed(format!("unban {subject_clone}: {e}")))
                                                .await;
                                        }
                                    }
                                });
                                // Also route through update() so any state in the
                                // model can react (currently a no-op).
                                model = update(model, Msg::UnbanRequested(subject));
                            }
                            KeyAction::Dispatch(other) => {
                                model = update(model, other);
                            }
                            KeyAction::Ignore => {}
                        }
                        terminal.draw(|f| views::draw(f, &model, &ui))?;
                    }
                    Some(Ok(Event::Resize(_, _))) => {
                        terminal.draw(|f| views::draw(f, &model, &ui))?;
                    }
                    Some(Ok(_)) => {} // mouse, focus — ignored
                    Some(Err(e)) => {
                        let _ = tx
                            .send(Msg::ConnectionFailed(format!("terminal: {e}")))
                            .await;
                    }
                    None => break,
                }
            }

            // Sigint / sigterm.
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    shutdown.cancel();
    Ok(())
}

fn current_list_len(model: &AppModel) -> usize {
    match model.view {
        hiveguard_ui::ViewKind::Bans => model.bans.len(),
        hiveguard_ui::ViewKind::Threats => model.threats.len(),
        hiveguard_ui::ViewKind::Plugins => model.plugins_status.len(),
        _ => 0,
    }
}

async fn trigger_refresh(rest: RestClient, tx: mpsc::Sender<Msg>) {
    tokio::spawn(async move {
        // Best-effort: any error becomes a ConnectionFailed so the user
        // sees it in the status bar; we don't abort the loop.
        match rest.info().await {
            Ok(info) => {
                let _ = tx
                    .send(Msg::Connected {
                        node_name: info.node_name,
                        version: info.version,
                    })
                    .await;
            }
            Err(e) => {
                let _ = tx
                    .send(Msg::ConnectionFailed(format!("info: {e}")))
                    .await;
            }
        }
        if let Ok(b) = rest.bans().await {
            let _ = tx.send(Msg::BansLoaded(b)).await;
        }
        if let Ok(t) = rest.threats().await {
            let _ = tx.send(Msg::ThreatsLoaded(t)).await;
        }
        if let Ok(p) = rest.plugins().await {
            let _ = tx.send(Msg::PluginsLoaded(p)).await;
        }
    });
}

async fn poll_loop(
    rest: RestClient,
    tx: mpsc::Sender<Msg>,
    shutdown: CancellationToken,
    interval: Duration,
) {
    // Bootstrap once immediately so the UI isn't empty before the first tick.
    trigger_refresh(rest.clone(), tx.clone()).await;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(interval) => {
                trigger_refresh(rest.clone(), tx.clone()).await;
            }
        }
    }
}

/// Best-effort: if the program panics, drop back to cooked mode so the
/// operator's shell isn't scrambled.
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        prev(info);
    }));
}
