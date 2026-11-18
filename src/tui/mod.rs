pub mod app;
pub mod ui;

use std::time::Duration;

use crossterm::event::{Event as CEvent, EventStream, KeyEvent, KeyEventKind};
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::crypto::VaultKeys;
use crate::daemon::clipboard::scrub_clipboard;
use crate::db::VaultDb;
use crate::tui::app::TuiApp;
use crate::tui::ui::render_tui;

enum LoopEvent {
    Key(KeyEvent),
    Tick,
}

/// Launches the interactive Ratatui v0.30+ Catalogue Viewer with panic-safe terminal restoration
/// and a channel-based async `EventStream` loop that filters `KeyEventKind::Press` for Windows compatibility.
pub async fn run_interactive_tui(db: VaultDb, keys: VaultKeys) -> color_eyre::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = TuiApp::new(db, keys, false)?;

    let (tx, mut rx) = mpsc::unbounded_channel::<LoopEvent>();

    let event_tx = tx.clone();
    let reader_handle = tokio::spawn(async move {
        let mut reader = EventStream::new();
        let mut tick_interval = tokio::time::interval(Duration::from_millis(250));

        loop {
            tokio::select! {
                _ = tick_interval.tick() => {
                    if event_tx.send(LoopEvent::Tick).is_err() {
                        break;
                    }
                }
                maybe_evt = reader.next() => {
                    match maybe_evt {
                        Some(Ok(CEvent::Key(key))) if key.kind == KeyEventKind::Press => {
                            if event_tx.send(LoopEvent::Key(key)).is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) | None => break,
                        _ => {}
                    }
                }
            }
        }
    });

    while app.running {
        terminal.draw(|frame| render_tui(&mut app, frame))?;
        if let Some(evt) = rx.recv().await {
            match evt {
                LoopEvent::Key(k) => app.handle_key_event(k),
                LoopEvent::Tick => app.refresh_totp_and_queue(),
            }
        } else {
            break;
        }
    }

    reader_handle.abort();
    ratatui::restore();

    if !app.local_queue.is_active() {
        let _ = scrub_clipboard();
    }
    Ok(())
}
