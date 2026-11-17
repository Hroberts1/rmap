//! Interactive terminal UI for rmap.
//!
//! Two screens: a setup form for building a scan, and a live results view
//! that fills in while the engine runs. The UI thread never blocks on the
//! network; it polls the engine's event channel between keypresses.

mod app;
mod ui;

use std::io;
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyEventKind};
use tokio::runtime::Handle;

pub use app::App;

/// Run the TUI until the user quits.
pub fn run(rt: Handle) -> io::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App::new(rt);
    let result = (|| -> io::Result<()> {
        while !app.should_quit() {
            terminal.draw(|frame| ui::draw(frame, &mut app))?;
            if event::poll(Duration::from_millis(50))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                app.on_key(key);
            }
            app.drain_events();
        }
        Ok(())
    })();
    ratatui::restore();
    result
}
