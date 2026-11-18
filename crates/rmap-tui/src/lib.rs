//! Interactive terminal UI for rmap.
//!
//! Two screens: a setup form for building a scan, and a live results view
//! that fills in while the engine runs. The UI thread never blocks on the
//! network; it polls the engine's event channel between keypresses.

mod app;
mod input;
mod rate;
mod report;
mod report_ui;
mod ui;

use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use tokio::runtime::Handle;

pub use app::App;

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Run the TUI until the user quits.
pub fn run(rt: Handle) -> io::Result<()> {
    install_restore_hook();
    let mut terminal = setup()?;
    let size = terminal.size().unwrap_or_default();
    rmap_log::info!("tui started, terminal {}x{}", size.width, size.height);

    let result = event_loop(&mut terminal, rt);
    restore();
    if let Err(e) = &result {
        rmap_log::error!("tui stopped with an I/O error: {e}");
    }
    result
}

fn event_loop(terminal: &mut Term, rt: Handle) -> io::Result<()> {
    let mut app = App::new(rt);
    let mut last_flush = Instant::now();
    while !app.should_quit() {
        terminal.draw(|frame| ui::draw(frame, &mut app))?;
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => app.on_key(key),
                Event::Paste(text) => app.on_paste(&text),
                Event::Resize(w, h) => rmap_log::debug!("terminal resized to {w}x{h}"),
                _ => {}
            }
        }
        app.drain_events();
        // Info and above flush as written; this catches buffered debug lines.
        if last_flush.elapsed() >= Duration::from_secs(1) {
            rmap_log::flush();
            last_flush = Instant::now();
        }
    }
    app.shutdown();
    Ok(())
}

fn setup() -> io::Result<Term> {
    enable_raw_mode()?;
    if let Err(e) = execute!(io::stdout(), EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(e);
    }
    // Pasted text then arrives as one Event::Paste, so a newline in a
    // pasted target list can't act as Enter. Terminals without support
    // (the legacy Windows console) just keep sending keys; not fatal.
    if let Err(e) = execute!(io::stdout(), EnableBracketedPaste) {
        rmap_log::debug!("bracketed paste unavailable: {e}");
    }
    Terminal::new(CrosstermBackend::new(io::stdout())).inspect_err(|_| restore())
}

/// Put the terminal back the way we found it. Safe to call more than once.
fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), DisableBracketedPaste);
    let _ = execute!(
        io::stdout(),
        LeaveAlternateScreen,
        ratatui::crossterm::cursor::Show
    );
}

/// Restore the terminal before a main-thread panic is reported, so the
/// message and crash-report path are readable. Panics on worker threads
/// leave the UI running; the scan view reports the failure instead.
fn install_restore_hook() {
    let next = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().name() == Some("main") {
            restore();
        }
        next(info);
    }));
}
