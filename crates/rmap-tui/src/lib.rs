//! Interactive terminal UI for rmap.
//!
//! Two screens: a setup form for building a scan, and a live results view
//! that fills in while the engine runs. The UI thread never blocks on the
//! network; it polls the engine's event channel between keypresses.

mod app;
mod clipboard;
mod filter;
mod input;
mod limits;
mod log_view;
mod mac;
mod mouse;
mod names;
mod profiles;
mod rate;
mod report;
mod report_ui;
mod rescan;
mod tabs;
mod theme;
mod ui;
mod vuln_status;

use std::io::{self, Stdout, Write};
use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyEventKind,
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
    // setup() turned capture on; App starts with it on too.
    let mut captured = app.mouse_capture;
    while !app.should_quit() {
        terminal.draw(|frame| ui::draw(frame, &mut app))?;
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => app.on_key(key),
                Event::Paste(text) => app.on_paste(&text),
                Event::Mouse(mouse) => app.on_mouse(mouse),
                Event::Resize(w, h) => rmap_log::debug!("terminal resized to {w}x{h}"),
                _ => {}
            }
        }
        if let Some(text) = app.clipboard.take() {
            copy_to_clipboard(terminal, &text);
        }
        if app.mouse_capture != captured {
            captured = app.mouse_capture;
            let result = if captured {
                execute!(io::stdout(), EnableMouseCapture)
            } else {
                execute!(io::stdout(), DisableMouseCapture)
            };
            if let Err(e) = result {
                rmap_log::warn!("could not change mouse capture: {e}");
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

/// Written straight to the terminal between frames; OSC 52 doesn't move
/// the cursor or draw, so ratatui's screen state stays valid.
fn copy_to_clipboard(terminal: &mut Term, text: &str) {
    let Some(seq) = clipboard::osc52(text, std::env::var_os("TMUX").is_some()) else {
        return;
    };
    let out = terminal.backend_mut();
    if let Err(e) = out.write_all(seq.as_bytes()).and_then(|()| out.flush()) {
        rmap_log::warn!("clipboard write failed: {e}");
    }
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
    if let Err(e) = execute!(io::stdout(), EnableMouseCapture) {
        rmap_log::debug!("mouse capture unavailable: {e}");
    }
    Terminal::new(CrosstermBackend::new(io::stdout())).inspect_err(|_| restore())
}

/// Put the terminal back the way we found it. Safe to call more than once.
fn restore() {
    // First: on Windows this restores the console mode saved when capture
    // was enabled (raw), so it must come before raw mode is turned off.
    let _ = execute!(io::stdout(), DisableMouseCapture);
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
