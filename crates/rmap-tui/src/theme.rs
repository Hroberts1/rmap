//! Colour policy. Honours `NO_COLOR` (https://no-color.org): when it is set
//! and non-empty, frames are drawn without foreground or background
//! colours. Modifiers (bold, dim, reversed) stay, so the selected row still
//! stands out.

use std::ffi::OsStr;
use std::sync::OnceLock;

use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier, Style};

/// Whether colours are off, read from the environment once.
pub fn no_color() -> bool {
    static NO_COLOR: OnceLock<bool> = OnceLock::new();
    *NO_COLOR.get_or_init(|| {
        let off = wants_no_color(std::env::var_os("NO_COLOR").as_deref());
        rmap_log::info!("colours {}", if off { "off (NO_COLOR)" } else { "on" });
        off
    })
}

fn wants_no_color(value: Option<&OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty())
}

/// Remove every colour from a drawn frame. Text that relied on a coloured
/// background to stand out (key labels, the chosen export format, the
/// gauge label) is reversed instead.
pub fn strip_colors(buf: &mut Buffer) {
    for cell in &mut buf.content {
        if cell.style().bg.is_some_and(|c| c != Color::Reset) {
            cell.set_style(Style::new().add_modifier(Modifier::REVERSED));
        }
        cell.set_fg(Color::Reset).set_bg(Color::Reset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, Screen};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rmap_core::{HostState, ScanEvent};

    #[test]
    fn no_color_needs_a_non_empty_value() {
        assert!(!wants_no_color(None));
        assert!(!wants_no_color(Some(OsStr::new(""))));
        assert!(wants_no_color(Some(OsStr::new("1"))));
        assert!(wants_no_color(Some(OsStr::new("0"))), "any value counts");
    }

    fn results_app() -> (tokio::runtime::Runtime, App) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(app.screen, Screen::Results));
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true;
        view.apply(ScanEvent::Host {
            ip: "10.0.0.2".parse().unwrap(),
            hostname: None,
            state: HostState::Up,
            rtt: None,
        });
        view.log("scan stopped".into());
        (rt, app)
    }

    fn draw(app: &mut App, w: u16, h: u16, strip: bool) -> Buffer {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| {
            crate::ui::draw(f, app);
            if strip {
                strip_colors(f.buffer_mut());
            }
        })
        .unwrap();
        term.backend().buffer().clone()
    }

    #[test]
    fn stripped_frames_have_no_colour_but_keep_highlights() {
        let (_rt, mut app) = results_app();
        for (w, h) in [(80, 24), (120, 32)] {
            let buf = draw(&mut app, w, h, true);
            assert!(
                buf.content
                    .iter()
                    .all(|c| c.fg == Color::Reset && c.bg == Color::Reset)
            );
            let reversed =
                |row: u16| (0..w).any(|x| buf[(x, row)].modifier.contains(Modifier::REVERSED));
            assert!(reversed(h - 1), "footer key labels stay visible");
            let host_row = (0..h)
                .find(|&y| {
                    let text: String = (0..w).map(|x| buf[(x, y)].symbol()).collect();
                    text.contains("10.0.0.2 ")
                })
                .unwrap();
            assert!(reversed(host_row), "the selected host stays highlighted");
        }
    }

    #[test]
    fn gauge_has_no_fixed_background() {
        let (_rt, mut app) = results_app();
        for (w, h) in [(80, 24), (120, 32)] {
            let buf = draw(&mut app, w, h, false);
            assert!(buf.content.iter().all(|c| c.bg != Color::DarkGray));
        }
    }
}
