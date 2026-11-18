//! The full-height log on the results screen, opened with `L`.
//!
//! `ScanView::log_view` holds how many lines the view is scrolled back from
//! the newest one, so `Some(0)` follows new lines as they arrive.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph};

use crate::app::ScanView;
use crate::ui::{draw_header, key_help, log_line};

const PAGE: usize = 10;

/// Keys while the log view is open. Returns false for keys it leaves to
/// the results screen (q, s, e, ?, ...).
pub(crate) fn on_key(view: &mut ScanView, key: &KeyEvent) -> bool {
    let Some(back) = view.log_view else {
        return false;
    };
    let top = view.log.len();
    view.log_view = match key.code {
        KeyCode::Esc | KeyCode::Char('L') => None,
        KeyCode::Up | KeyCode::Char('k') => Some((back + 1).min(top)),
        KeyCode::Down | KeyCode::Char('j') => Some(back.saturating_sub(1)),
        KeyCode::PageUp => Some((back + PAGE).min(top)),
        KeyCode::PageDown => Some(back.saturating_sub(PAGE)),
        KeyCode::Home | KeyCode::Char('g') => Some(top),
        KeyCode::End | KeyCode::Char('G') => Some(0),
        _ => return false,
    };
    true
}

pub(crate) fn draw(frame: &mut Frame, view: &mut ScanView) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    draw_header(frame, header, view);

    let rows = body.height.saturating_sub(2) as usize;
    let len = view.log.len();
    // Clamp here, where the page height is known.
    let back = view.log_view.unwrap_or(0).min(len.saturating_sub(rows));
    view.log_view = Some(back);
    let end = len - back;
    let start = end.saturating_sub(rows);
    let lines: Vec<Line> = view.log.range(start..end).map(|l| log_line(l)).collect();
    let title = if len == 0 {
        " log · empty ".to_string()
    } else {
        format!(" log · {}-{end} of {len} ", start + 1)
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(title)),
        body,
    );
    frame.render_widget(
        Paragraph::new(key_help(&[
            ("↑↓", "scroll"),
            ("PgUp PgDn", "page"),
            ("Home End", "oldest / newest"),
            ("L Esc", "close"),
        ])),
        footer,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, Screen};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::KeyModifiers;

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| crate::ui::draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .chunks(w.max(1) as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>() + "\n")
            .collect()
    }

    /// A stopped scan's results screen with `n` numbered log lines.
    fn results_with_log(n: usize) -> (tokio::runtime::Runtime, App) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut app = App::new(rt.handle().clone());
        app.form.targets = "127.0.0.1".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        press(&mut app, KeyCode::Enter);
        let view = app.scan.as_mut().unwrap();
        view.scan.stop();
        view.stopped = true;
        for i in 0..n {
            view.log(format!("entry #{i:03}"));
        }
        (rt, app)
    }

    fn log_view(app: &App) -> Option<usize> {
        app.scan.as_ref().unwrap().log_view
    }

    #[test]
    fn l_opens_a_scrollable_full_height_log() {
        let (_rt, mut app) = results_with_log(50);
        let screen = render(&mut app, 80, 24);
        assert!(!screen.contains("entry #030"), "small panel:\n{screen}");

        press(&mut app, KeyCode::Char('L'));
        let screen = render(&mut app, 80, 24);
        // 24 rows less header (4), borders (2) and footer (1): 17 lines.
        assert!(screen.contains("log · 34-50 of 50"), "{screen}");
        assert!(screen.contains("entry #049") && screen.contains("entry #033"));
        assert!(!screen.contains("entry #032"), "{screen}");
        assert!(screen.lines().last().unwrap().contains("close"));
        assert!(render(&mut app, 120, 40).contains("log · 18-50 of 50"));

        press(&mut app, KeyCode::Up);
        assert!(render(&mut app, 80, 24).contains("entry #032"));
        press(&mut app, KeyCode::Home);
        let screen = render(&mut app, 80, 24);
        assert!(screen.contains("entry #000") && screen.contains("log · 1-17 of 50"));
        assert_eq!(log_view(&app), Some(33), "clamped to the oldest page");
        press(&mut app, KeyCode::PageDown);
        assert_eq!(log_view(&app), Some(23));
        press(&mut app, KeyCode::End);
        assert_eq!(log_view(&app), Some(0));

        // Tiny terminals must not panic, and the scroll stays in range.
        press(&mut app, KeyCode::Home);
        for (w, h) in [(20, 6), (1, 1), (0, 0)] {
            render(&mut app, w, h);
        }

        press(&mut app, KeyCode::Esc);
        assert_eq!(log_view(&app), None);
        assert!(matches!(app.screen, Screen::Results), "Esc only closes it");
        press(&mut app, KeyCode::Char('L'));
        press(&mut app, KeyCode::Char('L'));
        assert_eq!(log_view(&app), None, "l toggles");
    }

    #[test]
    fn other_keys_still_reach_the_results_screen() {
        let (_rt, mut app) = results_with_log(0);
        press(&mut app, KeyCode::Char('L'));
        assert!(render(&mut app, 80, 24).contains("log · empty"));
        press(&mut app, KeyCode::Char('?'));
        assert!(app.help && log_view(&app).is_some());
        assert!(render(&mut app, 80, 24).contains("full log"));
    }
}
