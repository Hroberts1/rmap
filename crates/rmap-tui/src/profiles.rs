//! Scan profiles and recent targets for the setup form.
//!
//! A profile is every setup field except the targets. Three are built in;
//! the user can save more (Ctrl-S) and delete their own. The last few
//! target strings that started a scan are kept too (Ctrl-R). Both persist
//! as JSON next to the saved scans; a missing or unreadable file falls
//! back to the defaults with a warning, and a corrupt one is moved aside
//! so the next save can't silently destroy it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph};
use rmap_core::ScanType;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::{App, Confirm, Field};
use crate::input::TextInput;
use crate::ui::{ACCENT, centered, key_help};

const PROFILES_FILE: &str = "profiles.json";
const RECENT_FILE: &str = "recent.json";
const MAX_RECENT: usize = 10;
const MAX_NAME: usize = 40;
/// Long enough for a pasted list of a few hundred addresses.
const MAX_TEXT: usize = 8000;
/// Bigger files are treated as corrupt rather than read into memory.
const MAX_FILE_BYTES: u64 = 1 << 20;

/// Every setup field except the targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub ports: String,
    pub scan_type: ScanType,
    pub timing: u8,
    pub discovery: bool,
    pub service_detection: bool,
    pub vuln_matching: bool,
}

impl Profile {
    fn builtin(name: &str, ports: &str, timing: u8, discovery: bool, services: bool) -> Self {
        Profile {
            name: name.into(),
            ports: ports.into(),
            scan_type: ScanType::Connect,
            timing,
            discovery,
            service_detection: services,
            vuln_matching: services,
        }
    }

    /// One line for the picker: `common · TCP connect · T4 · services`.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{} · {} · T{}",
            self.ports,
            self.scan_type.label(),
            self.timing
        );
        if !self.discovery {
            s.push_str(" · no discovery");
        }
        if self.vuln_matching {
            s.push_str(" · services + vulns");
        } else if self.service_detection {
            s.push_str(" · services");
        }
        s
    }

    /// Reject what a hand-edited or damaged file could hold: control
    /// characters (terminal escapes) and out-of-range values.
    fn validated(mut self) -> Option<Self> {
        self.name = clean(&self.name, MAX_NAME)?;
        self.ports = clean(&self.ports, MAX_TEXT)?;
        if self.timing > 5 {
            return None;
        }
        self.service_detection |= self.vuln_matching;
        Some(self)
    }
}

pub fn builtins() -> Vec<Profile> {
    vec![
        Profile::builtin("Quick sweep", "common", 4, true, false),
        Profile::builtin("Full audit", "all", 3, true, true),
        Profile::builtin("Client baseline", "common", 3, true, true),
    ]
}

/// Trimmed text with no control characters, 1..=`max` characters long.
fn clean(s: &str, max: usize) -> Option<String> {
    let s = s.trim();
    let n = s.chars().count();
    (n > 0 && n <= max && !s.chars().any(char::is_control)).then(|| s.to_string())
}

/// An open picker or prompt over the setup form.
pub enum Picker {
    Profiles {
        selected: usize,
        note: Option<String>,
    },
    Recent {
        selected: usize,
    },
    Save {
        name: TextInput,
        error: Option<String>,
    },
}

pub struct Profiles {
    /// Where the files live; `None` keeps everything in memory (unit tests).
    dir: Option<PathBuf>,
    pub user: Vec<Profile>,
    pub recent: Vec<String>,
    pub picker: Option<Picker>,
}

impl Profiles {
    pub fn load(dir: Option<&Path>) -> Self {
        let mut p = Profiles {
            dir: dir.map(Path::to_path_buf),
            user: Vec::new(),
            recent: Vec::new(),
            picker: None,
        };
        let Some(dir) = dir else {
            return p;
        };
        let builtin = builtins();
        for v in read_list(&dir.join(PROFILES_FILE)) {
            match serde_json::from_value::<Profile>(v)
                .ok()
                .and_then(Profile::validated)
            {
                Some(prof) if !is_taken(&builtin, &prof.name) && !is_taken(&p.user, &prof.name) => {
                    p.user.push(prof)
                }
                _ => rmap_log::warn!("skipping an invalid or duplicate saved profile"),
            }
        }
        for v in read_list(&dir.join(RECENT_FILE)) {
            match v.as_str().and_then(|s| clean(s, MAX_TEXT)) {
                Some(t) if !p.recent.contains(&t) && p.recent.len() < MAX_RECENT => {
                    p.recent.push(t)
                }
                _ => rmap_log::warn!("skipping an invalid or duplicate recent target"),
            }
        }
        rmap_log::info!(
            "loaded {} saved profiles and {} recent targets from {}",
            p.user.len(),
            p.recent.len(),
            dir.display()
        );
        p
    }

    /// Built-ins first, then the user's own.
    pub fn all(&self) -> Vec<Profile> {
        let mut all = builtins();
        all.extend(self.user.iter().cloned());
        all
    }

    /// Save `profile` under its name, replacing a user profile of the same
    /// name. Built-in names are refused. A failed write keeps the profile
    /// for this session and reports the error.
    pub fn save_profile(&mut self, profile: Profile) -> Result<(), String> {
        if clean(&profile.name, MAX_NAME).is_none() {
            return Err(format!("name must be 1-{MAX_NAME} characters"));
        }
        let Some(profile) = profile.validated() else {
            return Err("fill in Ports first".into());
        };
        if is_taken(&builtins(), &profile.name) {
            return Err("that name belongs to a built-in profile".into());
        }
        match self
            .user
            .iter_mut()
            .find(|p| p.name.eq_ignore_ascii_case(&profile.name))
        {
            Some(existing) => *existing = profile,
            None => self.user.push(profile),
        }
        self.persist(PROFILES_FILE, &self.user)
    }

    /// Delete the profile at `index` in `all()`. Built-ins can't be deleted.
    pub fn delete(&mut self, index: usize) -> Result<(), String> {
        let Some(i) = index.checked_sub(builtins().len()) else {
            return Err("built-in profiles can't be deleted".into());
        };
        if i >= self.user.len() {
            return Ok(());
        }
        let gone = self.user.remove(i);
        rmap_log::info!("deleted profile {:?}", gone.name);
        self.persist(PROFILES_FILE, &self.user)
    }

    /// Put `targets` at the front of the recent list.
    pub fn remember_targets(&mut self, targets: &str) {
        let Some(t) = clean(targets, MAX_TEXT) else {
            return;
        };
        self.recent.retain(|r| *r != t);
        self.recent.insert(0, t);
        self.recent.truncate(MAX_RECENT);
        let _ = self.persist(RECENT_FILE, &self.recent);
    }

    /// Bracketed paste lands in the name prompt; other pickers ignore it.
    pub fn paste(&mut self, pasted: &str) {
        if let Some(Picker::Save { name, error }) = self.picker.as_mut() {
            name.insert_str(pasted.lines().next().unwrap_or(""));
            *error = None;
        }
    }

    fn persist<T: Serialize>(&self, file: &str, value: &T) -> Result<(), String> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        let path = dir.join(file);
        write_json(&path, value).map_err(|e| {
            rmap_log::warn!("could not write {}: {e}", path.display());
            format!("could not save to {}: {e}", path.display())
        })
    }
}

fn is_taken(list: &[Profile], name: &str) -> bool {
    list.iter().any(|p| p.name.eq_ignore_ascii_case(name))
}

/// A JSON array from `path`; empty if the file is missing or bad.
fn read_list(path: &Path) -> Vec<Value> {
    let bytes = match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Ok(m) if m.len() > MAX_FILE_BYTES => Err("file is too large".to_string()),
        _ => fs::read(path).map_err(|e| e.to_string()),
    };
    let parsed =
        bytes.and_then(|b| serde_json::from_slice::<Vec<Value>>(&b).map_err(|e| e.to_string()));
    match parsed {
        Ok(list) => list,
        Err(e) => {
            let aside = path.with_extension("json.corrupt");
            rmap_log::warn!(
                "ignoring unreadable {}: {e}; moved to {}",
                path.display(),
                aside.display()
            );
            if let Err(e) = fs::rename(path, &aside) {
                rmap_log::warn!("could not move {} aside: {e}", path.display());
            }
            Vec::new()
        }
    }
}

/// Write through a temp file and rename, so a crash mid-write can't leave
/// a half-written file behind.
pub(crate) fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

fn step(selected: &mut usize, len: usize, code: KeyCode) {
    let last = len.saturating_sub(1);
    *selected = match code {
        KeyCode::Up | KeyCode::Char('k') => selected.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => (*selected + 1).min(last),
        KeyCode::Home => 0,
        KeyCode::End => last,
        _ => *selected,
    };
}

impl App {
    /// Ctrl-P / Ctrl-R / Ctrl-S on the setup form. Returns whether the key
    /// was one of them.
    pub(crate) fn on_profiles_shortcut(&mut self, key: &KeyEvent) -> bool {
        if !key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        let picker = match key.code {
            KeyCode::Char('p') => Picker::Profiles {
                selected: 0,
                note: None,
            },
            KeyCode::Char('r') => Picker::Recent { selected: 0 },
            KeyCode::Char('s') => Picker::Save {
                name: TextInput::default(),
                error: None,
            },
            _ => return false,
        };
        self.profiles.picker = Some(picker);
        true
    }

    /// Keys while a picker or the name prompt is open.
    pub(crate) fn on_picker_key(&mut self, key: KeyEvent) {
        let Some(mut picker) = self.profiles.picker.take() else {
            return;
        };
        if key.code == KeyCode::Esc {
            return;
        }
        match &mut picker {
            Picker::Profiles { selected, note } => {
                *note = None;
                match key.code {
                    KeyCode::Enter => {
                        if let Some(p) = self.profiles.all().get(*selected) {
                            self.apply_profile(p);
                            return;
                        }
                    }
                    KeyCode::Delete | KeyCode::Char('d') => {
                        if *selected < builtins().len() {
                            *note = Some("built-in profiles can't be deleted".into());
                        } else {
                            self.confirm = Some(Confirm::DeleteProfile);
                        }
                    }
                    code => step(selected, self.profiles.all().len(), code),
                }
            }
            Picker::Recent { selected } => match key.code {
                KeyCode::Enter => {
                    if let Some(t) = self.profiles.recent.get(*selected) {
                        self.form.targets = TextInput::new(t.as_str());
                        self.form.focus = Field::Targets;
                        self.form.error = None;
                        return;
                    }
                }
                code => step(selected, self.profiles.recent.len(), code),
            },
            Picker::Save { name, error } => {
                if key.code == KeyCode::Enter {
                    let f = &self.form;
                    let profile = Profile {
                        name: name.to_string(),
                        ports: f.ports.trim().to_string(),
                        scan_type: f.scan_type,
                        timing: f.timing,
                        discovery: f.discovery,
                        service_detection: f.service_detection,
                        vuln_matching: f.vuln_matching,
                    };
                    match self.profiles.save_profile(profile) {
                        Ok(()) => {
                            rmap_log::info!("saved profile {:?}", name.trim());
                            return;
                        }
                        Err(e) => *error = Some(e),
                    }
                } else {
                    name.handle_key(&key);
                    *error = None;
                }
            }
        }
        self.profiles.picker = Some(picker);
    }

    /// Answer to `Confirm::DeleteProfile`: delete the highlighted profile.
    pub(crate) fn delete_selected_profile(&mut self) {
        let Some(Picker::Profiles { selected, .. }) = &self.profiles.picker else {
            return;
        };
        let index = *selected;
        let result = self.profiles.delete(index);
        let last = self.profiles.all().len() - 1; // built-ins keep it non-empty
        if let Some(Picker::Profiles { selected, note }) = self.profiles.picker.as_mut() {
            *selected = index.min(last);
            *note = result.err();
        }
    }

    pub(crate) fn apply_profile(&mut self, p: &Profile) {
        rmap_log::info!("applied profile {:?}", p.name);
        let (vulns_was_on, services_was_on) =
            (self.form.vuln_matching, self.form.service_detection);
        let f = &mut self.form;
        f.ports = TextInput::new(p.ports.as_str());
        f.scan_type = p.scan_type;
        f.timing = p.timing;
        f.discovery = p.discovery;
        f.service_detection = p.service_detection || p.vuln_matching;
        f.vuln_matching = p.vuln_matching;
        f.error = None;
        if p.vuln_matching && !vulns_was_on {
            self.vulns_ticked(services_was_on);
        }
    }
}

// -------------------------------------------------------------- drawing ---

pub fn draw(frame: &mut Frame, profiles: &Profiles) {
    match &profiles.picker {
        Some(Picker::Profiles { selected, note }) => {
            let all = profiles.all();
            let n_builtin = builtins().len();
            let items = all
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let tag = if i < n_builtin { "built-in" } else { "" };
                    Line::from(vec![
                        Span::raw(format!("{:<18}", p.name)).bold(),
                        Span::raw(format!("{tag:<10}")).dim(),
                        Span::raw(p.summary()),
                    ])
                })
                .collect();
            let help = [
                ("↑↓", "select"),
                ("Enter", "apply"),
                ("Del", "delete"),
                ("Esc", "close"),
            ];
            draw_list(
                frame,
                " profiles ",
                items,
                *selected,
                &help,
                note.as_deref(),
            );
        }
        Some(Picker::Recent { selected }) => {
            let items = if profiles.recent.is_empty() {
                vec![Line::from("no scans started yet").dim()]
            } else {
                profiles
                    .recent
                    .iter()
                    .map(|t| Line::from(t.clone()))
                    .collect()
            };
            let help = [("↑↓", "select"), ("Enter", "use"), ("Esc", "close")];
            draw_list(frame, " recent targets ", items, *selected, &help, None);
        }
        Some(Picker::Save { name, error }) => draw_save(frame, name, error.as_deref()),
        None => {}
    }
}

/// Same look as the saved-scan compare picker in `report_ui.rs`.
fn draw_list(
    frame: &mut Frame,
    title: &'static str,
    items: Vec<Line<'static>>,
    selected: usize,
    help: &[(&str, &str)],
    note: Option<&str>,
) {
    let area = centered(
        frame.area(),
        76.min(frame.area().width),
        (items.len() as u16 + 4)
            .clamp(6, 16)
            .min(frame.area().height),
    );
    frame.render_widget(Clear, area);
    let mut block = Block::bordered()
        .title(title.bold().fg(ACCENT))
        .border_style(Style::new().fg(ACCENT))
        .title_bottom(key_help(help).centered());
    if let Some(note) = note {
        block = block.title(
            Line::from(format!(" {note} "))
                .fg(Color::Yellow)
                .right_aligned(),
        );
    }
    let list = List::new(items.into_iter().map(ListItem::new).collect::<Vec<_>>())
        .block(block)
        .highlight_style(
            Style::new()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▌");
    let mut state = ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_save(frame: &mut Frame, name: &TextInput, error: Option<&str>) {
    let area = centered(
        frame.area(),
        60.min(frame.area().width),
        6.min(frame.area().height),
    );
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .title(" save profile ".bold().fg(ACCENT))
        .border_style(Style::new().fg(ACCENT))
        .title_bottom(key_help(&[("Enter", "save"), ("Esc", "cancel")]).centered());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let room = inner.width.saturating_sub(7) as usize;
    let (window, cursor) = name.window(room);
    let msg = match error {
        Some(e) => Line::from(format!(" ✗ {e}")).fg(Color::Red),
        None => Line::from(" saves every field except the targets").dim(),
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![Span::raw(" Name ").dim(), Span::raw(window)]),
            msg,
        ]),
        inner,
    );
    if inner.height > 0 && inner.width > 0 {
        let x = inner.x + 6 + cursor as u16;
        frame.set_cursor_position((x.min(inner.right().saturating_sub(1)), inner.y));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::app::Screen;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "rmap-profiles-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn app() -> (tokio::runtime::Runtime, App) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let app = App::new(rt.handle().clone());
        (rt, app)
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn ctrl(app: &mut App, c: char) {
        app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL));
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

    fn mine(name: &str) -> Profile {
        Profile {
            name: name.into(),
            ports: "22,80".into(),
            scan_type: ScanType::Syn,
            timing: 5,
            discovery: false,
            service_detection: true,
            vuln_matching: false,
        }
    }

    #[test]
    fn save_and_load_round_trip() {
        let tmp = TempDir::new();
        let mut p = Profiles::load(Some(&tmp.0));
        assert!(p.user.is_empty() && p.recent.is_empty(), "missing files");
        p.save_profile(mine("Office")).unwrap();
        for t in ["10.0.0.0/24", "10.0.1.1", "10.0.0.0/24"] {
            p.remember_targets(t);
        }
        let back = Profiles::load(Some(&tmp.0));
        assert_eq!(back.user, [mine("Office")]);
        assert_eq!(
            back.recent,
            ["10.0.0.0/24", "10.0.1.1"],
            "newest first, no dupes"
        );
    }

    #[test]
    fn recent_keeps_the_last_ten() {
        let mut p = Profiles::load(None);
        for i in 0..15 {
            p.remember_targets(&format!("10.0.0.{i}"));
        }
        p.remember_targets("   ");
        assert_eq!(p.recent.len(), MAX_RECENT);
        assert_eq!(p.recent[0], "10.0.0.14");
        let pasted: Vec<String> = (0..250)
            .map(|i| format!("10.1.{}.{}", i / 250, i % 250))
            .collect();
        p.remember_targets(&pasted.join(","));
        assert!(
            p.recent[0].starts_with("10.1.0.0,"),
            "long pasted lists are kept"
        );
    }

    #[test]
    fn corrupt_files_fall_back_and_are_kept_aside() {
        let tmp = TempDir::new();
        fs::write(tmp.0.join(PROFILES_FILE), "{ not json").unwrap();
        fs::write(tmp.0.join(RECENT_FILE), [0xff, 0xfe, 0x00]).unwrap();
        let p = Profiles::load(Some(&tmp.0));
        assert!(p.user.is_empty() && p.recent.is_empty());
        assert!(tmp.0.join("profiles.json.corrupt").exists());
        assert!(tmp.0.join("recent.json.corrupt").exists());

        // Valid JSON with bad entries: keep the good ones, drop the rest.
        let bad = serde_json::json!([
            mine("ok"),
            { "name": "x" },
            mine("\u{1b}[31mevil"),
            Profile { timing: 9, ..mine("fast") },
            mine("OK"),
            mine("quick sweep"),
        ]);
        fs::write(tmp.0.join(PROFILES_FILE), bad.to_string()).unwrap();
        fs::write(tmp.0.join(RECENT_FILE), r#"["a", 7, "b\u0007", "a", "c"]"#).unwrap();
        let p = Profiles::load(Some(&tmp.0));
        assert_eq!(p.user, [mine("ok")]);
        assert_eq!(p.recent, ["a", "c"]);
    }

    #[test]
    fn builtins_are_protected() {
        let mut p = Profiles::load(None);
        assert!(p.save_profile(mine("Full Audit")).is_err());
        assert!(p.save_profile(mine("  ")).is_err());
        assert!(p.delete(0).is_err());
        let no_ports = Profile {
            ports: " ".into(),
            ..mine("Mine")
        };
        assert_eq!(p.save_profile(no_ports).unwrap_err(), "fill in Ports first");
        p.save_profile(mine("Mine")).unwrap();
        p.save_profile(Profile {
            timing: 1,
            ..mine("mine")
        })
        .unwrap();
        assert_eq!(p.user.len(), 1, "same name replaces");
        assert_eq!(p.user[0].timing, 1);
        p.delete(builtins().len()).unwrap();
        assert!(p.user.is_empty());
    }

    #[test]
    fn applying_a_profile_sets_every_field() {
        let (_rt, mut app) = app();
        for p in builtins().into_iter().chain([mine("x")]) {
            // Start from the opposite of the profile, so every field moves.
            let f = &mut app.form;
            f.ports = "1".into();
            f.scan_type = ScanType::Udp;
            f.timing = 0;
            f.discovery = !p.discovery;
            f.service_detection = !p.service_detection;
            f.vuln_matching = !p.vuln_matching;
            f.error = Some("old".into());
            app.form.targets = "10.0.0.1".into();
            app.apply_profile(&p);
            let f = &app.form;
            assert_eq!(f.ports, p.ports.as_str());
            assert_eq!(f.scan_type, p.scan_type);
            assert_eq!(f.timing, p.timing);
            assert_eq!(f.discovery, p.discovery);
            assert_eq!(f.service_detection, p.service_detection);
            assert_eq!(f.vuln_matching, p.vuln_matching);
            assert!(f.error.is_none());
            assert_eq!(f.targets, "10.0.0.1", "targets untouched");
        }
    }

    #[test]
    fn profile_picker_navigates_applies_and_deletes() {
        let (_rt, mut app) = app();
        app.profiles.save_profile(mine("Mine")).unwrap();
        ctrl(&mut app, 'p');
        let selected = |app: &App| match app.profiles.picker {
            Some(Picker::Profiles { selected, .. }) => selected,
            _ => panic!("picker closed"),
        };
        press(&mut app, KeyCode::Up);
        assert_eq!(selected(&app), 0, "stops at the top");
        press(&mut app, KeyCode::End);
        assert_eq!(selected(&app), 3);
        press(&mut app, KeyCode::Down);
        assert_eq!(selected(&app), 3, "stops at the bottom");
        press(&mut app, KeyCode::Char('k'));
        press(&mut app, KeyCode::Char('d'));
        assert!(app.confirm.is_none(), "built-ins can't be deleted");
        assert!(render(&mut app, 80, 24).contains("can't be deleted"));

        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Delete);
        assert_eq!(app.confirm, Some(Confirm::DeleteProfile));
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(app.profiles.user.len(), 1, "n keeps it");
        press(&mut app, KeyCode::Delete);
        press(&mut app, KeyCode::Char('y'));
        assert!(app.profiles.user.is_empty());
        assert_eq!(selected(&app), 2, "selection clamps");

        press(&mut app, KeyCode::Home);
        press(&mut app, KeyCode::Enter);
        assert!(app.profiles.picker.is_none());
        assert_eq!((app.form.timing, app.form.service_detection), (4, false));
    }

    #[test]
    fn recent_picker_fills_targets() {
        let (_rt, mut app) = app();
        ctrl(&mut app, 'r');
        assert!(render(&mut app, 80, 24).contains("no scans started yet"));
        press(&mut app, KeyCode::Enter); // nothing to pick: harmless
        press(&mut app, KeyCode::Esc);
        assert!(app.profiles.picker.is_none());

        app.profiles.remember_targets("10.0.0.0/24");
        app.profiles.remember_targets("192.168.1.0/24");
        app.form.focus = Field::Timing;
        ctrl(&mut app, 'r');
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.form.targets, "10.0.0.0/24");
        assert_eq!(app.form.focus, Field::Targets);
    }

    #[test]
    fn starting_a_scan_remembers_its_targets() {
        let (_rt, mut app) = app();
        app.form.targets = " 127.0.0.1 ".into();
        app.form.ports = "9".into();
        app.form.discovery = false;
        press(&mut app, KeyCode::Enter);
        assert!(matches!(app.screen, Screen::Results));
        assert_eq!(app.profiles.recent, ["127.0.0.1"]);
    }

    #[test]
    fn save_prompt_saves_the_form() {
        let (_rt, mut app) = app();
        app.form.targets = "10.0.0.1".into();
        app.form.timing = 1;
        ctrl(&mut app, 's');
        for c in "Quick sweep".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        assert!(render(&mut app, 80, 24).contains("built-in profile"));
        ctrl(&mut app, 'u');
        app.on_paste("Night\nignored");
        press(&mut app, KeyCode::Enter);
        assert!(app.profiles.picker.is_none());
        assert_eq!(app.profiles.user[0].name, "Night");
        assert_eq!(app.profiles.user[0].timing, 1);
        assert_eq!(app.form.targets, "10.0.0.1", "typing went to the prompt");
    }

    #[test]
    fn renders_at_80x24_and_tiny_sizes() {
        let (_rt, mut app) = app();
        let setup = render(&mut app, 80, 24);
        for needle in ["^P", "profiles", "^R", "recent", "^S", "save profile"] {
            assert!(setup.contains(needle), "{needle}:\n{setup}");
        }
        ctrl(&mut app, 'p');
        let screen = render(&mut app, 80, 24);
        for needle in [
            "Quick sweep",
            "Full audit",
            "Client baseline",
            "built-in",
            "Enter",
        ] {
            assert!(screen.contains(needle), "{needle}:\n{screen}");
        }
        assert!(
            screen.contains("all · TCP connect · T3 · services + vulns"),
            "{screen}"
        );
        if std::env::var_os("RMAP_SHOW_RENDER").is_some() {
            println!("{setup}{screen}");
        }
        for (w, h) in [(120, 40), (40, 12), (20, 6), (1, 1)] {
            render(&mut app, w, h);
        }
        press(&mut app, KeyCode::Esc);
        ctrl(&mut app, 's');
        assert!(render(&mut app, 80, 24).contains("save profile"));
        for (w, h) in [(20, 6), (1, 1)] {
            render(&mut app, w, h);
        }
    }
}
