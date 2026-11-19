//! The Settings screen (`S` on the results screen, F2 on the setup form)
//! and the two ways to get CVE data: "Build from NVD" and "Download
//! prebuilt".
//!
//! Nothing here touches the network unless the user presses one of them,
//! or turned on the startup check. Both ask before starting. Download
//! fetches the manifest on a background thread, shows what it offers (and
//! whether it is older than the installed data), then on `y` installs it
//! on another background thread with live progress. Build says whether it
//! will be a full build or a refresh and roughly how long it takes, then
//! on `y` runs `rmap_nvd::build` on a background thread with live progress
//! and ETA; pressing the button again cancels it. Closing the screen
//! cancels a pending check or question; a download or build already
//! running finishes in the background and reports to the log panel.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use rmap_nvd::{BuildError, BuildOptions, BuildProgress, Built, Plan};
use rmap_vuln::{DbError, DbInfo, Manifest, Progress, UpdateError};

use crate::app::{App, WARNING_PREFIX};
use crate::input::TextInput;
use crate::mouse::HitMap;
use crate::settings::{
    self, ApiKey, KeySource, MAX_KEY_CHARS, STALE_DAYS, Settings, check_api_key, check_update_url,
};
use crate::ui::{ACCENT, centered, key_help};

/// The downloader's own URL limit.
const MAX_URL_CHARS: usize = 2048;
const MAX_DAYS_CHARS: usize = 3;
/// External text (manifest fields, error messages) is cut to this.
const MAX_SHOWN: usize = 300;

type FetchFn = fn(&str) -> Result<Manifest, UpdateError>;
type InstallFn = fn(&Manifest, &Path, &mut dyn FnMut(Progress)) -> Result<DbInfo, UpdateError>;
type BuildFn =
    fn(&BuildOptions, &mut dyn FnMut(BuildProgress), &AtomicBool) -> Result<Built, BuildError>;

/// The network side of getting CVE data: `rmap_vuln::{fetch_manifest,
/// install}` and `rmap_nvd::build`. Plain function pointers, so tests
/// drive the whole flow with fakes.
#[derive(Clone, Copy)]
pub struct Updater {
    pub fetch: FetchFn,
    pub install: InstallFn,
    pub build: BuildFn,
}

impl Default for Updater {
    fn default() -> Self {
        Updater {
            fetch: rmap_vuln::fetch_manifest,
            install: rmap_vuln::install,
            build: rmap_nvd::build,
        }
    }
}

/// What the installed CVE data file looks like, read when rmap starts,
/// when Settings opens and after an update. Not per frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbStatus {
    /// No data directory could be found.
    NoLocation,
    Missing,
    Invalid(String),
    Ready(DbInfo),
}

impl DbStatus {
    pub fn read(path: Option<&Path>) -> DbStatus {
        let Some(path) = path else {
            return DbStatus::NoLocation;
        };
        // Opened and closed straight away: an open file can't be replaced
        // on Windows.
        match rmap_vuln::Database::open(path) {
            Ok(db) => DbStatus::Ready(db.info().clone()),
            Err(DbError::NotFound) => DbStatus::Missing,
            Err(e) => DbStatus::Invalid(e.to_string()),
        }
    }

    /// Whether the setup form should hint that there's no data to match.
    pub fn needs_download(&self) -> bool {
        matches!(self, DbStatus::Missing | DbStatus::Invalid(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    BuildNvd,
    /// "Download prebuilt" (the original "Update now").
    UpdateNow,
    ApiKey,
    CopyLink,
    Url,
    ResetUrl,
    Startup,
    Days,
    Highlight,
}

const ROWS: [Row; 9] = [
    Row::BuildNvd,
    Row::UpdateNow,
    Row::ApiKey,
    Row::CopyLink,
    Row::Url,
    Row::ResetUrl,
    Row::Startup,
    Row::Days,
    Row::Highlight,
];

/// The open screen's own state: focus and the text being edited.
pub struct SettingsScreen {
    pub focus: Row,
    url: TextInput,
    days: TextInput,
    key: TextInput,
    /// "saved", or why a change wasn't; and whether it is an error.
    message: Option<(String, bool)>,
}

enum Job {
    Idle,
    Checking {
        host: String,
        rx: Receiver<Result<Manifest, UpdateError>>,
    },
    Confirm {
        manifest: Manifest,
        question: String,
    },
    Installing {
        rx: Receiver<InstallMsg>,
        progress: Option<Progress>,
    },
    ConfirmBuild {
        question: String,
    },
    Building {
        rx: Receiver<BuildMsg>,
        progress: Option<BuildProgress>,
        cancel: Arc<AtomicBool>,
    },
}

impl Job {
    /// Waiting for a y/n answer.
    fn asking(&self) -> bool {
        matches!(self, Job::Confirm { .. } | Job::ConfirmBuild { .. })
    }

    /// A download or build that runs on even if Settings closes.
    fn running(&self) -> bool {
        matches!(self, Job::Installing { .. } | Job::Building { .. })
    }
}

enum InstallMsg {
    Progress(Progress),
    Done(Result<DbInfo, UpdateError>),
}

enum BuildMsg {
    Progress(BuildProgress),
    Done(Result<Built, BuildError>),
}

pub struct SettingsState {
    pub settings: Settings,
    /// Where settings are saved; `None` keeps them in memory (unit tests).
    path: Option<PathBuf>,
    /// Where the CVE data is installed; `None` when there's nowhere.
    pub db_path: Option<PathBuf>,
    pub db: DbStatus,
    pub updater: Updater,
    pub screen: Option<SettingsScreen>,
    job: Job,
    startup: Option<Receiver<Result<Manifest, UpdateError>>>,
    /// The latest update result, startup notice or settings warning, and
    /// whether it is an error. Shown on the setup form and this screen.
    pub notice: Option<(String, bool)>,
    /// `NVD_API_KEY`, read once at startup (`None` in unit tests).
    pub env_key: Option<Result<String, ()>>,
}

impl SettingsState {
    pub fn new(path: Option<PathBuf>, db_path: Option<PathBuf>, updater: Updater) -> Self {
        let (settings, warning) = settings::load(path.as_deref());
        let db = DbStatus::read(db_path.as_deref());
        rmap_log::info!("CVE data {}: {db:?}", show_path(db_path.as_deref()));
        SettingsState {
            settings,
            path,
            db_path,
            db,
            updater,
            screen: None,
            job: Job::Idle,
            startup: None,
            notice: warning.map(|w| (clean(&w), true)),
            env_key: None,
        }
    }

    /// The real files, or in-memory defaults in unit tests.
    pub fn from_env() -> Self {
        let db_path = if cfg!(test) {
            None
        } else {
            rmap_vuln::default_path()
        };
        let mut s = SettingsState::new(settings::default_path(), db_path, Updater::default());
        if !cfg!(test) {
            s.env_key = settings::env_key();
        }
        match &s.env_key {
            Some(Ok(_)) => rmap_log::info!("NVD API key: from NVD_API_KEY"),
            Some(Err(())) => rmap_log::warn!("NVD_API_KEY is not a valid NVD API key; ignored"),
            None => {}
        }
        if s.settings.vuln_check_on_startup {
            s.start_startup_check();
        }
        s
    }

    /// Fetch the manifest in the background to say if newer data exists.
    /// Only ever runs when the user turned the startup check on.
    pub fn start_startup_check(&mut self) {
        let url = self.settings.vuln_update_url.clone();
        rmap_log::info!("startup check for newer CVE data at {}", host_of(&url));
        match spawn("rmap-vuln-startup", self.updater.fetch, url) {
            Ok(rx) => self.startup = Some(rx),
            Err(e) => rmap_log::info!("startup check not started: {e}"),
        }
    }

    pub fn is_open(&self) -> bool {
        self.screen.is_some()
    }

    /// Whether a check, download or build is in progress.
    pub fn is_busy(&self) -> bool {
        !matches!(self.job, Job::Idle)
    }

    /// The key "Build from NVD" would use, and where it comes from.
    fn build_key(&self) -> Option<(String, KeySource)> {
        settings::effective_key(&self.settings.nvd_api_key, self.env_key.clone())
    }

    fn persist(&mut self) {
        let result = match &self.path {
            Some(path) => settings::save(path, &self.settings),
            None => Ok(()),
        };
        if let Some(screen) = self.screen.as_mut() {
            screen.message = Some(match result {
                Ok(()) => ("saved".into(), false),
                Err(e) => (clean(&e), true),
            });
        }
    }
}

/// Runs `fetch(url)` on a named background thread.
fn spawn(
    name: &str,
    fetch: FetchFn,
    url: String,
) -> std::io::Result<Receiver<Result<Manifest, UpdateError>>> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            // The receiver is gone if the user closed Settings meanwhile.
            let _ = tx.send(fetch(&url));
        })?;
    Ok(rx)
}

impl App {
    pub(crate) fn open_settings(&mut self) {
        rmap_log::debug!("settings opened");
        let s = &mut self.settings;
        s.db = DbStatus::read(s.db_path.as_deref());
        s.screen = Some(SettingsScreen {
            focus: Row::BuildNvd,
            url: TextInput::new(s.settings.vuln_update_url.as_str()),
            days: TextInput::new(s.settings.vuln_stale_days.to_string()),
            key: TextInput::new(s.settings.nvd_api_key.0.as_str()),
            message: None,
        });
    }

    fn close_settings(&mut self) {
        let rejected = self.commit_text();
        let s = &mut self.settings;
        if matches!(s.job, Job::Checking { .. }) || s.job.asking() {
            rmap_log::info!("CVE data update cancelled: settings closed");
            s.job = Job::Idle;
        }
        // An edit that didn't validate is dropped; say so where it's seen.
        if let Some(e) = rejected {
            s.notice = Some((format!("{e}; change discarded"), true));
        }
        s.screen = None;
        rmap_log::debug!("settings closed");
    }

    /// A scan or rescan holds the CVE data open and would be reading it
    /// mid-update.
    fn scan_busy(&self) -> bool {
        self.scan
            .as_ref()
            .is_some_and(|v| v.is_running() || v.rescan.is_some())
    }

    pub(crate) fn on_settings_key(&mut self, key: KeyEvent) {
        if self.settings.job.asking() {
            let build = matches!(self.settings.job, Job::ConfirmBuild { .. });
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') if build => self.start_build(),
                KeyCode::Char('y') | KeyCode::Char('Y') => self.start_install(),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    let what = if build { "build" } else { "download" };
                    rmap_log::info!("CVE data {what} declined");
                    self.settings.job = Job::Idle;
                    self.set_message(&format!("{what} cancelled"), false);
                }
                _ => {}
            }
            return;
        }
        let Some(focus) = self.settings.screen.as_ref().map(|s| s.focus) else {
            return;
        };
        let code = key.code;
        // Enter/Space press buttons and flip toggles; ← → flip toggles too.
        let activate = matches!(code, KeyCode::Enter | KeyCode::Char(' '))
            || (matches!(focus, Row::Startup | Row::Highlight)
                && matches!(code, KeyCode::Left | KeyCode::Right));
        match code {
            KeyCode::Esc => self.close_settings(),
            KeyCode::Tab | KeyCode::Down => self.move_settings_focus(true),
            KeyCode::BackTab | KeyCode::Up => self.move_settings_focus(false),
            _ => match focus {
                Row::Url | Row::Days | Row::ApiKey if code == KeyCode::Enter => {
                    self.commit_text();
                }
                Row::Url | Row::Days | Row::ApiKey => self.edit_text(focus, &key),
                _ if !activate => {}
                Row::BuildNvd => self.build_nvd(),
                Row::UpdateNow => self.update_now(),
                Row::CopyLink => {
                    self.clipboard = Some(rmap_nvd::API_KEY_URL.into());
                    self.set_message(
                        "link copied (if your terminal allows OSC 52 clipboard writes)",
                        false,
                    );
                }
                Row::ResetUrl => {
                    let default = Settings::default().vuln_update_url;
                    if let Some(sc) = self.settings.screen.as_mut() {
                        sc.url = TextInput::new(default.as_str());
                    }
                    self.settings.settings.vuln_update_url = default;
                    rmap_log::info!("update URL reset to the default");
                    self.settings.persist();
                }
                Row::Startup => {
                    let s = &mut self.settings.settings;
                    s.vuln_check_on_startup = !s.vuln_check_on_startup;
                    self.settings.persist();
                }
                Row::Highlight => {
                    let s = &mut self.settings.settings;
                    s.vuln_highlight_exploited = !s.vuln_highlight_exploited;
                    self.settings.persist();
                }
            },
        }
    }

    pub(crate) fn on_settings_paste(&mut self, pasted: &str) {
        if self.settings.job.asking() {
            return;
        }
        let Some(sc) = self.settings.screen.as_mut() else {
            return;
        };
        let line = pasted.lines().next().unwrap_or("").trim();
        let focus = sc.focus;
        let Some((input, max)) = text_field(sc, focus) else {
            return;
        };
        let room = max.saturating_sub(input.len_chars());
        let text: String = line
            .chars()
            .filter(|&c| allowed(focus, c))
            .take(room)
            .collect();
        input.insert_str(&text);
        sc.message = None;
    }

    pub(crate) fn on_settings_mouse(&mut self, kind: MouseEventKind, pos: Position) {
        if kind != MouseEventKind::Down(MouseButton::Left) || self.settings.job.asking() {
            return;
        }
        let Some(&(row, _)) = self.hits.settings.iter().find(|(_, r)| r.contains(pos)) else {
            return;
        };
        if self.settings.screen.as_ref().map(|s| s.focus) != Some(row) {
            if self.commit_text().is_some() {
                return;
            }
            if let Some(sc) = self.settings.screen.as_mut() {
                sc.focus = row;
            }
        }
        if !matches!(row, Row::Url | Row::Days | Row::ApiKey) {
            let space = KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE);
            self.on_settings_key(space);
        }
    }

    fn set_message(&mut self, text: &str, error: bool) {
        if let Some(sc) = self.settings.screen.as_mut() {
            sc.message = Some((text.into(), error));
        }
    }

    /// Leaving a text field saves it; an invalid value keeps the focus
    /// there, with the reason shown, until it is fixed or Esc discards it.
    fn move_settings_focus(&mut self, forward: bool) {
        if self.commit_text().is_some() {
            return;
        }
        if let Some(sc) = self.settings.screen.as_mut() {
            let i = ROWS.iter().position(|r| *r == sc.focus).unwrap_or(0);
            let n = ROWS.len();
            sc.focus = ROWS[if forward {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            }];
        }
    }

    fn edit_text(&mut self, focus: Row, key: &KeyEvent) {
        let Some(sc) = self.settings.screen.as_mut() else {
            return;
        };
        let Some((input, max)) = text_field(sc, focus) else {
            return;
        };
        // Ctrl keys edit (Ctrl-U clears); every other character inserts.
        if let KeyCode::Char(c) = key.code
            && !key.modifiers.contains(KeyModifiers::CONTROL)
            && (input.len_chars() >= max || !allowed(focus, c))
        {
            return;
        }
        if input.handle_key(key) {
            sc.message = None;
        }
    }

    /// Saves the focused text field if it changed and is valid. An invalid
    /// value stays in the field with the reason shown, which is returned.
    fn commit_text(&mut self) -> Option<String> {
        let s = &mut self.settings;
        let sc = s.screen.as_mut()?;
        let error = match sc.focus {
            Row::Url => {
                let url = sc.url.trim().to_string();
                if url == s.settings.vuln_update_url {
                    return None;
                }
                match check_update_url(&url) {
                    Ok(()) => {
                        rmap_log::info!("update URL set to {}", host_of(&url));
                        s.settings.vuln_update_url = url;
                        s.persist();
                        return None;
                    }
                    Err(e) => clean(&format!("Update URL not saved: {e}")),
                }
            }
            Row::Days => {
                let text = sc.days.trim().to_string();
                if text == s.settings.vuln_stale_days.to_string() {
                    return None;
                }
                match text.parse::<u32>() {
                    Ok(days) if STALE_DAYS.contains(&days) => {
                        s.settings.vuln_stale_days = days;
                        s.persist();
                        return None;
                    }
                    _ => "Stale after not saved: enter a number of days from 1 to 365".into(),
                }
            }
            Row::ApiKey => {
                let key = sc.key.trim().to_string();
                if key == s.settings.nvd_api_key.0 {
                    return None;
                }
                match check_api_key(&key) {
                    Ok(()) => {
                        let what = if key.is_empty() { "cleared" } else { "saved" };
                        rmap_log::info!("NVD API key {what}");
                        s.settings.nvd_api_key = ApiKey(key);
                        s.persist();
                        return None;
                    }
                    // Never echoes the key.
                    Err(e) => format!("NVD API key not saved: {e}"),
                }
            }
            _ => return None,
        };
        rmap_log::info!("{error}");
        sc.message = Some((error.clone(), true));
        Some(error)
    }

    /// Step 1 of an update: fetch the manifest in the background.
    fn update_now(&mut self) {
        if self.scan_busy() {
            self.set_message(
                "stop the running scan first: it is reading the CVE data",
                true,
            );
            return;
        }
        let s = &mut self.settings;
        if s.job.running() {
            self.set_message("a download or build is already running", true);
            return;
        }
        if s.db_path.is_none() {
            self.set_message(
                "no data directory to install into (set HOME or LOCALAPPDATA)",
                true,
            );
            return;
        }
        let url = s.settings.vuln_update_url.clone();
        let host = host_of(&url);
        rmap_log::info!("CVE data update: checking {host}");
        match spawn("rmap-vuln-check", s.updater.fetch, url) {
            Ok(rx) => {
                s.job = Job::Checking { host, rx };
                s.notice = None;
                if let Some(sc) = s.screen.as_mut() {
                    sc.message = None;
                }
            }
            Err(e) => self.set_message(&format!("could not start the update: {e}"), true),
        }
    }

    /// Step 3, after `y`: download and install in the background.
    fn start_install(&mut self) {
        let s = &mut self.settings;
        let Job::Confirm { manifest, .. } = std::mem::replace(&mut s.job, Job::Idle) else {
            return;
        };
        let Some(dest) = s.db_path.clone() else {
            return;
        };
        rmap_log::info!(
            "CVE data download confirmed: built {}, {} bytes from {}",
            manifest.built_at,
            manifest.size,
            host_of(&manifest.db_url)
        );
        let (tx, rx) = mpsc::channel();
        let install = s.updater.install;
        let spawned = std::thread::Builder::new()
            .name("rmap-vuln-update".into())
            .spawn(move || {
                let result = install(&manifest, &dest, &mut |p| {
                    let _ = tx.send(InstallMsg::Progress(p));
                });
                let _ = tx.send(InstallMsg::Done(result));
            });
        match spawned {
            Ok(_) => s.job = Job::Installing { rx, progress: None },
            Err(e) => self.set_message(&format!("could not start the download: {e}"), true),
        }
    }

    /// "Build from NVD": asks first (full build or refresh, how long, which
    /// key); while a build runs, the same button cancels it.
    fn build_nvd(&mut self) {
        if let Job::Building { cancel, .. } = &self.settings.job {
            cancel.store(true, Ordering::Relaxed);
            rmap_log::info!("NVD build: cancel requested");
            self.set_message("cancelling after the current request…", false);
            return;
        }
        if self.scan_busy() {
            self.set_message(
                "stop the running scan first: it is reading the CVE data",
                true,
            );
            return;
        }
        let s = &mut self.settings;
        if s.job.running() {
            self.set_message("a download or build is already running", true);
            return;
        }
        let Some(dest) = s.db_path.clone() else {
            self.set_message(
                "no data directory to build into (set HOME or LOCALAPPDATA)",
                true,
            );
            return;
        };
        let plan = rmap_nvd::plan(&dest);
        let question = build_question(&plan, s.build_key().map(|(_, from)| from));
        rmap_log::info!("NVD build offered: {plan:?}");
        s.job = Job::ConfirmBuild { question };
        if let Some(sc) = s.screen.as_mut() {
            sc.message = None;
        }
    }

    /// After `y`: build in the background.
    fn start_build(&mut self) {
        let s = &mut self.settings;
        s.job = Job::Idle;
        let Some(dest) = s.db_path.clone() else {
            return;
        };
        let opts = BuildOptions::new(dest, s.build_key().map(|(key, _)| key));
        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let build = s.updater.build;
        let spawned = std::thread::Builder::new()
            .name("rmap-nvd-build".into())
            .spawn(move || {
                let result = build(
                    &opts,
                    &mut |p| {
                        let _ = tx.send(BuildMsg::Progress(p));
                    },
                    &flag,
                );
                let _ = tx.send(BuildMsg::Done(result));
            });
        match spawned {
            Ok(_) => {
                s.notice = None;
                s.job = Job::Building {
                    rx,
                    progress: None,
                    cancel,
                };
            }
            Err(e) => self.set_message(&format!("could not start the build: {e}"), true),
        }
    }

    /// Called every frame: collects background check and download results.
    pub(crate) fn poll_settings(&mut self) {
        let s = &mut self.settings;
        if let Some(rx) = &s.startup {
            match rx.try_recv() {
                Ok(result) => {
                    s.startup = None;
                    self.on_startup_manifest(result);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    s.startup = None;
                    rmap_log::info!("startup update check stopped without an answer");
                }
            }
        }
        let s = &mut self.settings;
        let finished = match &mut s.job {
            Job::Checking { rx, .. } => match rx.try_recv() {
                Ok(Ok(manifest)) => {
                    let question = question(&manifest, &s.db);
                    s.job = Job::Confirm { manifest, question };
                    None
                }
                Ok(Err(e)) => Some(Err(format!("CVE data update check failed: {e}"))),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => {
                    Some(Err("CVE data update check stopped unexpectedly".into()))
                }
            },
            Job::Installing { rx, progress } => loop {
                match rx.try_recv() {
                    Ok(InstallMsg::Progress(p)) => *progress = Some(p),
                    Ok(InstallMsg::Done(Ok(info))) => {
                        break Some(Ok(format!(
                            "CVE data updated: built {}, {} CVEs",
                            date10(&info.built_at),
                            thousands(info.cve_count)
                        )));
                    }
                    Ok(InstallMsg::Done(Err(e))) => {
                        break Some(Err(format!("CVE data update failed: {e}")));
                    }
                    Err(TryRecvError::Empty) => break None,
                    Err(TryRecvError::Disconnected) => {
                        break Some(Err("CVE data update stopped unexpectedly".into()));
                    }
                }
            },
            Job::Building { rx, progress, .. } => loop {
                match rx.try_recv() {
                    Ok(BuildMsg::Progress(p)) => *progress = Some(p),
                    Ok(BuildMsg::Done(Ok(b))) => {
                        let count = thousands(b.info.cve_count);
                        break Some(Ok(if b.refreshed {
                            format!(
                                "CVE data refreshed from NVD: {} changed CVEs read, {count} CVEs",
                                thousands(b.read)
                            )
                        } else {
                            format!("CVE data built from NVD: {count} CVEs")
                        }));
                    }
                    Ok(BuildMsg::Done(Err(BuildError::Cancelled))) => {
                        break Some(Ok("NVD build cancelled; CVE data unchanged".into()));
                    }
                    Ok(BuildMsg::Done(Err(e))) => {
                        break Some(Err(format!("NVD build failed: {e}")));
                    }
                    Err(TryRecvError::Empty) => break None,
                    Err(TryRecvError::Disconnected) => {
                        break Some(Err("NVD build stopped unexpectedly".into()));
                    }
                }
            },
            _ => None,
        };
        if let Some(result) = finished {
            s.job = Job::Idle;
            s.db = DbStatus::read(s.db_path.as_deref());
            match result {
                Ok(line) => self.report(&line, false),
                Err(line) => self.report(&line, true),
            }
        }
    }

    fn on_startup_manifest(&mut self, result: Result<Manifest, UpdateError>) {
        match result {
            Ok(m) => {
                let newer = match &self.settings.db {
                    DbStatus::Ready(info) => m.built_at > info.built_at,
                    _ => true,
                };
                if newer {
                    let line = format!(
                        "newer CVE data is available (built {}); press F2 / S to update",
                        date10(&m.built_at)
                    );
                    self.report(&line, false);
                } else {
                    rmap_log::info!("startup check: CVE data is up to date");
                }
            }
            // Offline is normal; not worth a banner.
            Err(e) => rmap_log::info!("startup update check failed: {e}"),
        }
    }

    /// A result line for the log file, the log panel and the notice line.
    fn report(&mut self, line: &str, error: bool) {
        let line = clean(line);
        rmap_log::info!("{line}");
        if let Some(view) = self.scan.as_mut() {
            view.log(if error {
                format!("{WARNING_PREFIX}{line}")
            } else {
                line.clone()
            });
        }
        self.settings.notice = Some((line, error));
    }
}

/// The y/n question for a fetched manifest, with the rollback guard: an
/// older or identical build than the installed one says so.
fn question(m: &Manifest, db: &DbStatus) -> String {
    let size = size_text(m.size);
    let built = date10(&m.built_at);
    let host = host_of(&m.db_url);
    let base = format!(
        "Download {size} of CVE data built {built} ({} CVEs) from {host}?",
        thousands(m.cve_count)
    );
    let q = match db {
        DbStatus::Ready(info) if !info.built_at.is_empty() => {
            match m.built_at.as_str().cmp(info.built_at.as_str()) {
                std::cmp::Ordering::Less => format!(
                    "{base} This is OLDER than the data you have ({}).",
                    date10(&info.built_at)
                ),
                std::cmp::Ordering::Equal => format!(
                    "You already have this data (built {built}). Download {size} from {host} again?"
                ),
                std::cmp::Ordering::Greater => base,
            }
        }
        _ => base,
    };
    clean(&q)
}

/// The y/n question before building from NVD.
fn build_question(plan: &Plan, key: Option<KeySource>) -> String {
    let what = match plan {
        Plan::Full(why) => format!(
            "Full build ({why}): every CVE, about 30 minutes without an API key, \
             10-15 with one."
        ),
        Plan::Refresh { age_days, .. } => format!(
            "Refresh: fetches only CVEs changed since the last NVD sync ({}), \
             usually a minute or two.",
            match age_days {
                0 => "today".to_string(),
                1 => "1 day ago".to_string(),
                n => format!("{n} days ago"),
            }
        ),
    };
    let key = match key {
        Some(KeySource::Settings) => "your NVD API key from Settings",
        Some(KeySource::Env) => "your NVD API key from NVD_API_KEY",
        None => "no API key (NVD's slower keyless rate)",
    };
    // All rmap's own text, so not cut to MAX_SHOWN like outside text.
    format!(
        "Build the CVE data from NVD? {what} Uses {key}; requests go to nvd.nist.gov and \
         cisa.gov. The current data is replaced only if the new file checks out. {}",
        rmap_nvd::NVD_NOTICE
    )
}

/// The focused text input and its length limit, if the row is one.
fn text_field(sc: &mut SettingsScreen, row: Row) -> Option<(&mut TextInput, usize)> {
    match row {
        Row::Url => Some((&mut sc.url, MAX_URL_CHARS)),
        Row::Days => Some((&mut sc.days, MAX_DAYS_CHARS)),
        Row::ApiKey => Some((&mut sc.key, MAX_KEY_CHARS)),
        _ => None,
    }
}

/// Characters a text field takes.
fn allowed(row: Row, c: char) -> bool {
    match row {
        Row::Days => c.is_ascii_digit(),
        Row::ApiKey => settings::key_char_ok(c),
        _ => true,
    }
}

/// "about 14 min left" for an ETA.
fn eta_text(eta: Duration) -> String {
    match eta.as_secs() {
        0..60 => "under a minute left".into(),
        s => format!("about {} min left", s.div_ceil(60)),
    }
}

/// Replaces control characters (terminal escapes) and caps the length, for
/// text that came from a server, a file or an error.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(MAX_SHOWN)
        .collect()
}

/// The host of a URL, for "from github.com" and log lines (never the
/// query string, which may carry a signed token).
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    clean(authority.rsplit('@').next().unwrap_or(""))
}

fn date10(s: &str) -> &str {
    s.get(..10).unwrap_or(s)
}

fn size_text(bytes: u64) -> String {
    if bytes >= 100_000 {
        format!("{:.1} MB", bytes as f64 / 1e6)
    } else {
        format!("{} KB", bytes.div_ceil(1000))
    }
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The end of `s` in `width` columns: a path's file name matters most.
fn tail(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        return s.to_string();
    }
    let keep = width.saturating_sub(1);
    std::iter::once('…')
        .take(width.min(1))
        .chain(s.chars().skip(n - keep))
        .collect()
}

fn show_path(path: Option<&Path>) -> String {
    path.map_or_else(|| "(no location)".into(), |p| p.display().to_string())
}

/// The status line for the installed data, and whether it needs attention.
fn status_text(db: &DbStatus, stale_days: u32, today: i64) -> (String, Style) {
    let warn = Style::new().fg(Color::Yellow);
    match db {
        DbStatus::Ready(info) => {
            let mut style = Style::new();
            let mut text = match crate::vuln_status::date_days(&info.built_at) {
                Some(day) => {
                    let age = today - day;
                    if age > i64::from(stale_days) {
                        style = warn;
                    }
                    let ago = match age {
                        ..=0 => "today".to_string(),
                        1 => "1 day ago".to_string(),
                        n => format!("{n} days ago"),
                    };
                    format!("built {} ({ago})", date10(&info.built_at))
                }
                None => {
                    style = warn;
                    "build date unknown".into()
                }
            };
            text += &format!(" · {} CVEs", thousands(info.cve_count));
            if info.source == rmap_nvd::SOURCE {
                text += &format!(" · {} (prebuilt download)", info.source);
            } else if !info.source.is_empty() {
                text += &format!(" · {}", info.source);
            }
            (clean(&text), style)
        }
        DbStatus::Missing => (
            "none yet: build or download it to turn on CVE matching".into(),
            warn,
        ),
        DbStatus::Invalid(e) => (
            clean(&format!(
                "unusable ({e}); building or downloading replaces it"
            )),
            Style::new().fg(Color::Red),
        ),
        DbStatus::NoLocation => (
            "no data directory found (set HOME or LOCALAPPDATA)".into(),
            warn,
        ),
    }
}

/// The line under the get-data buttons: what the background job is doing,
/// or the latest result.
fn job_line(state: &SettingsState, scan_busy: bool) -> Line<'static> {
    let text = match &state.job {
        Job::Checking { host, .. } => format!("checking {host}…"),
        Job::Confirm { .. } | Job::ConfirmBuild { .. } => "waiting for your answer…".into(),
        Job::Building { cancel, .. } if cancel.load(Ordering::Relaxed) => {
            "cancelling after the current request…".into()
        }
        Job::Building { progress, .. } => match progress {
            None | Some(BuildProgress::Kev) => "downloading the CISA KEV list…".into(),
            Some(BuildProgress::Nvd { read, total, eta }) => {
                let mut t = format!(
                    "NVD: {} of {} CVEs ({}%)",
                    thousands(*read),
                    thousands(*total),
                    (read.saturating_mul(100)).checked_div(*total).unwrap_or(0)
                );
                if let Some(eta) = eta {
                    t += &format!(" · {}", eta_text(*eta));
                }
                t
            }
            Some(BuildProgress::Retrying { wait }) => format!(
                "NVD is busy or rate limiting: retrying in {} s…",
                wait.as_secs()
            ),
            Some(BuildProgress::Writing) => "writing the database…".into(),
            Some(BuildProgress::Verifying) => "verifying the new database…".into(),
        },
        Job::Installing { progress, .. } => match progress {
            Some(Progress::Downloading { done, total }) => format!(
                "downloading {} of {} ({}%)",
                size_text(*done),
                size_text(*total),
                (done.saturating_mul(100)).checked_div(*total).unwrap_or(0)
            ),
            Some(Progress::Verifying) => "verifying the download…".into(),
            Some(Progress::Installing) => "installing…".into(),
            Some(Progress::Manifest) | None => "starting the download…".into(),
        },
        Job::Idle if scan_busy => {
            return Line::from("stop the running scan first: it is reading the CVE data")
                .fg(Color::Yellow);
        }
        Job::Idle => {
            return match &state.notice {
                Some((text, true)) => Line::from(format!("✗ {text}")).fg(Color::Red),
                Some((text, false)) => Line::from(format!("✓ {text}")).fg(Color::Green),
                None => Line::default(),
            };
        }
    };
    Line::from(text).fg(ACCENT)
}

pub(crate) fn draw(frame: &mut Frame, state: &SettingsState, scan_busy: bool, hits: &mut HitMap) {
    let Some(sc) = &state.screen else {
        return;
    };
    frame.render_widget(Clear, frame.area());
    let area = centered(
        frame.area(),
        76.min(frame.area().width),
        24.min(frame.area().height),
    );
    let block = Block::bordered()
        .title(Line::from(" rmap · settings ").bold().fg(ACCENT))
        .title_bottom(
            key_help(&[("Tab", "next"), ("Enter", "change"), ("Esc", "back")]).centered(),
        );
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [
        section,
        file,
        status,
        _,
        update,
        job,
        _,
        key,
        link,
        link_url,
        url,
        reset,
        startup,
        startup_note,
        days,
        highlight,
        _,
        message,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .margin(1)
    .areas(inner);
    // The two get-data buttons share a line: label (13) + "[ Build from
    // NVD ]" (18) + 2 spaces + "[ Download prebuilt ]" (21).
    let part = |x: u16, w: u16| {
        let x = update.x.saturating_add(x).min(update.right());
        Rect {
            x,
            width: w.min(update.right() - x),
            ..update
        }
    };
    hits.settings = vec![
        (Row::BuildNvd, part(0, 31)),
        (Row::UpdateNow, part(33, 21)),
        (Row::ApiKey, key),
        (Row::CopyLink, link),
        (Row::Url, url),
        (Row::ResetUrl, reset),
        (Row::Startup, startup),
        (Row::Days, days),
        (Row::Highlight, highlight),
    ];

    let label = |row: Option<Row>, text: &'static str| {
        let style = if row.is_some_and(|r| r == sc.focus) {
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::DIM)
        };
        Span::styled(format!("{text:>11}  "), style)
    };
    let button = |row: Row, text: &'static str, enabled: bool| {
        let span = Span::raw(format!("[ {text} ]"));
        if !enabled {
            span.dim()
        } else if sc.focus == row {
            span.reversed().bold()
        } else {
            span.bold()
        }
    };
    let check = |on: bool| if on { "[x] " } else { "[ ] " };
    let pad = || Span::raw(" ".repeat(13));
    let line = |frame: &mut Frame, area: Rect, spans: Vec<Span<'static>>| {
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    };

    line(
        frame,
        section,
        vec![Span::raw(" Vulnerability data").bold().fg(ACCENT)],
    );
    line(
        frame,
        file,
        vec![
            label(None, "Data file"),
            Span::raw(tail(
                &clean(&show_path(state.db_path.as_deref())),
                file.width.saturating_sub(13) as usize,
            ))
            .dim(),
        ],
    );
    let today = rmap_report::unix_millis_now().div_euclid(86_400_000);
    let (status_line, status_style) = status_text(&state.db, state.settings.vuln_stale_days, today);
    let [status_label, status_text_area] =
        Layout::horizontal([Constraint::Length(13), Constraint::Min(0)]).areas(status);
    frame.render_widget(
        Paragraph::new(Line::from(label(None, "Status"))),
        status_label,
    );
    frame.render_widget(
        Paragraph::new(Line::styled(status_line, status_style)).wrap(Wrap { trim: true }),
        status_text_area,
    );

    let building = matches!(state.job, Job::Building { .. });
    let free = !scan_busy && !state.job.running();
    let get_focus = Some(sc.focus).filter(|f| matches!(f, Row::BuildNvd | Row::UpdateNow));
    let mut update_spans = vec![
        label(get_focus, "Get data"),
        if building {
            button(Row::BuildNvd, " Cancel build ", true)
        } else {
            button(Row::BuildNvd, "Build from NVD", free)
        },
        Span::raw("  "),
        button(Row::UpdateNow, "Download prebuilt", free),
    ];
    if free && !state.is_busy() {
        update_spans.push(Span::raw("  both ask first").dim());
    }
    line(frame, update, update_spans);
    let mut job_spans = vec![pad()];
    job_spans.extend(job_line(state, scan_busy).spans);
    frame.render_widget(
        Paragraph::new(Line::from(job_spans)).wrap(Wrap { trim: false }),
        job,
    );

    // A focused input scrolls sideways so the cursor stays on screen; an
    // unfocused one shows its start, or `shown` in its place.
    let input = |frame: &mut Frame,
                 area: Rect,
                 row: Row,
                 name,
                 value: &TextInput,
                 shown: Option<Span<'static>>| {
        let width = area.width.saturating_sub(13) as usize;
        let (window, cursor) = if sc.focus == row {
            let (w, c) = value.window(width);
            (Span::raw(w), c)
        } else {
            let s = shown.unwrap_or_else(|| Span::raw(crate::ui::ellipsize(value, width)));
            (s, 0)
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![label(Some(row), name), window])),
            area,
        );
        if sc.focus == row && !state.job.asking() {
            let x = area.x + 13 + cursor as u16;
            frame.set_cursor_position((x.min(area.right().saturating_sub(1)), area.y));
        }
    };
    // The key is shown only while it is being edited.
    let saved = &state.settings.nvd_api_key.0;
    let key_shown = match &state.env_key {
        Some(Ok(_)) => Span::raw("set by NVD_API_KEY (overrides the saved key)").fg(ACCENT),
        Some(Err(())) => {
            Span::raw("NVD_API_KEY is not a valid key and is ignored").fg(Color::Yellow)
        }
        None if saved.is_empty() => Span::raw("none: optional, makes full builds faster").dim(),
        None => Span::raw(settings::mask(saved)),
    };
    input(
        frame,
        key,
        Row::ApiKey,
        "NVD API key",
        &sc.key,
        Some(key_shown),
    );
    line(
        frame,
        link,
        vec![
            pad(),
            button(Row::CopyLink, "Copy key request link", true),
            Span::raw("  free from NVD").dim(),
        ],
    );
    line(
        frame,
        link_url,
        vec![pad(), Span::raw(rmap_nvd::API_KEY_URL).dim()],
    );
    input(frame, url, Row::Url, "Update URL", &sc.url, None);
    let mut reset_spans = vec![pad(), button(Row::ResetUrl, "Reset URL to default", true)];
    if state.settings.vuln_update_url == rmap_vuln::DEFAULT_MANIFEST_URL {
        reset_spans.push(Span::raw("  (using the default)").dim());
    }
    line(frame, reset, reset_spans);
    line(
        frame,
        startup,
        vec![
            label(Some(Row::Startup), "On startup"),
            Span::raw(check(state.settings.vuln_check_on_startup)),
            Span::raw("check for updates on startup"),
        ],
    );
    line(
        frame,
        startup_note,
        vec![
            pad(),
            Span::raw("    contacts the update URL each time rmap starts").dim(),
        ],
    );
    let days_input = Rect {
        width: days.width.min(16),
        ..days
    };
    input(frame, days_input, Row::Days, "Stale after", &sc.days, None);
    frame.render_widget(
        Paragraph::new(Line::from("days: warn when CVE data is older than this")).dim(),
        Rect {
            x: days.x.saturating_add(17).min(days.right()),
            width: days.width.saturating_sub(17),
            ..days
        },
    );
    line(
        frame,
        highlight,
        vec![
            label(Some(Row::Highlight), "Highlight"),
            Span::raw(check(state.settings.vuln_highlight_exploited)),
            Span::raw("mark actively exploited CVEs (CISA KEV)"),
        ],
    );
    let shown = match &sc.message {
        Some((text, true)) => Line::from(format!("✗ {text}")).fg(Color::Red),
        Some((text, false)) => Line::from(format!("✓ {text}")).fg(Color::Green),
        None => Line::from(match &state.path {
            Some(path) => tail(
                &clean(&format!("changes save to {}", path.display())),
                message.width as usize,
            ),
            None => "changes last until rmap quits (no config directory)".into(),
        })
        .dim(),
    };
    frame.render_widget(Paragraph::new(shown), message);

    match &state.job {
        Job::Confirm { question, .. } => draw_question(frame, question, "download"),
        Job::ConfirmBuild { question } => draw_question(frame, question, "build"),
        _ => {}
    }
}

fn draw_question(frame: &mut Frame, question: &str, yes: &'static str) {
    let width = 64.min(frame.area().width);
    // Narrower than the box, since word wrapping leaves ragged lines.
    let text_w = usize::from(width.saturating_sub(10)).max(1);
    let lines = question.chars().count().div_ceil(text_w) as u16 + 1;
    let area = centered(frame.area(), width, (lines + 4).min(frame.area().height));
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(question.to_string()),
            Line::default(),
            key_help(&[("y", yes), ("n", "cancel")]).centered(),
        ])
        .wrap(Wrap { trim: true })
        .block(
            Block::bordered()
                .title(" confirm ".bold().fg(Color::Yellow))
                .border_style(Style::new().fg(Color::Yellow)),
        ),
        area,
    );
}

#[cfg(test)]
mod tests;
