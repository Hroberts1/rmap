//! Export, auto-save and scan comparison (Milestone 5).
//!
//! State and key handling for the export dialog, the saved-scan picker and
//! the diff screen. The results view feeds every engine event into a
//! `ReportBuilder` (see `ScanView::apply`); this module turns that into
//! files and diffs. Drawing lives in `report_ui.rs`.

use std::path::{Path, PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use rmap_engine::ScanConfig;
use rmap_report::{
    ConfigSummary, DiffLine, ExportFormat, SavedScan, ScanReport, ScanStore, diff, port_ranges,
    store::default_baseline, unix_millis_now,
};

use crate::app::{App, Screen};
use crate::input::TextInput;

/// The export dialog on the results screen.
pub struct ExportDialog {
    pub format: ExportFormat,
    pub path: TextInput,
    /// Outcome of the last attempt: `Ok(path)` or `Err(message)`.
    pub status: Option<Result<String, String>>,
}

impl ExportDialog {
    fn toggle_format(&mut self) {
        let next = self.format.next();
        // Swap the extension if the path still has the old one.
        let old = format!(".{}", self.format.extension());
        if self.path.to_ascii_lowercase().ends_with(&old) {
            // `old` is ASCII, so this byte offset is a char boundary.
            let stem = &self.path[..self.path.len() - old.len()];
            self.path = format!("{stem}.{}", next.extension()).into();
        }
        self.format = next;
    }
}

/// Picking a saved scan to compare the current one with.
pub struct ComparePicker {
    pub scans: Vec<SavedScan>,
    pub selected: usize,
    pub current: ScanReport,
}

/// The diff screen.
pub struct DiffView {
    pub old: String,
    pub new: String,
    pub changes: usize,
    pub lines: Vec<DiffLine>,
    pub scroll: usize,
}

pub enum Dialog {
    Export(ExportDialog),
    Compare(ComparePicker),
}

/// Where scans are saved: the real data directory, except in unit tests,
/// which opt in with a temp dir so they never touch the user's files.
pub fn default_store() -> Option<ScanStore> {
    if cfg!(test) {
        None
    } else {
        Some(ScanStore::from_env())
    }
}

/// The report's description of the scan the user asked for.
pub fn config_summary(targets: &str, exclude: &str, config: &ScanConfig) -> ConfigSummary {
    ConfigSummary {
        targets: targets.trim().to_string(),
        ports: port_ranges(config.ports.as_slice()),
        port_count: config.ports.len(),
        scan_type: config.scan_type,
        timing_level: config.timing.level,
        timing_name: config.timing.name.to_string(),
        discovery: config.discovery,
        service_detection: config.service_detection,
        exclude: exclude.trim().to_string(),
        max_rate: config.max_rate,
        resolve_names: config.resolve_names,
        dns_server: config.dns_server,
    }
}

impl App {
    /// Save the scan once it has finished, been stopped, or failed.
    pub fn autosave_if_done(&mut self) {
        let Some(view) = self.scan.as_mut() else {
            return;
        };
        if view.is_running() || view.save_attempted {
            return;
        }
        view.save_attempted = true;
        let now = unix_millis_now();
        if view.failed {
            view.report.mark_failed(now);
        } else if view.stopped {
            view.report.mark_stopped(now);
        }
        let Some(store) = &self.store else {
            return;
        };
        let report = view.report.report();
        match store.save(&report) {
            Ok(path) => {
                rmap_log::info!(
                    "saved {} scan ({} hosts) to {}",
                    report.status.as_str(),
                    report.hosts.len(),
                    path.display()
                );
                view.log(format!("saved to {}", path.display()));
                view.saved = Some(path);
            }
            Err(e) => {
                rmap_log::error!("could not save scan in {}: {e}", store.dir().display());
                view.log(format!(
                    "could not save scan in {}: {e}",
                    store.dir().display()
                ));
            }
        }
    }

    /// Stop a running scan and save it; called when the app exits.
    pub fn shutdown(&mut self) {
        if let Some(view) = self.scan.as_mut()
            && view.is_running()
        {
            view.scan.stop();
            view.stopped = true;
        }
        self.autosave_if_done();
    }

    pub(crate) fn open_export(&mut self) {
        let Some(view) = self.scan.as_ref() else {
            return;
        };
        let report = view.report.report();
        let format = ExportFormat::Json;
        let path = match &self.store {
            Some(store) => store.export_path(&report, format.extension()),
            None => PathBuf::from(format!("rmap-export.{}", format.extension())),
        };
        rmap_log::debug!("export dialog opened");
        self.dialog = Some(Dialog::Export(ExportDialog {
            format,
            path: path.display().to_string().into(),
            status: None,
        }));
    }

    pub(crate) fn open_compare(&mut self) {
        let Some(view) = self.scan.as_mut() else {
            return;
        };
        if view.is_running() {
            view.log("finish or stop the scan (s) before comparing".into());
            return;
        }
        let Some(store) = &self.store else {
            view.log("saved scans are unavailable".into());
            return;
        };
        let (mut scans, errors) = store.list();
        for (path, e) in &errors {
            rmap_log::warn!("skipping unreadable saved scan {}: {e}", path.display());
        }
        rmap_log::info!(
            "listed {} saved scans in {} ({} unreadable)",
            scans.len(),
            store.dir().display(),
            errors.len()
        );
        // The current scan can't be its own baseline.
        if let Some(own) = &view.saved {
            scans.retain(|s| &s.path != own);
        }
        let current = view.report.report();
        let Some(selected) = default_baseline(&scans, &current, None) else {
            view.log(format!(
                "no other saved scans to compare with in {}",
                store.dir().display()
            ));
            return;
        };
        self.dialog = Some(Dialog::Compare(ComparePicker {
            scans,
            selected,
            current,
        }));
    }

    /// Keys while a dialog is open. Returns after handling every key, so
    /// the screen underneath never sees them.
    pub(crate) fn on_dialog_key(&mut self, key: KeyEvent) {
        match self.dialog.take() {
            Some(Dialog::Export(mut d)) => {
                match key.code {
                    KeyCode::Esc => return,
                    KeyCode::Tab | KeyCode::BackTab => {
                        d.toggle_format();
                        d.status = None;
                    }
                    KeyCode::Enter => self.run_export(&mut d),
                    _ => {
                        if d.path.handle_key(&key) {
                            d.status = None;
                        }
                    }
                }
                self.dialog = Some(Dialog::Export(d));
            }
            Some(Dialog::Compare(mut p)) => {
                let last = p.scans.len().saturating_sub(1);
                match key.code {
                    KeyCode::Esc => return,
                    KeyCode::Up | KeyCode::Char('k') => p.selected = p.selected.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') => p.selected = (p.selected + 1).min(last),
                    KeyCode::PageUp => p.selected = p.selected.saturating_sub(10),
                    KeyCode::PageDown => p.selected = (p.selected + 10).min(last),
                    KeyCode::Home => p.selected = 0,
                    KeyCode::End => p.selected = last,
                    KeyCode::Enter => {
                        if let Some(base) = p.scans.get(p.selected) {
                            self.show_diff(base, &p.current);
                            return;
                        }
                    }
                    _ => {}
                }
                self.dialog = Some(Dialog::Compare(p));
            }
            None => {}
        }
    }

    fn run_export(&mut self, d: &mut ExportDialog) {
        let Some(view) = self.scan.as_mut() else {
            return;
        };
        let path = d.path.trim();
        if path.is_empty() {
            d.status = Some(Err("enter a file path".into()));
            return;
        }
        let path = Path::new(path);
        let report = view.report.report();
        match rmap_report::export(&report, d.format, path) {
            Ok(()) => {
                rmap_log::info!(
                    "exported {} scan as {} to {}",
                    report.status.as_str(),
                    d.format.label(),
                    path.display()
                );
                view.log(format!(
                    "exported {} to {}",
                    d.format.label(),
                    path.display()
                ));
                d.status = Some(Ok(path.display().to_string()));
            }
            Err(e) => {
                rmap_log::warn!("export as {} failed: {e}", d.format.label());
                view.log(format!("export failed: {e}"));
                d.status = Some(Err(e));
            }
        }
    }

    fn show_diff(&mut self, base: &SavedScan, current: &ScanReport) {
        rmap_log::info!("comparing with saved scan {}", base.path.display());
        let d = diff(&base.report, current);
        rmap_log::info!("diff found {} changes", d.len());
        self.diff = Some(DiffView {
            old: base.summary(),
            new: current.summary(),
            changes: d.len(),
            lines: d.lines(),
            scroll: 0,
        });
        self.screen = Screen::Diff;
    }

    pub(crate) fn on_diff_key(&mut self, key: KeyEvent) {
        let Some(view) = self.diff.as_mut() else {
            self.screen = Screen::Results;
            return;
        };
        let last = view.lines.len().saturating_sub(1);
        match key.code {
            KeyCode::Esc | KeyCode::Char('b') => {
                self.diff = None;
                self.screen = Screen::Results;
            }
            KeyCode::Char('q') => {
                rmap_log::info!("quit from diff screen");
                self.request_quit();
            }
            KeyCode::Down | KeyCode::Char('j') => view.scroll = (view.scroll + 1).min(last),
            KeyCode::Up | KeyCode::Char('k') => view.scroll = view.scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => view.scroll = (view.scroll + 10).min(last),
            KeyCode::PageUp => view.scroll = view.scroll.saturating_sub(10),
            KeyCode::Home | KeyCode::Char('g') => view.scroll = 0,
            KeyCode::End | KeyCode::Char('G') => view.scroll = last,
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
