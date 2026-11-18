//! Saved scans on disk.
//!
//! Each finished or stopped scan is written as JSON to the scans directory
//! with a sortable, timestamped name (`scan-20261117-143005-123.json`), so
//! listing the directory in reverse name order lists scans newest first.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::json;
use crate::model::ScanReport;

/// The platform's conventional place for application data, plus `rmap`.
fn data_dir() -> PathBuf {
    let env = |k| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        env("LOCALAPPDATA").map(|p| p.join("rmap"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|p| p.join("Library/Application Support/rmap"))
    } else {
        env("XDG_DATA_HOME")
            .map(|p| p.join("rmap"))
            .or_else(|| env("HOME").map(|p| p.join(".local/share/rmap")))
    };
    base.unwrap_or_else(|| std::env::temp_dir().join("rmap"))
}

/// A saved scan, as listed.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedScan {
    pub path: PathBuf,
    pub report: ScanReport,
}

impl SavedScan {
    pub fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    pub fn summary(&self) -> String {
        self.report.summary()
    }
}

/// Where saved scans and exports live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanStore {
    dir: PathBuf,
    exports: PathBuf,
}

impl ScanStore {
    /// A store in `dir`, with exports in `dir/exports`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        ScanStore {
            exports: dir.join("exports"),
            dir,
        }
    }

    /// `RMAP_SCAN_DIR` if set, otherwise the platform data directory
    /// (scans in `.../rmap/scans`, exports in `.../rmap/exports`).
    pub fn from_env() -> Self {
        match std::env::var_os("RMAP_SCAN_DIR").filter(|v| !v.is_empty()) {
            Some(dir) => ScanStore::new(PathBuf::from(dir)),
            None => {
                let base = data_dir();
                ScanStore {
                    dir: base.join("scans"),
                    exports: base.join("exports"),
                }
            }
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn exports_dir(&self) -> &Path {
        &self.exports
    }

    /// A file stem from the report's start time: `20261117-143005-123`.
    fn stamp(report: &ScanReport) -> String {
        let t = report.started();
        format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}-{:03}",
            t.year, t.month, t.day, t.hour, t.minute, t.second, t.millis
        )
    }

    /// Default export path for `report` in the given extension.
    pub fn export_path(&self, report: &ScanReport, extension: &str) -> PathBuf {
        self.exports
            .join(format!("rmap-{}.{extension}", Self::stamp(report)))
    }

    /// Save a report, never overwriting another scan. Returns its path.
    pub fn save(&self, report: &ScanReport) -> io::Result<PathBuf> {
        let text = json::to_string(report).map_err(io::Error::other)?;
        fs::create_dir_all(&self.dir)?;
        let stamp = Self::stamp(report);
        for n in 0..1000 {
            let name = if n == 0 {
                format!("scan-{stamp}.json")
            } else {
                format!("scan-{stamp}-{n:03}.json")
            };
            let path = self.dir.join(name);
            // create_new claims the name, so two saves can't clobber each
            // other. A write cut short leaves a file that `list` reports
            // as unreadable rather than a silently wrong scan.
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    if let Err(e) = file
                        .write_all(text.as_bytes())
                        .and_then(|_| file.sync_all())
                    {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(e);
                    }
                    return Ok(path);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("too many scans saved at {stamp}"),
        ))
    }

    /// Read one saved scan.
    pub fn load(path: &Path) -> Result<ScanReport, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Saved scans, newest first. Files that can't be read are skipped and
    /// returned separately as `(path, error)`.
    pub fn list(&self) -> (Vec<SavedScan>, Vec<(PathBuf, String)>) {
        let mut scans = Vec::new();
        let mut errors = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return (scans, errors);
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("scan-") && n.ends_with(".json"))
            })
            .collect();
        // By stem, so `scan-X-001` (a second save in the same millisecond)
        // sorts after `scan-X`.
        paths.sort_by(|a, b| b.file_stem().cmp(&a.file_stem()));
        for path in paths {
            match Self::load(&path) {
                Ok(report) => scans.push(SavedScan { path, report }),
                Err(e) => errors.push((path, e)),
            }
        }
        (scans, errors)
    }
}

/// The scan in `scans` that `current` should be compared with by default:
/// the newest one with the same targets that isn't `current` itself, else
/// the newest other scan. Returns an index into `scans`.
pub fn default_baseline(
    scans: &[SavedScan],
    current: &ScanReport,
    current_path: Option<&Path>,
) -> Option<usize> {
    let others = || {
        scans
            .iter()
            .enumerate()
            .filter(move |(_, s)| Some(s.path.as_path()) != current_path)
            .filter(move |(_, s)| s.report.started_ms <= current.started_ms)
    };
    others()
        .find(|(_, s)| s.report.config.targets.trim() == current.config.targets.trim())
        .or_else(|| others().next())
        .or_else(|| {
            scans
                .iter()
                .enumerate()
                .find(|(_, s)| Some(s.path.as_path()) != current_path)
        })
        .map(|(i, _)| i)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::builder::tests::config;

    /// A fresh, empty directory under the system temp dir; removed on drop.
    pub(crate) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "rmap-report-test-{tag}-{}-{}",
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

    fn report(started_ms: i64, targets: &str) -> ScanReport {
        let mut c = config();
        c.targets = targets.into();
        ScanReport::new(c, started_ms)
    }

    #[test]
    fn saves_and_lists_newest_first() {
        let tmp = TempDir::new("list");
        let store = ScanStore::new(tmp.0.join("scans"));
        assert!(store.list().0.is_empty(), "missing dir lists as empty");

        let day = 86_400_000;
        let a = store.save(&report(1_700_000_000_000, "a")).unwrap();
        let c = store
            .save(&report(1_700_000_000_000 + 2 * day, "c"))
            .unwrap();
        let b = store.save(&report(1_700_000_000_000 + day, "b")).unwrap();
        // Same millisecond: gets a suffix instead of overwriting.
        let c2 = store
            .save(&report(1_700_000_000_000 + 2 * day, "c2"))
            .unwrap();
        assert_ne!(c, c2);
        assert!(
            c.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("scan-20231116-")
        );

        // Junk that should be ignored or reported.
        fs::write(store.dir().join("notes.txt"), "hi").unwrap();
        fs::write(store.dir().join("scan-99999999-broken.json"), "{oops").unwrap();
        fs::create_dir_all(store.dir().join("scan-dir.json")).unwrap();

        let (scans, errors) = store.list();
        let order: Vec<&str> = scans
            .iter()
            .map(|s| s.report.config.targets.as_str())
            .collect();
        assert_eq!(order, ["c2", "c", "b", "a"]);
        assert_eq!(scans[3].path, a);
        assert_eq!(scans[2].path, b);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].0.ends_with("scan-99999999-broken.json"));
        assert!(scans[0].summary().contains("c2"));
        assert!(scans[0].file_name().starts_with("scan-"));

        assert_eq!(ScanStore::load(&b).unwrap().config.targets, "b");
        assert!(ScanStore::load(&tmp.0.join("nope.json")).is_err());
    }

    #[test]
    fn save_into_unwritable_location_errors() {
        let tmp = TempDir::new("bad");
        let file = tmp.0.join("a-file");
        fs::write(&file, "x").unwrap();
        // A directory can't be created under a regular file.
        let store = ScanStore::new(file.join("scans"));
        assert!(store.save(&report(0, "x")).is_err());
    }

    #[test]
    fn export_paths_live_in_the_exports_dir() {
        let store = ScanStore::new("/data/scans");
        let p = store.export_path(&report(0, "x"), "xml");
        assert_eq!(
            p,
            Path::new("/data/scans/exports/rmap-19700101-000000-000.xml")
        );
    }

    #[test]
    fn baseline_prefers_same_targets() {
        let scans: Vec<SavedScan> = [(400, "b"), (300, "a"), (200, "b"), (100, "a")]
            .iter()
            .map(|(t, tg)| SavedScan {
                path: PathBuf::from(format!("scan-{t}.json")),
                report: report(*t, tg),
            })
            .collect();
        let cur = report(400, "a");
        let cur_path = PathBuf::from("scan-400.json");
        assert_eq!(default_baseline(&scans, &cur, Some(&cur_path)), Some(1));
        let other = report(500, " c ");
        assert_eq!(default_baseline(&scans, &other, None), Some(0), "newest");
        // Only the current scan is saved: nothing to compare with.
        assert_eq!(default_baseline(&scans[..1], &cur, Some(&cur_path)), None);
        assert_eq!(default_baseline(&[], &cur, None), None);
        // Everything saved is newer than the current scan: still offer one.
        let old = report(1, "z");
        assert_eq!(default_baseline(&scans, &old, None), Some(0));
    }
}
