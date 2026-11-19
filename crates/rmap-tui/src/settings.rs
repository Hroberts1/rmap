//! User settings, persisted as `settings.json` in rmap's config directory.
//!
//! Every field has a default, unknown fields are ignored, and a value that
//! fails validation falls back to its default with a warning, so an old,
//! newer or hand-edited file never stops rmap from starting. A file that
//! isn't JSON at all is moved to `settings.json.bad` rather than being
//! overwritten by the next save.

use std::cell::Cell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE: &str = "settings.json";
/// Bigger files are treated as corrupt rather than read into memory.
const MAX_FILE_BYTES: u64 = 64 * 1024;
pub const STALE_DAYS: std::ops::RangeInclusive<u32> = 1..=365;

/// Options people may reasonably want differently. Flat on purpose: add a
/// field with a default and a line in the README's Settings section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Where "Update now" reads the CVE data manifest (`vulns.json`).
    pub vuln_update_url: String,
    /// Fetch the manifest when rmap starts and say if newer data exists.
    /// Never downloads the data itself.
    pub vuln_check_on_startup: bool,
    /// CVE data older than this many days is flagged (1..=365).
    pub vuln_stale_days: u32,
    /// Show the "actively exploited (CISA KEV)" line under such CVEs.
    pub vuln_highlight_exploited: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            vuln_update_url: rmap_vuln::DEFAULT_MANIFEST_URL.to_string(),
            vuln_check_on_startup: false,
            vuln_stale_days: 30,
            vuln_highlight_exploited: true,
        }
    }
}

impl Settings {
    /// Resets fields a hand-edited or damaged file got wrong, returning a
    /// note per reset field.
    fn validate(&mut self) -> Vec<String> {
        let mut notes = Vec::new();
        let default = Settings::default();
        if let Err(e) = check_update_url(&self.vuln_update_url) {
            notes.push(format!("vuln_update_url: {e}; using the default"));
            self.vuln_update_url = default.vuln_update_url;
        }
        if !STALE_DAYS.contains(&self.vuln_stale_days) {
            notes.push(format!(
                "vuln_stale_days must be 1-365, not {}; using {}",
                self.vuln_stale_days, default.vuln_stale_days
            ));
            self.vuln_stale_days = default.vuln_stale_days;
        }
        notes
    }
}

/// An update URL rmap would fetch: the same rules the downloader applies.
pub fn check_update_url(url: &str) -> Result<(), String> {
    rmap_vuln::check_url(url)
        .map(drop)
        .map_err(|e| e.to_string())
}

/// `settings.json` in the platform's config directory: `%APPDATA%\rmap` on
/// Windows, `~/Library/Application Support/rmap` on macOS,
/// `$XDG_CONFIG_HOME/rmap` or `~/.config/rmap` elsewhere. `None` in unit
/// tests (they must never touch the user's file) or when no directory can
/// be found.
pub fn default_path() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    }
    let env = |k| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let dir = if cfg!(windows) {
        env("APPDATA").map(|p| p.join("rmap"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|p| p.join("Library/Application Support/rmap"))
    } else {
        env("XDG_CONFIG_HOME")
            .map(|p| p.join("rmap"))
            .or_else(|| env("HOME").map(|p| p.join(".config/rmap")))
    };
    dir.map(|d| d.join(FILE))
}

/// Reads `path`, returning the settings and a one-line warning when the
/// file was unusable or had bad values. A missing file is just defaults.
pub fn load(path: Option<&Path>) -> (Settings, Option<String>) {
    let Some(path) = path else {
        return (Settings::default(), None);
    };
    let bytes = match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            rmap_log::info!("no settings file at {}; using defaults", path.display());
            return (Settings::default(), None);
        }
        Ok(m) if m.len() > MAX_FILE_BYTES => Err("file is too large".to_string()),
        _ => fs::read(path).map_err(|e| e.to_string()),
    };
    let parsed =
        bytes.and_then(|b| serde_json::from_slice::<Settings>(&b).map_err(|e| e.to_string()));
    let mut settings = match parsed {
        Ok(s) => s,
        Err(e) => {
            let aside = path.with_extension("json.bad");
            rmap_log::warn!("unreadable settings {}: {e}", path.display());
            let warning = match fs::rename(path, &aside) {
                Ok(()) => format!(
                    "settings file was unreadable ({e}); using defaults, old file kept as {}",
                    aside.display()
                ),
                Err(re) => {
                    rmap_log::warn!("could not move {} aside: {re}", path.display());
                    format!("settings file was unreadable ({e}); using defaults")
                }
            };
            return (Settings::default(), Some(warning));
        }
    };
    let notes = settings.validate();
    for n in &notes {
        rmap_log::warn!("settings {}: {n}", path.display());
    }
    rmap_log::info!("settings from {}: {settings:?}", path.display());
    let warning = (!notes.is_empty()).then(|| format!("settings: {}", notes.join("; ")));
    (settings, warning)
}

/// Writes `settings` to `path` atomically (temp file, then rename).
pub fn save(path: &Path, settings: &Settings) -> Result<(), String> {
    crate::profiles::write_json(path, settings).map_err(|e| {
        rmap_log::warn!("could not write {}: {e}", path.display());
        format!("could not save {}: {e}", path.display())
    })?;
    rmap_log::info!("saved settings to {}: {settings:?}", path.display());
    Ok(())
}

// The frame's display settings. `ui::draw` sets them from `App` before
// drawing, so render helpers deep in the tree read them without threading
// `Settings` through every signature. Thread-local: only the UI thread
// draws, and parallel tests can't see each other's values.
thread_local! {
    static DISPLAY: Cell<(u32, bool)> = const { Cell::new((30, true)) };
}

pub(crate) fn set_display(s: &Settings) {
    DISPLAY.set((s.vuln_stale_days, s.vuln_highlight_exploited));
}

pub(crate) fn stale_days() -> u32 {
    DISPLAY.get().0
}

pub(crate) fn highlight_exploited() -> bool {
    DISPLAY.get().1
}

/// A fresh directory under the temp dir, removed on drop.
#[cfg(test)]
pub(crate) struct TempDir(pub PathBuf);

#[cfg(test)]
impl TempDir {
    pub fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rmap-settings-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

#[cfg(test)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_defaults_match_settings_defaults() {
        let d = Settings::default();
        std::thread::spawn(move || {
            assert_eq!(stale_days(), d.vuln_stale_days);
            assert_eq!(highlight_exploited(), d.vuln_highlight_exploited);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn missing_file_gives_defaults_and_save_round_trips() {
        let dir = TempDir::new("roundtrip");
        let path = dir.0.join("nested").join(FILE);
        assert_eq!(load(Some(&path)), (Settings::default(), None));
        let s = Settings {
            vuln_update_url: "http://127.0.0.1:8080/vulns.json".into(),
            vuln_check_on_startup: true,
            vuln_stale_days: 7,
            vuln_highlight_exploited: false,
        };
        save(&path, &s).unwrap();
        assert_eq!(load(Some(&path)), (s, None));
        assert!(
            !path.with_extension("json.tmp").exists(),
            "temp file renamed"
        );
    }

    #[test]
    fn unknown_and_missing_fields_are_fine() {
        let dir = TempDir::new("partial");
        let path = dir.0.join(FILE);
        fs::write(
            &path,
            r#"{"vuln_stale_days": 90, "from_the_future": [1, 2]}"#,
        )
        .unwrap();
        let (s, warning) = load(Some(&path));
        assert_eq!(warning, None);
        assert_eq!(s.vuln_stale_days, 90);
        assert_eq!(s.vuln_update_url, rmap_vuln::DEFAULT_MANIFEST_URL);
        assert!(s.vuln_highlight_exploited && !s.vuln_check_on_startup);
    }

    #[test]
    fn bad_values_fall_back_per_field() {
        let dir = TempDir::new("badvalues");
        let path = dir.0.join(FILE);
        fs::write(
            &path,
            r#"{"vuln_update_url": "http://evil.example/\u001b[2J", "vuln_stale_days": 0,
                "vuln_check_on_startup": true}"#,
        )
        .unwrap();
        let (s, warning) = load(Some(&path));
        assert_eq!(s.vuln_update_url, rmap_vuln::DEFAULT_MANIFEST_URL);
        assert_eq!(s.vuln_stale_days, 30);
        assert!(s.vuln_check_on_startup, "valid fields are kept");
        let warning = warning.unwrap();
        assert!(warning.contains("vuln_update_url") && warning.contains("1-365"));
        assert!(path.exists(), "a parseable file is not moved aside");
    }

    #[test]
    fn corrupt_file_is_moved_aside_not_overwritten() {
        let dir = TempDir::new("corrupt");
        let path = dir.0.join(FILE);
        for junk in [
            &b"{not json"[..],
            b"",
            b"\xff\xfe",
            b"{\"vuln_stale_days\": \"x\"}",
        ] {
            fs::write(&path, junk).unwrap();
            let (s, warning) = load(Some(&path));
            assert_eq!(s, Settings::default());
            assert!(warning.unwrap().contains("settings.json.bad"), "{junk:?}");
            assert!(!path.exists());
            assert_eq!(fs::read(path.with_extension("json.bad")).unwrap(), junk);
        }
        // Huge files aren't read at all.
        fs::write(&path, vec![b' '; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(load(Some(&path)).1.unwrap().contains("too large"));
    }

    #[test]
    fn update_urls_follow_the_downloader_rules() {
        for ok in [
            rmap_vuln::DEFAULT_MANIFEST_URL,
            "https://mirror.example.org/rmap/vulns.json",
            "http://127.0.0.1:8000/vulns.json",
            "http://localhost/vulns.json",
            "http://[::1]:9/v.json",
        ] {
            assert_eq!(check_update_url(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "http://example.com/vulns.json",
            "ftp://example.com/v.json",
            "https://user:pw@example.com/v.json",
            "https://exa mple.com/",
            "https://example.com/\u{1b}[31m",
            "file:///etc/passwd",
            "vulns.json",
            &format!("https://example.com/{}", "a".repeat(5000)),
        ] {
            assert!(check_update_url(bad).is_err(), "{bad:?}");
        }
    }
}
