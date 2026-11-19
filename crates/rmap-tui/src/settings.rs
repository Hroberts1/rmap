//! User settings, persisted as `settings.json` in rmap's config directory.
//!
//! Every field has a default, unknown fields are ignored, and a value that
//! fails validation falls back to its default with a warning, so an old,
//! newer or hand-edited file never stops rmap from starting. A file that
//! isn't JSON at all is moved to `settings.json.bad` rather than being
//! overwritten by the next save.

use std::cell::Cell;
use std::fmt;
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
    /// Where "Download prebuilt" reads the CVE data manifest (`vulns.json`).
    pub vuln_update_url: String,
    /// Fetch the manifest when rmap starts and say if newer data exists.
    /// Never downloads the data itself.
    pub vuln_check_on_startup: bool,
    /// CVE data older than this many days is flagged (1..=365).
    pub vuln_stale_days: u32,
    /// Show the "actively exploited (CISA KEV)" line under such CVEs.
    pub vuln_highlight_exploited: bool,
    /// The user's own NVD API key for "Build from NVD"; empty for none.
    /// The `NVD_API_KEY` environment variable overrides it.
    pub nvd_api_key: ApiKey,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            vuln_update_url: rmap_vuln::DEFAULT_MANIFEST_URL.to_string(),
            vuln_check_on_startup: false,
            vuln_stale_days: 30,
            vuln_highlight_exploited: true,
            nvd_api_key: ApiKey::default(),
        }
    }
}

/// An NVD API key. Its `Debug` hides it, since settings are logged, and
/// logs end up in crash reports.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApiKey(pub String);

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_empty() { "none" } else { "(set)" })
    }
}

/// NVD keys are UUIDs (36 characters); this leaves room for a format
/// change without accepting anything that could be more than a token.
pub const MAX_KEY_CHARS: usize = 64;

pub fn key_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Empty (no key), or a plausible API key. The message never echoes it.
pub fn check_api_key(key: &str) -> Result<(), String> {
    if key.chars().count() > MAX_KEY_CHARS {
        Err(format!("too long (at most {MAX_KEY_CHARS} characters)"))
    } else if !key.chars().all(key_char_ok) {
        Err("only letters, digits, - and _ are allowed".into())
    } else {
        Ok(())
    }
}

/// `••••••••-…-1a2b`: enough to tell keys apart, not to use one.
pub fn mask(key: &str) -> String {
    let n = key.chars().count();
    if n < 12 {
        return "••••••••".into();
    }
    let last: String = key.chars().skip(n - 4).collect();
    format!("••••••••-…-{last}")
}

/// Where the key "Build from NVD" uses comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Env,
    Settings,
}

/// The `NVD_API_KEY` environment variable: unset or empty, else whether
/// it is a usable key.
pub fn env_key() -> Option<Result<String, ()>> {
    let v = std::env::var("NVD_API_KEY").ok()?;
    let v = v.trim();
    (!v.is_empty()).then(|| check_api_key(v).map(|_| v.to_string()).map_err(drop))
}

/// The key to build with: a valid `env` key wins over the saved one.
pub fn effective_key(
    saved: &ApiKey,
    env: Option<Result<String, ()>>,
) -> Option<(String, KeySource)> {
    match env {
        Some(Ok(k)) => Some((k, KeySource::Env)),
        _ if saved.0.is_empty() => None,
        _ => Some((saved.0.clone(), KeySource::Settings)),
    }
}

impl Settings {
    /// Resets fields a hand-edited or damaged file got wrong, returning a
    /// note per reset field.
    fn validate(&mut self) -> Vec<String> {
        let mut notes = Vec::new();
        let default = Settings::default();
        // Not a user's choice, just the old default: follow it silently.
        if self.vuln_update_url == rmap_vuln::OLD_DEFAULT_MANIFEST_URL {
            self.vuln_update_url = default.vuln_update_url.clone();
        }
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
        if let Err(e) = check_api_key(&self.nvd_api_key.0) {
            notes.push(format!("nvd_api_key: {e}; ignoring the saved key"));
            self.nvd_api_key = default.nvd_api_key;
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
    write_private(path, settings).map_err(|e| {
        rmap_log::warn!("could not write {}: {e}", path.display());
        format!("could not save {}: {e}", path.display())
    })?;
    rmap_log::info!("saved settings to {}: {settings:?}", path.display());
    Ok(())
}

/// Like `profiles::write_json`, but the file can hold an API key: on Unix
/// it is created readable by the owner only (0600) before anything is
/// written. On Windows it inherits the per-user `%APPDATA%` folder's
/// access, which other ordinary users can't read.
fn write_private(path: &Path, settings: &Settings) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(settings).map_err(io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    // A stale temp file would keep its old permissions.
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    io::Write::write_all(&mut opts.open(&tmp)?, text.as_bytes())?;
    fs::rename(&tmp, path)
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
            nvd_api_key: ApiKey("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0".into()),
        };
        save(&path, &s).unwrap();
        assert_eq!(load(Some(&path)), (s, None));
        assert!(
            !path.with_extension("json.tmp").exists(),
            "temp file renamed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner-only: it can hold an API key");
        }
    }

    #[test]
    fn api_key_is_validated_masked_and_never_debug_printed() {
        let key = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        assert_eq!(check_api_key(key), Ok(()));
        assert_eq!(check_api_key(""), Ok(()), "no key");
        for bad in [
            "has space",
            "new\nline",
            "esc\u{1b}[2J",
            "é",
            "a/b",
            &"a".repeat(MAX_KEY_CHARS + 1),
        ] {
            let e = check_api_key(bad).unwrap_err();
            assert!(!e.contains(bad), "{e}");
        }
        assert_eq!(mask(key), "••••••••-…-e1f0");
        assert_eq!(mask("short"), "••••••••");
        let s = Settings {
            nvd_api_key: ApiKey(key.into()),
            ..Settings::default()
        };
        let shown = format!("{s:?}");
        assert!(
            !shown.contains("0f1e") && shown.contains("(set)"),
            "{shown}"
        );

        let saved = ApiKey(key.into());
        assert_eq!(effective_key(&ApiKey::default(), None), None);
        assert_eq!(
            effective_key(&saved, None),
            Some((key.to_string(), KeySource::Settings))
        );
        assert_eq!(
            effective_key(&saved, Some(Ok("from-env".into()))),
            Some(("from-env".to_string(), KeySource::Env))
        );
        assert_eq!(
            effective_key(&saved, Some(Err(()))),
            Some((key.to_string(), KeySource::Settings)),
            "a bad env key is ignored"
        );

        let dir = TempDir::new("badkey");
        let path = dir.0.join(FILE);
        fs::write(
            &path,
            r#"{"nvd_api_key": "x\u001b]52;c;aGk=\u0007", "vuln_stale_days": 9}"#,
        )
        .unwrap();
        let (s, warning) = load(Some(&path));
        assert_eq!((s.nvd_api_key, s.vuln_stale_days), (ApiKey::default(), 9));
        let warning = warning.unwrap();
        assert!(
            warning.contains("nvd_api_key") && !warning.contains("aGk"),
            "{warning}"
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
    fn the_old_default_url_moves_to_the_new_one() {
        let dir = TempDir::new("old-url");
        let path = dir.0.join(FILE);
        let json = format!(
            r#"{{"vuln_update_url": "{}"}}"#,
            rmap_vuln::OLD_DEFAULT_MANIFEST_URL
        );
        fs::write(&path, json).unwrap();
        let (s, warning) = load(Some(&path));
        assert_eq!(warning, None);
        assert_eq!(s.vuln_update_url, rmap_vuln::DEFAULT_MANIFEST_URL);
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
