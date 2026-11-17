//! Local diagnostic logging and crash reports for rmap.
//!
//! Nothing here leaves the machine. Each run writes one plain-text log file,
//! and a panic writes a crash report next to it with a backtrace and the most
//! recent log lines, so an edge case can be reproduced from what the user
//! attaches to a bug report.
//!
//! Configuration, via environment variables:
//! - `RMAP_LOG`: `off`, `error`, `warn`, `info` (default), `debug` or `trace`
//! - `RMAP_LOG_DIR`: where to write files, instead of the platform default
//!
//! Lines at `debug` and above are always kept in an in-memory ring buffer,
//! even when the file level is `info`, so crash reports carry detailed
//! context without bloating every log file.

mod crash;
mod time;

use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

pub use crash::{crash_report, install_panic_hook};
pub use time::{Timestamp, file_stamp};

/// Log files and crash reports kept per directory; older ones are deleted.
const KEEP_FILES: usize = 20;
/// Lines held in memory for crash reports.
const RECENT_LINES: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    /// Parse a level name. `Ok(None)` means logging is switched off.
    pub fn parse(s: &str) -> Result<Option<Level>, String> {
        Ok(Some(match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "0" => return Ok(None),
            "error" => Level::Error,
            "warn" | "warning" => Level::Warn,
            "info" | "" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            other => return Err(format!("unknown log level '{other}'")),
        }))
    }
}

/// Where and how much to log.
#[derive(Debug, Clone)]
pub struct Config {
    pub dir: PathBuf,
    /// `None` disables logging entirely, crash reports included.
    pub level: Option<Level>,
    pub keep: usize,
}

impl Config {
    /// Read `RMAP_LOG` and `RMAP_LOG_DIR`, falling back to defaults.
    /// An unrecognised level is reported and treated as `info`.
    pub fn from_env() -> (Config, Option<String>) {
        let (level, problem) = match std::env::var("RMAP_LOG") {
            Ok(v) => match Level::parse(&v) {
                Ok(level) => (level, None),
                Err(e) => (
                    Some(Level::Info),
                    Some(format!("RMAP_LOG: {e}; using info")),
                ),
            },
            Err(_) => (Some(Level::Info), None),
        };
        let dir = std::env::var_os("RMAP_LOG_DIR")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(default_dir);
        (
            Config {
                dir,
                level,
                keep: KEEP_FILES,
            },
            problem,
        )
    }
}

/// The platform's conventional place for application logs.
pub fn default_dir() -> PathBuf {
    let env = |k| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        env("LOCALAPPDATA").map(|p| p.join("rmap").join("logs"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|p| p.join("Library/Logs/rmap"))
    } else {
        env("XDG_STATE_HOME")
            .map(|p| p.join("rmap/logs"))
            .or_else(|| env("HOME").map(|p| p.join(".local/state/rmap/logs")))
    };
    base.unwrap_or_else(|| std::env::temp_dir().join("rmap").join("logs"))
}

struct Logger {
    file_level: Level,
    file: Mutex<Option<BufWriter<File>>>,
    path: PathBuf,
    dir: PathBuf,
    recent: Mutex<VecDeque<String>>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
/// Most verbose level anything will record; 0 until `init` succeeds.
static MAX_LEVEL: AtomicU8 = AtomicU8::new(0);

/// Start logging for this process. Returns the log file path, or `None` if
/// logging is switched off. Safe to call more than once; later calls return
/// the existing path.
pub fn init(config: &Config) -> io::Result<Option<PathBuf>> {
    let Some(file_level) = config.level else {
        return Ok(None);
    };
    if let Some(existing) = LOGGER.get() {
        return Ok(Some(existing.path.clone()));
    }
    fs::create_dir_all(&config.dir)?;
    prune(&config.dir, "rmap-", ".log", config.keep.saturating_sub(1));
    prune(&config.dir, "crash-", ".txt", config.keep);

    let path = config
        .dir
        .join(format!("rmap-{}-{}.log", file_stamp(), std::process::id()));
    let file = File::create(&path)?;
    let logger = Logger {
        file_level,
        file: Mutex::new(Some(BufWriter::new(file))),
        path: path.clone(),
        dir: config.dir.clone(),
        recent: Mutex::new(VecDeque::with_capacity(RECENT_LINES)),
    };
    if LOGGER.set(logger).is_err() {
        // Another thread won the race; use its file.
        return Ok(LOGGER.get().map(|l| l.path.clone()));
    }
    MAX_LEVEL.store(file_level.max(Level::Debug) as u8, Ordering::Relaxed);
    write_header(file_level);
    Ok(Some(path))
}

fn write_header(level: Level) {
    let args: Vec<String> = std::env::args().collect();
    log(
        Level::Info,
        "rmap_log",
        format_args!(
            "session start version={} os={} arch={} pid={} level={} args={:?}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::process::id(),
            level.as_str().to_ascii_lowercase(),
            args,
        ),
    );
}

/// Whether a message at `level` would be recorded anywhere. The macros check
/// this first so disabled messages cost one atomic load.
#[inline]
pub fn enabled(level: Level) -> bool {
    level as u8 <= MAX_LEVEL.load(Ordering::Relaxed)
}

/// Record a message. Prefer the `error!`/`warn!`/`info!`/`debug!`/`trace!`
/// macros, which fill in `target` and skip formatting when disabled.
pub fn log(level: Level, target: &str, args: fmt::Arguments<'_>) {
    let Some(logger) = LOGGER.get() else { return };
    let line = format_line(Timestamp::now(), level, target, &thread_label(), args);

    if level <= Level::Debug {
        let mut recent = lock(&logger.recent);
        if recent.len() == RECENT_LINES {
            recent.pop_front();
        }
        recent.push_back(line.clone());
    }
    if level <= logger.file_level {
        let mut file = lock(&logger.file);
        if let Some(w) = file.as_mut() {
            let ok = writeln!(w, "{line}").is_ok() && (level > Level::Info || w.flush().is_ok());
            if !ok {
                // Disk full or similar. Stop writing rather than fail repeatedly.
                *file = None;
            }
        }
    }
}

/// One log line: timestamp, level, module, thread, then the message with
/// newlines escaped so every record stays on a single line.
pub fn format_line(
    ts: Timestamp,
    level: Level,
    target: &str,
    thread: &str,
    args: fmt::Arguments<'_>,
) -> String {
    let msg = args.to_string();
    let msg = if msg.contains(['\n', '\r']) {
        msg.replace('\r', "\\r").replace('\n', "\\n")
    } else {
        msg
    };
    format!("{ts} {:<5} [{thread}] {target}: {msg}", level.as_str())
}

fn thread_label() -> String {
    let t = std::thread::current();
    match t.name() {
        Some(name) => name.to_string(),
        None => format!("{:?}", t.id()),
    }
}

/// Flush buffered lines to disk.
pub fn flush() {
    if let Some(logger) = LOGGER.get()
        && let Some(w) = lock(&logger.file).as_mut()
    {
        let _ = w.flush();
    }
}

/// Path of this session's log file, if logging is on.
pub fn log_path() -> Option<&'static Path> {
    LOGGER.get().map(|l| l.path.as_path())
}

/// Directory holding logs and crash reports, if logging is on.
pub fn log_dir() -> Option<&'static Path> {
    LOGGER.get().map(|l| l.dir.as_path())
}

/// The most recent lines at `debug` and above, oldest first.
pub fn recent() -> Vec<String> {
    LOGGER
        .get()
        .map(|l| lock(&l.recent).iter().cloned().collect())
        .unwrap_or_default()
}

/// Lock a mutex, recovering it if a panicking thread poisoned it: logging
/// must keep working while a crash is being recorded.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Delete the oldest files matching `prefix*suffix` so at most `keep` remain.
/// File names embed a sortable timestamp, so name order is age order.
pub fn prune(dir: &Path, prefix: &str, suffix: &str, keep: usize) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
        })
        .collect();
    if files.len() <= keep {
        return;
    }
    files.sort();
    for old in &files[..files.len() - keep] {
        let _ = fs::remove_file(old);
    }
}

#[macro_export]
macro_rules! log_at {
    ($level:expr, $($arg:tt)+) => {
        if $crate::enabled($level) {
            $crate::log($level, module_path!(), format_args!($($arg)+));
        }
    };
}

#[macro_export]
macro_rules! error { ($($arg:tt)+) => { $crate::log_at!($crate::Level::Error, $($arg)+) }; }
#[macro_export]
macro_rules! warn { ($($arg:tt)+) => { $crate::log_at!($crate::Level::Warn, $($arg)+) }; }
#[macro_export]
macro_rules! info { ($($arg:tt)+) => { $crate::log_at!($crate::Level::Info, $($arg)+) }; }
#[macro_export]
macro_rules! debug { ($($arg:tt)+) => { $crate::log_at!($crate::Level::Debug, $($arg)+) }; }
#[macro_export]
macro_rules! trace { ($($arg:tt)+) => { $crate::log_at!($crate::Level::Trace, $($arg)+) }; }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_levels() {
        assert_eq!(Level::parse("DEBUG"), Ok(Some(Level::Debug)));
        assert_eq!(Level::parse(" warning "), Ok(Some(Level::Warn)));
        assert_eq!(Level::parse(""), Ok(Some(Level::Info)));
        assert_eq!(Level::parse("off"), Ok(None));
        assert!(Level::parse("loud").is_err());
    }

    #[test]
    fn levels_order_by_verbosity() {
        assert!(Level::Error < Level::Warn && Level::Debug < Level::Trace);
    }

    #[test]
    fn line_format_is_single_line() {
        let ts = Timestamp::from_unix_millis(0);
        let line = format_line(
            ts,
            Level::Warn,
            "rmap_engine",
            "main",
            format_args!("a\nb\r\nc"),
        );
        assert_eq!(
            line,
            "1970-01-01T00:00:00.000Z WARN  [main] rmap_engine: a\\nb\\r\\nc"
        );
    }

    #[test]
    fn prune_keeps_newest() {
        let dir = std::env::temp_dir().join(format!("rmap-log-prune-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        for i in 0..5 {
            File::create(dir.join(format!("rmap-2026010{i}-000000-1.log"))).unwrap();
        }
        File::create(dir.join("unrelated.txt")).unwrap();
        prune(&dir, "rmap-", ".log", 2);
        let mut left: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "rmap-20260103-000000-1.log",
                "rmap-20260104-000000-1.log",
                "unrelated.txt"
            ]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn default_dir_is_absolute_or_temp() {
        let d = default_dir();
        assert!(
            d.ends_with("logs") || d.ends_with("rmap"),
            "{}",
            d.display()
        );
    }

    /// The only test that touches the global logger, so tests stay independent.
    #[test]
    fn init_writes_file_and_ring_buffer() {
        let dir = std::env::temp_dir().join(format!("rmap-log-init-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let config = Config {
            dir: dir.clone(),
            level: Some(Level::Info),
            keep: 3,
        };
        let path = init(&config).unwrap().expect("logging on");
        assert_eq!(
            init(&config).unwrap().as_deref(),
            Some(path.as_path()),
            "second init reuses file"
        );

        info!("hello {}", 42);
        debug!("only in memory");
        trace!("nowhere");
        flush();

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("session start version="));
        assert!(text.contains("INFO  ") && text.contains("hello 42"));
        assert!(
            !text.contains("only in memory"),
            "debug stays out of an info-level file"
        );
        let recent = recent().join("\n");
        assert!(recent.contains("only in memory"));
        assert!(!recent.contains("nowhere"));
        assert_eq!(log_dir(), Some(dir.as_path()));
        assert!(enabled(Level::Debug) && !enabled(Level::Trace));
    }
}
