//! Crash reports written when the program panics.

use std::backtrace::Backtrace;
use std::fmt::Write as _;
use std::fs;
use std::panic::PanicHookInfo;
use std::path::PathBuf;

use crate::{Level, Timestamp, file_stamp, flush, log, log_dir, log_path, recent};

/// Build the text of a crash report.
pub fn crash_report(
    message: &str,
    location: &str,
    thread: &str,
    backtrace: &str,
    recent: &[String],
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "rmap crash report");
    let _ = writeln!(out, "=================");
    let _ = writeln!(out, "time:     {}", Timestamp::now());
    let _ = writeln!(out, "version:  {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(
        out,
        "platform: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _ = writeln!(out, "thread:   {thread}");
    let _ = writeln!(out, "location: {location}");
    let _ = writeln!(out, "message:  {message}");
    if let Some(path) = log_path() {
        let _ = writeln!(out, "log file: {}", path.display());
    }
    let _ = writeln!(out, "\nbacktrace\n---------\n{backtrace}");
    let _ = writeln!(
        out,
        "recent log lines (oldest first)\n-------------------------------"
    );
    if recent.is_empty() {
        let _ = writeln!(out, "(none)");
    }
    for line in recent {
        let _ = writeln!(out, "{line}");
    }
    out
}

fn panic_message(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "(non-string panic payload)".into())
}

/// Install a panic hook that logs the panic and writes a crash report.
///
/// Call this before any other code installs its own hook (such as the TUI's
/// terminal-restoring hook), so that theirs runs first and ours runs last.
///
/// A panic on the main thread ends the program, so the default hook still
/// prints the panic and we print where the report went. A panic on another
/// thread (such as a scan worker) is recorded silently: printing to stderr
/// would corrupt the TUI, and the UI surfaces the failure itself.
pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("unnamed").to_string();
        let message = panic_message(info);
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".into());

        log(
            Level::Error,
            "rmap_log::panic",
            format_args!("panic on thread '{thread_name}' at {location}: {message}"),
        );
        flush();

        let report_path = write_report(&message, &location, &thread_name);
        if thread_name == "main" {
            default_hook(info);
            if let Some(path) = report_path {
                eprintln!(
                    "\nrmap crashed. A crash report was saved to:\n  {}\n\
                     Please attach it (after checking it for addresses you'd rather not share) \
                     when filing an issue.",
                    path.display()
                );
            }
        }
    }));
}

fn write_report(message: &str, location: &str, thread: &str) -> Option<PathBuf> {
    let dir = log_dir()?;
    let backtrace = Backtrace::force_capture().to_string();
    let report = crash_report(message, location, thread, &backtrace, &recent());
    let path = dir.join(format!("crash-{}-{}.txt", file_stamp(), std::process::id()));
    fs::write(&path, report).ok()?;
    log(
        Level::Error,
        "rmap_log::panic",
        format_args!("crash report written to {}", path.display()),
    );
    flush();
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_contains_everything_needed_to_reproduce() {
        let recent = vec!["line one".to_string(), "line two".to_string()];
        let r = crash_report(
            "index out of bounds",
            "src/app.rs:10:5",
            "main",
            "0: frame",
            &recent,
        );
        for needle in [
            "index out of bounds",
            "src/app.rs:10:5",
            "thread:   main",
            "0: frame",
            "line one\nline two",
            env!("CARGO_PKG_VERSION"),
        ] {
            assert!(r.contains(needle), "missing {needle:?} in:\n{r}");
        }
    }

    #[test]
    fn report_without_history() {
        assert!(crash_report("x", "y", "z", "", &[]).contains("(none)"));
    }
}
