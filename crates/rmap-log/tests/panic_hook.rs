//! End-to-end check that a panic produces a crash report on disk. Lives in
//! its own test binary because it installs a process-wide logger and hook.

use std::fs;

use rmap_log::{Config, Level};

#[test]
fn worker_panic_writes_crash_report() {
    let dir = std::env::temp_dir().join(format!("rmap-log-panic-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let config = Config {
        dir: dir.clone(),
        level: Some(Level::Info),
        keep: 5,
    };
    let log_file = rmap_log::init(&config).unwrap().expect("logging on");
    rmap_log::install_panic_hook();

    rmap_log::debug!("context before the crash: probing 192.0.2.7:443");
    let result = std::thread::Builder::new()
        .name("rmap-worker".into())
        .spawn(|| panic!("simulated edge case: index 3 out of range"))
        .unwrap()
        .join();
    assert!(result.is_err(), "the thread should have panicked");

    let crash_files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("crash-")
        })
        .collect();
    assert_eq!(
        crash_files.len(),
        1,
        "exactly one crash report in {}",
        dir.display()
    );

    let report = fs::read_to_string(&crash_files[0]).unwrap();
    assert!(
        report.contains("simulated edge case: index 3 out of range"),
        "{report}"
    );
    assert!(report.contains("thread:   rmap-worker"), "{report}");
    assert!(
        report.contains("panic_hook.rs"),
        "location is recorded:\n{report}"
    );
    assert!(
        report.contains("context before the crash: probing 192.0.2.7:443"),
        "debug lines reach the report even when the file level is info:\n{report}"
    );
    assert!(
        report.contains(&log_file.display().to_string()),
        "report points at the log file"
    );

    let log = fs::read_to_string(&log_file).unwrap();
    assert!(log.contains("panic on thread 'rmap-worker'"), "{log}");
    assert!(log.contains("crash report written to"), "{log}");

    let _ = fs::remove_dir_all(&dir);
}
