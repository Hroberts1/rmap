fn main() -> std::io::Result<()> {
    let (config, config_problem) = rmap_log::Config::from_env();
    if let Err(e) = rmap_log::init(&config) {
        // Logging is a diagnostic aid; never refuse to start over it.
        eprintln!(
            "rmap: could not open log directory {}: {e}",
            config.dir.display()
        );
    }
    if let Some(problem) = config_problem {
        rmap_log::warn!("{problem}");
    }
    // Before the TUI's terminal-restoring hook, so that one runs first.
    rmap_log::install_panic_hook();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rmap-worker")
        .build()?;
    let result = rmap_tui::run(runtime.handle().clone());

    // Stop worker threads before the final log line so nothing logs after it.
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    match &result {
        Ok(()) => rmap_log::info!("session end"),
        Err(e) => rmap_log::error!("session end with error: {e}"),
    }
    rmap_log::flush();
    result
}
