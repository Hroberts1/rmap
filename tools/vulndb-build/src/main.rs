//! Builds rmap's prebuilt vulnerability database (`vulns.db`) with
//! `rmap-nvd`, the same builder as Settings -> "Build from NVD". A
//! maintainer tool run by `.github/workflows/vulndb.yml`, not part of the
//! scanner.
//!
//! Configured by environment variables:
//! - `NVD_API_KEY`: optional; raises NVD's rate limit from 5 to 50
//!   requests per 30 s.
//! - `OUT_DIR`: where `vulns.db` and `vulns.meta.json` go (default `.`).
//!   Neither file may exist yet.
//! - `NVD_MAX_PAGES`: stop after this many pages, for a quick trial run.
//!   Also skips the minimum-size check, so never set it when publishing.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use rmap_nvd::{BuildOptions, BuildProgress, MIN_CVES, SOURCE};
use rmap_vuln::SCHEMA_VERSION;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vulndb-build: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let env = |k| {
        std::env::var(k)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let key = env("NVD_API_KEY");
    let out_dir = PathBuf::from(env("OUT_DIR").unwrap_or_else(|| ".".into()));
    let max_pages = match env("NVD_MAX_PAGES") {
        Some(v) => Some(
            v.parse::<u64>()
                .map_err(|_| format!("NVD_MAX_PAGES={v:?} is not a number"))?,
        ),
        None => None,
    };
    let db_path = out_dir.join("vulns.db");
    let meta_path = out_dir.join("vulns.meta.json");
    for p in [&db_path, &meta_path] {
        if p.exists() {
            return Err(format!("{} already exists", p.display()));
        }
    }
    eprintln!(
        "NVD API key: {}; out: {}",
        if key.is_some() {
            "set"
        } else {
            "not set (slow rate limit)"
        },
        out_dir.display()
    );

    let mut opts = BuildOptions::new(db_path.clone(), key);
    opts.source = SOURCE.into();
    opts.allow_refresh = false;
    opts.max_pages = max_pages;
    let built = rmap_nvd::build(&opts, &mut print_progress, &AtomicBool::new(false))
        .map_err(|e| format!("{}: {e}", db_path.display()))?;
    let info = built.info;
    eprintln!("kept {} CVEs", info.cve_count);
    if info.cve_count < MIN_CVES {
        eprintln!("warning: below {MIN_CVES} CVEs; allowed only because NVD_MAX_PAGES is set");
    }
    let meta = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "built_at": info.built_at,
        "cve_count": info.cve_count,
        "source": info.source,
    });
    std::fs::write(&meta_path, format!("{meta:#}\n"))
        .map_err(|e| format!("{}: {e}", meta_path.display()))?;
    eprintln!("wrote {} and {}", db_path.display(), meta_path.display());
    Ok(())
}

fn print_progress(p: BuildProgress) {
    match p {
        BuildProgress::Kev => eprintln!("downloading CISA KEV"),
        BuildProgress::Nvd { read, total, eta } => eprintln!(
            "NVD: {read}/{total} CVEs read{}",
            eta.map_or(String::new(), |d| format!(", ~{}s left", d.as_secs()))
        ),
        BuildProgress::Retrying { wait } => eprintln!("retrying in {}s", wait.as_secs()),
        BuildProgress::Writing => eprintln!("writing"),
        BuildProgress::Verifying => eprintln!("verifying"),
    }
}
