//! Scan reports: a serializable record of one scan, built from the engine's
//! event stream, plus export (JSON, Nmap-compatible XML, and client-facing
//! Markdown, CSV and HTML), saved scans on disk, and diffing two reports.
//!
//! Everything here except [`store`] is pure: no clocks, no I/O. Callers pass
//! timestamps in, which keeps the builder and the exporters easy to test.

pub mod builder;
pub mod csv;
pub mod devices;
pub mod diff;
pub mod html;
pub mod json;
pub mod markdown;
pub mod model;
pub mod store;
mod summary;
pub mod tags;
pub mod xml;

pub use builder::ReportBuilder;
pub use devices::{DeviceGroup, dedup_per_device, device_groups};
pub use diff::{DiffKind, DiffLine, ScanDiff, diff};
pub use model::{
    ConfigSummary, FORMAT_VERSION, HostReport, RunStatus, ScanReport, port_ranges, unix_millis_now,
};
pub use store::{SavedScan, ScanStore};

/// Export formats the TUI offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Xml,
    Markdown,
    Csv,
    Html,
}

impl ExportFormat {
    /// Every format, in the order the TUI offers them.
    pub const ALL: [ExportFormat; 5] = [
        ExportFormat::Json,
        ExportFormat::Xml,
        ExportFormat::Markdown,
        ExportFormat::Csv,
        ExportFormat::Html,
    ];

    /// The format after this one, wrapping around.
    pub fn next(self) -> ExportFormat {
        let i = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Xml => "xml",
            ExportFormat::Markdown => "md",
            ExportFormat::Csv => "csv",
            ExportFormat::Html => "html",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ExportFormat::Json => "JSON",
            ExportFormat::Xml => "Nmap XML",
            ExportFormat::Markdown => "Markdown",
            ExportFormat::Csv => "CSV",
            ExportFormat::Html => "HTML",
        }
    }

    /// The report rendered in this format.
    pub fn render(self, report: &ScanReport) -> Result<String, String> {
        match self {
            ExportFormat::Json => json::to_string(report).map_err(|e| e.to_string()),
            ExportFormat::Xml => Ok(xml::to_string(report)),
            ExportFormat::Markdown => Ok(markdown::to_string(report)),
            ExportFormat::Csv => Ok(csv::to_string(report)),
            ExportFormat::Html => Ok(html::to_string(report)),
        }
    }
}

/// Write `report` to `path` in `format`, creating parent directories.
pub fn export(
    report: &ScanReport,
    format: ExportFormat,
    path: &std::path::Path,
) -> Result<(), String> {
    let text = format.render(report)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::TempDir;

    #[test]
    fn export_writes_both_formats_and_creates_dirs() {
        let tmp = TempDir::new("export");
        let report = json::tests::sample();
        let json_path = tmp.0.join("a/b/out.json");
        export(&report, ExportFormat::Json, &json_path).unwrap();
        let back = json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(back, report);

        let xml_path = tmp.0.join("out.xml");
        export(&report, ExportFormat::Xml, &xml_path).unwrap();
        assert!(
            std::fs::read_to_string(&xml_path)
                .unwrap()
                .contains("<nmaprun")
        );

        // Writing to a directory fails with the path in the message.
        let err = export(&report, ExportFormat::Json, &tmp.0).unwrap_err();
        assert!(err.contains(&tmp.0.display().to_string()), "{err}");
        assert_eq!(ExportFormat::Xml.extension(), "xml");
    }

    #[test]
    fn every_format_exports_and_next_cycles_through_all() {
        let tmp = TempDir::new("export-all");
        let report = json::tests::sample();
        let mut f = ExportFormat::Json;
        for _ in 0..ExportFormat::ALL.len() {
            let path = tmp.0.join(format!("out.{}", f.extension()));
            export(&report, f, &path).unwrap();
            assert!(std::fs::read_to_string(&path).unwrap().contains("22"));
            f = f.next();
        }
        assert_eq!(f, ExportFormat::Json);
    }
}
