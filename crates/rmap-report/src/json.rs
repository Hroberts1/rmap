//! JSON export and import.

use crate::model::{FORMAT_VERSION, ScanReport};

/// The report as pretty-printed JSON.
pub fn to_string(report: &ScanReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

/// Parse a report, rejecting files written by a newer, incompatible rmap.
pub fn from_str(text: &str) -> Result<ScanReport, String> {
    #[derive(serde::Deserialize)]
    struct Header {
        format_version: Option<u32>,
    }
    let header: Header =
        serde_json::from_str(text).map_err(|e| format!("not an rmap report: {e}"))?;
    match header.format_version {
        None => return Err("not an rmap report: no format_version".into()),
        Some(v) if v > FORMAT_VERSION => {
            return Err(format!(
                "report format {v} is newer than this rmap understands ({FORMAT_VERSION}); upgrade rmap"
            ));
        }
        Some(_) => {}
    }
    serde_json::from_str(text).map_err(|e| format!("invalid rmap report: {e}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use rmap_core::{DetectMethod, HostState, PortResult, PortState, Protocol, ScanEvent, Service};

    use super::*;
    use crate::ReportBuilder;
    use crate::builder::tests::{config, ip};

    pub(crate) fn sample() -> ScanReport {
        let mut b = ReportBuilder::new(config(), 1_763_389_805_123);
        b.apply(&ScanEvent::Host {
            ip: ip("10.0.0.2"),
            hostname: Some("db.lan".into()),
            state: HostState::Up,
            rtt: Some(Duration::from_micros(1_234)),
        });
        b.apply(&ScanEvent::Host {
            ip: ip("::1"),
            hostname: None,
            state: HostState::Assumed,
            rtt: None,
        });
        b.apply(&ScanEvent::Port {
            ip: ip("10.0.0.2"),
            result: PortResult::new(
                22,
                Protocol::Tcp,
                PortState::Open,
                Some(Duration::from_micros(900)),
            ),
        });
        b.apply(&ScanEvent::Port {
            ip: ip("10.0.0.2"),
            result: PortResult::new(161, Protocol::Udp, PortState::OpenFiltered, None),
        });
        b.apply(&ScanEvent::Service {
            ip: ip("10.0.0.2"),
            protocol: Protocol::Tcp,
            port: 22,
            service: Service {
                name: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: Some("9.6p1".into()),
                info: Some("Ubuntu Linux; protocol 2.0".into()),
                os_hint: Some("Linux".into()),
                cpes: vec!["cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*".into()],
                method: DetectMethod::Probe,
                confidence: 10,
            },
        });
        b.apply(&ScanEvent::HostDone {
            ip: ip("10.0.0.2"),
            closed: 997,
            filtered: 1,
            elapsed: Duration::from_secs(1),
        });
        b.apply(&ScanEvent::Finished {
            elapsed: Duration::from_millis(4_321),
        });
        b.report()
    }

    #[test]
    fn round_trip() {
        let report = sample();
        let text = to_string(&report).unwrap();
        assert!(text.contains("\n  \"format_version\": 1"), "pretty: {text}");
        assert_eq!(from_str(&text).unwrap(), report);
    }

    #[test]
    fn empty_report_round_trips() {
        let report = ScanReport::new(config(), 0);
        assert_eq!(from_str(&to_string(&report).unwrap()).unwrap(), report);
    }

    #[test]
    fn unknown_fields_are_ignored_and_missing_optionals_default() {
        let mut v: serde_json::Value =
            serde_json::from_str(&to_string(&sample()).unwrap()).unwrap();
        v["future_field"] = serde_json::json!({"x": 1});
        let host = &mut v["hosts"][0];
        host.as_object_mut().unwrap().remove("ports");
        host.as_object_mut().unwrap().remove("hostname");
        let r = from_str(&v.to_string()).unwrap();
        assert!(r.hosts[0].ports.is_empty() && r.hosts[0].hostname.is_none());
    }

    #[test]
    fn rejects_newer_and_foreign_files() {
        let mut v: serde_json::Value =
            serde_json::from_str(&to_string(&sample()).unwrap()).unwrap();
        v["format_version"] = (FORMAT_VERSION + 1).into();
        assert!(from_str(&v.to_string()).unwrap_err().contains("newer"));
        assert!(from_str("{}").unwrap_err().contains("format_version"));
        assert!(from_str("not json").is_err());
        assert!(from_str("").is_err());
        assert!(from_str("[1,2]").is_err());
        assert!(from_str(r#"{"format_version":1}"#).is_err());
    }
}
