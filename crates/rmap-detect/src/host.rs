//! Labels that need the whole host, not one port: once every port of a
//! host has been detected, [`refine`] revisits port-table guesses and TLS on
//! the SSH port using what the other ports and the MAC vendor revealed.

use rmap_core::{DetectMethod, Protocol, Service};

/// `info` prefix for TLS on 22/tcp that looks like a UniFi device's
/// inform/adoption listener.
pub const UNIFI_INFORM: &str = "UniFi device inform/adoption (TLS on 22)";

/// `info` of the Zebra Web Services port-number guess.
const ZEBRA_9200: &str = "Zebra Web Services (guess from the host's Zebra banner)";

/// A UniFi device's self-signed CN: its MAC as 12 hex digits, then an
/// alphanumeric suffix (optionally after `-` or `_`).
pub fn unifi_cn(cn: &str) -> bool {
    let (Some(mac), Some(rest)) = (cn.get(..12), cn.get(12..)) else {
        return false;
    };
    let suffix = rest.strip_prefix(['-', '_']).unwrap_or(rest);
    mac.bytes().all(|b| b.is_ascii_hexdigit())
        && !suffix.is_empty()
        && suffix.len() <= 32
        && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Relabel `ports` of one host in place, given its MAC `vendor`. Returns
/// the indices of the services it changed, so they can be re-reported.
pub fn refine(ports: &mut [(u16, Protocol, Service)], vendor: Option<&str>) -> Vec<usize> {
    let zebra = vendor.is_some_and(|v| v.contains("Zebra"))
        || ports
            .iter()
            .any(|(_, _, s)| s.product.as_deref().is_some_and(|p| p.starts_with("Zebra")));
    let ubiquiti = vendor.is_some_and(|v| v.contains("Ubiquiti"));
    let mut changed = Vec::new();
    for (i, (port, protocol, s)) in ports.iter_mut().enumerate() {
        if *protocol != Protocol::Tcp {
            continue;
        }
        if zebra && *port == 9200 && s.method == DetectMethod::PortTable {
            s.name = "zebra-link-os".into();
            s.info.get_or_insert_with(|| ZEBRA_9200.into());
            changed.push(i);
        } else if ubiquiti
            && *port == 22
            && s.name == "tls"
            && let Some(rest) = s
                .info
                .as_deref()
                .and_then(|t| t.strip_prefix(crate::NOT_SSH))
        {
            s.info = Some(format!("{UNIFI_INFORM}{rest}"));
            changed.push(i);
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(name: &str, method: DetectMethod) -> Service {
        Service {
            name: name.into(),
            method,
            ..Default::default()
        }
    }

    #[test]
    fn unifi_cns() {
        assert!(unifi_cn("f09fc2a1b2c3U7PG2"));
        assert!(unifi_cn("F09FC2A1B2C3_US"));
        assert!(!unifi_cn("f09fc2a1b2c3"), "no suffix");
        assert!(!unifi_cn("unifi.example.test"));
        assert!(!unifi_cn("f09fc2a1b2c3 x"));
        assert!(!unifi_cn("f09fc2a1b2cé1"), "never slices inside a char");
    }

    #[test]
    fn zebra_host_relabels_9200() {
        let mut ftp = svc("ftp", DetectMethod::Banner);
        ftp.product = Some("Zebra print server".into());
        let mut ports = vec![
            (21, Protocol::Tcp, ftp),
            (
                9200,
                Protocol::Tcp,
                svc("elasticsearch", DetectMethod::PortTable),
            ),
        ];
        assert_eq!(refine(&mut ports, None), [1]);
        assert_eq!(ports[1].2.display_name(), "zebra-link-os?");
        assert_eq!(ports[1].2.info.as_deref(), Some(ZEBRA_9200));

        // Without Zebra evidence, the guess stays; a real match is never touched.
        let mut other = vec![(
            9200,
            Protocol::Tcp,
            svc("elasticsearch", DetectMethod::PortTable),
        )];
        assert!(refine(&mut other, Some("Dell")).is_empty());
        let mut real = vec![(9200, Protocol::Tcp, svc("http", DetectMethod::Probe))];
        assert!(refine(&mut real, Some("Zebra Technologies")).is_empty());
    }

    #[test]
    fn ubiquiti_mac_names_tls_on_22() {
        let mut tls = svc("tls", DetectMethod::Probe);
        tls.info = Some(format!("{}; TLSv1.2; self-signed", crate::NOT_SSH));
        let mut ports = vec![(22, Protocol::Tcp, tls)];
        assert!(refine(&mut ports.clone(), Some("Dell")).is_empty());
        assert_eq!(refine(&mut ports, Some("Ubiquiti")), [0]);
        assert_eq!(
            ports[0].2.info.as_deref(),
            Some("UniFi device inform/adoption (TLS on 22); TLSv1.2; self-signed")
        );
    }
}
