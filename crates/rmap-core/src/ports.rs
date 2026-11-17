//! Port list parsing and a small table of well-known service names.
//!
//! The common-port list and service names below are rmap's own, built from
//! IANA well-known assignments and everyday operational experience. They are
//! deliberately not derived from Nmap's `nmap-services` frequency data.

use crate::{ParseError, err};

/// A sorted, de-duplicated list of TCP/UDP ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortList(Vec<u16>);

impl PortList {
    /// Parse a port specification.
    ///
    /// - `22,80,443` — individual ports
    /// - `1-1024` — inclusive ranges
    /// - `-` or `all` — every port, 1-65535
    /// - `common` — rmap's built-in list of commonly used ports
    ///
    /// Items can be mixed: `common,8000-8100`.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let mut ports = Vec::new();
        for item in input
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
        {
            match item.to_ascii_lowercase().as_str() {
                "-" | "all" => ports.extend(1..=u16::MAX),
                "common" => ports.extend_from_slice(COMMON_PORTS),
                _ => {
                    let (lo, hi) = item.split_once('-').unwrap_or((item, item));
                    let lo = parse_port(lo, item)?;
                    let hi = parse_port(hi, item)?;
                    if lo > hi {
                        return err(format!("{item}: port range runs backwards"));
                    }
                    ports.extend(lo..=hi);
                }
            }
        }
        if ports.is_empty() {
            return err("no ports given");
        }
        ports.sort_unstable();
        ports.dedup();
        Ok(PortList(ports))
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn parse_port(s: &str, item: &str) -> Result<u16, ParseError> {
    match s.trim().parse::<u16>() {
        Ok(0) | Err(_) => err(format!("{item}: ports must be 1-65535")),
        Ok(p) => Ok(p),
    }
}

/// Ports commonly found open on servers, workstations and network gear.
pub const COMMON_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 37, 53, 69, 79, 80, 81, 88, 102, 110, 111, 113, 119, 123, 135, 137, 139,
    143, 161, 179, 389, 427, 443, 445, 465, 500, 502, 513, 514, 515, 548, 554, 587, 623, 631, 636,
    873, 902, 989, 990, 993, 995, 1080, 1194, 1433, 1521, 1701, 1723, 1883, 1900, 2049, 2082, 2083,
    2181, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 3478, 4443, 4786, 5000, 5060, 5061, 5222, 5432,
    5601, 5900, 5985, 5986, 6379, 6443, 6667, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9100, 9200, 9443, 10000, 11211, 27017, 47808, 49152,
];

/// Conventional service name for a TCP port, if rmap knows one.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        37 => "time",
        53 => "dns",
        69 => "tftp",
        79 => "finger",
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8888 => "http",
        88 => "kerberos",
        102 => "s7comm",
        110 => "pop3",
        111 => "rpcbind",
        113 => "ident",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        179 => "bgp",
        389 => "ldap",
        427 => "svrloc",
        443 | 4443 | 8443 | 9443 => "https",
        445 => "smb",
        465 => "smtps",
        500 => "isakmp",
        502 => "modbus",
        513 => "rlogin",
        514 => "rsh",
        515 => "printer",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        623 => "ipmi",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        902 => "vmware-auth",
        989 => "ftps-data",
        990 => "ftps",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1194 => "openvpn",
        1433 => "mssql",
        1521 => "oracle",
        1701 => "l2tp",
        1723 => "pptp",
        1883 => "mqtt",
        1900 => "upnp",
        2049 => "nfs",
        2082 | 2083 => "cpanel",
        2181 => "zookeeper",
        2375 => "docker",
        2376 => "docker-tls",
        3000 => "dev-http",
        3128 => "squid",
        3268 => "ldap-gc",
        3306 => "mysql",
        3389 => "rdp",
        3478 => "stun",
        4786 => "cisco-smi",
        5000 => "upnp-http",
        5060 => "sip",
        5061 => "sips",
        5222 => "xmpp",
        5432 => "postgres",
        5601 => "kibana",
        5900 => "vnc",
        5985 => "winrm",
        5986 => "winrm-https",
        6379 => "redis",
        6443 => "kube-api",
        6667 => "irc",
        7001 => "weblogic",
        9000 => "http-alt",
        9090 => "web-console",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        10000 => "webmin",
        11211 => "memcached",
        27017 => "mongodb",
        47808 => "bacnet",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lists_and_ranges() {
        let p = PortList::parse("443, 22,80-82,22").unwrap();
        assert_eq!(p.as_slice(), &[22, 80, 81, 82, 443]);
    }

    #[test]
    fn all_and_common() {
        assert_eq!(PortList::parse("-").unwrap().len(), 65535);
        let c = PortList::parse("common,65000").unwrap();
        assert_eq!(c.len(), COMMON_PORTS.len() + 1);
    }

    #[test]
    fn common_list_is_sorted_and_unique() {
        assert!(COMMON_PORTS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(PortList::parse("0").is_err());
        assert!(PortList::parse("70000").is_err());
        assert!(PortList::parse("90-80").is_err());
        assert!(PortList::parse("ssh").is_err());
        assert!(PortList::parse("  ").is_err());
    }
}
