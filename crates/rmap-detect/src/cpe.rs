//! CPE 2.3 names for detected products, in the form NVD uses, so that
//! vulnerability matching (Milestone 4) can look them up.
//!
//! Versions are split the way NVD records them: a trailing letter suffix
//! becomes the `update` field (`OpenSSH 8.9p1` → version `8.9`, update `p1`;
//! `ProFTPD 1.3.5e` → `1.3.5`, `e`), as does a second word (`0.9.60 beta`).
//! An unknown version is `*` (any), and so is the update when there is none.

use rmap_core::Service;

struct Entry {
    /// `Service::product` exactly as the match rules produce it.
    product: &'static str,
    vendor: &'static str,
    name: &'static str,
    /// Whether the version a banner reports is the product's version.
    /// For example, Exchange's SMTP banner reports a Windows build number.
    versioned: bool,
}

const fn e(product: &'static str, vendor: &'static str, name: &'static str) -> Entry {
    Entry {
        product,
        vendor,
        name,
        versioned: true,
    }
}

const fn unversioned(product: &'static str, vendor: &'static str, name: &'static str) -> Entry {
    Entry {
        product,
        vendor,
        name,
        versioned: false,
    }
}

/// Product → NVD vendor and product. Add a row here whenever a match rule
/// introduces a new product name, plus a case in the tests below.
const TABLE: &[Entry] = &[
    e("OpenSSH", "openbsd", "openssh"),
    e("Dropbear sshd", "dropbear_ssh_project", "dropbear_ssh"),
    e("nginx", "f5", "nginx"),
    e("Apache httpd", "apache", "http_server"),
    e(
        "Microsoft IIS httpd",
        "microsoft",
        "internet_information_services",
    ),
    e("lighttpd", "lighttpd", "lighttpd"),
    e("Caddy", "caddyserver", "caddy"),
    e("Postfix smtpd", "postfix", "postfix"),
    e("Exim smtpd", "exim", "exim"),
    e("Sendmail", "sendmail", "sendmail"),
    unversioned("Microsoft Exchange smtpd", "microsoft", "exchange_server"),
    e("vsftpd", "beasts", "vsftpd"),
    e("ProFTPD", "proftpd", "proftpd"),
    e("Pure-FTPd", "pureftpd", "pure-ftpd"),
    e("FileZilla ftpd", "filezilla-project", "filezilla_server"),
    unversioned(
        "Microsoft ftpd",
        "microsoft",
        "internet_information_services",
    ),
    e("Dovecot pop3d", "dovecot", "dovecot"),
    e("Dovecot imapd", "dovecot", "dovecot"),
    e(
        "Courier pop3d",
        "double_precision_incorporated",
        "courier-imap",
    ),
    e(
        "Courier Imapd",
        "double_precision_incorporated",
        "courier-imap",
    ),
    e("MySQL", "oracle", "mysql"),
    e("MariaDB", "mariadb", "mariadb"),
    e("PostgreSQL", "postgresql", "postgresql"),
    e("Redis", "redis", "redis"),
    e("Valkey", "lfprojects", "valkey"),
    e("MongoDB", "mongodb", "mongodb"),
    e("Memcached", "memcached", "memcached"),
    e("Elasticsearch", "elastic", "elasticsearch"),
    e("RabbitMQ", "vmware", "rabbitmq"),
    e("Asterisk", "digium", "asterisk"),
    unversioned("Apple remote desktop vnc", "apple", "apple_remote_desktop"),
];

/// Every product name the table knows, for tests.
pub fn known_products() -> impl Iterator<Item = &'static str> {
    TABLE.iter().map(|e| e.product)
}

/// CPE names for a detected service; empty when the product is unknown.
pub fn for_service(s: &Service) -> Vec<String> {
    let Some(product) = &s.product else {
        return Vec::new();
    };
    let Some(entry) = TABLE.iter().find(|e| e.product == product) else {
        return Vec::new();
    };
    let (version, update) = match &s.version {
        Some(v) if entry.versioned => split_version(v),
        _ => (None, None),
    };
    vec![format!(
        "cpe:2.3:a:{}:{}:{}:{}:*:*:*:*:*:*",
        entry.vendor,
        entry.name,
        version.as_deref().map(escape).unwrap_or_else(|| "*".into()),
        update.as_deref().map(escape).unwrap_or_else(|| "*".into()),
    )]
}

/// `8.9p1` → (`8.9`, `p1`); `0.9.60 beta` → (`0.9.60`, `beta`);
/// `1.24.0` → (`1.24.0`, none).
pub fn split_version(raw: &str) -> (Option<String>, Option<String>) {
    let raw = raw.trim().to_ascii_lowercase();
    let mut words = raw.split_whitespace();
    let Some(first) = words.next() else {
        return (None, None);
    };
    let second = words.next().map(str::to_string);
    // Numeric dotted prefix followed by a letter suffix.
    let numeric_end = first
        .bytes()
        .position(|b| !(b.is_ascii_digit() || b == b'.'))
        .unwrap_or(first.len());
    let (num, suffix) = first.split_at(numeric_end);
    let num = num.trim_end_matches('.');
    let letter_suffix = suffix
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic())
        && suffix.bytes().all(|b| b.is_ascii_alphanumeric());
    if !num.is_empty() && num.as_bytes()[0].is_ascii_digit() && letter_suffix {
        return (Some(num.to_string()), Some(suffix.to_string()));
    }
    (Some(first.to_string()), second)
}

/// Quote characters CPE 2.3 formatted strings reserve. Letters, digits,
/// `.`, `-` and `_` pass through; spaces and non-ASCII are dropped.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => out.push(c.to_ascii_lowercase()),
            c if c.is_ascii_graphic() => {
                out.push('\\');
                out.push(c);
            }
            _ => {}
        }
    }
    if out.is_empty() { "*".into() } else { out }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpe(product: &str, version: Option<&str>) -> Option<String> {
        let s = Service {
            name: "x".into(),
            product: Some(product.into()),
            version: version.map(Into::into),
            ..Default::default()
        };
        for_service(&s).pop()
    }

    #[test]
    fn nvd_style_names() {
        let cases = [
            (
                "OpenSSH",
                Some("8.9p1"),
                "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*",
            ),
            (
                "OpenSSH",
                Some("9.6"),
                "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*",
            ),
            (
                "Dropbear sshd",
                Some("2022.83"),
                "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2022.83:*:*:*:*:*:*:*",
            ),
            (
                "nginx",
                Some("1.24.0"),
                "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
            ),
            (
                "Apache httpd",
                Some("2.4.58"),
                "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
            ),
            (
                "Microsoft IIS httpd",
                Some("10.0"),
                "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*",
            ),
            (
                "lighttpd",
                Some("1.4.73"),
                "cpe:2.3:a:lighttpd:lighttpd:1.4.73:*:*:*:*:*:*:*",
            ),
            ("Caddy", None, "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*"),
            (
                "Postfix smtpd",
                None,
                "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*",
            ),
            (
                "Exim smtpd",
                Some("4.96"),
                "cpe:2.3:a:exim:exim:4.96:*:*:*:*:*:*:*",
            ),
            (
                "Sendmail",
                Some("8.15.2"),
                "cpe:2.3:a:sendmail:sendmail:8.15.2:*:*:*:*:*:*:*",
            ),
            (
                "Microsoft Exchange smtpd",
                Some("8.0.3790.4675"),
                "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
            ),
            (
                "vsftpd",
                Some("3.0.5"),
                "cpe:2.3:a:beasts:vsftpd:3.0.5:*:*:*:*:*:*:*",
            ),
            (
                "ProFTPD",
                Some("1.3.5e"),
                "cpe:2.3:a:proftpd:proftpd:1.3.5:e:*:*:*:*:*:*",
            ),
            (
                "ProFTPD",
                Some("1.3.8rc4"),
                "cpe:2.3:a:proftpd:proftpd:1.3.8:rc4:*:*:*:*:*:*",
            ),
            (
                "Pure-FTPd",
                None,
                "cpe:2.3:a:pureftpd:pure-ftpd:*:*:*:*:*:*:*:*",
            ),
            (
                "FileZilla ftpd",
                Some("0.9.60 beta"),
                "cpe:2.3:a:filezilla-project:filezilla_server:0.9.60:beta:*:*:*:*:*:*",
            ),
            (
                "Microsoft ftpd",
                None,
                "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
            ),
            (
                "Dovecot imapd",
                None,
                "cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*",
            ),
            (
                "Courier Imapd",
                None,
                "cpe:2.3:a:double_precision_incorporated:courier-imap:*:*:*:*:*:*:*:*",
            ),
            (
                "MySQL",
                Some("8.0.36"),
                "cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*",
            ),
            (
                "MariaDB",
                Some("10.11.6"),
                "cpe:2.3:a:mariadb:mariadb:10.11.6:*:*:*:*:*:*:*",
            ),
            (
                "PostgreSQL",
                Some("16.1"),
                "cpe:2.3:a:postgresql:postgresql:16.1:*:*:*:*:*:*:*",
            ),
            (
                "Redis",
                Some("7.2.4"),
                "cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*",
            ),
            (
                "Valkey",
                Some("8.0.1"),
                "cpe:2.3:a:lfprojects:valkey:8.0.1:*:*:*:*:*:*:*",
            ),
            (
                "MongoDB",
                Some("7.0.5"),
                "cpe:2.3:a:mongodb:mongodb:7.0.5:*:*:*:*:*:*:*",
            ),
            (
                "Memcached",
                Some("1.6.21"),
                "cpe:2.3:a:memcached:memcached:1.6.21:*:*:*:*:*:*:*",
            ),
            (
                "Elasticsearch",
                Some("8.11.1"),
                "cpe:2.3:a:elastic:elasticsearch:8.11.1:*:*:*:*:*:*:*",
            ),
            (
                "RabbitMQ",
                Some("3.12.10"),
                "cpe:2.3:a:vmware:rabbitmq:3.12.10:*:*:*:*:*:*:*",
            ),
            (
                "Asterisk",
                Some("18.10.0~dfsg"),
                "cpe:2.3:a:digium:asterisk:18.10.0\\~dfsg:*:*:*:*:*:*:*",
            ),
        ];
        for (product, version, want) in cases {
            assert_eq!(
                cpe(product, version).as_deref(),
                Some(want),
                "{product} {version:?}"
            );
        }
    }

    #[test]
    fn every_table_row_produces_a_cpe() {
        // Guards against adding a row without thinking about its CPE.
        for p in known_products() {
            assert!(cpe(p, Some("1.0")).is_some(), "{p}");
        }
    }

    #[test]
    fn unknown_products_get_no_cpe() {
        assert_eq!(cpe("cloudflare", Some("1.0")), None);
        assert!(for_service(&Service::default()).is_empty());
    }

    #[test]
    fn version_splitting() {
        let s = |v: &str| split_version(v);
        assert_eq!(s("7.4p1"), (Some("7.4".into()), Some("p1".into())));
        assert_eq!(s("1.2.3"), (Some("1.2.3".into()), None));
        assert_eq!(s("1.2.3-rc1"), (Some("1.2.3-rc1".into()), None));
        assert_eq!(s("2.0 Beta"), (Some("2.0".into()), Some("beta".into())));
        assert_eq!(s("v2"), (Some("v2".into()), None));
        assert_eq!(s("  "), (None, None));
        assert_eq!(escape("a:b*c d"), "a\\:b\\*cd");
        assert_eq!(escape("é"), "*");
    }
}
