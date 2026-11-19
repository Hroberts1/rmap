//! Page titles from HTTP responses, and the one same-host redirect that is
//! worth following to find one. Many devices only name themselves in the
//! HTML `<title>` ("UniFi OS", "Brother MFC-L6700DW series").

use std::net::SocketAddr;

/// Most characters kept from a title.
const MAX_TITLE: usize = 80;
/// Longest redirect path we will request.
const MAX_PATH: usize = 512;

/// The cleaned `<title>` text of an HTTP response, if it has a non-empty
/// one. Safe to show in a terminal: controls and bidi overrides are gone.
pub fn title(response: &[u8]) -> Option<String> {
    let mut at = 0;
    let open = loop {
        let i = at + find_ci(&response[at..], b"<title")?;
        // `<title>` or `<title lang=..>`, not `<titlex>`.
        match response.get(i + 6) {
            Some(b'>' | b'/') => break i + 6,
            Some(c) if c.is_ascii_whitespace() => break i + 6,
            _ => at = i + 6,
        }
    };
    let start = open + response[open..].iter().position(|&b| b == b'>')? + 1;
    let rest = &response[start..];
    let end = find_ci(rest, b"</title").unwrap_or(rest.len());
    clean(&decode_entities(&String::from_utf8_lossy(&rest[..end])))
}

/// `info` with `title "…"` appended, `; `-joined like other info fields.
pub fn with_title(info: Option<String>, title: &str) -> Option<String> {
    let t = format!("title \"{title}\"");
    Some(match info {
        Some(i) if !i.is_empty() => format!("{i}; {t}"),
        _ => t,
    })
}

/// A product name from titles that reliably name one.
// shortcut: one entry; add more only when a title is as unambiguous.
pub fn product(title: &str) -> Option<&'static str> {
    title.starts_with("UniFi OS").then_some("UniFi OS")
}

/// The path to request when `response` is a 301/302/303/307/308 to the
/// same host as `addr`. Other hosts, other schemes and odd bytes give `None`.
pub fn redirect(response: &[u8], addr: SocketAddr) -> Option<String> {
    let status = response.get(9..13)?;
    if !response.starts_with(b"HTTP/1.")
        || !matches!(status, b"301 " | b"302 " | b"303 " | b"307 " | b"308 ")
    {
        return None;
    }
    let head_end = find_ci(response, b"\r\n\r\n").unwrap_or(response.len());
    let location = response[..head_end]
        .split(|&b| b == b'\n')
        .find_map(|line| {
            let colon = line.iter().position(|&b| b == b':')?;
            line[..colon]
                .eq_ignore_ascii_case(b"location")
                .then(|| line[colon + 1..].trim_ascii())
        })?;
    let location = std::str::from_utf8(location).ok()?;
    let path = if location.starts_with('/') && !location.starts_with("//") {
        location
    } else {
        let rest = location
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("http://"))
            .map(|_| &location[7..])?;
        let slash = rest.find('/').unwrap_or(rest.len());
        let host = &rest[..slash];
        let ip = match addr {
            SocketAddr::V4(a) => a.ip().to_string(),
            SocketAddr::V6(a) => format!("[{}]", a.ip()),
        };
        let same = host == format!("{ip}:{}", addr.port()) || (host == ip && addr.port() == 80);
        if !same {
            return None;
        }
        if slash == rest.len() {
            "/"
        } else {
            &rest[slash..]
        }
    };
    // Printable ASCII only: it goes into our request line verbatim.
    (path.len() <= MAX_PATH && path.bytes().all(|b| b.is_ascii_graphic())).then(|| path.to_string())
}

/// The request line and headers for `path`, as the http-get probe sends.
pub fn request(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.0\r\nUser-Agent: rmap\r\nAccept: */*\r\n\r\n").into_bytes()
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// Decode `&amp; &lt; &gt; &quot; &#39; &apos; &nbsp;` and numeric
/// references; anything else is left as written.
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let decoded = rest[1..]
            .find(';')
            .filter(|&n| n <= 10)
            .and_then(|n| Some((entity(&rest[1..1 + n])?, n + 2)));
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity(name: &str) -> Option<char> {
    let code = if let Some(hex) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
        u32::from_str_radix(hex, 16).ok()?
    } else if let Some(dec) = name.strip_prefix('#') {
        dec.parse().ok()?
    } else {
        return match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ => None,
        };
    };
    char::from_u32(code)
}

/// Collapse whitespace, drop controls and bidi/format characters, cap the
/// length. `None` if nothing printable is left.
fn clean(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
        } else if !c.is_control() && !is_bidi(c) {
            if space {
                out.push(' ');
                space = false;
            }
            out.push(c);
        }
    }
    if out.is_empty() {
        return None;
    }
    if out.chars().count() > MAX_TITLE {
        out = out.chars().take(MAX_TITLE - 1).chain(['…']).collect();
    }
    Some(out)
}

/// Characters that reorder or hide text on screen.
fn is_bidi(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(body: &str) -> Option<String> {
        title(format!("HTTP/1.1 200 OK\r\n\r\n{body}").as_bytes())
    }

    #[test]
    fn extracts_titles() {
        assert_eq!(
            t("<html><title>UniFi OS</title>").as_deref(),
            Some("UniFi OS")
        );
        assert_eq!(
            t("<TITLE lang=\"en\">IIS Windows Server</TiTlE>").as_deref(),
            Some("IIS Windows Server")
        );
        assert_eq!(t("<title\n>x</title>").as_deref(), Some("x"));
        assert_eq!(
            t("<titlex>no</titlex><title>yes</title>").as_deref(),
            Some("yes")
        );
        assert_eq!(
            t("<title>\n   HP LaserJet\t\r\n  MFP M426fdn  </title>").as_deref(),
            Some("HP LaserJet MFP M426fdn")
        );
        assert_eq!(
            t("<title>Brother MFC-L6700DW series").as_deref(),
            Some("Brother MFC-L6700DW series")
        );
        assert_eq!(t("<title>  </title>"), None);
        assert_eq!(t("<html>no title</html>"), None);
        assert_eq!(t("<title"), None);
    }

    #[test]
    fn decodes_entities() {
        assert_eq!(
            t("<title>A &amp; B &lt;x&gt; &quot;q&quot; &#39;s&apos; &#65;&#x42;&#X43; &bogus; &#xzz; & end&</title>").as_deref(),
            Some("A & B <x> \"q\" 's' ABC &bogus; &#xzz; & end&")
        );
        assert_eq!(
            t("<title>&#1114112;&#xD800;</title>").as_deref(),
            Some("&#1114112;&#xD800;")
        );
    }

    #[test]
    fn strips_controls_and_bidi() {
        assert_eq!(
            t("<title>a\x1b[31mred\x07\u{202e}evil\u{2066}\u{200b}&#27;[2J&#x9b;b</title>")
                .as_deref(),
            Some("a[31mredevil[2Jb")
        );
    }

    #[test]
    fn caps_length() {
        let long = t(&format!("<title>{}</title>", "é".repeat(200))).unwrap();
        assert_eq!(long.chars().count(), MAX_TITLE);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn survives_huge_and_binary_bodies() {
        let mut big = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'a', 1 << 20));
        big.extend_from_slice(b"<title>end</title>");
        assert_eq!(title(&big).as_deref(), Some("end"));
        let garbage: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let _ = title(&garbage);
        assert_eq!(
            title(b"<title>\xff\xfeok\xc3</title>").as_deref(),
            Some("\u{fffd}\u{fffd}ok\u{fffd}")
        );
    }

    #[test]
    fn appends_to_info() {
        assert_eq!(with_title(None, "x").as_deref(), Some("title \"x\""));
        assert_eq!(
            with_title(Some("Ubuntu".into()), "x").as_deref(),
            Some("Ubuntu; title \"x\"")
        );
    }

    #[test]
    fn follows_only_same_host_redirects() {
        let v4: SocketAddr = "192.0.2.1:80".parse().unwrap();
        let alt: SocketAddr = "192.0.2.1:8080".parse().unwrap();
        let r = |loc: &str| format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\n\r\n").into_bytes();
        assert_eq!(redirect(&r("/login"), v4).as_deref(), Some("/login"));
        assert_eq!(
            redirect(b"HTTP/1.0 301 Moved\r\nlocation:/a?b=1\r\n\r\n", v4).as_deref(),
            Some("/a?b=1")
        );
        assert_eq!(
            redirect(&r("http://192.0.2.1/x"), v4).as_deref(),
            Some("/x")
        );
        assert_eq!(redirect(&r("HTTP://192.0.2.1"), v4).as_deref(), Some("/"));
        assert_eq!(
            redirect(&r("http://192.0.2.1:8080/x"), alt).as_deref(),
            Some("/x")
        );
        assert_eq!(redirect(&r("http://192.0.2.1/x"), alt), None);
        assert_eq!(redirect(&r("http://192.0.2.2/x"), v4), None);
        assert_eq!(redirect(&r("http://192.0.2.1.evil.test/x"), v4), None);
        assert_eq!(redirect(&r("http://192.0.2.1@evil.test/x"), v4), None);
        assert_eq!(redirect(&r("https://192.0.2.1/x"), v4), None);
        assert_eq!(redirect(&r("//evil.test/x"), v4), None);
        assert_eq!(redirect(&r("/a b"), v4), None);
        assert_eq!(
            redirect(b"HTTP/1.1 302 Found\r\nLocation: /a\rX: y\r\n\r\n", v4),
            None
        );
        assert_eq!(
            redirect(b"HTTP/1.1 200 OK\r\nLocation: /a\r\n\r\n", v4),
            None
        );
        let v6: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        assert_eq!(
            redirect(&r("http://[2001:db8::1]/x"), v6).as_deref(),
            Some("/x")
        );
    }
}
