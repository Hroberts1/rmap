//! Copy to the system clipboard with the OSC 52 terminal escape sequence.
//!
//! No clipboard library: the terminal does the work. Supported by most
//! modern terminals (Windows Terminal, iTerm2, kitty, WezTerm, Alacritty,
//! foot, xterm with `allowWindowOps`), but some disable OSC 52 or ask
//! first, and then `y` does nothing visible. Inside tmux the sequence is
//! wrapped in DCS passthrough, which also needs `set -g allow-passthrough on`
//! (or `set-clipboard on`) in tmux. GNU screen is not handled.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::app::{Pane, ScanView};

/// Largest text we copy. The base64 payload is about 4/3 of this, under the
/// limits terminals and tmux put on a single escape sequence.
pub const MAX_COPY_BYTES: usize = 8 * 1024;

/// `y` (address) or `Y` (CVE IDs) on the results screen. Logs the outcome
/// and returns the text to put on the clipboard, if any.
pub(crate) fn copy_selection(view: &mut ScanView, cves: bool) -> Option<String> {
    let result = if cves { cve_ids(view) } else { address(view) };
    match result {
        Ok((text, note)) if text.len() > MAX_COPY_BYTES => {
            view.log(format!(
                "nothing copied: {note} is {} bytes, over the {MAX_COPY_BYTES}-byte limit",
                text.len()
            ));
            None
        }
        Ok((text, note)) => {
            view.log(format!("copied {note}"));
            Some(text)
        }
        Err(why) => {
            view.log(format!("nothing to copy: {why}"));
            None
        }
    }
}

/// The selected host's IP, or `ip:port` when the ports pane is focused.
/// Returns the text and how to describe it in the log.
fn address(view: &ScanView) -> Result<(String, String), &'static str> {
    let ip = view.selected.ok_or("no host selected")?;
    let text = match view.focus {
        Pane::Hosts => ip.to_string(),
        Pane::Ports => {
            let port = view
                .selected_ports()
                .get(view.port_selected)
                .ok_or("no open port selected")?;
            // SocketAddr brackets IPv6: [fe80::1]:22.
            SocketAddr::new(ip, port.port).to_string()
        }
    };
    Ok((text.clone(), text))
}

/// CVE IDs on the selected port, or on every port of the selected host when
/// the hosts pane is focused, comma separated and without duplicates.
fn cve_ids(view: &ScanView) -> Result<(String, String), &'static str> {
    let ip = view.selected.ok_or("no host selected")?;
    let ports = view.selected_ports();
    let (ports, from) = match view.focus {
        Pane::Hosts => (ports, ip.to_string()),
        Pane::Ports => {
            let i = view.port_selected;
            let port = ports.get(i).ok_or("no open port selected")?;
            (&ports[i..=i], SocketAddr::new(ip, port.port).to_string())
        }
    };
    let mut seen = BTreeSet::new();
    let ids: Vec<&str> = ports
        .iter()
        .flat_map(|p| &p.vulnerabilities)
        .map(|v| v.id.as_str())
        .filter(|id| !id.is_empty() && seen.insert(*id))
        .collect();
    if ids.is_empty() {
        return Err(match view.focus {
            Pane::Hosts => "no CVEs on this host",
            Pane::Ports => "no CVEs on this port",
        });
    }
    let n = ids.len();
    let plural = if n == 1 { "" } else { "s" };
    Ok((ids.join(","), format!("{n} CVE ID{plural} from {from}")))
}

/// The OSC 52 "set clipboard" sequence for `text`, or `None` if it's over
/// [`MAX_COPY_BYTES`]. Control characters are dropped first: the base64
/// payload can't break the escape framing, but a newline or escape in
/// scanned data would still land in the user's clipboard and could run a
/// command when pasted into a shell. With `tmux`, the sequence is wrapped
/// in tmux's DCS passthrough (inner ESCs doubled).
pub fn osc52(text: &str, tmux: bool) -> Option<String> {
    if text.len() > MAX_COPY_BYTES {
        return None;
    }
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    let seq = format!("\x1b]52;c;{}\x07", base64(clean.as_bytes()));
    Some(if tmux {
        format!("\x1bPtmux;{}\x1b\\", seq.replace('\x1b', "\x1b\x1b"))
    } else {
        seq
    })
}

/// Standard base64 (RFC 4648 section 4) with `=` padding.
pub fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want, "{input:?}");
        }
        // Every bit pattern, including the last two alphabet characters.
        assert_eq!(base64(&[0x00, 0x10, 0x83]), "ABCD");
        assert_eq!(base64(&[0xfb, 0xff, 0xbf]), "+/+/");
        assert_eq!(base64(&[0xff]), "/w==");
        assert_eq!(base64("192.168.1.20:22".as_bytes()), "MTkyLjE2OC4xLjIwOjIy");
    }

    #[test]
    fn osc52_framing() {
        assert_eq!(
            osc52("foobar", false).unwrap(),
            "\x1b]52;c;Zm9vYmFy\x07",
            "plain"
        );
        assert_eq!(
            osc52("foobar", true).unwrap(),
            "\x1bPtmux;\x1b\x1b]52;c;Zm9vYmFy\x07\x1b\\",
            "tmux passthrough doubles the inner ESC"
        );
    }

    #[test]
    fn osc52_drops_control_characters_and_keeps_the_frame_intact() {
        let hostile = "CVE-1\x1b]52;c;evil\x07\x1b[2J\r\nrm -rf ~\u{9b}31m\u{7f}";
        for tmux in [false, true] {
            let seq = osc52(hostile, tmux).unwrap();
            let payload = seq
                .split_once("]52;c;")
                .and_then(|(_, rest)| rest.split_once('\x07'))
                .unwrap()
                .0;
            assert!(
                payload
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)),
                "{payload:?}"
            );
            // Exactly one OSC introducer and one terminator.
            assert_eq!(seq.matches(']').count(), 1, "{seq:?}");
            assert_eq!(seq.matches('\x07').count(), 1, "{seq:?}");
            assert_eq!(
                payload,
                base64("CVE-1]52;c;evil[2Jrm -rf ~31m".as_bytes()),
                "only the control characters are gone"
            );
        }
        // Non-ASCII text survives as UTF-8.
        assert_eq!(osc52("é", false).unwrap(), "\x1b]52;c;w6k=\x07");
    }

    #[test]
    fn osc52_caps_the_payload() {
        assert!(osc52(&"a".repeat(MAX_COPY_BYTES), false).is_some());
        assert!(osc52(&"a".repeat(MAX_COPY_BYTES + 1), false).is_none());
    }
}
