//! What a telnet server sends first: its option negotiation (IAC commands,
//! RFC 854/855) and any login prompt text, summarised for `Service::info`.
//! A real login service and a decoy that only negotiates look different.

use crate::escape;

const IAC: u8 = 255;
const SB: u8 = 250;
const SE: u8 = 240;
/// Most negotiations listed before `+N more`.
const MAX_OPTIONS: usize = 6;
/// Most bytes of prompt text shown.
const MAX_PROMPT: usize = 60;

/// `IAC: WILL ECHO, WILL SGA; prompt "login: "`, or `None` when the bytes
/// hold neither negotiation nor text.
pub fn summary(bytes: &[u8]) -> Option<String> {
    let mut options = Vec::new();
    let mut text = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != IAC {
            text.push(b);
            i += 1;
            continue;
        }
        let Some(&cmd) = bytes.get(i + 1) else { break };
        match cmd {
            IAC => {
                text.push(IAC);
                i += 2;
            }
            251..=254 => {
                if let Some(&opt) = bytes.get(i + 2) {
                    options.push(format!("{} {}", verb(cmd), option(opt)));
                }
                i += 3;
            }
            SB => {
                // Skip to IAC SE; an unterminated subnegotiation ends the read.
                let end = bytes[i + 2..]
                    .windows(2)
                    .position(|w| w == [IAC, SE])
                    .map(|p| i + 2 + p + 2);
                options.push(format!(
                    "SB {}",
                    bytes.get(i + 2).map_or("?".into(), |&o| option(o))
                ));
                i = end.unwrap_or(bytes.len());
            }
            _ => i += 2, // NOP, GA and other two-byte commands
        }
    }
    let mut parts = Vec::new();
    if !options.is_empty() {
        let more = options.len().saturating_sub(MAX_OPTIONS);
        options.truncate(MAX_OPTIONS);
        let mut s = format!("IAC: {}", options.join(", "));
        if more > 0 {
            s.push_str(&format!(" +{more} more"));
        }
        parts.push(s);
    }
    let prompt = text.trim_ascii();
    if !prompt.is_empty() {
        parts.push(format!("prompt \"{}\"", escape(prompt, MAX_PROMPT)));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

fn verb(cmd: u8) -> &'static str {
    match cmd {
        251 => "WILL",
        252 => "WONT",
        253 => "DO",
        _ => "DONT",
    }
}

fn option(opt: u8) -> String {
    match opt {
        0 => "BINARY",
        1 => "ECHO",
        3 => "SGA",
        5 => "STATUS",
        24 => "TTYPE",
        31 => "NAWS",
        32 => "TSPEED",
        33 => "LFLOW",
        34 => "LINEMODE",
        35 => "XDISPLOC",
        36 => "ENVIRON",
        39 => "NEW-ENVIRON",
        n => return n.to_string(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_and_prompt() {
        let bytes = b"\xff\xfb\x01\xff\xfb\x03\r\nZT410 login: ";
        assert_eq!(
            summary(bytes).as_deref(),
            Some("IAC: WILL ECHO, WILL SGA; prompt \"ZT410 login:\"")
        );
    }

    #[test]
    fn negotiation_only_and_subnegotiation() {
        let bytes = b"\xff\xfd\x18\xff\xfa\x18\x01\xff\xf0\xff\xfd\x63";
        assert_eq!(
            summary(bytes).as_deref(),
            Some("IAC: DO TTYPE, SB TTYPE, DO 99")
        );
        let many = b"\xff\xfd\x18".repeat(9);
        assert_eq!(
            summary(&many).unwrap(),
            "IAC: DO TTYPE, DO TTYPE, DO TTYPE, DO TTYPE, DO TTYPE, DO TTYPE +3 more"
        );
    }

    #[test]
    fn hostile_prompt_text_is_escaped_and_capped() {
        let mut bytes = b"\xff\xfb\x01\x1b[2J\x07".to_vec();
        bytes.extend(b"A".repeat(200));
        let s = summary(&bytes).unwrap();
        assert!(!s.chars().any(char::is_control), "{s}");
        assert!(s.ends_with("…\""), "{s}");
        assert_eq!(summary(b""), None);
        assert_eq!(summary(b"\r\n"), None);
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for len in 0..400 {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    // Lean on IAC and command bytes to hit every branch.
                    [255, 250, 240, 251, 253, b'a', x as u8][(x >> 40) as usize % 7]
                })
                .collect();
            let _ = summary(&bytes);
        }
    }
}
