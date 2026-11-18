//! Randomised robustness tests: everything that reads bytes from the
//! network, or patterns from the database, must survive arbitrary input.
//! A failure prints the seed and iteration so it can be replayed.

use rmap_detect::db::{BUILTIN, Database};
use rmap_detect::pattern::Pattern;
use rmap_detect::{Detector, der, tls};

/// xorshift64*: small, deterministic, no dependencies.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// Bytes drawn mostly from `alphabet`, to reach deeper parser states.
    fn from(&mut self, alphabet: &[u8], max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n)
            .map(|_| {
                if self.below(10) == 0 {
                    self.next() as u8
                } else {
                    alphabet[self.below(alphabet.len())]
                }
            })
            .collect()
    }
    /// Mutate a valid input: flip, drop, insert or truncate.
    fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        for _ in 0..=self.below(4) {
            if v.is_empty() {
                break;
            }
            let i = self.below(v.len());
            match self.below(4) {
                0 => v[i] ^= 1 << self.below(8),
                1 => {
                    v.remove(i);
                }
                2 => v.insert(i, self.next() as u8),
                _ => v.truncate(i),
            }
        }
        v
    }
}

fn seed() -> u64 {
    std::env::var("RMAP_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5eed_0fd3_7ec7)
}

fn guard<T>(what: &str, seed: u64, iter: usize, input: &[u8], f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => panic!(
            "{what} panicked: RMAP_FUZZ_SEED={seed} iteration {iter} input {:?}",
            rmap_detect::escape(input, 400)
        ),
    }
}

#[test]
fn every_rule_survives_garbage_responses() {
    let seed = seed();
    let mut rng = Rng::new(seed);
    let detector = Detector::builtin();
    let probes = detector.database().probes.len();
    let protocolish = b"SSH-220 +OK*HTTP/1.0\r\n\x00\xff\x03\x16RFBServer: ()/.:-_0123456789abcSMB";
    for iter in 0..3_000 {
        let input = match iter % 3 {
            0 => rng.bytes(600),
            1 => rng.from(protocolish, 600),
            _ => {
                let base: &[u8] = match rng.below(3) {
                    0 => b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu) PHP/8.1\r\n\r\n",
                    1 => b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
                    _ => b"+PONG\r\n$99\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux x\r\n",
                };
                rng.mutate(base)
            }
        };
        let probe = iter % probes;
        guard("Detector::analyze", seed, iter, &input, || {
            detector.analyze(probe, &input, 443)
        });
    }
}

#[test]
fn tls_and_der_survive_garbage() {
    let seed = seed();
    let mut rng = Rng::new(seed ^ 0x7);
    let tlsish = [
        0x16, 0x03, 0x01, 0x02, 0x0b, 0x00, 0x30, 0x31, 0x82, 0x81, 0x06, 0x55, 0x04,
    ];
    for iter in 0..20_000 {
        let input = if iter % 2 == 0 {
            rng.bytes(300)
        } else {
            rng.from(&tlsish, 300)
        };
        guard("tls::analyze", seed, iter, &input, || tls::analyze(&input));
        guard("der::certificate", seed, iter, &input, || {
            der::certificate(&input)
        });
    }
}

#[test]
fn pattern_compiler_and_matcher_survive_garbage() {
    let seed = seed();
    let mut rng = Rng::new(seed ^ 0x99);
    let syntax = br"()[]{}^$|.*+?\\-,:dwsDWSxrn0aZ19 ";
    let haystack = rng.bytes(200);
    for iter in 0..20_000 {
        let src_bytes = rng.from(syntax, 40);
        let src = String::from_utf8_lossy(&src_bytes).into_owned();
        guard("Pattern::new / captures", seed, iter, &src_bytes, || {
            if let Ok(p) = Pattern::new(&src) {
                let _ = p.captures(&haystack);
                let _ = p.captures(&[]);
            }
        });
    }
}

#[test]
fn database_parser_survives_garbage() {
    let seed = seed();
    let mut rng = Rng::new(seed ^ 0x1234);
    let lines: Vec<&str> = BUILTIN.lines().collect();
    for iter in 0..3_000 {
        // Shuffle real lines and mutate some of them.
        let mut src = String::new();
        for _ in 0..rng.below(30) {
            let line = lines[rng.below(lines.len())].as_bytes();
            let line = if rng.below(3) == 0 {
                rng.mutate(line)
            } else {
                line.to_vec()
            };
            src.push_str(&String::from_utf8_lossy(&line));
            src.push('\n');
        }
        guard("Database::parse", seed, iter, src.as_bytes(), || {
            if let Ok(db) = Database::parse(&src) {
                for i in 0..db.probes.len() {
                    let _ = db.identify(i, b"SSH-2.0-x\r\nHTTP/1.1 200 OK\r\n");
                }
            }
        });
    }
}
