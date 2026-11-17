//! Timing templates, T0 (slowest, quietest) through T5 (fastest, loudest).

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub level: u8,
    pub name: &'static str,
    /// Probes in flight across the whole scan.
    pub concurrency: usize,
    /// Hosts scanned at the same time.
    pub host_parallelism: usize,
    /// How long to wait for a connection before trying again.
    pub connect_timeout: Duration,
    /// Extra attempts after a timeout before calling a port filtered.
    pub retries: u8,
    /// Pause before each probe. Non-zero only for the stealthy templates.
    pub scan_delay: Duration,
}

impl Timing {
    /// The template for level 0-5. Out-of-range levels clamp to 5.
    ///
    /// Concurrency stays under 1,024 sockets so default Linux file
    /// descriptor limits are not exceeded; the engine backs off and retries
    /// if it runs out anyway.
    pub fn template(level: u8) -> Self {
        let ms = Duration::from_millis;
        let (name, concurrency, host_parallelism, timeout, retries, delay) = match level {
            0 => ("paranoid", 1, 1, ms(5000), 2, ms(5000)),
            1 => ("sneaky", 1, 1, ms(3000), 2, ms(1000)),
            2 => ("polite", 10, 4, ms(2000), 2, ms(100)),
            3 => ("normal", 400, 32, ms(1500), 1, ms(0)),
            4 => ("aggressive", 800, 64, ms(750), 1, ms(0)),
            _ => ("insane", 1000, 128, ms(300), 0, ms(0)),
        };
        Timing {
            level: level.min(5),
            name,
            concurrency,
            host_parallelism,
            connect_timeout: timeout,
            retries,
            scan_delay: delay,
        }
    }
}

impl Default for Timing {
    fn default() -> Self {
        Timing::template(3)
    }
}
