//! Unprivileged ICMP echo on Windows through the IP Helper API. Unlike raw
//! sockets it needs no admin rights, so it catches hosts that answer ping
//! but have no open or refusing TCP discovery port.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use rmap_core::Timing;

type Handle = *mut c_void;
const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const IP_SUCCESS: u32 = 0;

/// The leading fields of `ICMP_ECHO_REPLY`, the same on 32- and 64-bit.
#[repr(C)]
struct EchoReplyHead {
    address: u32,
    status: u32,
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn IcmpCreateFile() -> Handle;
    fn IcmpCloseHandle(handle: Handle) -> i32;
    fn IcmpSendEcho(
        handle: Handle,
        destination: u32,
        request_data: *const c_void,
        request_size: u16,
        request_options: *const c_void,
        reply_buffer: *mut c_void,
        reply_size: u32,
        timeout_ms: u32,
    ) -> u32;
}

const PAYLOAD: [u8; 32] = *b"rmap-host-discovery-echo-request";

/// Ping `ip` until it answers or the template's tries run out. The caller
/// paces hosts against the rate cap; dropping this future cancels it, though
/// a blocking call already in flight runs out its own timeout.
// TODO: IPv6 via Icmp6CreateFile/Icmp6SendEcho2; it relies on the TCP ping.
pub async fn ping(ip: IpAddr, timing: &Timing) -> Option<Duration> {
    let IpAddr::V4(dst) = ip else { return None };
    let limit = timing.connect_timeout.max(Duration::from_secs(1));
    for try_no in 0..=timing.retries {
        if !timing.scan_delay.is_zero() {
            tokio::time::sleep(timing.scan_delay).await;
        }
        let rtt = tokio::task::spawn_blocking(move || echo(dst, limit))
            .await
            .ok()
            .flatten();
        rmap_log::trace!("icmp echo {dst} try={try_no} limit={limit:?} rtt={rtt:?}");
        if rtt.is_some() {
            return rtt;
        }
    }
    None
}

/// One blocking echo request. `None` on timeout or any error.
pub fn echo(dst: Ipv4Addr, limit: Duration) -> Option<Duration> {
    // ICMP_ECHO_REPLY (40 bytes on x64) + echoed payload + 8 bytes for an
    // ICMP error, as the API docs require; 8-byte aligned for the struct.
    let mut reply = [0u64; 16];
    // (+16 for the IO_STATUS_BLOCK the IcmpSendEcho2 docs also mention.)
    const _: () = assert!(16 * 8 >= 40 + PAYLOAD.len() + 8 + 16);
    let timeout_ms = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX);

    // SAFETY: takes no arguments; the result is checked before use.
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE {
        rmap_log::debug!("IcmpCreateFile failed: {}", std::io::Error::last_os_error());
        return None;
    }
    let started = Instant::now();
    // SAFETY: `handle` is open; the request and reply pointers are valid for
    // the sizes passed, which the reply buffer exceeds per the docs above.
    let replies = unsafe {
        IcmpSendEcho(
            handle,
            u32::from_ne_bytes(dst.octets()),
            PAYLOAD.as_ptr().cast(),
            PAYLOAD.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            std::mem::size_of_val(&reply) as u32,
            timeout_ms,
        )
    };
    let rtt = started.elapsed();
    let err = (replies == 0).then(std::io::Error::last_os_error);
    // SAFETY: `handle` came from IcmpCreateFile and is closed exactly once.
    unsafe { IcmpCloseHandle(handle) };
    if let Some(e) = err {
        rmap_log::trace!("icmp echo {dst}: {e}");
        return None;
    }
    // SAFETY: with replies > 0 the buffer starts with an ICMP_ECHO_REPLY,
    // whose first 8 bytes are `EchoReplyHead`; the buffer is larger and aligned.
    let head = unsafe { reply.as_ptr().cast::<EchoReplyHead>().read() };
    // A router's unreachable/TTL error is a reply too, from another address.
    (head.status == IP_SUCCESS && head.address == u32::from_ne_bytes(dst.octets())).then_some(rtt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_answers() {
        assert!(echo(Ipv4Addr::LOCALHOST, Duration::from_secs(2)).is_some());
    }

    #[test]
    fn unrouted_host_times_out() {
        let started = Instant::now();
        assert!(echo(Ipv4Addr::new(192, 0, 2, 1), Duration::from_millis(500)).is_none());
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
