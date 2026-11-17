//! The internet checksum (RFC 1071) and the TCP/UDP pseudo-header.

use std::net::Ipv4Addr;

/// Add `data` to a running one's-complement sum as big-endian 16-bit words.
/// An odd trailing byte is padded with a zero, as RFC 1071 specifies.
pub fn add(mut sum: u64, data: &[u8]) -> u64 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum += u64::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        sum += u64::from(u16::from_be_bytes([*last, 0]));
    }
    sum
}

/// Fold carries back into 16 bits and complement: the final checksum.
pub fn finish(mut sum: u64) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The internet checksum of `data`.
///
/// Running it over data that already contains a correct checksum yields 0.
pub fn internet_checksum(data: &[u8]) -> u16 {
    finish(add(0, data))
}

/// Sum of the IPv4 pseudo-header used by TCP and UDP checksums.
pub fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, length: u16) -> u64 {
    let mut sum = add(0, &src.octets());
    sum = add(sum, &dst.octets());
    sum += u64::from(protocol);
    sum + u64::from(length)
}

/// Checksum of a TCP or UDP `segment` (header and payload) over IPv4.
///
/// The segment's own checksum field must be zero when building, or hold the
/// received value when verifying (a correct packet then yields 0).
/// Segments longer than 65,535 bytes can't be carried by IPv4; their length
/// is truncated in the pseudo-header, so the result is meaningless.
pub fn transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, segment: &[u8]) -> u16 {
    let len = segment.len() as u16;
    finish(add(pseudo_header(src, dst, protocol, len), segment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        // RFC 1071 section 3: the words 0001 f203 f4f5 f6f7 sum to ddf2.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(add(0, &data), 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7);
        assert_eq!(!internet_checksum(&data), 0xddf2);
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn odd_length_pads_with_zero() {
        assert_eq!(internet_checksum(&[0x12]), !0x1200);
        assert_eq!(
            internet_checksum(&[0x12, 0x34, 0x56]),
            internet_checksum(&[0x12, 0x34, 0x56, 0x00])
        );
    }

    #[test]
    fn empty_and_all_ones() {
        assert_eq!(internet_checksum(&[]), 0xffff);
        assert_eq!(internet_checksum(&[0xff, 0xff]), 0x0000);
    }

    #[test]
    fn verifying_a_checksummed_buffer_gives_zero() {
        let mut data = vec![0x45, 0x00, 0x00, 0x1c, 0xab, 0xcd, 0x00, 0x00, 0, 0];
        let c = internet_checksum(&data);
        data[8..10].copy_from_slice(&c.to_be_bytes());
        assert_eq!(internet_checksum(&data), 0);
    }

    #[test]
    fn large_input_does_not_overflow() {
        let data = vec![0xff; 1 << 20];
        assert_eq!(internet_checksum(&data), 0);
    }
}
