//! MAC-address (EUI-48) parsing, canonical formatting, address-bit flags, and
//! modified EUI-64 conversion (the IPv6 SLAAC interface identifier, RFC 4291
//! §2.5.1 / Appendix A).
//!
//! Everything here is total: malformed input returns `None`, never panics. The
//! vendor lookup against the bundled IEEE registry lives in [`crate::oui`].

use std::net::Ipv6Addr;

/// A 48-bit MAC address (EUI-48), most significant byte first.
pub type Mac = [u8; 6];

/// Parse a MAC address from any common text notation:
///
/// - six colon- or dash-separated groups of one or two hex digits
///   (`00:1b:63:84:45:e6`, `00-1B-63-84-45-E6`, `0:1b:63:84:45:e6`);
/// - Cisco dotted notation, three groups of four hex digits (`001b.6384.45e6`);
/// - twelve bare hex digits (`001b638445e6`).
///
/// Case-insensitive; surrounding whitespace is ignored. Mixed separators, a
/// wrong group count, or non-hex characters yield `None`.
pub fn parse_mac(text: &str) -> Option<Mac> {
    let s = text.trim();
    if s.is_empty() || !s.is_ascii() {
        return None;
    }
    let has_colon = s.contains(':');
    let has_dash = s.contains('-');
    let has_dot = s.contains('.');
    match (has_colon, has_dash, has_dot) {
        (false, false, false) => parse_bare(s),
        (true, false, false) => parse_groups(s, ':'),
        (false, true, false) => parse_groups(s, '-'),
        (false, false, true) => parse_dotted(s),
        _ => None,
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a run of hex digits (at most 16) into an integer.
fn hex_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 16 {
        return None;
    }
    s.bytes()
        .try_fold(0u64, |acc, c| Some((acc << 4) | u64::from(hex_val(c)?)))
}

fn parse_bare(s: &str) -> Option<Mac> {
    if s.len() != 12 {
        return None;
    }
    mac_from_u64(hex_u64(s)?)
}

fn parse_groups(s: &str, sep: char) -> Option<Mac> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split(sep) {
        if n == 6 || part.is_empty() || part.len() > 2 {
            return None;
        }
        out[n] = u8::try_from(hex_u64(part)?).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

fn parse_dotted(s: &str) -> Option<Mac> {
    let mut v: u64 = 0;
    let mut n = 0;
    for part in s.split('.') {
        if n == 3 || part.len() != 4 {
            return None;
        }
        v = (v << 16) | hex_u64(part)?;
        n += 1;
    }
    if n != 3 {
        return None;
    }
    mac_from_u64(v)
}

/// A MAC from raw bytes: exactly six bytes (as an IPFIX `macAddress` IE such as
/// `sourceMacAddress` is carried on the wire). Any other length is `None`.
pub fn mac_from_bytes(bytes: &[u8]) -> Option<Mac> {
    <[u8; 6]>::try_from(bytes).ok()
}

/// A MAC from an integer holding the 48-bit address in its low bits
/// (`0x001b638445e6`). Values ≥ 2^48 are `None`.
pub fn mac_from_u64(v: u64) -> Option<Mac> {
    if v >> 48 != 0 {
        return None;
    }
    let b = v.to_be_bytes();
    Some([b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Canonical form: lowercase, colon-separated, two digits per byte
/// (`00:1b:63:84:45:e6`).
pub fn format_mac(mac: &Mac) -> String {
    let mut s = String::with_capacity(17);
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// I/G bit (least significant bit of the first octet): a group (multicast or
/// broadcast) address rather than a single interface.
pub fn is_multicast(mac: &Mac) -> bool {
    mac[0] & 0x01 != 0
}

/// U/L bit (second least significant bit of the first octet): locally
/// administered — assigned by software rather than burned in from an IEEE
/// block. Randomized (privacy) MACs on modern phones and laptops set this bit.
pub fn is_local(mac: &Mac) -> bool {
    mac[0] & 0x02 != 0
}

/// The all-ones broadcast address `ff:ff:ff:ff:ff:ff`.
pub fn is_broadcast(mac: &Mac) -> bool {
    mac.iter().all(|&b| b == 0xff)
}

/// Modified EUI-64 interface identifier for a MAC (RFC 4291 Appendix A): insert
/// `ff:fe` between the OUI and the NIC-specific half and invert the U/L bit.
pub fn eui48_to_eui64(mac: &Mac) -> [u8; 8] {
    [
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// Format a 64-bit interface identifier as four IPv6 hextets
/// (`021b:63ff:fe84:45e6`), ready to append to a /64 prefix
/// (`'fe80::' || …`).
pub fn format_interface_id(iid: &[u8; 8]) -> String {
    let h = |i: usize| u16::from_be_bytes([iid[i], iid[i + 1]]);
    format!("{:04x}:{:04x}:{:04x}:{:04x}", h(0), h(2), h(4), h(6))
}

/// Recover the MAC embedded in an IPv6 address whose interface identifier is a
/// modified EUI-64 (SLAAC without privacy extensions): the IID must carry
/// `ff:fe` in its middle. Returns `None` for any other address (random /
/// privacy IIDs, IPv4, malformed text). A trailing `/prefix` is ignored.
pub fn mac_from_ipv6(text: &str) -> Option<Mac> {
    let s = text.trim();
    let addr_part = s.split_once('/').map_or(s, |(a, _)| a);
    let addr: Ipv6Addr = addr_part.parse().ok()?;
    let o = addr.octets();
    if o[11] != 0xff || o[12] != 0xfe {
        return None;
    }
    Some([o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]])
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPLE: Mac = [0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6];

    #[test]
    fn parses_every_notation() {
        for s in [
            "00:1b:63:84:45:e6",
            "00:1B:63:84:45:E6",
            "00-1b-63-84-45-e6",
            "0:1b:63:84:45:e6",
            "001b.6384.45e6",
            "001B.6384.45E6",
            "001b638445e6",
            "  001b638445e6\n",
        ] {
            assert_eq!(parse_mac(s), Some(APPLE), "{s:?}");
        }
    }

    #[test]
    fn rejects_invalid() {
        for s in [
            "",
            "   ",
            "00:1b:63:84:45",
            "00:1b:63:84:45:e6:01",
            "00:1b:63:84:45:",
            "00:1b:63-84:45:e6",
            "001:b6:38:44:5e:6",
            "00:1b:63:84:45:g6",
            "001b.6384.45e",
            "001b.6384.45e6.0000",
            "001b638445e",
            "001b638445e6f",
            "zz1b638445e6",
            "+1b638445e6",
            "00:1b:63:84:45:é6",
            "::::::",
            "-----",
            "...",
        ] {
            assert_eq!(parse_mac(s), None, "{s:?}");
        }
    }

    #[test]
    fn bytes_and_integers() {
        assert_eq!(mac_from_bytes(&APPLE), Some(APPLE));
        assert_eq!(mac_from_bytes(&APPLE[..5]), None);
        assert_eq!(mac_from_bytes(&[0; 7]), None);
        assert_eq!(mac_from_u64(0x001b_6384_45e6), Some(APPLE));
        assert_eq!(mac_from_u64(1 << 48), None);
        assert_eq!(format_mac(&APPLE), "00:1b:63:84:45:e6");
    }

    #[test]
    fn flags() {
        assert!(!is_multicast(&APPLE) && !is_local(&APPLE) && !is_broadcast(&APPLE));
        let mcast = parse_mac("01:00:5e:00:00:fb").unwrap();
        assert!(is_multicast(&mcast) && !is_local(&mcast) && !is_broadcast(&mcast));
        let random = parse_mac("da:a1:19:12:34:56").unwrap();
        assert!(is_local(&random) && !is_multicast(&random));
        let bcast = parse_mac("ff:ff:ff:ff:ff:ff").unwrap();
        assert!(is_broadcast(&bcast) && is_multicast(&bcast) && is_local(&bcast));
    }

    #[test]
    fn modified_eui64() {
        // RFC 4291 Appendix A: insert FFFE and invert the universal/local bit.
        let iid = eui48_to_eui64(&parse_mac("34-56-78-9a-bc-de").unwrap());
        assert_eq!(iid, [0x36, 0x56, 0x78, 0xff, 0xfe, 0x9a, 0xbc, 0xde]);
        assert_eq!(format_interface_id(&iid), "3656:78ff:fe9a:bcde");
        assert_eq!(
            format_interface_id(&eui48_to_eui64(&APPLE)),
            "021b:63ff:fe84:45e6"
        );
        // A locally administered MAC flips the other way (bit cleared).
        assert_eq!(eui48_to_eui64(&[0x02, 0, 0, 0, 0, 1])[0], 0x00);
    }

    #[test]
    fn mac_back_out_of_slaac_ipv6() {
        assert_eq!(mac_from_ipv6("fe80::21b:63ff:fe84:45e6"), Some(APPLE));
        assert_eq!(
            mac_from_ipv6("2001:db8::21b:63ff:fe84:45e6/64"),
            Some(APPLE)
        );
        assert_eq!(
            mac_from_ipv6("fe80::3656:78ff:fe9a:bcde"),
            parse_mac("34:56:78:9a:bc:de")
        );
        // Privacy / random IIDs carry no MAC.
        assert_eq!(mac_from_ipv6("2001:db8::1"), None);
        assert_eq!(mac_from_ipv6("10.0.0.1"), None);
        assert_eq!(mac_from_ipv6("not an address"), None);
        assert_eq!(mac_from_ipv6(""), None);
        // Round trip.
        let ll = format!("fe80::{}", format_interface_id(&eui48_to_eui64(&APPLE)));
        assert_eq!(mac_from_ipv6(&ll), Some(APPLE));
    }
}
