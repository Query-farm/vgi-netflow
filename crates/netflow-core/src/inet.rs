//! Encode an IP address into DuckDB's internal `INET` physical layout.
//!
//! DuckDB's core `INET` type is, on the Arrow boundary, a
//! `STRUCT(ip_type UTINYINT, address HUGEINT, mask USMALLINT)`, and DuckDB always
//! imports an `INET` back as that struct (the logical `INET` type does not
//! round-trip through Arrow). So `src_addr` / `dst_addr` / `next_hop` are emitted
//! as exactly that struct — a zero-cost `::INET` cast from native `INET` — so
//! containment joins (`src_addr::INET <<= '10.0.0.0/8'::INET`) and prefix joins
//! against geoip / threat-intel work without parsing a string.
//!
//! Encoding (validated against DuckDB's `inet` extension, shared with vgi-bgp):
//! - `ip_type`: `1` IPv4, `2` IPv6.
//! - `address` (little-endian `i128`): IPv4 → the 32 address bits in the low
//!   bits; IPv6 → the 128 network-order bits with the sign bit flipped
//!   (`XOR 2^127`), matching DuckDB's signed-HUGEINT mapping.
//! - `mask`: prefix length (host addresses use the full width, /32 or /128).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The three field values of one DuckDB `INET` struct cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InetVal {
    /// `1` = IPv4, `2` = IPv6.
    pub ip_type: u8,
    /// The DuckDB `HUGEINT` address value, little-endian `i128` bytes.
    pub address_le: [u8; 16],
    /// Prefix length in bits.
    pub mask: u16,
}

const IP_TYPE_V4: u8 = 1;
const IP_TYPE_V6: u8 = 2;

/// Encode a bare host [`IpAddr`] (full-width mask).
pub fn encode_ip(ip: IpAddr) -> InetVal {
    match ip {
        IpAddr::V4(_) => encode(ip, 32),
        IpAddr::V6(_) => encode(ip, 128),
    }
}

/// Encode an address + prefix length into the DuckDB `INET` field triple.
pub fn encode(ip: IpAddr, mask: u16) -> InetVal {
    match ip {
        IpAddr::V4(v4) => {
            let addr = u32::from_be_bytes(v4.octets()) as i128;
            InetVal {
                ip_type: IP_TYPE_V4,
                address_le: addr.to_le_bytes(),
                mask,
            }
        }
        IpAddr::V6(v6) => {
            let be = u128::from_be_bytes(v6.octets());
            let flipped = be ^ (1u128 << 127);
            InetVal {
                ip_type: IP_TYPE_V6,
                address_le: (flipped as i128).to_le_bytes(),
                mask,
            }
        }
    }
}

/// Encode 4 on-wire bytes as an IPv4 host `INET`, or `None` on a length mismatch.
pub fn inet4(b: &[u8]) -> Option<InetVal> {
    if b.len() == 4 {
        Some(encode_ip(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))))
    } else {
        None
    }
}

/// Encode 16 on-wire bytes as an IPv6 host `INET`, or `None` on a length mismatch.
pub fn inet6(b: &[u8]) -> Option<InetVal> {
    if b.len() == 16 {
        let mut o = [0u8; 16];
        o.copy_from_slice(b);
        Some(encode_ip(IpAddr::V6(Ipv6Addr::from(o))))
    } else {
        None
    }
}

impl InetVal {
    /// Render back to a canonical IP text string (for tests / diagnostics).
    pub fn to_ip_string(&self) -> String {
        let v = i128::from_le_bytes(self.address_le);
        if self.ip_type == IP_TYPE_V4 {
            Ipv4Addr::from((v as u32).to_be_bytes()).to_string()
        } else {
            let be = (v as u128) ^ (1u128 << 127);
            Ipv6Addr::from(be.to_be_bytes()).to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn ipv4_round_trips() {
        let v = inet4(&[203, 0, 113, 5]).unwrap();
        assert_eq!(v.ip_type, 1);
        assert_eq!(v.mask, 32);
        assert_eq!(i128::from_le_bytes(v.address_le), 0xCB00_7105);
        assert_eq!(v.to_ip_string(), "203.0.113.5");
    }

    #[test]
    fn ipv6_sign_bit_flipped_round_trips() {
        let v = encode_ip(IpAddr::from_str("2001:db8::1").unwrap());
        assert_eq!(v.ip_type, 2);
        assert_eq!(v.address_le[15], 0xa0); // 0x20 ^ 0x80
        assert_eq!(v.to_ip_string(), "2001:db8::1");
    }
}
