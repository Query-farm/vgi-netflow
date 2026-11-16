//! Zero-panic gate for the MAC / OUI helpers: arbitrary text, bytes, and
//! integers must never panic, and every parsed MAC round-trips through the
//! canonical form.

use netflow_core::{mac, oui};
use proptest::prelude::*;

proptest! {
    #[test]
    fn arbitrary_text_never_panics(s in ".{0,40}") {
        if let Some(m) = mac::parse_mac(&s) {
            prop_assert_eq!(mac::parse_mac(&mac::format_mac(&m)), Some(m));
            let _ = oui::lookup(&m);
        }
        let _ = mac::mac_from_ipv6(&s);
    }

    #[test]
    fn macish_text_never_panics(s in "[0-9a-fA-F:.\\-]{0,20}") {
        if let Some(m) = mac::parse_mac(&s) {
            prop_assert_eq!(mac::parse_mac(&mac::format_mac(&m)), Some(m));
        }
    }

    #[test]
    fn arbitrary_bytes_and_ints(b in proptest::collection::vec(any::<u8>(), 0..10), v in any::<u64>()) {
        if let Some(m) = mac::mac_from_bytes(&b) {
            let _ = oui::vendor(&m);
            let iid = mac::eui48_to_eui64(&m);
            let ll = format!("fe80::{}", mac::format_interface_id(&iid));
            prop_assert_eq!(mac::mac_from_ipv6(&ll), Some(m));
        }
        if let Some(m) = mac::mac_from_u64(v) {
            let _ = oui::lookup(&m).map(|a| a.prefix_cidr());
        }
    }
}
