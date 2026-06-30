//! Bundled Information-Element registries: the standard IANA IPFIX IE snapshot
//! and the enterprise-scoped (per-PEN) vendor tables.

pub mod enterprise;
pub mod iana_ie;

pub use iana_ie::{IeDef, IeType};

/// Resolve an IE to its `(name, type)`, honoring the enterprise bit.
///
/// `enterprise_number` is `0` for a standard IANA IE, or the PEN for an
/// enterprise IE. Returns `None` when the element is not in the bundled tables;
/// the caller then degrades to `e<PEN>id<n>` / `id<n>` naming.
pub fn resolve(enterprise_number: u32, id: u16) -> Option<&'static IeDef> {
    if enterprise_number == 0 {
        iana_ie::lookup(id)
    } else {
        enterprise::lookup(enterprise_number, id)
    }
}
