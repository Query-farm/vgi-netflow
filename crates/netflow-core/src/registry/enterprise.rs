//! Enterprise-scoped Information Elements (RFC 7011 §3.4.3): IEs whose id has the
//! enterprise bit set and are scoped by a 4-byte Private Enterprise Number (PEN).
//!
//! A curated table for the common vendors (VMware PEN 6876, Nokia PEN 637). An
//! enterprise IE that is not in this table falls through to `e<PEN>id<n>` naming
//! in [`crate::normalize`] with the raw bytes preserved in `raw_fields` and a
//! `enterprise-unmapped` diagnostic note — never dropped.

use super::iana_ie::{IeDef, IeType};

/// VMware Private Enterprise Number.
pub const PEN_VMWARE: u32 = 6876;
/// Nokia Private Enterprise Number.
pub const PEN_NOKIA: u32 = 637;

/// Look up an enterprise IE by `(pen, id)` (id with the enterprise bit already
/// cleared). Returns `None` for an unknown vendor/element.
pub fn lookup(pen: u32, id: u16) -> Option<&'static IeDef> {
    let table: &[IeDef] = match pen {
        PEN_VMWARE => VMWARE,
        PEN_NOKIA => NOKIA,
        _ => return None,
    };
    table.iter().find(|d| d.id == id)
}

use IeType::*;

/// VMware NSX / vSphere enterprise IEs (PEN 6876), curated subset.
static VMWARE: &[IeDef] = &[
    IeDef {
        id: 880,
        name: "vmware.tenantProtocol",
        ty: Unsigned8,
    },
    IeDef {
        id: 881,
        name: "vmware.tenantSourceIPv4",
        ty: Ipv4Address,
    },
    IeDef {
        id: 882,
        name: "vmware.tenantDestIPv4",
        ty: Ipv4Address,
    },
    IeDef {
        id: 883,
        name: "vmware.tenantSourceIPv6",
        ty: Ipv6Address,
    },
    IeDef {
        id: 884,
        name: "vmware.tenantDestIPv6",
        ty: Ipv6Address,
    },
    IeDef {
        id: 886,
        name: "vmware.tenantSourcePort",
        ty: Unsigned16,
    },
    IeDef {
        id: 888,
        name: "vmware.tenantDestPort",
        ty: Unsigned16,
    },
    IeDef {
        id: 890,
        name: "vmware.virtualObsID",
        ty: String,
    },
];

/// Nokia / ALU enterprise IEs (PEN 637), curated subset.
static NOKIA: &[IeDef] = &[
    IeDef {
        id: 91,
        name: "nokia.applicationId",
        ty: Unsigned32,
    },
    IeDef {
        id: 92,
        name: "nokia.applicationName",
        ty: String,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmware_known_pen() {
        assert!(lookup(PEN_VMWARE, 881).is_some());
        assert!(lookup(99999, 881).is_none());
    }
}
