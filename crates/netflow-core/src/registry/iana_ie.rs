//! Curated snapshot of the IANA "IPFIX Information Elements" registry
//! (<https://www.iana.org/assignments/ipfix/ipfix.xhtml>, RFC 7012).
//!
//! Maps an IPFIX / NetFlow-v9 Information-Element id to its `(name, abstract
//! data type)`. NetFlow v9 field types share the IANA id space with IPFIX, so a
//! single table serves both decoders.
//!
//! ## Why a committed curated table (not build-time codegen)
//!
//! The spec (§4) floats two options — regenerate `iana_ie.rs` from a bundled
//! registry snapshot at build time, or commit the table — and flags the
//! redistribution terms as something to re-confirm. IANA protocol registries are
//! published for public use; we commit a **curated** snapshot here (the IEs that
//! drive the normalized schema in [`crate::normalize`], plus the common
//! observability IEs) rather than running a network fetch in `build.rs`, so the
//! build stays hermetic and offline. Attribution: IANA / RFC 7012, linked from
//! the catalog `source_url`. The table is trivially extensible — add a row.
//!
//! Unmapped ids fall through to `e0id<n>` / `id<n>` naming in
//! [`crate::normalize`] with the raw bytes preserved in `raw_fields`.

/// The abstract data type of an Information Element (RFC 7012 §3.1), reduced to
/// the families the worker needs to render and normalize a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IeType {
    Unsigned8,
    Unsigned16,
    Unsigned32,
    Unsigned64,
    Signed32,
    Signed64,
    Float64,
    Boolean,
    MacAddress,
    Ipv4Address,
    Ipv6Address,
    /// `dateTimeSeconds` — 4-byte seconds since the Unix epoch.
    DateTimeSeconds,
    /// `dateTimeMilliseconds` — 8-byte milliseconds since the Unix epoch.
    DateTimeMilliseconds,
    /// `dateTimeMicroseconds` — NTP-style 8-byte (seconds, fraction).
    DateTimeMicroseconds,
    /// `dateTimeNanoseconds` — NTP-style 8-byte (seconds, fraction).
    DateTimeNanoseconds,
    String,
    OctetArray,
}

/// A single registry row.
#[derive(Clone, Copy, Debug)]
pub struct IeDef {
    pub id: u16,
    pub name: &'static str,
    pub ty: IeType,
}

/// Look up a standard (enterprise_number == 0) Information Element by id.
pub fn lookup(id: u16) -> Option<&'static IeDef> {
    REGISTRY.iter().find(|d| d.id == id)
}

use IeType::*;

/// The curated IANA IPFIX IE snapshot. Ordered by id for readability.
pub static REGISTRY: &[IeDef] = &[
    IeDef {
        id: 1,
        name: "octetDeltaCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 2,
        name: "packetDeltaCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 3,
        name: "deltaFlowCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 4,
        name: "protocolIdentifier",
        ty: Unsigned8,
    },
    IeDef {
        id: 5,
        name: "ipClassOfService",
        ty: Unsigned8,
    },
    IeDef {
        id: 6,
        name: "tcpControlBits",
        ty: Unsigned16,
    },
    IeDef {
        id: 7,
        name: "sourceTransportPort",
        ty: Unsigned16,
    },
    IeDef {
        id: 8,
        name: "sourceIPv4Address",
        ty: Ipv4Address,
    },
    IeDef {
        id: 9,
        name: "sourceIPv4PrefixLength",
        ty: Unsigned8,
    },
    IeDef {
        id: 10,
        name: "ingressInterface",
        ty: Unsigned32,
    },
    IeDef {
        id: 11,
        name: "destinationTransportPort",
        ty: Unsigned16,
    },
    IeDef {
        id: 12,
        name: "destinationIPv4Address",
        ty: Ipv4Address,
    },
    IeDef {
        id: 13,
        name: "destinationIPv4PrefixLength",
        ty: Unsigned8,
    },
    IeDef {
        id: 14,
        name: "egressInterface",
        ty: Unsigned32,
    },
    IeDef {
        id: 15,
        name: "ipNextHopIPv4Address",
        ty: Ipv4Address,
    },
    IeDef {
        id: 16,
        name: "bgpSourceAsNumber",
        ty: Unsigned32,
    },
    IeDef {
        id: 17,
        name: "bgpDestinationAsNumber",
        ty: Unsigned32,
    },
    IeDef {
        id: 18,
        name: "bgpNextHopIPv4Address",
        ty: Ipv4Address,
    },
    IeDef {
        id: 21,
        name: "flowEndSysUpTime",
        ty: Unsigned32,
    },
    IeDef {
        id: 22,
        name: "flowStartSysUpTime",
        ty: Unsigned32,
    },
    IeDef {
        id: 23,
        name: "postOctetDeltaCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 24,
        name: "postPacketDeltaCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 27,
        name: "sourceIPv6Address",
        ty: Ipv6Address,
    },
    IeDef {
        id: 28,
        name: "destinationIPv6Address",
        ty: Ipv6Address,
    },
    IeDef {
        id: 29,
        name: "sourceIPv6PrefixLength",
        ty: Unsigned8,
    },
    IeDef {
        id: 30,
        name: "destinationIPv6PrefixLength",
        ty: Unsigned8,
    },
    IeDef {
        id: 31,
        name: "flowLabelIPv6",
        ty: Unsigned32,
    },
    IeDef {
        id: 32,
        name: "icmpTypeCodeIPv4",
        ty: Unsigned16,
    },
    IeDef {
        id: 33,
        name: "igmpType",
        ty: Unsigned8,
    },
    IeDef {
        id: 34,
        name: "samplingInterval",
        ty: Unsigned32,
    },
    IeDef {
        id: 35,
        name: "samplingAlgorithm",
        ty: Unsigned8,
    },
    IeDef {
        id: 36,
        name: "flowActiveTimeout",
        ty: Unsigned16,
    },
    IeDef {
        id: 37,
        name: "flowIdleTimeout",
        ty: Unsigned16,
    },
    IeDef {
        id: 40,
        name: "exportedOctetTotalCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 41,
        name: "exportedMessageTotalCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 42,
        name: "exportedFlowRecordTotalCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 52,
        name: "minimumTTL",
        ty: Unsigned8,
    },
    IeDef {
        id: 53,
        name: "maximumTTL",
        ty: Unsigned8,
    },
    IeDef {
        id: 56,
        name: "sourceMacAddress",
        ty: MacAddress,
    },
    IeDef {
        id: 57,
        name: "postDestinationMacAddress",
        ty: MacAddress,
    },
    IeDef {
        id: 58,
        name: "vlanId",
        ty: Unsigned16,
    },
    IeDef {
        id: 59,
        name: "postVlanId",
        ty: Unsigned16,
    },
    IeDef {
        id: 60,
        name: "ipVersion",
        ty: Unsigned8,
    },
    IeDef {
        id: 61,
        name: "flowDirection",
        ty: Unsigned8,
    },
    IeDef {
        id: 62,
        name: "ipNextHopIPv6Address",
        ty: Ipv6Address,
    },
    IeDef {
        id: 63,
        name: "bgpNextHopIPv6Address",
        ty: Ipv6Address,
    },
    IeDef {
        id: 70,
        name: "mplsTopLabelStackSection",
        ty: OctetArray,
    },
    IeDef {
        id: 80,
        name: "destinationMacAddress",
        ty: MacAddress,
    },
    IeDef {
        id: 81,
        name: "postSourceMacAddress",
        ty: MacAddress,
    },
    IeDef {
        id: 82,
        name: "interfaceName",
        ty: String,
    },
    IeDef {
        id: 83,
        name: "interfaceDescription",
        ty: String,
    },
    IeDef {
        id: 85,
        name: "octetTotalCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 86,
        name: "packetTotalCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 88,
        name: "fragmentOffset",
        ty: Unsigned16,
    },
    IeDef {
        id: 89,
        name: "forwardingStatus",
        ty: Unsigned8,
    },
    IeDef {
        id: 128,
        name: "bgpNextAdjacentAsNumber",
        ty: Unsigned32,
    },
    IeDef {
        id: 129,
        name: "bgpPrevAdjacentAsNumber",
        ty: Unsigned32,
    },
    IeDef {
        id: 130,
        name: "exporterIPv4Address",
        ty: Ipv4Address,
    },
    IeDef {
        id: 131,
        name: "exporterIPv6Address",
        ty: Ipv6Address,
    },
    IeDef {
        id: 136,
        name: "flowEndReason",
        ty: Unsigned8,
    },
    IeDef {
        id: 139,
        name: "icmpTypeCodeIPv6",
        ty: Unsigned16,
    },
    IeDef {
        id: 144,
        name: "exportingProcessId",
        ty: Unsigned32,
    },
    IeDef {
        id: 145,
        name: "templateId",
        ty: Unsigned16,
    },
    IeDef {
        id: 148,
        name: "flowId",
        ty: Unsigned64,
    },
    IeDef {
        id: 150,
        name: "flowStartSeconds",
        ty: DateTimeSeconds,
    },
    IeDef {
        id: 151,
        name: "flowEndSeconds",
        ty: DateTimeSeconds,
    },
    IeDef {
        id: 152,
        name: "flowStartMilliseconds",
        ty: DateTimeMilliseconds,
    },
    IeDef {
        id: 153,
        name: "flowEndMilliseconds",
        ty: DateTimeMilliseconds,
    },
    IeDef {
        id: 154,
        name: "flowStartMicroseconds",
        ty: DateTimeMicroseconds,
    },
    IeDef {
        id: 155,
        name: "flowEndMicroseconds",
        ty: DateTimeMicroseconds,
    },
    IeDef {
        id: 156,
        name: "flowStartNanoseconds",
        ty: DateTimeNanoseconds,
    },
    IeDef {
        id: 157,
        name: "flowEndNanoseconds",
        ty: DateTimeNanoseconds,
    },
    IeDef {
        id: 160,
        name: "systemInitTimeMilliseconds",
        ty: DateTimeMilliseconds,
    },
    IeDef {
        id: 161,
        name: "flowDurationMilliseconds",
        ty: Unsigned32,
    },
    IeDef {
        id: 176,
        name: "icmpTypeIPv4",
        ty: Unsigned8,
    },
    IeDef {
        id: 177,
        name: "icmpCodeIPv4",
        ty: Unsigned8,
    },
    IeDef {
        id: 178,
        name: "icmpTypeIPv6",
        ty: Unsigned8,
    },
    IeDef {
        id: 179,
        name: "icmpCodeIPv6",
        ty: Unsigned8,
    },
    IeDef {
        id: 180,
        name: "udpSourcePort",
        ty: Unsigned16,
    },
    IeDef {
        id: 181,
        name: "udpDestinationPort",
        ty: Unsigned16,
    },
    IeDef {
        id: 182,
        name: "tcpSourcePort",
        ty: Unsigned16,
    },
    IeDef {
        id: 183,
        name: "tcpDestinationPort",
        ty: Unsigned16,
    },
    IeDef {
        id: 184,
        name: "tcpSequenceNumber",
        ty: Unsigned32,
    },
    IeDef {
        id: 185,
        name: "tcpAcknowledgementNumber",
        ty: Unsigned32,
    },
    IeDef {
        id: 186,
        name: "tcpWindowSize",
        ty: Unsigned16,
    },
    IeDef {
        id: 187,
        name: "tcpUrgentPointer",
        ty: Unsigned16,
    },
    IeDef {
        id: 189,
        name: "ipHeaderLength",
        ty: Unsigned8,
    },
    IeDef {
        id: 192,
        name: "ipTTL",
        ty: Unsigned8,
    },
    IeDef {
        id: 195,
        name: "ipDiffServCodePoint",
        ty: Unsigned8,
    },
    IeDef {
        id: 205,
        name: "udpMessageLength",
        ty: Unsigned16,
    },
    IeDef {
        id: 206,
        name: "isMulticast",
        ty: Unsigned8,
    },
    IeDef {
        id: 224,
        name: "ipTotalLength",
        ty: Unsigned64,
    },
    IeDef {
        id: 225,
        name: "postNATSourceIPv4Address",
        ty: Ipv4Address,
    },
    IeDef {
        id: 226,
        name: "postNATDestinationIPv4Address",
        ty: Ipv4Address,
    },
    IeDef {
        id: 227,
        name: "postNAPTSourceTransportPort",
        ty: Unsigned16,
    },
    IeDef {
        id: 228,
        name: "postNAPTDestinationTransportPort",
        ty: Unsigned16,
    },
    IeDef {
        id: 230,
        name: "natEvent",
        ty: Unsigned8,
    },
    IeDef {
        id: 233,
        name: "firewallEvent",
        ty: Unsigned8,
    },
    IeDef {
        id: 234,
        name: "ingressVRFID",
        ty: Unsigned32,
    },
    IeDef {
        id: 235,
        name: "egressVRFID",
        ty: Unsigned32,
    },
    IeDef {
        id: 243,
        name: "dot1qVlanId",
        ty: Unsigned16,
    },
    IeDef {
        id: 244,
        name: "dot1qPriority",
        ty: Unsigned8,
    },
    IeDef {
        id: 245,
        name: "dot1qCustomerVlanId",
        ty: Unsigned16,
    },
    IeDef {
        id: 256,
        name: "ethernetType",
        ty: Unsigned16,
    },
    IeDef {
        id: 277,
        name: "observationPointId",
        ty: Unsigned64,
    },
    IeDef {
        id: 300,
        name: "observationDomainName",
        ty: String,
    },
    IeDef {
        id: 302,
        name: "selectorId",
        ty: Unsigned64,
    },
    IeDef {
        id: 305,
        name: "samplingPacketInterval",
        ty: Unsigned32,
    },
    IeDef {
        id: 306,
        name: "samplingPacketSpace",
        ty: Unsigned32,
    },
    IeDef {
        id: 309,
        name: "samplingSize",
        ty: Unsigned32,
    },
    IeDef {
        id: 318,
        name: "selectorIdTotalFlowsObserved",
        ty: Unsigned64,
    },
    IeDef {
        id: 322,
        name: "observationTimeSeconds",
        ty: DateTimeSeconds,
    },
    IeDef {
        id: 323,
        name: "observationTimeMilliseconds",
        ty: DateTimeMilliseconds,
    },
    IeDef {
        id: 324,
        name: "observationTimeMicroseconds",
        ty: DateTimeMicroseconds,
    },
    IeDef {
        id: 325,
        name: "observationTimeNanoseconds",
        ty: DateTimeNanoseconds,
    },
    IeDef {
        id: 351,
        name: "layer2OctetDeltaCount",
        ty: Unsigned64,
    },
    IeDef {
        id: 352,
        name: "layer2OctetTotalCount",
        ty: Unsigned64,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_sorted() {
        for w in REGISTRY.windows(2) {
            assert!(w[0].id < w[1].id, "registry must be strictly id-ordered");
        }
    }

    #[test]
    fn key_normalization_ies_present() {
        for id in [1u16, 2, 4, 7, 8, 11, 12, 152, 153] {
            assert!(lookup(id).is_some(), "IE {id} should be present");
        }
        assert_eq!(lookup(8).unwrap().name, "sourceIPv4Address");
        assert_eq!(lookup(8).unwrap().ty, IeType::Ipv4Address);
    }
}
