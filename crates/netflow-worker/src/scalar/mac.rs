//! MAC-address enrichment scalars: vendor lookup against the bundled IEEE
//! registry (`oui_vendor`, `oui_lookup`), canonical formatting
//! (`mac_normalize`), address-bit flags (`mac_is_multicast`, `mac_is_local`,
//! `mac_is_broadcast`), and modified EUI-64 conversion (`eui48_to_eui64`,
//! `mac_from_ipv6`).
//!
//! The MAC argument is ANY-typed and accepts a `VARCHAR` in any common notation,
//! a 6-byte `BLOB` (how IPFIX carries `sourceMacAddress` — e.g.
//! `raw_fields['sourceMacAddress']` from `flows()`), or an integer holding the
//! 48-bit address. Unparseable input yields NULL, never an error or panic.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder};
use arrow_array::cast::AsArray;
use arrow_array::types::{
    Int16Type, Int32Type, Int64Type, Int8Type, UInt16Type, UInt32Type, UInt64Type, UInt8Type,
};
use arrow_array::{Array, ArrayRef, RecordBatch, StructArray};
use arrow_schema::{DataType, Field, Fields};
use netflow_core::mac::{self, Mac};
use netflow_core::oui;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction, Worker,
};
use vgi_rpc::{Result, RpcError};

/// Which enrichment a [`MacScalar`] computes.
#[derive(Clone, Copy)]
enum Op {
    Vendor,
    Lookup,
    Normalize,
    IsMulticast,
    IsLocal,
    IsBroadcast,
    Eui64,
    FromIpv6,
}

struct MacScalar(Op);

/// Register every MAC enrichment scalar.
pub fn register(worker: &mut Worker) {
    for op in [
        Op::Vendor,
        Op::Lookup,
        Op::Normalize,
        Op::IsMulticast,
        Op::IsLocal,
        Op::IsBroadcast,
        Op::Eui64,
        Op::FromIpv6,
    ] {
        worker.register_scalar(MacScalar(op));
    }
}

fn lookup_fields() -> Fields {
    Fields::from(vec![
        Field::new("prefix", DataType::Utf8, true),
        Field::new("block", DataType::Utf8, true),
        Field::new("organization", DataType::Utf8, true),
    ])
}

/// Static per-function metadata.
struct Spec {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    doc_llm: &'static str,
    doc_md: &'static str,
    keywords: &'static str,
    /// `(description, sql)` executable examples (the first is also the native
    /// `Meta.example`).
    examples: &'static [(&'static str, &'static str)],
}

const MAC_ARG_DOC: &str = "The MAC address to inspect — text in colon, dash, Cisco dotted \
     (aabb.ccdd.eeff) or bare-hex notation, its six raw address bytes (e.g. \
     raw_fields['sourceMacAddress'] from flows()), or the 48-bit address as a number.";

impl Op {
    fn ret(self) -> DataType {
        match self {
            Op::Vendor | Op::Normalize | Op::Eui64 | Op::FromIpv6 => DataType::Utf8,
            Op::Lookup => DataType::Struct(lookup_fields()),
            Op::IsMulticast | Op::IsLocal | Op::IsBroadcast => DataType::Boolean,
        }
    }

    fn spec(self) -> Spec {
        match self {
            Op::Vendor => Spec {
                name: "oui_vendor",
                title: "MAC Vendor Lookup",
                description: "Registered IEEE organization for a MAC address",
                doc_llm: "Return the organization the IEEE Registration Authority assigned a MAC \
                    address's prefix to (e.g. 'Apple, Inc.', 'Cisco Systems, Inc'), from a bundled \
                    snapshot of the IEEE MA-L (24-bit OUI), MA-M (28-bit) and MA-S (36-bit) \
                    registries; the longest matching prefix wins. NULL when the prefix is \
                    unassigned — which includes virtually every locally administered / randomized \
                    MAC — or the input is not a MAC. Accepts `VARCHAR` in any common notation, a \
                    6-byte `BLOB` (so it applies directly to raw_fields['sourceMacAddress'] / \
                    raw_fields['destinationMacAddress'] from flows()), or an integer. No network \
                    access: the registry is compiled into the worker.",
                doc_md: "MAC address → registered IEEE organization name (MA-L/MA-M/MA-S, longest \
                    prefix). NULL if unassigned, randomized, or not a MAC.",
                keywords: "oui, mac vendor, manufacturer, organization, ieee, mac address, \
                    vendor lookup, nic, device fingerprint, asset inventory, ma-l, ma-m, ma-s",
                examples: &[
                    (
                        "Look up the vendor of an Apple NIC's MAC address.",
                        "SELECT netflow.main.oui_vendor('00-1B-63-84-45-E6') AS vendor",
                    ),
                    (
                        "A randomized (locally administered) MAC has no registered vendor — NULL.",
                        "SELECT netflow.main.oui_vendor('da:a1:19:12:34:56') AS vendor",
                    ),
                ],
            },
            Op::Lookup => Spec {
                name: "oui_lookup",
                title: "MAC Registry Assignment",
                description: "IEEE registry assignment (prefix, block, organization) for a MAC",
                doc_llm: "Return the IEEE registry assignment matching a MAC address as \
                    `STRUCT(prefix VARCHAR, block VARCHAR, organization VARCHAR)`: `prefix` is the \
                    assigned block in MAC/CIDR notation (e.g. '00:1b:63:00:00:00/24'), `block` is \
                    the IEEE registry it came from — 'MA-L' (24-bit OUI), 'MA-M' (28-bit) or \
                    'MA-S' (36-bit) — and `organization` the registered name. The longest prefix \
                    wins, so a MAC inside an MA-S block reports the MA-S holder rather than the \
                    IEEE Registration Authority's parent MA-L. NULL when unassigned or not a MAC. \
                    Use oui_vendor when only the name is needed.",
                doc_md: "MAC address → `STRUCT(prefix, block, organization)` from the bundled \
                    IEEE MA-L/MA-M/MA-S registries; NULL if unassigned.",
                keywords: "oui, registry, assignment, ma-l, ma-m, ma-s, ieee, mac prefix, \
                    organization, mac vendor, block size",
                examples: &[
                    (
                        "Show which IEEE block and prefix an Apple MAC belongs to.",
                        "SELECT netflow.main.oui_lookup('00:1b:63:84:45:e6') AS assignment",
                    ),
                    (
                        "A MAC inside a 28-bit MA-M block reports that block's holder.",
                        "SELECT netflow.main.oui_lookup('a4:58:0f:d0:00:01').block AS block",
                    ),
                ],
            },
            Op::Normalize => Spec {
                name: "mac_normalize",
                title: "MAC Address Normalization",
                description: "Canonical lowercase colon form of a MAC address",
                doc_llm: "Rewrite a MAC address into the canonical lowercase colon-separated form \
                    'aa:bb:cc:dd:ee:ff' from any common notation: colon or dash separated (one or \
                    two hex digits per group, any case), Cisco dotted 'aabb.ccdd.eeff', or 12 \
                    bare hex digits; also accepts a 6-byte `BLOB` or an integer. NULL on anything \
                    that is not a MAC (wrong length, mixed separators, non-hex). Use it as a join \
                    key across sources that format MACs differently (DHCP logs, switch CAM \
                    tables, flow exports, asset inventories).",
                doc_md: "Normalize a MAC (colon / dash / Cisco dotted / bare hex / 6-byte `BLOB`) \
                    to `aa:bb:cc:dd:ee:ff`; NULL if invalid.",
                keywords: "mac normalize, canonical, format, mac address, cisco dotted, eui-48, \
                    join key, clean, parse",
                examples: &[
                    (
                        "Normalize a Cisco dotted-notation MAC.",
                        "SELECT netflow.main.mac_normalize('001B.6384.45E6') AS mac",
                    ),
                    (
                        "Text that is not a MAC normalizes to NULL.",
                        "SELECT netflow.main.mac_normalize('00:1b:63:84:45') AS mac",
                    ),
                ],
            },
            Op::IsMulticast => Spec {
                name: "mac_is_multicast",
                title: "MAC Multicast Flag",
                description: "Whether a MAC is a group (multicast/broadcast) address",
                doc_llm: "TRUE when a MAC address has the I/G (individual/group) bit set — the \
                    least significant bit of the first octet — meaning it addresses a group \
                    (multicast, including broadcast) rather than one interface, e.g. \
                    01:00:5e:… IPv4 multicast or 33:33:… IPv6 multicast. FALSE for unicast. NULL \
                    when the input is not a MAC.",
                doc_md: "TRUE if the MAC's I/G bit is set (multicast or broadcast); NULL if not a \
                    MAC.",
                keywords: "multicast, group address, i/g bit, mac address, broadcast, unicast, \
                    flag",
                examples: &[
                    (
                        "An IPv4 multicast (mDNS) destination MAC is a group address.",
                        "SELECT netflow.main.mac_is_multicast('01:00:5e:00:00:fb') AS multicast",
                    ),
                    (
                        "An ordinary NIC MAC is unicast.",
                        "SELECT netflow.main.mac_is_multicast('00:1b:63:84:45:e6') AS multicast",
                    ),
                ],
            },
            Op::IsLocal => Spec {
                name: "mac_is_local",
                title: "MAC Locally-Administered Flag",
                description: "Whether a MAC is locally administered (e.g. randomized)",
                doc_llm: "TRUE when a MAC address has the U/L bit set — the second least \
                    significant bit of the first octet — meaning it was assigned by software \
                    rather than burned in from an IEEE block. Modern phones and laptops use such \
                    randomized MACs for privacy, as do VMs, containers and many virtual \
                    interfaces, so this flags MAC randomization when counting devices or \
                    fingerprinting vendors. FALSE for universally administered MACs. NULL when \
                    the input is not a MAC.",
                doc_md: "TRUE if the MAC's U/L bit is set — locally administered, e.g. a \
                    randomized privacy MAC; NULL if not a MAC.",
                keywords: "locally administered, randomized mac, mac randomization, privacy, \
                    u/l bit, virtual mac, mac address, flag",
                examples: &[
                    (
                        "A randomized phone MAC is locally administered.",
                        "SELECT netflow.main.mac_is_local('da:a1:19:12:34:56') AS randomized",
                    ),
                    (
                        "A burned-in Apple NIC MAC is universally administered.",
                        "SELECT netflow.main.mac_is_local('00:1b:63:84:45:e6') AS randomized",
                    ),
                ],
            },
            Op::IsBroadcast => Spec {
                name: "mac_is_broadcast",
                title: "MAC Broadcast Flag",
                description: "Whether a MAC is the all-ones broadcast address",
                doc_llm: "TRUE only for the Ethernet broadcast address ff:ff:ff:ff:ff:ff (in any \
                    notation); FALSE for every other MAC, including other multicast addresses \
                    (use mac_is_multicast for those). NULL when the input is not a MAC.",
                doc_md: "TRUE if the MAC is `ff:ff:ff:ff:ff:ff`; NULL if not a MAC.",
                keywords: "broadcast, ff:ff:ff:ff:ff:ff, mac address, flag, layer 2, ethernet",
                examples: &[
                    (
                        "The all-ones address is broadcast.",
                        "SELECT netflow.main.mac_is_broadcast('FF-FF-FF-FF-FF-FF') AS broadcast",
                    ),
                    (
                        "A multicast address is not broadcast.",
                        "SELECT netflow.main.mac_is_broadcast('01:00:5e:00:00:fb') AS broadcast",
                    ),
                ],
            },
            Op::Eui64 => Spec {
                name: "eui48_to_eui64",
                title: "MAC to Modified EUI-64",
                description: "Modified EUI-64 IPv6 interface identifier for a MAC",
                doc_llm: "Convert a 48-bit MAC address to the modified EUI-64 interface \
                    identifier IPv6 stateless autoconfiguration (SLAAC) derives from it (RFC 4291 \
                    Appendix A): insert ff:fe between the two halves and invert the U/L bit. \
                    Returned as four IPv6 hextets, e.g. '021b:63ff:fe84:45e6', so \
                    'fe80::' || eui48_to_eui64(mac) is the interface's link-local address. NULL \
                    when the input is not a MAC. mac_from_ipv6 is the inverse.",
                doc_md: "MAC → modified EUI-64 interface ID as IPv6 hextets \
                    (`021b:63ff:fe84:45e6`), per RFC 4291; NULL if not a MAC.",
                keywords: "eui-64, modified eui-64, slaac, ipv6, interface identifier, \
                    link-local, rfc 4291, mac address",
                examples: &[
                    (
                        "Derive the modified EUI-64 interface identifier of a MAC.",
                        "SELECT netflow.main.eui48_to_eui64('00:1b:63:84:45:e6') AS iid",
                    ),
                    (
                        "Build the SLAAC link-local IPv6 address for a MAC.",
                        "SELECT 'fe80::' || netflow.main.eui48_to_eui64('34-56-78-9A-BC-DE') \
                         AS link_local",
                    ),
                ],
            },
            Op::FromIpv6 => Spec {
                name: "mac_from_ipv6",
                title: "MAC from SLAAC IPv6 Address",
                description: "MAC embedded in a modified-EUI-64 IPv6 address",
                doc_llm: "Recover the MAC address embedded in an IPv6 address whose interface \
                    identifier is a modified EUI-64 (classic SLAAC, recognizable by ff:fe in the \
                    middle of the low 64 bits), returning it in canonical 'aa:bb:cc:dd:ee:ff' \
                    form. NULL for addresses with random/privacy or manually assigned interface \
                    IDs, IPv4 addresses, and non-addresses. Takes `VARCHAR` (a trailing /prefix is \
                    ignored); cast an `INET` such as `src_addr::INET` from flows() with `::VARCHAR`. Chain \
                    with oui_vendor to attribute IPv6 hosts to a hardware vendor.",
                doc_md: "IPv6 address with a modified EUI-64 interface ID → embedded MAC \
                    (`aa:bb:cc:dd:ee:ff`); NULL otherwise.",
                keywords: "slaac, eui-64, ipv6, mac address, interface identifier, link-local, \
                    reverse, extract",
                examples: &[
                    (
                        "Extract the MAC from a SLAAC link-local address.",
                        "SELECT netflow.main.mac_from_ipv6('fe80::21b:63ff:fe84:45e6') AS mac",
                    ),
                    (
                        "A privacy-extension address embeds no MAC — NULL.",
                        "SELECT netflow.main.mac_from_ipv6('2001:db8::1') AS mac",
                    ),
                ],
            },
        }
    }
}

impl ScalarFunction for MacScalar {
    fn name(&self) -> &str {
        self.0.spec().name
    }

    fn metadata(&self) -> FunctionMetadata {
        let spec = self.0.spec();
        let composed = crate::meta::composed_mac_enrichment();
        let mut tags =
            crate::meta::object_tags(spec.title, spec.doc_llm, spec.doc_md, spec.keywords);
        tags.push(("vgi.category".into(), "enrichment".into()));
        let mut examples: Vec<(&str, &str)> = spec.examples.to_vec();
        if matches!(self.0, Op::Vendor | Op::IsLocal) {
            examples.push((composed.0, composed.1.as_str()));
        }
        tags.push((
            "vgi.executable_examples".into(),
            crate::meta::executable_examples_json(&examples),
        ));
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&examples),
        ));
        let (ex_desc, ex_sql) = spec.examples[0];
        FunctionMetadata {
            description: spec.description.into(),
            return_type: Some(self.0.ret()),
            examples: vec![FunctionExample {
                sql: ex_sql.into(),
                description: ex_desc.into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        match self.0 {
            Op::FromIpv6 => vec![ArgSpec::column(
                "address",
                0,
                "varchar",
                "An IPv6 address as text (optionally with a /prefix length), e.g. \
                 'fe80::21b:63ff:fe84:45e6'.",
            )],
            _ => vec![ArgSpec::any_column("mac", 0, MAC_ARG_DOC)],
        }
    }

    fn on_bind(&self, params: &BindParams) -> Result<BindResponse> {
        if !matches!(self.0, Op::FromIpv6) {
            if let Some(field) = params
                .input_schema
                .as_ref()
                .and_then(|s| s.fields().first())
            {
                if !accepts(field.data_type()) {
                    return Err(RpcError::value_error(format!(
                        "{}: expected a MAC as VARCHAR, BLOB, or integer, got {}",
                        self.0.spec().name,
                        field.data_type()
                    )));
                }
            }
        }
        Ok(BindResponse::result(self.0.ret()))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let n = batch.num_rows();
        let out: ArrayRef = match self.0 {
            Op::Vendor | Op::Normalize | Op::Eui64 | Op::FromIpv6 => {
                let mut b = StringBuilder::new();
                for row in 0..n {
                    let v = match self.0 {
                        Op::FromIpv6 => text_at(col, row)?
                            .and_then(mac::mac_from_ipv6)
                            .map(|m| mac::format_mac(&m)),
                        _ => mac_at(col, row)?.and_then(|m| match self.0 {
                            Op::Vendor => oui::vendor(&m).map(str::to_string),
                            Op::Normalize => Some(mac::format_mac(&m)),
                            _ => Some(mac::format_interface_id(&mac::eui48_to_eui64(&m))),
                        }),
                    };
                    b.append_option(v);
                }
                Arc::new(b.finish())
            }
            Op::IsMulticast | Op::IsLocal | Op::IsBroadcast => {
                let f: fn(&Mac) -> bool = match self.0 {
                    Op::IsMulticast => mac::is_multicast,
                    Op::IsLocal => mac::is_local,
                    _ => mac::is_broadcast,
                };
                let mut b = BooleanBuilder::with_capacity(n);
                for row in 0..n {
                    b.append_option(mac_at(col, row)?.map(|m| f(&m)));
                }
                Arc::new(b.finish())
            }
            Op::Lookup => {
                let mut prefix = StringBuilder::new();
                let mut block = StringBuilder::new();
                let mut org = StringBuilder::new();
                let mut validity = arrow_array::builder::BooleanBufferBuilder::new(n);
                for row in 0..n {
                    match mac_at(col, row)?.and_then(|m| oui::lookup(&m)) {
                        Some(a) => {
                            prefix.append_value(a.prefix_cidr());
                            block.append_value(a.block.as_str());
                            org.append_value(a.organization);
                            validity.append(true);
                        }
                        None => {
                            prefix.append_null();
                            block.append_null();
                            org.append_null();
                            validity.append(false);
                        }
                    }
                }
                let children: Vec<ArrayRef> = vec![
                    Arc::new(prefix.finish()),
                    Arc::new(block.finish()),
                    Arc::new(org.finish()),
                ];
                let nulls = arrow_buffer::NullBuffer::new(validity.finish());
                Arc::new(StructArray::new(lookup_fields(), children, Some(nulls)))
            }
        };
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

/// Input types a MAC argument accepts.
fn accepts(dt: &DataType) -> bool {
    use DataType::*;
    matches!(
        dt,
        Utf8 | LargeUtf8
            | Utf8View
            | Binary
            | LargeBinary
            | BinaryView
            | FixedSizeBinary(_)
            | Int8
            | Int16
            | Int32
            | Int64
            | UInt8
            | UInt16
            | UInt32
            | UInt64
            | Null
    )
}

fn text_at(col: &ArrayRef, row: usize) -> Result<Option<&str>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Utf8 => col.as_string::<i32>().value(row),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row),
        DataType::Utf8View => col.as_string_view().value(row),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a VARCHAR argument, got {other}"
            )))
        }
    }))
}

/// The MAC in `col[row]`: `None` for a NULL cell or anything that is not a MAC.
fn mac_at(col: &ArrayRef, row: usize) -> Result<Option<Mac>> {
    if col.is_null(row) {
        return Ok(None);
    }
    fn int(v: i128) -> Option<Mac> {
        u64::try_from(v).ok().and_then(mac::mac_from_u64)
    }
    Ok(match col.data_type() {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => {
            text_at(col, row)?.and_then(mac::parse_mac)
        }
        DataType::Binary => mac::mac_from_bytes(col.as_binary::<i32>().value(row)),
        DataType::LargeBinary => mac::mac_from_bytes(col.as_binary::<i64>().value(row)),
        DataType::BinaryView => mac::mac_from_bytes(col.as_binary_view().value(row)),
        DataType::FixedSizeBinary(_) => mac::mac_from_bytes(col.as_fixed_size_binary().value(row)),
        DataType::Int8 => int(col.as_primitive::<Int8Type>().value(row).into()),
        DataType::Int16 => int(col.as_primitive::<Int16Type>().value(row).into()),
        DataType::Int32 => int(col.as_primitive::<Int32Type>().value(row).into()),
        DataType::Int64 => int(col.as_primitive::<Int64Type>().value(row).into()),
        DataType::UInt8 => int(col.as_primitive::<UInt8Type>().value(row).into()),
        DataType::UInt16 => int(col.as_primitive::<UInt16Type>().value(row).into()),
        DataType::UInt32 => int(col.as_primitive::<UInt32Type>().value(row).into()),
        DataType::UInt64 => int(col.as_primitive::<UInt64Type>().value(row).into()),
        DataType::Null => None,
        other => {
            return Err(RpcError::value_error(format!(
                "expected a MAC as VARCHAR, BLOB, or integer, got {other}"
            )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{BinaryArray, StringArray, UInt64Array};

    const EX_MAC: &str = "00-1B-63-84-45-E6";

    #[test]
    fn reads_every_input_shape() {
        let apple = Some([0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6]);
        let s: ArrayRef = Arc::new(StringArray::from(vec![Some(EX_MAC), Some("nope"), None]));
        assert_eq!(mac_at(&s, 0).unwrap(), apple);
        assert_eq!(mac_at(&s, 1).unwrap(), None);
        assert_eq!(mac_at(&s, 2).unwrap(), None);
        let b: ArrayRef = Arc::new(BinaryArray::from(vec![
            &[0x00u8, 0x1b, 0x63, 0x84, 0x45, 0xe6][..],
            &[1u8, 2, 3][..],
        ]));
        assert_eq!(mac_at(&b, 0).unwrap(), apple);
        assert_eq!(mac_at(&b, 1).unwrap(), None);
        let u: ArrayRef = Arc::new(UInt64Array::from(vec![0x001b_6384_45e6, u64::MAX]));
        assert_eq!(mac_at(&u, 0).unwrap(), apple);
        assert_eq!(mac_at(&u, 1).unwrap(), None);
    }

    #[test]
    fn every_function_has_examples() {
        for op in [
            Op::Vendor,
            Op::Lookup,
            Op::Normalize,
            Op::IsMulticast,
            Op::IsLocal,
            Op::IsBroadcast,
            Op::Eui64,
            Op::FromIpv6,
        ] {
            let spec = op.spec();
            assert!(spec.examples.len() >= 2, "{}", spec.name);
            for (_, sql) in spec.examples {
                assert!(sql.contains(&format!("netflow.main.{}(", spec.name)));
            }
        }
    }
}
