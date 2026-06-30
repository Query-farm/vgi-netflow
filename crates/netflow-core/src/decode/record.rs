//! Shared v9/IPFIX data-record slicing and IE→normalized-column mapping.
//!
//! A Data Set is `field_length`-sized slices in template order — meaningless
//! without the cached layout. This module takes a resolved [`TemplateEntry`] plus
//! the raw Data Set payload and produces normalized [`FlowRecord`]s, honoring
//! IPFIX variable-length encoding (v9 templates never use it). All slicing is
//! bounds-checked; a short record degrades to a `truncated` diagnostic row.

use crate::buf::Cursor;
use crate::cache::{FieldSpec, TemplateEntry, TemplateKind};
use crate::inet::{inet4, inet6};
use crate::normalize::{be_uint, FlowRecord};
use crate::registry::{self, IeType};

/// Per-datagram header context threaded into each emitted record.
#[derive(Clone)]
pub struct Ctx {
    pub exporter: String,
    pub obs_domain: u32,
    /// `"9"` or `"10"`.
    pub version: &'static str,
    pub export_time: Option<i64>,
    pub sequence: Option<u64>,
    /// v9 header sysUptime in milliseconds (None for IPFIX).
    pub sys_uptime_ms: Option<u64>,
    pub template_id: u16,
}

/// Resolve a field specifier to a [`FieldSpec`] at template-parse time.
pub fn field_spec(enterprise_number: u32, ie_id: u16, length: u16) -> FieldSpec {
    match registry::resolve(enterprise_number, ie_id) {
        Some(def) => FieldSpec {
            ie_id,
            enterprise_number,
            length,
            name: def.name.to_string(),
            ie_type: ie_type_name(def.ty).to_string(),
        },
        None => {
            let name = if enterprise_number == 0 {
                format!("id{ie_id}")
            } else {
                format!("e{enterprise_number}id{ie_id}")
            };
            FieldSpec {
                ie_id,
                enterprise_number,
                length,
                name,
                ie_type: "octetArray".to_string(),
            }
        }
    }
}

fn ie_type_name(t: IeType) -> &'static str {
    use IeType::*;
    match t {
        Unsigned8 => "unsigned8",
        Unsigned16 => "unsigned16",
        Unsigned32 => "unsigned32",
        Unsigned64 => "unsigned64",
        Signed32 => "signed32",
        Signed64 => "signed64",
        Float64 => "float64",
        Boolean => "boolean",
        MacAddress => "macAddress",
        Ipv4Address => "ipv4Address",
        Ipv6Address => "ipv6Address",
        DateTimeSeconds => "dateTimeSeconds",
        DateTimeMilliseconds => "dateTimeMilliseconds",
        DateTimeMicroseconds => "dateTimeMicroseconds",
        DateTimeNanoseconds => "dateTimeNanoseconds",
        String => "string",
        OctetArray => "octetArray",
    }
}

/// Decode a whole Data Set payload into zero or more flow records.
///
/// Records are sliced in sequence until the remaining bytes can no longer hold a
/// full record (trailing padding is ignored). `mode_flows_only` drops Options
/// records entirely.
pub fn decode_data_set(
    tpl: &TemplateEntry,
    payload: &[u8],
    ctx: &Ctx,
    mode_flows_only: bool,
) -> Vec<FlowRecord> {
    if mode_flows_only && tpl.kind == TemplateKind::Options {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = Cursor::new(payload);
    // Minimum fixed footprint: any variable field can be as small as 0 bytes, so
    // a template with a variable field has min 0 — guard the loop on progress.
    let min_fixed: usize = tpl
        .fields
        .iter()
        .filter(|f| !f.is_variable())
        .map(|f| f.length as usize)
        .sum();

    loop {
        let rem = cur.remaining();
        if rem == 0 {
            break;
        }
        // For purely fixed templates, stop once the remainder is shorter than one
        // record (padding). For variable templates min_fixed may be 0; we attempt
        // a decode and bail if it underruns.
        if min_fixed > 0 && rem < min_fixed {
            break;
        }
        let start = cur.position();
        match decode_one_record(tpl, &mut cur, ctx) {
            Some(rec) => out.push(rec),
            None => {
                // Underrun mid-record → emit a truncated diagnostic and stop.
                out.push(FlowRecord::diagnostic(
                    &ctx.exporter,
                    ctx.version,
                    ctx.obs_domain,
                    ctx.export_time,
                    ctx.sequence,
                    "truncated".to_string(),
                ));
                break;
            }
        }
        // Guard against a zero-advance loop (all-variable template, empty record).
        if cur.position() == start {
            break;
        }
    }
    out
}

/// Decode a single record, advancing `cur`. Returns `None` on underrun.
fn decode_one_record(tpl: &TemplateEntry, cur: &mut Cursor, ctx: &Ctx) -> Option<FlowRecord> {
    let mut rec = FlowRecord {
        exporter: ctx.exporter.clone(),
        flow_version: ctx.version.to_string(),
        obs_domain: ctx.obs_domain,
        template_id: Some(ctx.template_id),
        export_time: ctx.export_time,
        sequence: ctx.sequence,
        ..Default::default()
    };
    // Raw sysUptime deltas (v9) collected for post-hoc absolute-time resolution.
    let mut start_sysup: Option<u32> = None;
    let mut end_sysup: Option<u32> = None;

    for f in &tpl.fields {
        let len = if f.is_variable() {
            read_varlen(cur)?
        } else {
            f.length as usize
        };
        let bytes = cur.take(len)?.to_vec();
        map_field(&mut rec, f, &bytes, &mut start_sysup, &mut end_sysup);
    }

    resolve_times(&mut rec, ctx, start_sysup, end_sysup);
    Some(rec)
}

/// Read an IPFIX variable-length prefix (RFC 7011 §7): a single length byte, or
/// `0xFF` followed by a 2-byte length.
fn read_varlen(cur: &mut Cursor) -> Option<usize> {
    let first = cur.u8()?;
    if first < 255 {
        Some(first as usize)
    } else {
        Some(cur.u16()? as usize)
    }
}

/// Map one decoded field's bytes onto the normalized record (or raw_fields).
fn map_field(
    rec: &mut FlowRecord,
    f: &FieldSpec,
    bytes: &[u8],
    start_sysup: &mut Option<u32>,
    end_sysup: &mut Option<u32>,
) {
    // Enterprise fields never populate normalized columns; preserve them raw.
    if f.enterprise_number != 0 {
        if f.name.starts_with('e') && f.ie_type == "octetArray" {
            rec.note("enterprise-unmapped");
        }
        rec.put_raw(f.name.clone(), bytes.to_vec());
        return;
    }

    let u = be_uint(bytes);
    match f.ie_id {
        8 | 130 => rec.src_addr = inet4(bytes).or(rec.src_addr.take()),
        27 | 131 => rec.src_addr = inet6(bytes).or(rec.src_addr.take()),
        12 | 226 => rec.dst_addr = inet4(bytes).or(rec.dst_addr.take()),
        28 => rec.dst_addr = inet6(bytes).or(rec.dst_addr.take()),
        7 | 180 | 182 => rec.src_port = Some(u as u16),
        11 | 181 | 183 => rec.dst_port = Some(u as u16),
        4 => rec.protocol = Some(u as u8),
        5 | 195 => rec.tos = Some(u as u8),
        6 => rec.tcp_flags = Some((u & 0xff) as u8),
        1 | 23 | 85 | 351 | 352 => {
            if rec.bytes.is_none() || f.ie_id == 1 {
                rec.bytes = Some(u);
            }
        }
        2 | 24 | 86 => {
            if rec.packets.is_none() || f.ie_id == 2 {
                rec.packets = Some(u);
            }
        }
        10 => rec.input_snmp = Some(u as u32),
        14 => rec.output_snmp = Some(u as u32),
        16 => rec.src_as = Some(u as u32),
        17 => rec.dst_as = Some(u as u32),
        15 | 18 => rec.next_hop = inet4(bytes).or(rec.next_hop.take()),
        62 | 63 => rec.next_hop = inet6(bytes).or(rec.next_hop.take()),
        9 | 29 => rec.src_mask = Some(u as u8),
        13 | 30 => rec.dst_mask = Some(u as u8),
        34 | 305 => rec.sampling_rate = Some(u as u32),
        61 => rec.direction = Some(u as u8),
        22 => *start_sysup = Some(u as u32),
        21 => *end_sysup = Some(u as u32),
        150 => rec.flow_start = Some(u as i64 * 1_000_000),
        151 => rec.flow_end = Some(u as i64 * 1_000_000),
        152 => rec.flow_start = Some(u as i64 * 1_000),
        153 => rec.flow_end = Some(u as i64 * 1_000),
        154 | 156 => rec.flow_start = ntp_micros(bytes).or(rec.flow_start),
        155 | 157 => rec.flow_end = ntp_micros(bytes).or(rec.flow_end),
        _ => rec.put_raw(f.name.clone(), bytes.to_vec()),
    }
}

/// Resolve v9 sysUptime-delta flow times to absolute microseconds using the
/// datagram header (`export_time` minus header `sysUptime` = boot wallclock).
fn resolve_times(
    rec: &mut FlowRecord,
    ctx: &Ctx,
    start_sysup: Option<u32>,
    end_sysup: Option<u32>,
) {
    let (Some(export), Some(uptime)) = (ctx.export_time, ctx.sys_uptime_ms) else {
        return;
    };
    let boot_micros = export - (uptime as i64) * 1_000;
    if rec.flow_start.is_none() {
        if let Some(s) = start_sysup {
            rec.flow_start = Some(boot_micros + s as i64 * 1_000);
        }
    }
    if rec.flow_end.is_none() {
        if let Some(e) = end_sysup {
            rec.flow_end = Some(boot_micros + e as i64 * 1_000);
        }
    }
}

/// Decode an 8-byte NTP timestamp (seconds since 1900 + 32-bit fraction) to
/// microseconds since the Unix epoch.
fn ntp_micros(bytes: &[u8]) -> Option<i64> {
    if bytes.len() != 8 {
        return None;
    }
    let secs1900 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64;
    let frac = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64;
    let epoch_secs = secs1900 - 2_208_988_800; // 1900→1970 offset
    let frac_micros = (frac * 1_000_000) >> 32;
    Some(epoch_secs * 1_000_000 + frac_micros as i64)
}
