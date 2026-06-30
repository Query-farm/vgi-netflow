//! NetFlow v5 — fixed 24-byte header + up to 30 × 48-byte records. Stateless.

use crate::buf::Cursor;
use crate::decode::header::parse_header;
use crate::inet::inet4;
use crate::normalize::FlowRecord;

const V5_RECORD_LEN: usize = 48;

/// Decode a NetFlow v5 datagram into normalized rows. Never panics: a truncated
/// record stops the scan after emitting a `truncated` diagnostic.
pub fn decode(data: &[u8], exporter: &str) -> Vec<FlowRecord> {
    let Some(hdr) = parse_header(data) else {
        return vec![FlowRecord::diagnostic(
            exporter,
            "5",
            0,
            None,
            None,
            "decode-error:bad-v5-header".to_string(),
        )];
    };
    let count = hdr.count.unwrap_or(0) as usize;
    let obs_domain = hdr.obs_domain.unwrap_or(0);
    let boot_micros = match (hdr.export_time, hdr.sys_uptime) {
        (Some(e), Some(u)) => Some(e - (u as i64) * 1_000),
        _ => None,
    };

    let mut out = Vec::with_capacity(count);
    let mut cur = Cursor::new(data);
    cur.skip(24); // header

    for _ in 0..count {
        let Some(slice) = cur.take(V5_RECORD_LEN) else {
            out.push(FlowRecord::diagnostic(
                exporter,
                "5",
                obs_domain,
                hdr.export_time,
                hdr.sequence,
                "truncated".to_string(),
            ));
            break;
        };
        out.push(decode_record(
            slice,
            exporter,
            obs_domain,
            &hdr,
            boot_micros,
        ));
    }
    out
}

fn decode_record(
    b: &[u8],
    exporter: &str,
    obs_domain: u32,
    hdr: &crate::decode::header::ExportHeader,
    boot_micros: Option<i64>,
) -> FlowRecord {
    let mut c = Cursor::new(b);
    // All reads are within the validated 48-byte slice, so unwraps are safe; we
    // still use `?`-free Option chaining defensively via local closures.
    let src = c.take(4).map(|s| s.to_vec()).unwrap_or_default();
    let dst = c.take(4).map(|s| s.to_vec()).unwrap_or_default();
    let nexthop = c.take(4).map(|s| s.to_vec()).unwrap_or_default();
    let input = c.u16().unwrap_or(0);
    let output = c.u16().unwrap_or(0);
    let dpkts = c.u32().unwrap_or(0);
    let doctets = c.u32().unwrap_or(0);
    let first = c.u32().unwrap_or(0);
    let last = c.u32().unwrap_or(0);
    let srcport = c.u16().unwrap_or(0);
    let dstport = c.u16().unwrap_or(0);
    let _pad1 = c.u8();
    let tcp_flags = c.u8().unwrap_or(0);
    let prot = c.u8().unwrap_or(0);
    let tos = c.u8().unwrap_or(0);
    let src_as = c.u16().unwrap_or(0);
    let dst_as = c.u16().unwrap_or(0);
    let src_mask = c.u8().unwrap_or(0);
    let dst_mask = c.u8().unwrap_or(0);

    let (flow_start, flow_end) = match boot_micros {
        Some(boot) => (
            Some(boot + first as i64 * 1_000),
            Some(boot + last as i64 * 1_000),
        ),
        None => (None, None),
    };

    FlowRecord {
        exporter: exporter.to_string(),
        flow_version: "5".to_string(),
        obs_domain,
        template_id: None,
        export_time: hdr.export_time,
        sequence: hdr.sequence,
        src_addr: inet4(&src),
        dst_addr: inet4(&dst),
        src_port: Some(srcport),
        dst_port: Some(dstport),
        protocol: Some(prot),
        tcp_flags: Some(tcp_flags),
        bytes: Some(doctets as u64),
        packets: Some(dpkts as u64),
        flow_start,
        flow_end,
        src_as: Some(src_as as u32),
        dst_as: Some(dst_as as u32),
        input_snmp: Some(input as u32),
        output_snmp: Some(output as u32),
        next_hop: inet4(&nexthop),
        tos: Some(tos),
        src_mask: Some(src_mask),
        dst_mask: Some(dst_mask),
        sampling_rate: None,
        direction: None,
        raw_fields: Vec::new(),
        diagnostics: None,
    }
}
