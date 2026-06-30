//! sFlow v5 (sflow.org / InMon) — XDR-encoded packet-sampling datagrams.
//! Stateless (self-describing, no templates). Flow samples carry sampled packet
//! headers / parsed L3-L4; counter samples carry interface counters. Both are
//! normalized into the flow schema; sampled byte/packet counts are scaled by the
//! sampling rate (unscaled values preserved in `raw_fields`).

use crate::buf::Cursor;
use crate::inet::{inet4, inet6};
use crate::normalize::{ipv4, ipv6, FlowRecord};

/// Decode an sFlow v5 datagram into normalized rows. `mode_flows_only` drops
/// counter samples (which have no 5-tuple). Never panics.
pub fn decode(data: &[u8], exporter: &str, mode_flows_only: bool) -> Vec<FlowRecord> {
    let mut c = Cursor::new(data);
    let bad = |seq| {
        vec![FlowRecord::diagnostic(
            exporter,
            "sflow5",
            0,
            None,
            seq,
            "decode-error:bad-sflow-header".to_string(),
        )]
    };
    let Some(version) = c.u32() else {
        return bad(None);
    };
    if version != 5 {
        return bad(None);
    }
    let Some(addr_type) = c.u32() else {
        return bad(None);
    };
    let agent = match addr_type {
        1 => c.take(4).and_then(ipv4),
        2 => c.take(16).and_then(ipv6),
        _ => return bad(None),
    };
    let (Some(sub_agent_id), Some(sequence), Some(_uptime), Some(num_samples)) =
        (c.u32(), c.u32(), c.u32(), c.u32())
    else {
        return bad(None);
    };
    let exporter_id = if exporter.is_empty() {
        agent.clone().unwrap_or_default()
    } else {
        exporter.to_string()
    };

    let mut out = Vec::new();
    for _ in 0..num_samples.min(65_536) {
        let (Some(sample_type), Some(sample_len)) = (c.u32(), c.u32()) else {
            break;
        };
        let Some(body) = c.take(sample_len as usize) else {
            out.push(FlowRecord::diagnostic(
                &exporter_id,
                "sflow5",
                sub_agent_id,
                None,
                Some(sequence as u64),
                "truncated".to_string(),
            ));
            break;
        };
        match sample_type & 0x0fff {
            1 | 3 => out.extend(decode_flow_sample(
                body,
                &exporter_id,
                sub_agent_id,
                sequence as u64,
                sample_type & 0x0fff == 3,
            )),
            2 | 4 => {
                if !mode_flows_only {
                    out.push(decode_counter_sample(
                        body,
                        &exporter_id,
                        sub_agent_id,
                        sequence as u64,
                        sample_type & 0x0fff == 4,
                    ));
                }
            }
            _ => {}
        }
    }
    out
}

fn decode_flow_sample(
    body: &[u8],
    exporter: &str,
    obs_domain: u32,
    sequence: u64,
    expanded: bool,
) -> Vec<FlowRecord> {
    let mut c = Cursor::new(body);
    let _seq = c.u32();
    if expanded {
        c.u32(); // source_id_type
        c.u32(); // source_id_index
    } else {
        c.u32(); // source_id
    }
    let sampling_rate = c.u32().unwrap_or(1).max(1);
    let _sample_pool = c.u32();
    let _drops = c.u32();
    let (input, output) = if expanded {
        c.u32();
        let i = c.u32();
        c.u32();
        let o = c.u32();
        (i, o)
    } else {
        (c.u32(), c.u32())
    };
    let num_records = c.u32().unwrap_or(0).min(4096);

    let mut base = FlowRecord {
        exporter: exporter.to_string(),
        flow_version: "sflow5".to_string(),
        obs_domain,
        sequence: Some(sequence),
        sampling_rate: Some(sampling_rate),
        input_snmp: input,
        output_snmp: output,
        ..Default::default()
    };

    for _ in 0..num_records {
        let (Some(rec_type), Some(rec_len)) = (c.u32(), c.u32()) else {
            break;
        };
        let Some(rbody) = c.take(rec_len as usize) else {
            break;
        };
        // Low 12 bits = format; high 20 bits = enterprise (0 = standard).
        match rec_type & 0x0fff {
            1 => parse_raw_header(rbody, &mut base, sampling_rate),
            3 => parse_sampled_ipv4(rbody, &mut base, sampling_rate),
            4 => parse_sampled_ipv6(rbody, &mut base, sampling_rate),
            _ => {}
        }
    }
    vec![base]
}

/// sFlow `sampled_ipv4` (format 3): an already-parsed IPv4 5-tuple.
fn parse_sampled_ipv4(b: &[u8], rec: &mut FlowRecord, rate: u32) {
    let mut c = Cursor::new(b);
    let length = c.u32().unwrap_or(0);
    let protocol = c.u32().unwrap_or(0);
    let src = c.take(4).map(|x| x.to_vec()).unwrap_or_default();
    let dst = c.take(4).map(|x| x.to_vec()).unwrap_or_default();
    let src_port = c.u32().unwrap_or(0);
    let dst_port = c.u32().unwrap_or(0);
    let tcp_flags = c.u32().unwrap_or(0);
    let tos = c.u32().unwrap_or(0);
    rec.src_addr = inet4(&src);
    rec.dst_addr = inet4(&dst);
    rec.protocol = Some(protocol as u8);
    rec.src_port = Some(src_port as u16);
    rec.dst_port = Some(dst_port as u16);
    rec.tcp_flags = Some(tcp_flags as u8);
    rec.tos = Some(tos as u8);
    scale_counts(rec, length as u64, rate);
}

/// sFlow `sampled_ipv6` (format 4).
fn parse_sampled_ipv6(b: &[u8], rec: &mut FlowRecord, rate: u32) {
    let mut c = Cursor::new(b);
    let length = c.u32().unwrap_or(0);
    let protocol = c.u32().unwrap_or(0);
    let src = c.take(16).map(|x| x.to_vec()).unwrap_or_default();
    let dst = c.take(16).map(|x| x.to_vec()).unwrap_or_default();
    let src_port = c.u32().unwrap_or(0);
    let dst_port = c.u32().unwrap_or(0);
    let tcp_flags = c.u32().unwrap_or(0);
    let _priority = c.u32();
    rec.src_addr = inet6(&src);
    rec.dst_addr = inet6(&dst);
    rec.protocol = Some(protocol as u8);
    rec.src_port = Some(src_port as u16);
    rec.dst_port = Some(dst_port as u16);
    rec.tcp_flags = Some(tcp_flags as u8);
    scale_counts(rec, length as u64, rate);
}

/// sFlow `sampled_header` (format 1): a raw sampled packet header. We parse the
/// Ethernet → IPv4/IPv6 → TCP/UDP chain best-effort for the 5-tuple.
fn parse_raw_header(b: &[u8], rec: &mut FlowRecord, rate: u32) {
    let mut c = Cursor::new(b);
    let _protocol = c.u32();
    let frame_length = c.u32().unwrap_or(0);
    let _stripped = c.u32();
    let header_size = c.u32().unwrap_or(0) as usize;
    let header = c.take(header_size).unwrap_or(&[]);
    scale_counts(rec, frame_length as u64, rate);
    parse_l2(header, rec);
}

/// Minimal Ethernet/IPv4/IPv6/TCP/UDP parse over a sampled header.
fn parse_l2(h: &[u8], rec: &mut FlowRecord) {
    let mut c = Cursor::new(h);
    // Ethernet II: dst(6) src(6) ethertype(2), with optional 802.1Q tag.
    if c.skip(12) {
        let mut ethertype = c.u16().unwrap_or(0);
        if ethertype == 0x8100 {
            c.skip(2); // VLAN tag
            ethertype = c.u16().unwrap_or(0);
        }
        match ethertype {
            0x0800 => parse_ipv4(&mut c, rec),
            0x86dd => parse_ipv6(&mut c, rec),
            _ => {}
        }
    }
}

fn parse_ipv4(c: &mut Cursor, rec: &mut FlowRecord) {
    let Some(vihl) = c.u8() else { return };
    let ihl = (vihl & 0x0f) as usize * 4;
    let Some(tos) = c.u8() else { return };
    c.skip(2); // total length
    c.skip(2); // id
    c.skip(2); // flags/frag
    c.skip(1); // ttl
    let proto = c.u8().unwrap_or(0);
    c.skip(2); // checksum
    let src = c.take(4).map(|x| x.to_vec()).unwrap_or_default();
    let dst = c.take(4).map(|x| x.to_vec()).unwrap_or_default();
    rec.src_addr = inet4(&src);
    rec.dst_addr = inet4(&dst);
    rec.protocol = Some(proto);
    rec.tos = Some(tos);
    // Skip any IPv4 options to reach L4 (header is `ihl` bytes from its start).
    let consumed = 20usize;
    if ihl > consumed {
        c.skip(ihl - consumed);
    }
    parse_l4(c, proto, rec);
}

fn parse_ipv6(c: &mut Cursor, rec: &mut FlowRecord) {
    let Some(_vtc) = c.u32() else { return }; // version/traffic-class/flow-label
    c.skip(2); // payload length
    let next_header = c.u8().unwrap_or(0);
    c.skip(1); // hop limit
    let src = c.take(16).map(|x| x.to_vec()).unwrap_or_default();
    let dst = c.take(16).map(|x| x.to_vec()).unwrap_or_default();
    rec.src_addr = inet6(&src);
    rec.dst_addr = inet6(&dst);
    rec.protocol = Some(next_header);
    parse_l4(c, next_header, rec);
}

fn parse_l4(c: &mut Cursor, proto: u8, rec: &mut FlowRecord) {
    match proto {
        6 => {
            // TCP: src_port(2) dst_port(2) seq(4) ack(4) offset/flags
            let sp = c.u16().unwrap_or(0);
            let dp = c.u16().unwrap_or(0);
            c.skip(8);
            let _data_off = c.u8();
            let flags = c.u8().unwrap_or(0);
            rec.src_port = Some(sp);
            rec.dst_port = Some(dp);
            rec.tcp_flags = Some(flags);
        }
        17 => {
            let sp = c.u16().unwrap_or(0);
            let dp = c.u16().unwrap_or(0);
            rec.src_port = Some(sp);
            rec.dst_port = Some(dp);
        }
        _ => {}
    }
}

/// Scale a sampled frame length by the sampling rate, preserving the unscaled
/// value in `raw_fields` (§5 normalization rule 1).
fn scale_counts(rec: &mut FlowRecord, frame_length: u64, rate: u32) {
    rec.bytes = Some(frame_length.saturating_mul(rate as u64));
    rec.packets = Some(rate as u64);
    rec.put_raw(
        "sflow.frame_length",
        (frame_length as u32).to_be_bytes().to_vec(),
    );
    rec.put_raw("sflow.sampling_rate", rate.to_be_bytes().to_vec());
}

// (interface-index values are kept as their raw `Option<u32>`; sFlow's special
// "format" encodings are preserved verbatim in the normalized columns.)

fn decode_counter_sample(
    body: &[u8],
    exporter: &str,
    obs_domain: u32,
    sequence: u64,
    expanded: bool,
) -> FlowRecord {
    let mut c = Cursor::new(body);
    let _seq = c.u32();
    if expanded {
        c.u32();
        c.u32();
    } else {
        c.u32();
    }
    let num_records = c.u32().unwrap_or(0).min(4096);
    let mut rec = FlowRecord {
        exporter: exporter.to_string(),
        flow_version: "sflow5".to_string(),
        obs_domain,
        sequence: Some(sequence),
        diagnostics: None,
        ..Default::default()
    };
    rec.note("counter-sample");
    for _ in 0..num_records {
        let (Some(rec_type), Some(rec_len)) = (c.u32(), c.u32()) else {
            break;
        };
        let Some(rbody) = c.take(rec_len as usize) else {
            break;
        };
        rec.put_raw(
            format!("sflow.counter_format_{}", rec_type & 0x0fff),
            rbody.to_vec(),
        );
    }
    rec
}
