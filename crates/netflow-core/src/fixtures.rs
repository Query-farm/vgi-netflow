//! Deterministic golden flow-export datagrams, built in code.
//!
//! One source of truth for both the core unit tests and the `gen_fixtures`
//! example (which writes them to `test/data/*.dat` for the haybarn SQL E2E). Each
//! builder returns a raw UDP-payload datagram exactly as an exporter would emit
//! it. Public sample captures are great but offline-fragile; building the bytes
//! here keeps the golden vectors reproducible and reviewable.

/// A tiny big-endian byte writer.
#[derive(Default)]
struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    fn ipv4(&mut self, a: u8, b: u8, c: u8, d: u8) -> &mut Self {
        self.0.extend_from_slice(&[a, b, c, d]);
        self
    }
    fn done(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Header export time used by all stateful fixtures (2023-11-14T22:13:20Z).
pub const EXPORT_UNIX_SECS: u32 = 1_700_000_000;
/// v9 header sysUptime (ms since boot) used by the v9 fixtures.
pub const V9_SYS_UPTIME_MS: u32 = 100_000;

// ---------------------------------------------------------------- NetFlow v5

/// A NetFlow v5 datagram with two records (a TCP flow and a UDP flow).
pub fn netflow_v5() -> Vec<u8> {
    let mut w = W::default();
    // Header (24 bytes).
    w.u16(5)
        .u16(2) // version, count
        .u32(V9_SYS_UPTIME_MS) // sysUptime
        .u32(EXPORT_UNIX_SECS)
        .u32(0) // unix_nsecs
        .u32(10) // flow_sequence
        .u8(0)
        .u8(1) // engine_type, engine_id
        .u16(0); // sampling
                 // Record 1: 10.0.0.1:1234 -> 10.0.0.2:80 TCP, 10 pkts / 1000 bytes.
    push_v5_record(
        &mut w,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        6,
        0x18,
        10,
        1000,
        64500,
        64501,
    );
    // Record 2: 192.168.1.1:5353 -> 8.8.8.8:53 UDP, 2 pkts / 200 bytes.
    push_v5_record(
        &mut w,
        [192, 168, 1, 1],
        [8, 8, 8, 8],
        5353,
        53,
        17,
        0,
        2,
        200,
        0,
        15169,
    );
    w.done()
}

#[allow(clippy::too_many_arguments)]
fn push_v5_record(
    w: &mut W,
    src: [u8; 4],
    dst: [u8; 4],
    sp: u16,
    dp: u16,
    proto: u8,
    flags: u8,
    pkts: u32,
    octets: u32,
    src_as: u16,
    dst_as: u16,
) {
    w.ipv4(src[0], src[1], src[2], src[3])
        .ipv4(dst[0], dst[1], dst[2], dst[3])
        .ipv4(10, 0, 0, 254) // nexthop
        .u16(1)
        .u16(2) // input, output
        .u32(pkts)
        .u32(octets)
        .u32(90_000)
        .u32(95_000) // First, Last sysUptime
        .u16(sp)
        .u16(dp)
        .u8(0)
        .u8(flags)
        .u8(proto)
        .u8(0) // pad1, tcp_flags, prot, tos
        .u16(src_as)
        .u16(dst_as)
        .u8(24)
        .u8(24) // src_mask, dst_mask
        .u16(0); // pad2
}

// ---------------------------------------------------------------- NetFlow v9

/// Template id used by the v9 fixtures.
pub const V9_TEMPLATE_ID: u16 = 256;
/// Observation domain (source id) used by the v9 fixtures.
pub const V9_OBS_DOMAIN: u32 = 1;

/// v9 Template-only datagram (defines template 256). Sent before the data
/// datagram in the cross-batch priming test.
pub fn netflow_v9_template() -> Vec<u8> {
    let mut tmpl = W::default();
    // Template record: id=256, 7 fields.
    tmpl.u16(V9_TEMPLATE_ID).u16(7);
    for (ty, len) in [
        (8u16, 4u16),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (2, 4),
        (1, 4),
    ] {
        tmpl.u16(ty).u16(len);
    }
    let body = tmpl.done();
    let mut w = W::default();
    v9_header(&mut w, 1);
    flowset(&mut w, 0, &body); // FlowSet id 0 = Template
    w.done()
}

/// v9 Data-only datagram (one record for template 256). Undecodable until the
/// template datagram above has been seen.
pub fn netflow_v9_data() -> Vec<u8> {
    let mut rec = W::default();
    // src 10.1.1.1 -> dst 10.1.1.2, sp 4000 dp 443, proto 6, pkts 5, octets 800.
    rec.ipv4(10, 1, 1, 1)
        .ipv4(10, 1, 1, 2)
        .u16(4000)
        .u16(443)
        .u8(6)
        .u32(5)
        .u32(800);
    let body = rec.done();
    let mut w = W::default();
    v9_header(&mut w, 1);
    flowset(&mut w, V9_TEMPLATE_ID, &body);
    w.done()
}

/// A single v9 datagram that carries the template AND its data (template first).
pub fn netflow_v9_combined() -> Vec<u8> {
    let mut tmpl = W::default();
    tmpl.u16(V9_TEMPLATE_ID).u16(7);
    for (ty, len) in [
        (8u16, 4u16),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (2, 4),
        (1, 4),
    ] {
        tmpl.u16(ty).u16(len);
    }
    let mut rec = W::default();
    rec.ipv4(172, 16, 0, 1)
        .ipv4(172, 16, 0, 2)
        .u16(1111)
        .u16(22)
        .u8(6)
        .u32(3)
        .u32(180);
    let mut w = W::default();
    v9_header(&mut w, 2);
    flowset(&mut w, 0, &tmpl.done());
    flowset(&mut w, V9_TEMPLATE_ID, &rec.done());
    w.done()
}

fn v9_header(w: &mut W, count: u16) {
    w.u16(9)
        .u16(count)
        .u32(V9_SYS_UPTIME_MS)
        .u32(EXPORT_UNIX_SECS)
        .u32(20)
        .u32(V9_OBS_DOMAIN);
}

/// Wrap a body in a `{id, length, body}` FlowSet/Set header.
fn flowset(w: &mut W, id: u16, body: &[u8]) {
    let length = (body.len() + 4) as u16;
    w.u16(id).u16(length).bytes(body);
}

// ---------------------------------------------------------------- IPFIX

/// IPFIX data template id.
pub const IPFIX_TEMPLATE_ID: u16 = 256;
/// IPFIX variable-length + enterprise template id.
pub const IPFIX_VAR_TEMPLATE_ID: u16 = 257;
/// IPFIX options template id.
pub const IPFIX_OPTIONS_TEMPLATE_ID: u16 = 258;
/// IPFIX observation domain.
pub const IPFIX_OBS_DOMAIN: u32 = 42;

/// IPFIX datagram: a Template Set defining a fixed flow template, plus a Data Set
/// with one fully-decodable IPv4/TCP flow (absolute millisecond timestamps).
pub fn ipfix_basic() -> Vec<u8> {
    let mut tmpl = W::default();
    tmpl.u16(IPFIX_TEMPLATE_ID).u16(9);
    for (id, len) in [
        (8u16, 4u16),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 8),
        (2, 8),
        (152, 8),
        (153, 8),
    ] {
        tmpl.u16(id).u16(len);
    }

    let mut data = W::default();
    data.ipv4(203, 0, 113, 5)
        .ipv4(198, 51, 100, 9)
        .u16(33000)
        .u16(443)
        .u8(6)
        .u64(1_500_000) // octets
        .u64(1_200) // packets
        .u64(1_700_000_000_000) // flowStartMilliseconds
        .u64(1_700_000_010_000); // flowEndMilliseconds

    let mut w = W::default();
    ipfix_header(
        &mut w,
        &[(2u16, tmpl.done()), (IPFIX_TEMPLATE_ID, data.done())],
    );
    w.done()
}

/// IPFIX datagram exercising a variable-length IE (interfaceName) and an
/// enterprise IE (VMware PEN 6876, id 880).
pub fn ipfix_variable_enterprise() -> Vec<u8> {
    let mut tmpl = W::default();
    // 4 fields: src(8,4), dst(12,4), interfaceName(82, variable), vmware(880,1,PEN6876)
    tmpl.u16(IPFIX_VAR_TEMPLATE_ID).u16(4);
    tmpl.u16(8).u16(4);
    tmpl.u16(12).u16(4);
    tmpl.u16(82).u16(0xFFFF); // variable length
    tmpl.u16(0x8000 | 880).u16(1).u32(6876); // enterprise bit + PEN

    let mut data = W::default();
    data.ipv4(10, 9, 9, 1).ipv4(10, 9, 9, 2);
    let ifname = b"eth0";
    data.u8(ifname.len() as u8).bytes(ifname); // 1-byte varlen prefix + value
    data.u8(7); // vmware.tenantProtocol value

    let mut w = W::default();
    ipfix_header(
        &mut w,
        &[(2u16, tmpl.done()), (IPFIX_VAR_TEMPLATE_ID, data.done())],
    );
    w.done()
}

/// IPFIX datagram with an Options Template + Options Data record (sampling
/// configuration).
pub fn ipfix_options() -> Vec<u8> {
    // Options Template Set (id 3): template 258, field_count=2, scope_field_count=1.
    let mut tmpl = W::default();
    tmpl.u16(IPFIX_OPTIONS_TEMPLATE_ID).u16(2).u16(1);
    tmpl.u16(144).u16(4); // scope: exportingProcessId
    tmpl.u16(34).u16(4); // option: samplingInterval

    let mut data = W::default();
    data.u32(1001) // exportingProcessId
        .u32(1000); // samplingInterval

    let mut w = W::default();
    ipfix_header(
        &mut w,
        &[
            (3u16, tmpl.done()),
            (IPFIX_OPTIONS_TEMPLATE_ID, data.done()),
        ],
    );
    w.done()
}

/// Build an IPFIX datagram from `(set_id, body)` pairs, computing the header
/// `length` field.
fn ipfix_header(w: &mut W, sets: &[(u16, Vec<u8>)]) {
    let mut body = W::default();
    for (id, b) in sets {
        let length = (b.len() + 4) as u16;
        body.u16(*id).u16(length).bytes(b);
    }
    let body = body.done();
    let total = (16 + body.len()) as u16;
    w.u16(10)
        .u16(total)
        .u32(EXPORT_UNIX_SECS)
        .u32(7)
        .u32(IPFIX_OBS_DOMAIN)
        .bytes(&body);
}

// ---------------------------------------------------------------- sFlow v5

/// sFlow v5 datagram: one flow sample (sampled_ipv4) + one counter sample.
pub fn sflow_basic() -> Vec<u8> {
    let mut w = W::default();
    // Header: version=5, agent IPv4 10.0.0.9, sub_agent 0, seq 1, uptime, 2 samples.
    w.u32(5)
        .u32(1)
        .ipv4(10, 0, 0, 9)
        .u32(0)
        .u32(1)
        .u32(1_000)
        .u32(2);

    // --- Flow sample (type 1) ---
    let mut fs = W::default();
    fs.u32(100) // sample sequence
        .u32(0) // source_id
        .u32(4096) // sampling_rate
        .u32(0) // sample_pool
        .u32(0) // drops
        .u32(5) // input
        .u32(6) // output
        .u32(1); // num flow records
                 // sampled_ipv4 record (format 3).
    let mut rec = W::default();
    rec.u32(64) // length
        .u32(6) // protocol TCP
        .ipv4(192, 0, 2, 10)
        .ipv4(192, 0, 2, 20)
        .u32(51000)
        .u32(80)
        .u32(0x18)
        .u32(0);
    let recb = rec.done();
    fs.u32(3).u32(recb.len() as u32).bytes(&recb);
    let fsb = fs.done();
    w.u32(1).u32(fsb.len() as u32).bytes(&fsb);

    // --- Counter sample (type 2) ---
    let mut cs = W::default();
    cs.u32(200).u32(0).u32(1); // seq, source_id, num records
    let counters = vec![0u8; 88]; // generic interface counters payload
    cs.u32(1).u32(counters.len() as u32).bytes(&counters);
    let csb = cs.done();
    w.u32(2).u32(csb.len() as u32).bytes(&csb);

    w.done()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_have_recognizable_headers() {
        assert_eq!(&netflow_v5()[0..2], &[0, 5]);
        assert_eq!(&netflow_v9_template()[0..2], &[0, 9]);
        assert_eq!(&ipfix_basic()[0..2], &[0, 10]);
        assert_eq!(&sflow_basic()[0..4], &[0, 0, 0, 5]);
    }
}
