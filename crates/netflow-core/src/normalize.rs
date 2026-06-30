//! The normalized cross-version flow record (§5).
//!
//! v5 / v9 / IPFIX / sFlow all decode into this one wide row so a single query
//! spans every exporter and version. Anything the normalized columns cannot hold
//! lands in `raw_fields` (the lossless escape hatch), keyed by IE name (or
//! `e<PEN>id<n>` for unmapped enterprise IEs).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::inet::InetVal;

/// One normalized flow row. Optional columns are `None` when the source format
/// did not carry that field. Address columns are DuckDB-`INET` triples (§5) so
/// `src_addr::INET <<= …` containment joins work without string parsing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowRecord {
    pub exporter: String,
    /// `"5"`, `"9"`, `"10"` (IPFIX), or `"sflow5"`.
    pub flow_version: String,
    pub obs_domain: u32,
    pub template_id: Option<u16>,
    /// Datagram export time, microseconds since the Unix epoch (UTC).
    pub export_time: Option<i64>,
    pub sequence: Option<u64>,
    pub src_addr: Option<InetVal>,
    pub dst_addr: Option<InetVal>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<u8>,
    pub tcp_flags: Option<u8>,
    pub bytes: Option<u64>,
    pub packets: Option<u64>,
    /// Flow start, microseconds since the Unix epoch (UTC).
    pub flow_start: Option<i64>,
    pub flow_end: Option<i64>,
    pub src_as: Option<u32>,
    pub dst_as: Option<u32>,
    pub input_snmp: Option<u32>,
    pub output_snmp: Option<u32>,
    pub next_hop: Option<InetVal>,
    pub tos: Option<u8>,
    pub src_mask: Option<u8>,
    pub dst_mask: Option<u8>,
    pub sampling_rate: Option<u32>,
    pub direction: Option<u8>,
    /// Every IE not mapped to a normalized column, keyed by IE name; value is the
    /// raw on-wire bytes. Insertion order is preserved.
    pub raw_fields: Vec<(String, Vec<u8>)>,
    /// `None` on a clean decode; else `missing-template:<dom>/<id>`, `truncated`,
    /// `unknown-ie`, `enterprise-unmapped`, or `decode-error:<detail>`.
    pub diagnostics: Option<String>,
}

impl FlowRecord {
    /// A header-only record carrying just the exporter/version/domain context,
    /// used for `missing-template` and decode-error diagnostics.
    pub fn diagnostic(
        exporter: &str,
        version: &str,
        obs_domain: u32,
        export_time: Option<i64>,
        sequence: Option<u64>,
        diag: String,
    ) -> Self {
        FlowRecord {
            exporter: exporter.to_string(),
            flow_version: version.to_string(),
            obs_domain,
            export_time,
            sequence,
            diagnostics: Some(diag),
            ..Default::default()
        }
    }

    /// Append a raw field, keeping insertion order.
    pub fn put_raw(&mut self, name: impl Into<String>, bytes: Vec<u8>) {
        self.raw_fields.push((name.into(), bytes));
    }

    /// Merge a diagnostic note (joining with `;` if one already exists).
    pub fn note(&mut self, msg: &str) {
        match &mut self.diagnostics {
            Some(d) => {
                if !d.split(';').any(|p| p == msg) {
                    d.push(';');
                    d.push_str(msg);
                }
            }
            None => self.diagnostics = Some(msg.to_string()),
        }
    }
}

/// Render 4 bytes as a dotted IPv4 string.
pub fn ipv4(b: &[u8]) -> Option<String> {
    if b.len() == 4 {
        Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string())
    } else {
        None
    }
}

/// Render 16 bytes as a canonical IPv6 string.
pub fn ipv6(b: &[u8]) -> Option<String> {
    if b.len() == 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(b);
        Some(Ipv6Addr::from(octets).to_string())
    } else {
        None
    }
}

/// Big-endian unsigned read of up to 8 bytes (IPFIX reduced-size encoding).
pub fn be_uint(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &byte in b.iter().take(8) {
        v = (v << 8) | byte as u64;
    }
    v
}
