//! Decode orchestration: version dispatch, per-datagram decode, cross-datagram
//! pending retry, and end-of-scan flush.
//!
//! The public entry points ([`decode_datagram`], [`retry_pending`],
//! [`flush_pending`]) thread the [`crate::cache::TemplateCache`] — the
//! externalized scan state — and never panic on malformed input.

pub mod header;
pub mod ipfix;
pub mod record;
pub mod sflow;
pub mod v5;
pub mod v9;

use crate::cache::{TemplateCache, TemplateKey};
use crate::decode::record::{decode_data_set, Ctx};
use crate::normalize::FlowRecord;

/// Output filtering mode (`flows()` `mode` argument).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Decode everything (default); options + counter samples included.
    Auto,
    /// Drop sFlow counter samples and v9/IPFIX options records.
    FlowsOnly,
    /// Alias of `Auto` — emit every decodable record.
    All,
}

impl Mode {
    pub fn parse(s: &str) -> Mode {
        match s {
            "flows-only" => Mode::FlowsOnly,
            "all" => Mode::All,
            _ => Mode::Auto,
        }
    }
    fn flows_only(self) -> bool {
        matches!(self, Mode::FlowsOnly)
    }
}

/// Which formats a decode entry point accepts. A datagram of a disallowed format
/// yields a `decode-error` diagnostic row (never a panic, never a drop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restrict {
    /// `flows()` — accept all four formats.
    Any,
    /// `netflow_decode()` — v5 and v9 only.
    NetflowOnly,
    /// `ipfix_decode()` — IPFIX (v10) only.
    IpfixOnly,
    /// `sflow_decode()` — sFlow v5 only.
    SflowOnly,
}

/// Per-call decode options.
#[derive(Clone, Debug)]
pub struct DecodeOptions {
    /// Cache scope: the source device id. Empty = "default" (template ids may
    /// collide across exporters — supply this for multi-device lakes).
    pub exporter: String,
    /// Force the cache-key observation domain (overrides the datagram's).
    pub obs_domain_override: Option<u32>,
    pub mode: Mode,
    /// Wall-clock "now" in microseconds, stamped into template first/last-seen.
    pub now_micros: i64,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        DecodeOptions {
            exporter: String::new(),
            obs_domain_override: None,
            mode: Mode::Auto,
            now_micros: 0,
        }
    }
}

/// Decode one datagram, updating the cache, then retry any pending data whose
/// template the cache now knows. Returns the rows produced by this datagram
/// (plus any newly-resolvable buffered rows).
pub fn decode_datagram(
    data: &[u8],
    opts: &DecodeOptions,
    cache: &mut TemplateCache,
    restrict: Restrict,
) -> Vec<FlowRecord> {
    let version = header::probe_version(data);
    let exporter = opts.exporter.as_str();
    let flows_only = opts.mode.flows_only();

    let mut out = match (version, restrict) {
        (Some("5"), Restrict::Any | Restrict::NetflowOnly) => v5::decode(data, exporter),
        (Some("9"), Restrict::Any | Restrict::NetflowOnly) => v9::decode(
            data,
            exporter,
            opts.obs_domain_override,
            cache,
            opts.now_micros,
            flows_only,
        ),
        (Some("10"), Restrict::Any | Restrict::IpfixOnly) => ipfix::decode(
            data,
            exporter,
            opts.obs_domain_override,
            cache,
            opts.now_micros,
            flows_only,
        ),
        (Some("sflow5"), Restrict::Any | Restrict::SflowOnly) => {
            sflow::decode(data, exporter, flows_only)
        }
        (Some(v), _) => vec![FlowRecord::diagnostic(
            exporter,
            v,
            0,
            None,
            None,
            format!("decode-error:format-{v}-not-accepted-here"),
        )],
        (None, _) => vec![FlowRecord::diagnostic(
            exporter,
            "",
            0,
            None,
            None,
            "decode-error:not-a-flow-datagram".to_string(),
        )],
    };

    // A template learned in this datagram may resolve data buffered earlier.
    if matches!(version, Some("9") | Some("10")) && !cache.pending_is_empty() {
        out.extend(retry_pending(cache, opts.now_micros, flows_only));
    }
    out
}

/// Drain and decode every pending Data Set whose template the cache now knows.
/// Records still missing a template stay buffered (flushed at end of scan).
pub fn retry_pending(cache: &mut TemplateCache, now: i64, flows_only: bool) -> Vec<FlowRecord> {
    let mut out = Vec::new();
    for key in cache.pending_keys() {
        if cache.peek(&key).is_none() {
            continue;
        }
        let Some(tpl) = cache.use_template(&key, now) else {
            continue;
        };
        for rec in cache.take_pending(&key) {
            let version: &'static str = if rec.version == "10" { "10" } else { "9" };
            let ctx = Ctx {
                exporter: key.exporter.clone(),
                obs_domain: key.obs_domain,
                version,
                export_time: rec.export_time,
                sequence: rec.sequence,
                sys_uptime_ms: rec.sys_uptime_ms,
                template_id: key.template_id,
            };
            out.extend(decode_data_set(&tpl, &rec.bytes, &ctx, flows_only));
        }
    }
    out
}

/// End-of-scan flush: every still-pending Data Set is emitted as a
/// `missing-template` diagnostic (carrying only header-recoverable fields), never
/// dropped silently. Clears the pending buffer.
pub fn flush_pending(cache: &mut TemplateCache) -> Vec<FlowRecord> {
    let mut out = Vec::new();
    for (key, recs) in cache.drain_pending() {
        let TemplateKey {
            exporter,
            obs_domain,
            template_id,
        } = key;
        let version = if recs.first().map(|r| r.version.as_str()) == Some("10") {
            "10"
        } else {
            "9"
        };
        for rec in recs {
            out.push(FlowRecord::diagnostic(
                &exporter,
                version,
                obs_domain,
                rec.export_time,
                rec.sequence,
                format!("missing-template:{obs_domain}/{template_id}"),
            ));
        }
    }
    out
}
