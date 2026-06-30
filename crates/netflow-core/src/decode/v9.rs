//! NetFlow v9 (RFC 3954) — 20-byte header + a sequence of FlowSets:
//! id 0 = Template, id 1 = Options Template, id ≥ 256 = Data (keyed by template
//! id). Template-stateful: data is sliced against the cached layout.

use crate::buf::Cursor;
use crate::cache::{
    FieldSpec, PendingRecord, TemplateCache, TemplateEntry, TemplateKey, TemplateKind,
};
use crate::decode::header::parse_header;
use crate::decode::record::{decode_data_set, field_spec, Ctx};
use crate::normalize::FlowRecord;

/// Sentinel "enterprise number" used to tag v9 Options scope fields so they are
/// never mistaken for a same-id IANA Information Element during normalization.
pub const SCOPE_PEN: u32 = 0xFFFF_FFFF;

struct FlowSet<'a> {
    id: u16,
    body: &'a [u8],
}

/// Decode a NetFlow v9 datagram. Upserts templates into `cache`, decodes data
/// records against cached layouts, and buffers data that precedes its template.
pub fn decode(
    data: &[u8],
    exporter: &str,
    obs_override: Option<u32>,
    cache: &mut TemplateCache,
    now: i64,
    mode_flows_only: bool,
) -> Vec<FlowRecord> {
    let Some(hdr) = parse_header(data) else {
        return vec![FlowRecord::diagnostic(
            exporter,
            "9",
            0,
            None,
            None,
            "decode-error:bad-v9-header".to_string(),
        )];
    };
    let obs_domain = obs_override.unwrap_or(hdr.obs_domain.unwrap_or(0));
    let ctx_base = Ctx {
        exporter: exporter.to_string(),
        obs_domain,
        version: "9",
        export_time: hdr.export_time,
        sequence: hdr.sequence,
        sys_uptime_ms: hdr.sys_uptime.map(|u| u as u64),
        template_id: 0,
    };

    let flowsets = match split_flowsets(&data[20.min(data.len())..]) {
        Ok(fs) => fs,
        Err(diag) => {
            return vec![FlowRecord::diagnostic(
                exporter,
                "9",
                obs_domain,
                hdr.export_time,
                hdr.sequence,
                diag,
            )]
        }
    };

    // Pass 1: learn every template in this datagram (so data later in the SAME
    // datagram resolves even if its template followed it).
    for fs in &flowsets {
        match fs.id {
            0 => parse_templates(fs.body, exporter, obs_domain, now, cache),
            1 => parse_options_templates(fs.body, exporter, obs_domain, now, cache),
            _ => {}
        }
    }

    // Pass 2: decode data sets.
    let mut out = Vec::new();
    for fs in &flowsets {
        if fs.id < 256 {
            continue;
        }
        let key = TemplateKey {
            exporter: exporter.to_string(),
            obs_domain,
            template_id: fs.id,
        };
        if let Some(tpl) = cache.use_template(&key, now) {
            let mut ctx = ctx_base.clone();
            ctx.template_id = fs.id;
            out.extend(decode_data_set(&tpl, fs.body, &ctx, mode_flows_only));
        } else {
            // Template not yet seen → buffer for cross-datagram retry, or emit a
            // missing-template diagnostic immediately if the pending buffer is full.
            let rec = PendingRecord {
                export_time: hdr.export_time,
                sequence: hdr.sequence,
                version: "9".into(),
                sys_uptime_ms: hdr.sys_uptime.map(|u| u as u64),
                bytes: fs.body.to_vec(),
            };
            if !cache.push_pending(key, rec) {
                out.push(FlowRecord::diagnostic(
                    exporter,
                    "9",
                    obs_domain,
                    hdr.export_time,
                    hdr.sequence,
                    format!("missing-template:{obs_domain}/{}", fs.id),
                ));
            }
        }
    }
    out
}

/// Split a FlowSet region into `{id, body}` entries, validating each length
/// against the remaining buffer (a hostile length never over-reads).
fn split_flowsets(mut region: &[u8]) -> Result<Vec<FlowSet<'_>>, String> {
    let mut out = Vec::new();
    while region.len() >= 4 {
        let id = u16::from_be_bytes([region[0], region[1]]);
        let length = u16::from_be_bytes([region[2], region[3]]) as usize;
        if length < 4 {
            return Err("set-length-overrun".to_string());
        }
        if length > region.len() {
            return Err("set-length-overrun".to_string());
        }
        out.push(FlowSet {
            id,
            body: &region[4..length],
        });
        region = &region[length..];
    }
    Ok(out)
}

/// Parse a Template FlowSet body (one or more templates) and upsert each.
fn parse_templates(
    body: &[u8],
    exporter: &str,
    obs_domain: u32,
    now: i64,
    cache: &mut TemplateCache,
) {
    let mut c = Cursor::new(body);
    while c.remaining() >= 4 {
        let Some(template_id) = c.u16() else { break };
        let Some(field_count) = c.u16() else { break };
        let mut fields = Vec::with_capacity(field_count as usize);
        let mut ok = true;
        for _ in 0..field_count {
            let (Some(ty), Some(len)) = (c.u16(), c.u16()) else {
                ok = false;
                break;
            };
            fields.push(field_spec(0, ty, len));
        }
        if !ok || template_id == 0 {
            break;
        }
        cache.upsert(
            TemplateKey {
                exporter: exporter.to_string(),
                obs_domain,
                template_id,
            },
            TemplateEntry {
                kind: TemplateKind::Data,
                fields,
                scope_field_count: 0,
                first_seen: now,
                last_seen: now,
                use_count: 0,
            },
        );
    }
}

/// Parse an Options Template FlowSet body (RFC 3954 §6.2).
fn parse_options_templates(
    body: &[u8],
    exporter: &str,
    obs_domain: u32,
    now: i64,
    cache: &mut TemplateCache,
) {
    let mut c = Cursor::new(body);
    while c.remaining() >= 6 {
        let Some(template_id) = c.u16() else { break };
        let Some(scope_len) = c.u16() else { break };
        let Some(option_len) = c.u16() else { break };
        let scope_count = (scope_len / 4) as usize;
        let option_count = (option_len / 4) as usize;
        let mut fields = Vec::with_capacity(scope_count + option_count);
        let mut ok = true;
        for _ in 0..scope_count {
            let (Some(ty), Some(len)) = (c.u16(), c.u16()) else {
                ok = false;
                break;
            };
            fields.push(FieldSpec {
                ie_id: ty,
                enterprise_number: SCOPE_PEN,
                length: len,
                name: format!("scope_{}", scope_name(ty)),
                ie_type: "octetArray".to_string(),
            });
        }
        if ok {
            for _ in 0..option_count {
                let (Some(ty), Some(len)) = (c.u16(), c.u16()) else {
                    ok = false;
                    break;
                };
                fields.push(field_spec(0, ty, len));
            }
        }
        if !ok || template_id == 0 {
            break;
        }
        cache.upsert(
            TemplateKey {
                exporter: exporter.to_string(),
                obs_domain,
                template_id,
            },
            TemplateEntry {
                kind: TemplateKind::Options,
                fields,
                scope_field_count: scope_count as u16,
                first_seen: now,
                last_seen: now,
                use_count: 0,
            },
        );
        // Options Template FlowSets are commonly padded; stop on an all-zero tail.
        if c.peek(2) == Some(&[0, 0]) {
            break;
        }
    }
}

fn scope_name(ty: u16) -> &'static str {
    match ty {
        1 => "system",
        2 => "interface",
        3 => "linecard",
        4 => "cache",
        5 => "template",
        _ => "other",
    }
}
