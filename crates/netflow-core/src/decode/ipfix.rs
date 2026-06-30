//! IPFIX (RFC 7011, version 10) — 16-byte header + a sequence of Sets:
//! id 2 = Template, id 3 = Options Template, id ≥ 256 = Data. Adds
//! variable-length IEs (`0xFFFF` marker) and enterprise IEs (high bit of the IE
//! id set → a 4-byte Private Enterprise Number follows). The headline decoder.

use crate::buf::Cursor;
use crate::cache::{PendingRecord, TemplateCache, TemplateEntry, TemplateKey, TemplateKind};
use crate::decode::header::parse_header;
use crate::decode::record::{decode_data_set, field_spec, Ctx};
use crate::normalize::FlowRecord;

struct Set<'a> {
    id: u16,
    body: &'a [u8],
}

/// Decode an IPFIX datagram. Upserts templates/options templates into `cache`,
/// decodes data sets against cached layouts, and buffers data preceding its
/// template for cross-batch retry.
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
            "10",
            0,
            None,
            None,
            "decode-error:bad-ipfix-header".to_string(),
        )];
    };
    let obs_domain = obs_override.unwrap_or(hdr.obs_domain.unwrap_or(0));
    let ctx_base = Ctx {
        exporter: exporter.to_string(),
        obs_domain,
        version: "10",
        export_time: hdr.export_time,
        sequence: hdr.sequence,
        sys_uptime_ms: None, // IPFIX uses absolute flow timestamps
        template_id: 0,
    };

    let sets = match split_sets(&data[16.min(data.len())..]) {
        Ok(s) => s,
        Err(diag) => {
            return vec![FlowRecord::diagnostic(
                exporter,
                "10",
                obs_domain,
                hdr.export_time,
                hdr.sequence,
                diag,
            )]
        }
    };

    // Pass 1: learn templates.
    for s in &sets {
        match s.id {
            2 => parse_templates(s.body, exporter, obs_domain, now, false, cache),
            3 => parse_templates(s.body, exporter, obs_domain, now, true, cache),
            _ => {}
        }
    }

    // Pass 2: decode data sets.
    let mut out = Vec::new();
    for s in &sets {
        if s.id < 256 {
            continue;
        }
        let key = TemplateKey {
            exporter: exporter.to_string(),
            obs_domain,
            template_id: s.id,
        };
        if let Some(tpl) = cache.use_template(&key, now) {
            let mut ctx = ctx_base.clone();
            ctx.template_id = s.id;
            out.extend(decode_data_set(&tpl, s.body, &ctx, mode_flows_only));
        } else {
            let rec = PendingRecord {
                export_time: hdr.export_time,
                sequence: hdr.sequence,
                version: "10".into(),
                sys_uptime_ms: None,
                bytes: s.body.to_vec(),
            };
            if !cache.push_pending(key, rec) {
                out.push(FlowRecord::diagnostic(
                    exporter,
                    "10",
                    obs_domain,
                    hdr.export_time,
                    hdr.sequence,
                    format!("missing-template:{obs_domain}/{}", s.id),
                ));
            }
        }
    }
    out
}

/// Split a Set region into `{id, body}`, validating each declared length against
/// the remaining buffer (bounded allocation: a 0xFFFF / 4 GB lie is rejected as
/// `bad-ipfix-set`, never allocated).
fn split_sets(mut region: &[u8]) -> Result<Vec<Set<'_>>, String> {
    let mut out = Vec::new();
    while region.len() >= 4 {
        let id = u16::from_be_bytes([region[0], region[1]]);
        let length = u16::from_be_bytes([region[2], region[3]]) as usize;
        if length < 4 || length > region.len() {
            return Err("bad-ipfix-set".to_string());
        }
        out.push(Set {
            id,
            body: &region[4..length],
        });
        region = &region[length..];
    }
    Ok(out)
}

/// Parse a (possibly Options) Template Set body, upserting each template.
fn parse_templates(
    body: &[u8],
    exporter: &str,
    obs_domain: u32,
    now: i64,
    options: bool,
    cache: &mut TemplateCache,
) {
    let mut c = Cursor::new(body);
    while c.remaining() >= 4 {
        let Some(template_id) = c.u16() else { break };
        let Some(field_count) = c.u16() else { break };
        if template_id == 0 || field_count == 0 {
            // Withdrawal templates (field_count == 0) — skip; padding tail.
            break;
        }
        let scope_field_count = if options {
            match c.u16() {
                Some(v) => v,
                None => break,
            }
        } else {
            0
        };
        let mut fields = Vec::with_capacity(field_count as usize);
        let mut ok = true;
        for _ in 0..field_count {
            let Some(raw_id) = c.u16() else {
                ok = false;
                break;
            };
            let Some(length) = c.u16() else {
                ok = false;
                break;
            };
            let (enterprise_number, ie_id) = if raw_id & 0x8000 != 0 {
                match c.u32() {
                    Some(pen) => (pen, raw_id & 0x7fff),
                    None => {
                        ok = false;
                        break;
                    }
                }
            } else {
                (0, raw_id)
            };
            fields.push(field_spec(enterprise_number, ie_id, length));
        }
        if !ok {
            break;
        }
        cache.upsert(
            TemplateKey {
                exporter: exporter.to_string(),
                obs_domain,
                template_id,
            },
            TemplateEntry {
                kind: if options {
                    TemplateKind::Options
                } else {
                    TemplateKind::Data
                },
                fields,
                scope_field_count,
                first_seen: now,
                last_seen: now,
                use_count: 0,
            },
        );
        // Stop on an all-zero padding tail.
        if c.peek(2) == Some(&[0, 0]) {
            break;
        }
    }
}
