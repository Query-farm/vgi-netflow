//! `FlowDecode` — the shared table-in-out decoder backing `flows`,
//! `netflow_decode`, `ipfix_decode`, and `sflow_decode`.
//!
//! The input is a relation carrying a `datagram` BLOB column (and optional
//! `exporter` / `obs_domain` / `mode` columns, read per row). Each datagram
//! decodes to zero or more normalized flow rows. The
//! [`TemplateCache`](netflow_core::TemplateCache) is loaded from per-execution
//! storage at the start of every batch and stored back at the end, so a template
//! learned in batch 1 decodes data in batch N and the cache survives HTTP worker
//! rehydration. End-of-stream (`finish`) flushes still-buffered data as
//! `missing-template` diagnostics — never dropped.

use arrow_array::RecordBatch;
use netflow_core::{decode_datagram, flush_pending, DecodeOptions, Mode, Restrict};
use vgi::table_in_out::TableInOutFunction;
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{Result, RpcError};

use crate::arrow_map::{flow_schema, rows_to_batch};
use crate::scalar::blob_bytes;
use crate::state::{load_scan_cache, store_scan_cache};
use crate::table_in_out::{find_datagram_col, find_named_col, text_at, u32_at};

pub struct FlowDecode {
    name: &'static str,
    restrict: Restrict,
    /// `flows` is the only one honoring a `mode` column.
    with_mode: bool,
    /// `sflow_decode` is stateless and ignores an `obs_domain` column.
    with_obs_domain: bool,
}

impl FlowDecode {
    pub fn flows() -> Self {
        FlowDecode {
            name: "flows",
            restrict: Restrict::Any,
            with_mode: true,
            with_obs_domain: true,
        }
    }

    pub fn new(name: &'static str, restrict: Restrict) -> Self {
        FlowDecode {
            name,
            restrict,
            with_mode: false,
            with_obs_domain: !matches!(restrict, Restrict::SflowOnly),
        }
    }
}

/// Wall-clock now in microseconds (for template first/last-seen stamps).
fn now_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

impl TableInOutFunction for FlowDecode {
    fn name(&self) -> &str {
        self.name
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: describe(self.name).to_string(),
            tags: tags_for(self.name),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column(
            "relation",
            0,
            "table",
            "A relation carrying a `datagram` BLOB column (captured exporter datagrams or UDP \
             payloads carved out of pcap), and optionally an `exporter` VARCHAR column (cache \
             scope / source device id, read per row so template ids never collide across \
             exporters), an `obs_domain` integer column (override the header observation domain), \
             and a `mode` VARCHAR column ('auto' / 'flows-only' / 'all'). Feed datagrams in \
             capture order so a Template Set is seen before the Data Sets that reference it.",
        )]
    }

    fn on_bind(&self, params: &BindParams) -> Result<BindResponse> {
        let input = params.input_schema.clone().ok_or_else(|| {
            RpcError::value_error(format!("{}: requires an input relation", self.name))
        })?;
        // Validate the datagram column exists at bind time.
        find_datagram_col(&input)?;
        Ok(BindResponse {
            output_schema: flow_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<Vec<RecordBatch>> {
        let schema = batch.schema();
        let di = find_datagram_col(&schema)?;
        let exporter_col = find_named_col(&schema, "exporter");
        let obs_col = if self.with_obs_domain {
            find_named_col(&schema, "obs_domain")
        } else {
            None
        };
        let mode_col = if self.with_mode {
            find_named_col(&schema, "mode")
        } else {
            None
        };

        let datagram = batch.column(di);
        let mut cache = load_scan_cache(params);
        let now = now_micros();
        let mut rows = Vec::new();
        for row in 0..batch.num_rows() {
            let Some(bytes) = blob_bytes(datagram, row)? else {
                continue; // NULL datagram → no rows
            };
            let opts = DecodeOptions {
                exporter: exporter_col
                    .and_then(|i| text_at(batch.column(i), row))
                    .unwrap_or_default(),
                obs_domain_override: obs_col.and_then(|i| u32_at(batch.column(i), row)),
                mode: mode_col
                    .and_then(|i| text_at(batch.column(i), row))
                    .map(|s| Mode::parse(&s))
                    .unwrap_or(Mode::Auto),
                now_micros: now,
            };
            rows.extend(decode_datagram(bytes, &opts, &mut cache, self.restrict));
        }
        store_scan_cache(params, &cache);
        Ok(vec![rows_to_batch(&rows, &params.output_schema)?])
    }

    fn has_finish(&self) -> bool {
        true
    }

    fn finish(&self, params: &ProcessParams) -> Result<Vec<RecordBatch>> {
        let mut cache = load_scan_cache(params);
        let rows = flush_pending(&mut cache);
        store_scan_cache(params, &cache);
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![rows_to_batch(&rows, &params.output_schema)?])
    }
}

fn describe(name: &str) -> &'static str {
    match name {
        "flows" => "Decode captured flow-export datagrams (NetFlow v5/v9, IPFIX, sFlow v5) to normalized flow rows",
        "netflow_decode" => "Decode NetFlow v5 / v9 datagrams to normalized flow rows",
        "ipfix_decode" => "Decode IPFIX (v10) datagrams to normalized flow rows",
        "sflow_decode" => "Decode sFlow v5 datagrams to normalized flow rows",
        _ => "Decode flow-export datagrams",
    }
}

/// Per-function discovery metadata (title / doc_llm / doc_md / keywords) + a
/// result-columns table.
fn tags_for(name: &str) -> Vec<(String, String)> {
    let (title, llm, md, kw) = match name {
        "flows" => (
            "Unified Flow Decode (relation in)",
            "Auto-detect the version of each captured flow-export datagram (NetFlow v5/v9, IPFIX, \
             sFlow v5) and decode it to one normalized wide flow row per record: src/dst as INET, \
             ports, protocol, byte/packet counts, TCP flags, resolved flow start/end timestamps, \
             AS numbers, interfaces, next hop, ToS, sampling, plus a raw_fields MAP of every \
             unmapped Information Element. Threads a per-exporter, per-observation-domain template \
             cache across rows and scan batches so v9/IPFIX data decodes against templates seen in \
             earlier datagrams. Pass a relation with a `datagram` BLOB column (and optionally an \
             `exporter` column so template ids do not collide across devices): \
             FROM netflow.main.flows((FROM (SELECT content AS datagram, filename AS exporter FROM \
             read_blob('caps/*.dat')))). Feed datagrams in capture order.",
            "Decode any flow-export datagram to normalized flow rows (the wide schema). Pass a \
             relation with a `datagram` BLOB column (and optional `exporter` / `obs_domain` / \
             `mode`). Auto-detects v5/v9/IPFIX/sFlow and threads the template cache.",
            "netflow, ipfix, sflow, flow, flows, decode, network, security, observability, \
             template, datagram, normalize, relation, lateral",
        ),
        "netflow_decode" => (
            "NetFlow v5/v9 Decode (relation in)",
            "Decode NetFlow v5 (fixed) and NetFlow v9 (RFC 3954, template-based) datagrams from a \
             relation's `datagram` BLOB column to the normalized flow schema. v9 threads the \
             template cache; an IPFIX or sFlow datagram yields a decode-error diagnostic. Pass an \
             optional `exporter` column for per-device cache scoping.",
            "Decode NetFlow v5/v9 datagrams from a relation's `datagram` column to normalized \
             flow rows. v9 is template-stateful.",
            "netflow, v5, v9, rfc3954, decode, flow, template, network, relation",
        ),
        "ipfix_decode" => (
            "IPFIX Decode (relation in)",
            "Decode IPFIX (RFC 7011, version 10) datagrams from a relation's `datagram` BLOB column \
             to the normalized flow schema with full template, options-template, enterprise-IE \
             (private enterprise number) and variable-length IE handling. The headline \
             template-stateful decoder. A non-IPFIX datagram yields a decode-error diagnostic.",
            "Decode IPFIX (v10) datagrams from a relation's `datagram` column — templates, \
             enterprise + variable-length IEs.",
            "ipfix, rfc7011, decode, flow, template, enterprise, variable-length, network, relation",
        ),
        "sflow_decode" => (
            "sFlow v5 Decode (relation in)",
            "Decode sFlow v5 (sflow.org / InMon) packet-sampling datagrams from a relation's \
             `datagram` BLOB column to the normalized flow schema. Flow samples (sampled headers / \
             sampled IPv4/IPv6) yield 5-tuple rows with byte/packet counts scaled by the sampling \
             rate; counter samples yield rows with the counters in raw_fields. Stateless.",
            "Decode sFlow v5 datagrams from a relation's `datagram` column. Stateless; sampled \
             counts scaled by the sampling rate.",
            "sflow, sflow5, sampling, decode, flow, counters, network, inmon, relation",
        ),
        _ => ("Flow Decode", "Decode flow datagrams.", "Decode flow datagrams.", "flow, decode"),
    };
    let mut tags = crate::meta::object_tags(title, llm, md, kw);
    tags.push((
        "vgi.result_columns_md".into(),
        "| column | type | description |\n\
         |---|---|---|\n\
         | `exporter` | VARCHAR | Source device / cache scope. |\n\
         | `flow_version` | VARCHAR | '5' / '9' / '10' / 'sflow5'. |\n\
         | `src_addr` / `dst_addr` | INET | Endpoints (cast ::INET for `<<=`). |\n\
         | `src_port` / `dst_port` | USMALLINT | L4 ports. |\n\
         | `protocol` | UTINYINT | IP protocol number. |\n\
         | `bytes` / `packets` | UBIGINT | Counters. |\n\
         | `flow_start` / `flow_end` | TIMESTAMPTZ | Resolved flow times. |\n\
         | `raw_fields` | MAP(VARCHAR, BLOB) | Unmapped IEs. |\n\
         | `diagnostics` | VARCHAR | NULL on clean decode. |"
            .into(),
    ));
    tags
}
