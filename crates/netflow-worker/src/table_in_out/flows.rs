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
use vgi::{ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams};
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
            examples: vec![doc_example(self.name)],
            tags: tags_for(self.name),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        // sFlow carries no templates or observation domain and is self-contained
        // per datagram, so its input relation description must NOT imply the
        // template-cache / obs_domain semantics of v9/IPFIX (otherwise the docs
        // contradict the "stateless" claim — VGI180).
        let relation_doc = if self.with_obs_domain {
            "A relation carrying a `datagram` column of raw captured bytes (exporter datagrams or \
             UDP payloads carved out of pcap), and optionally an `exporter` column (cache scope / \
             source device id, read per row so template ids never collide across exporters), an \
             `obs_domain` column (override the header observation domain), and a `mode` column \
             ('auto' / 'flows-only' / 'all'). Feed datagrams in capture order so a Template Set is \
             seen before the Data Sets that reference it."
        } else {
            "A relation carrying a `datagram` column of raw captured sFlow v5 bytes (exporter \
             datagrams or UDP payloads carved out of pcap), and optionally an `exporter` column \
             used purely as a source-device label copied onto each output row. sFlow v5 is \
             self-contained per datagram — there is no template cache and no observation domain — \
             so datagrams may be decoded in any order and independently of one another."
        };
        vec![ArgSpec::column("relation", 0, "table", relation_doc)]
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

/// The declared `vgi.result_columns_schema` for the normalized flow output —
/// one `(name, DuckDB type, description)` per column, in the exact order and
/// with the exact canonical types `DESCRIBE netflow.main.flows(...)` reports
/// (the INET address columns surface as the physical DuckDB `INET` struct, not
/// as `INET`, because the logical type does not round-trip through Arrow). Kept
/// in lockstep with [`crate::arrow_map::flow_schema`].
const INET_STRUCT: &str = "STRUCT(ip_type UTINYINT, address HUGEINT, mask USMALLINT)";
fn flow_result_columns() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("exporter", "VARCHAR", "Cache key / source device (as supplied via the exporter column or derived)."),
        ("flow_version", "VARCHAR", "Wire format of the source datagram: '5', '9', '10' (IPFIX), or 'sflow5'."),
        ("obs_domain", "UINTEGER", "v9 source-id / IPFIX observation domain (the template-id namespace)."),
        ("template_id", "USMALLINT", "v9/IPFIX template id the record decoded against; NULL for v5 / sFlow."),
        ("export_time", "TIMESTAMP WITH TIME ZONE", "Datagram export time taken from the export header."),
        ("sequence", "UBIGINT", "Export sequence number (used for gap / loss detection)."),
        ("src_addr", INET_STRUCT, "Source IP; cast ::INET for `<<=` containment joins."),
        ("dst_addr", INET_STRUCT, "Destination IP; cast ::INET for `<<=` containment joins."),
        ("src_port", "USMALLINT", "Layer-4 source port."),
        ("dst_port", "USMALLINT", "Layer-4 destination port."),
        ("protocol", "UTINYINT", "IP protocol number (6 = TCP, 17 = UDP, ...)."),
        ("tcp_flags", "UTINYINT", "Cumulative TCP control flags observed for the flow."),
        ("bytes", "UBIGINT", "Octet count (for sFlow, scaled by the sampling rate)."),
        ("packets", "UBIGINT", "Packet count (for sFlow, the sampling rate)."),
        ("flow_start", "TIMESTAMP WITH TIME ZONE", "Flow start time, resolved to an absolute timestamp."),
        ("flow_end", "TIMESTAMP WITH TIME ZONE", "Flow end time, resolved to an absolute timestamp."),
        ("src_as", "UINTEGER", "Origin autonomous-system number (when the exporter reports it)."),
        ("dst_as", "UINTEGER", "Peer autonomous-system number (when the exporter reports it)."),
        ("input_snmp", "UINTEGER", "Ingress interface ifIndex."),
        ("output_snmp", "UINTEGER", "Egress interface ifIndex."),
        ("next_hop", INET_STRUCT, "BGP / IP next hop; cast ::INET to use it."),
        ("tos", "UTINYINT", "IP type-of-service / DSCP byte."),
        ("src_mask", "UTINYINT", "Source prefix length in bits (v5 / v9)."),
        ("dst_mask", "UTINYINT", "Destination prefix length in bits (v5 / v9)."),
        ("sampling_rate", "UINTEGER", "sFlow sampling N / IPFIX samplingInterval; NULL when none."),
        ("direction", "UTINYINT", "flowDirection (0 = ingress, 1 = egress) when present."),
        ("raw_fields", "MAP(VARCHAR, BLOB)", "Every Information Element not mapped to a named column, keyed by IE name -> raw bytes."),
        ("diagnostics", "VARCHAR", "NULL on a clean decode; else missing-template / truncated / decode-error / ..."),
    ]
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
             earlier datagrams. Pass a relation carrying a `datagram` column of captured bytes \
             (and optionally an `exporter` column so template ids do not collide across devices); \
             the runnable example shows the exact call shape. Feed datagrams in capture order.",
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
    tags.push(("vgi.category".into(), "decode".into()));
    // Structured result schema (VGI307/VGI321). All four decode functions share
    // the one normalized `flow_schema()` output, so they share this declaration.
    // Columns are listed in exactly the order (and with the DuckDB types) the
    // worker emits — note the INET columns surface as their physical struct and
    // `raw_fields` as MAP(VARCHAR, BLOB), matching what DESCRIBE reports (VGI910).
    tags.push((
        "vgi.result_columns_schema".into(),
        crate::meta::result_columns_schema_json(&flow_result_columns()),
    ));
    let (ex_desc, ex_sql) = executable_example(name);
    tags.push((
        "vgi.executable_examples".into(),
        crate::meta::executable_examples_json(&[(ex_desc, ex_sql.as_str())]),
    ));
    tags
}

/// A self-contained runnable example per function — decode an inline hex sample
/// datagram (no external files, no `LOAD inet`) so `vgi-lint --execute` can run
/// it directly against the attached worker.
fn executable_example(name: &str) -> (&'static str, String) {
    use crate::meta::{SAMPLE_IPFIX_HEX, SAMPLE_SFLOW_HEX, SAMPLE_V5_HEX, SAMPLE_V9_HEX};
    match name {
        "flows" => (
            "Auto-detect and decode a captured NetFlow v5 datagram (two records) to \
             normalized flow rows.",
            format!(
                "SELECT flow_version, dst_port, protocol, bytes, packets \
                 FROM netflow.main.flows((SELECT from_hex('{SAMPLE_V5_HEX}') AS datagram)) \
                 ORDER BY dst_port"
            ),
        ),
        "netflow_decode" => (
            "Decode a NetFlow v9 datagram that carries its template and one data record.",
            format!(
                "SELECT flow_version, dst_port, protocol, packets \
                 FROM netflow.main.netflow_decode((SELECT from_hex('{SAMPLE_V9_HEX}') AS datagram))"
            ),
        ),
        "ipfix_decode" => (
            "Decode an IPFIX (v10) datagram: a Template Set plus one fully-decodable IPv4/TCP \
             flow.",
            format!(
                "SELECT flow_version, dst_port, protocol, bytes, packets \
                 FROM netflow.main.ipfix_decode((SELECT from_hex('{SAMPLE_IPFIX_HEX}') AS datagram))"
            ),
        ),
        "sflow_decode" => (
            "Decode an sFlow v5 datagram (one flow sample + one counter sample).",
            format!(
                "SELECT flow_version, dst_port, protocol \
                 FROM netflow.main.sflow_decode((SELECT from_hex('{SAMPLE_SFLOW_HEX}') AS datagram)) \
                 WHERE dst_port IS NOT NULL"
            ),
        ),
        _ => (
            "Decode a captured NetFlow v5 datagram to normalized flow rows.",
            format!(
                "SELECT flow_version, dst_port \
                 FROM netflow.main.flows((SELECT from_hex('{SAMPLE_V5_HEX}') AS datagram))"
            ),
        ),
    }
}

/// A second, self-contained runnable example per function — it decodes an
/// inline hex sample datagram and demonstrates the per-row `exporter` column
/// (cache-scope id). Self-contained and INET-free so it runs as written in the
/// `vgi-lint --execute` sandbox; for the real-world `read_blob(...)` /
/// `::INET`-join pattern over a capture archive see the worker's `doc_md`.
fn doc_example(name: &str) -> FunctionExample {
    use crate::meta::{SAMPLE_IPFIX_HEX, SAMPLE_SFLOW_HEX, SAMPLE_V5_HEX, SAMPLE_V9_HEX};
    let (sql, description): (String, &str) = match name {
        "flows" => (
            format!(
                "SELECT exporter, count(*) AS flows, sum(bytes) AS total_bytes \
                 FROM netflow.main.flows((SELECT from_hex('{SAMPLE_V5_HEX}') AS datagram, \
                 'router-1' AS exporter)) GROUP BY exporter"
            ),
            "Decode a datagram with a per-row exporter id (cache scope) and aggregate the decoded \
             flows by exporter.",
        ),
        "netflow_decode" => (
            format!(
                "SELECT exporter, flow_version, src_port, dst_port, packets \
                 FROM netflow.main.netflow_decode((SELECT from_hex('{SAMPLE_V9_HEX}') AS datagram, \
                 'router-1' AS exporter))"
            ),
            "Decode a NetFlow v9 datagram, scoping the template cache to exporter 'router-1' so \
             template ids never collide across devices.",
        ),
        "ipfix_decode" => (
            format!(
                "SELECT flow_version, src_port, dst_port, bytes, packets \
                 FROM netflow.main.ipfix_decode((SELECT from_hex('{SAMPLE_IPFIX_HEX}') AS datagram))"
            ),
            "Decode an IPFIX datagram and read the mapped 5-tuple plus byte/packet counters.",
        ),
        "sflow_decode" => (
            format!(
                "SELECT flow_version, src_port, dst_port, protocol \
                 FROM netflow.main.sflow_decode((SELECT from_hex('{SAMPLE_SFLOW_HEX}') AS datagram)) \
                 WHERE dst_port IS NOT NULL"
            ),
            "Decode an sFlow v5 datagram; flow-sample rows carry the sampled 5-tuple (counter \
             samples have NULL ports).",
        ),
        _ => (
            format!(
                "SELECT flow_version, dst_port \
                 FROM netflow.main.flows((SELECT from_hex('{SAMPLE_V5_HEX}') AS datagram))"
            ),
            "Decode captured flow-export datagrams to normalized flow rows.",
        ),
    };
    FunctionExample {
        sql,
        description: description.to_string(),
        expected_output: None,
    }
}
