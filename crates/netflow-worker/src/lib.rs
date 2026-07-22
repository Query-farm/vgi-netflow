//! The `netflow` VGI worker (library).
//!
//! Function registration and catalog metadata live here so both entrypoints
//! share them verbatim: `main.rs` (the native binary, stdio/HTTP transport) and
//! the `netflow-wasm` crate (the browser build, which serves the same `Worker`
//! over a SharedArrayBuffer byte channel instead).
//!
//! A standalone binary DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'vgi-netflow' AS netflow (TYPE vgi)`). It decodes captured
//! flow-export datagrams — NetFlow v5/v9, IPFIX, and sFlow v5 — from a BLOB
//! column into normalized flow rows, under the catalog `netflow`, schema `main`:
//!
//! ```sql
//! ATTACH 'netflow' (TYPE vgi, LOCATION './target/release/netflow-worker');
//! LOAD inet;
//! -- The decoders are table-in-out: pass a relation with a `datagram` BLOB
//! -- column (and optional per-row `exporter`), not a correlated LATERAL column.
//! SELECT src_addr::INET, dst_addr::INET, bytes
//! FROM netflow.main.flows((FROM (SELECT content AS datagram, filename AS exporter
//!                                 FROM read_blob('caps/*.dat'))))
//! WHERE diagnostics IS NULL;
//! ```
//!
//! All wire decoding + the serde template cache live in `netflow-core`; the
//! `scalar` / `table` / `table_in_out` modules are thin Arrow / VGI adapters.

mod arrow_map;
mod meta;
mod scalar;
mod state;
mod table;
mod table_in_out;

use vgi::catalog::{CatSchema, CatView, CatalogModel};
use vgi::Worker;

/// Catalog + schema metadata surfaced to DuckDB and the `vgi-lint` linter.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Decode captured NetFlow v5/v9, IPFIX, and sFlow v5 flow-export datagrams into \
             normalized flow rows — template-stateful, in-engine, no collector stack."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "NetFlow / IPFIX / sFlow Flow Decoder".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                crate::meta::keywords_json(
                    "netflow, ipfix, sflow, flow, flow records, netflow v5, netflow v9, ipfix v10, \
                     rfc 3954, rfc 7011, sflow v5, template, observation domain, network, security, \
                     observability, ndr, netsecops, flow lake, geoip, asn, threat intel, decode, \
                     datagram, information element",
                ),
            ),
            (
                "vgi.doc_llm".to_string(),
                "Decode raw network flow-export datagrams (NetFlow v5/v9, IPFIX, sFlow v5) from a \
                 `BLOB` column into typed, normalized flow rows: src/dst as INET, ports, protocol, \
                 byte/packet counts, TCP flags, resolved flow start/end timestamps, AS numbers, \
                 interfaces, next hop, ToS, sampling, plus a raw_fields `MAP` of every unmapped \
                 Information Element. The hard part — and the value — is template-stateful v9/IPFIX \
                 decode: a Data Set carries only a template id, and the matching Template Set may \
                 have arrived in a much earlier datagram, so the worker maintains a per-exporter, \
                 per-observation-domain template cache as externalized VGI scan state that survives \
                 batch boundaries and HTTP rehydration. Use it for SQL forensics over captured flow \
                 archives — join flows to geoip/ASN, threat-intel, and asset inventory, at scale, \
                 with no collector. Reach for it whenever you have raw exporter datagrams (or UDP \
                 payloads carved out of pcap) in a `BLOB` column and want queryable, normalized flow \
                 rows without standing up a collector stack."
                    .to_string(),
            ),
            (
                "vgi.doc_md".to_string(),
                "# netflow\n\nDecode captured **flow-export datagrams** — NetFlow **v5** (fixed), \
                 NetFlow **v9** (RFC 3954, template-based), **IPFIX** (RFC 7011, template-based, \
                 enterprise + variable-length IEs), and **sFlow v5** (packet sampling) — from a \
                 `BLOB` column of captured exporter datagrams (or UDP payloads carved out of pcap) \
                 into one **normalized** wide flow row per record.\n\nThe moat is correct \
                 **template-stateful** v9/IPFIX decode at lake scale: a Data Set carries no field \
                 descriptors, only a template id, and the Template Set that defines the layout \
                 arrives out-of-band — so the worker keeps a **template cache keyed by (exporter, \
                 observation domain, template id)** as serializable VGI scan state that survives \
                 scan-batch boundaries and HTTP worker rehydration (a template seen in datagram 1 \
                 decodes data in datagram 10,000). A data record that arrives before its template \
                 is buffered and retried, or emitted with `diagnostics = 'missing-template:…'` — \
                 never dropped.\n\nAddresses are emitted as DuckDB **INET** (`LOAD inet;`), so \
                 `src_addr::INET <<= '10.0.0.0/8'::INET` containment joins to geoip / threat-intel \
                 work directly. The worker decodes captured bytes only — it opens no UDP socket and \
                 makes no egress (collector mode is roadmap)."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&agent_test_tasks()),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-netflow/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-netflow/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-netflow".to_string()),
        // The worker's own build version (the crate's Cargo version), surfaced on
        // the catalog so an agent reads it from vgi_catalogs() without spending a
        // query — replaces the removed parameterless netflow_version() scalar.
        implementation_version: Some(netflow_core::version().to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "NetFlow / IPFIX / sFlow flow-export decode functions and template-cache \
                 introspection."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "NetFlow — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    crate::meta::keywords_json(
                        "flows, netflow_decode, ipfix_decode, sflow_decode, templates, \
                         flow_version, header, well_formed, netflow, ipfix, sflow, template",
                    ),
                ),
                ("domain".to_string(), "network-security".to_string()),
                ("category".to_string(), "flow-decode".to_string()),
                ("topic".to_string(), "netflow-ipfix-sflow".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "The single schema for the netflow worker. It groups flow-export decoders \
                     (turn a captured datagram column into normalized flow rows), template-cache \
                     introspection, and lightweight probe/validation scalars. The decoders thread \
                     a per-exporter, per-observation-domain template cache as externalized scan \
                     state so template-based v9/IPFIX data decodes against templates seen in \
                     earlier datagrams. Start from `supported_formats` to see which formats decode \
                     and which function handles each, then call that decoder."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "## The `netflow` schema\n\n\
                     Everything the worker exposes lives in this one schema — qualify every call \
                     as `netflow.main.<name>(...)`. Its job is to turn a column of raw captured \
                     flow-export datagrams into normalized, typed flow rows, entirely in-engine \
                     and with no collector stack.\n\n\
                     The capabilities fall into a few groups:\n\n\
                     - **Decoders** take a relation with a `datagram` `BLOB` column and return the \
                     wide normalized flow schema, auto-detecting NetFlow v5/v9, IPFIX, and sFlow \
                     v5 (or restricting to a single family).\n\
                     - **Template-cache introspection** projects the per-exporter, \
                     per-observation-domain templates the stateful v9/IPFIX decoders have learned \
                     so far in the session.\n\
                     - **Probe / validation scalars** identify or structurally validate a single \
                     datagram cheaply, without running a full decode.\n\n\
                     A small **reference** table lists the flow-export formats the worker \
                     understands and which decoder handles each, so an agent can orient before \
                     calling anything. Browse that first, then reach for the matching decoder."
                        .to_string(),
                ),
                (
                    "vgi.categories".to_string(),
                    "[{\"name\":\"decode\",\"description\":\"Table functions that decode captured \
                     flow-export datagrams (NetFlow v5/v9, IPFIX, sFlow v5) into normalized flow \
                     rows.\"},{\"name\":\"introspection\",\"description\":\"Inspect the learned \
                     per-exporter, per-observation-domain template cache that stateful v9/IPFIX \
                     decode depends on.\"},{\"name\":\"probe\",\"description\":\"Lightweight \
                     scalars that identify or validate a datagram without a full decode.\"},\
                     {\"name\":\"reference\",\"description\":\"Curated lookup tables an agent can \
                     browse to orient — e.g. the flow-export formats this worker decodes and the \
                     function that handles each.\"}]"
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    crate::meta::example_queries_json(&[
                        (
                            "Route a mixed column of captured datagrams: label each by its \
                             flow-export version before decoding.",
                            "SELECT netflow.main.flow_version(content) AS version, count(*) \
                             FROM read_blob('caps/*.dat') GROUP BY version",
                        ),
                        (
                            "Decode a capture archive to normalized flow rows and join source \
                             addresses to a threat-intel prefix list via INET containment.",
                            "SELECT f.src_addr::INET AS src, f.dst_port, f.bytes \
                             FROM netflow.main.flows((FROM (SELECT content AS datagram, \
                             filename AS exporter FROM read_blob('caps/*.dat')))) f \
                             WHERE f.diagnostics IS NULL AND f.src_addr::INET <<= '10.0.0.0/8'::INET",
                        ),
                        (
                            "After decoding, inspect which v9/IPFIX templates the worker learned \
                             in this session, per exporter.",
                            "SELECT exporter, template_id, kind, field_count \
                             FROM netflow.main.templates() ORDER BY exporter, template_id",
                        ),
                    ]),
                ),
            ],
            views: vec![formats_view()],
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

/// A browsable, VALUES-backed reference view: the flow-export formats this worker
/// decodes and which decoder handles each. Gives an agent a real table to list
/// and query before it has to guess a decode function's arguments (VGI146), and —
/// being pure `VALUES` — it scans with no network, credentials, or worker
/// round-trip (VGI903/VGI911).
fn formats_view() -> CatView {
    CatView {
        name: "supported_formats".to_string(),
        definition: "SELECT format, version, rfc, template_stateful, decoder, flow_version, notes \
             FROM (VALUES \
             ('NetFlow', '5', 'Cisco NetFlow v5', false, 'netflow_decode', '5', \
              'Fixed 48-byte records; no templates.'), \
             ('NetFlow', '9', 'RFC 3954', true, 'netflow_decode', '9', \
              'Template-based; the Template Set may arrive in an earlier datagram.'), \
             ('IPFIX', '10', 'RFC 7011', true, 'ipfix_decode', '10', \
              'Template-based, with enterprise and variable-length Information Elements.'), \
             ('sFlow', '5', 'sFlow.org v5', false, 'sflow_decode', 'sflow5', \
              'Packet sampling; byte/packet counts scaled by the sampling rate.')) \
             AS t(format, version, rfc, template_stateful, decoder, flow_version, notes)"
            .to_string(),
        comment: Some(
            "One row per flow-export format the worker decodes, with its version, defining spec, \
             whether decoding is template-stateful, and the decode function that handles it."
                .to_string(),
        ),
        tags: {
            let mut tags = crate::meta::object_tags(
                "Supported Flow-Export Formats",
                "A curated reference listing every flow-export format this worker can decode — \
                 NetFlow v5, NetFlow v9, IPFIX (v10), and sFlow v5 — with, for each, its wire \
                 version, the RFC or vendor spec that defines it, whether decoding it is \
                 template-stateful (needs a previously-seen template, as v9 and IPFIX do), the \
                 `flow_version` value it produces in decoded rows, and which `netflow.main` \
                 decode function handles it. An agent should browse this table first to learn \
                 what is decodable and which function to call, rather than guessing a decoder's \
                 arguments up front. It is a static VALUES-backed view, so it always returns \
                 these four rows with no input.",
                "Reference table of the flow-export formats the worker decodes (NetFlow v5/v9, \
                 IPFIX, sFlow v5), each with its version, defining spec, template-stateful flag, \
                 produced `flow_version` value, and handling decode function. Browse it to orient \
                 before calling a decoder.",
                "supported formats, formats, reference, netflow, ipfix, sflow, versions, decoders, \
                 capabilities, catalog, template-stateful",
            );
            tags.push(("vgi.category".into(), "reference".into()));
            tags.push(("domain".into(), "network-security".into()));
            tags.push(("topic".into(), "netflow-ipfix-sflow".into()));
            tags.push((
                "vgi.example_queries".into(),
                crate::meta::example_queries_json(&[
                    (
                        "List the template-stateful formats (the ones whose decode needs a learned \
                         template) and which function decodes each.",
                        "SELECT format, version, decoder \
                         FROM netflow.main.supported_formats \
                         WHERE template_stateful \
                         ORDER BY version",
                    ),
                    (
                        "Look up which decode function handles IPFIX and the flow_version value it \
                         emits.",
                        "SELECT decoder, flow_version, rfc \
                         FROM netflow.main.supported_formats \
                         WHERE format = 'IPFIX'",
                    ),
                ]),
            ));
            tags
        },
        column_comments: vec![
            (
                "format".to_string(),
                "Flow-export protocol family: 'NetFlow', 'IPFIX', or 'sFlow'.".to_string(),
            ),
            (
                "version".to_string(),
                "Protocol version as it appears on the wire (e.g. '5', '9', '10').".to_string(),
            ),
            (
                "rfc".to_string(),
                "The RFC or vendor specification that defines the format.".to_string(),
            ),
            (
                "template_stateful".to_string(),
                "TRUE when decoding needs a previously-seen template (NetFlow v9, IPFIX); FALSE \
                 for self-contained formats (NetFlow v5, sFlow)."
                    .to_string(),
            ),
            (
                "decoder".to_string(),
                "The netflow.main table function that decodes this format (the unified `flows` \
                 handles all of them)."
                    .to_string(),
            ),
            (
                "flow_version".to_string(),
                "The value this format produces in the decoded rows' `flow_version` column."
                    .to_string(),
            ),
            (
                "notes".to_string(),
                "One-line summary of the format's decoding characteristics.".to_string(),
            ),
        ],
    }
}

/// The catalog-level agent-suitability suite (`vgi.agent_test_tasks`), graded by
/// `vgi-lint simulate` / VGI920. Every object in the catalog is exercised by at
/// least one task (VGI520). Each task hands the analyst a self-contained input
/// (an inline hex datagram or a literal blob) and asks for a small deterministic
/// result, so an honest solution grades cleanly against the hidden reference.
fn agent_test_tasks() -> Vec<crate::meta::AgentTask> {
    use crate::meta::{
        AgentTask, SAMPLE_IPFIX_HEX, SAMPLE_SFLOW_HEX, SAMPLE_V5_HEX, SAMPLE_V9_HEX,
    };
    vec![
        AgentTask {
            name: "probe_unknown",
            prompt: "I have a one-byte blob that is not a flow datagram. Probe its flow-export \
                     version; it should come back NULL. Return a single column named v."
                .to_string(),
            reference_sql: vec!["SELECT netflow.main.flow_version('\\x00'::BLOB) AS v".to_string()],
            ignore_column_names: false,
            unordered: false,
        },
        AgentTask {
            name: "validate_garbage",
            prompt: "Classify the garbage two-byte blob 0xDEAD with the validator and return \
                     just the failure kind as a single column named kind."
                .to_string(),
            reference_sql: vec![
                "SELECT netflow.main.well_formed('\\xde\\xad'::BLOB).kind AS kind".to_string(),
            ],
            ignore_column_names: false,
            unordered: false,
        },
        AgentTask {
            name: "count_v5_flows",
            prompt: format!(
                "I captured this NetFlow v5 export datagram as a hex string: {SAMPLE_V5_HEX}. \
                 Decode it with the unified flow decoder and tell me how many normalized flow \
                 rows it yields. Return one row, one column named flow_count."
            ),
            reference_sql: vec![format!(
                "SELECT count(*) AS flow_count \
                 FROM netflow.main.flows((SELECT from_hex('{SAMPLE_V5_HEX}') AS datagram))"
            )],
            ignore_column_names: true,
            unordered: false,
        },
        AgentTask {
            name: "decode_v9_dst_port",
            prompt: format!(
                "This is a NetFlow v9 export datagram in hex (it carries its template and one \
                 data record): {SAMPLE_V9_HEX}. Decode it with the NetFlow-specific decoder and \
                 return the layer-4 destination port of the single decoded flow. One row, one \
                 column named dst_port."
            ),
            reference_sql: vec![format!(
                "SELECT dst_port \
                 FROM netflow.main.netflow_decode((SELECT from_hex('{SAMPLE_V9_HEX}') AS datagram))"
            )],
            ignore_column_names: true,
            unordered: false,
        },
        AgentTask {
            name: "decode_ipfix_protocol",
            prompt: format!(
                "Decode this IPFIX (version 10) datagram given as hex: {SAMPLE_IPFIX_HEX}. Return \
                 the IP protocol number of the decoded flow. One row, one column named protocol."
            ),
            reference_sql: vec![format!(
                "SELECT protocol \
                 FROM netflow.main.ipfix_decode((SELECT from_hex('{SAMPLE_IPFIX_HEX}') AS datagram))"
            )],
            ignore_column_names: true,
            unordered: false,
        },
        AgentTask {
            name: "count_sflow_samples",
            prompt: format!(
                "Decode this sFlow v5 datagram given as hex: {SAMPLE_SFLOW_HEX}. Count how many \
                 flow-sample rows it produces — that is, decoded rows that carry a non-NULL \
                 destination port (counter samples have no ports). One row, one column named \
                 flow_samples."
            ),
            reference_sql: vec![format!(
                "SELECT count(*) AS flow_samples \
                 FROM netflow.main.sflow_decode((SELECT from_hex('{SAMPLE_SFLOW_HEX}') AS datagram)) \
                 WHERE dst_port IS NOT NULL"
            )],
            ignore_column_names: true,
            unordered: false,
        },
        AgentTask {
            name: "read_export_header",
            prompt: format!(
                "Without fully decoding its records, read just the export header of this NetFlow \
                 v5 datagram given as hex: {SAMPLE_V5_HEX}. Return its protocol version and its \
                 record count, in that order — one row, a `version` column then a `records` \
                 column."
            ),
            reference_sql: vec![format!(
                "SELECT netflow.main.header(from_hex('{SAMPLE_V5_HEX}')::BLOB)['version'] AS version, \
                 netflow.main.header(from_hex('{SAMPLE_V5_HEX}')::BLOB)['count'] AS records"
            )],
            ignore_column_names: true,
            unordered: false,
        },
        AgentTask {
            name: "inspect_learned_templates",
            prompt: format!(
                "Two steps, in one session. First decode this IPFIX datagram (hex) scoping the \
                 template cache to the exporter id 'sim-tmpl-probe': {SAMPLE_IPFIX_HEX}. Then \
                 inspect the worker's template cache, filtered to that same exporter, and tell me \
                 how many templates it learned. Your final answer is the count — one row, one \
                 column named n."
            ),
            reference_sql: vec![
                format!(
                    "SELECT count(*) FROM netflow.main.ipfix_decode((SELECT \
                     from_hex('{SAMPLE_IPFIX_HEX}') AS datagram, 'sim-tmpl-probe' AS exporter))"
                ),
                "SELECT count(*) AS n FROM netflow.main.templates(exporter => 'sim-tmpl-probe')"
                    .to_string(),
            ],
            ignore_column_names: true,
            unordered: false,
        },
        AgentTask {
            name: "browse_stateful_formats",
            prompt: "Using only the worker's own reference table of supported formats, list the \
                     decode functions for the flow-export formats whose decoding is \
                     template-stateful (needs a previously-seen template). Return one `decoder` \
                     column, ordered alphabetically."
                .to_string(),
            reference_sql: vec![
                "SELECT decoder FROM netflow.main.supported_formats \
                 WHERE template_stateful ORDER BY decoder"
                    .to_string(),
            ],
            ignore_column_names: true,
            unordered: false,
        },
    ]
}

/// The catalog name DuckDB sees in `ATTACH 'netflow' (TYPE vgi, …)`. Defaults to
/// `netflow`, but honors an explicit override so a test harness can rename it.
/// Also exports the variable so downstream SDK code observes the same default.
pub fn catalog_name() -> String {
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "netflow");
    }
    std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "netflow".to_string())
}

/// Build a fully-registered worker: every scalar, table, and table-in-out
/// function plus the catalog metadata. Callers choose the transport — `run()`
/// natively, `serve_reader_writer()` in the browser.
pub fn build_worker() -> Worker {
    let name = catalog_name();
    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    table_in_out::register(&mut worker);
    worker.set_catalog(catalog_metadata(&name));
    worker
}
