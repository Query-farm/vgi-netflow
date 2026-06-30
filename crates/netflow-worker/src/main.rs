//! The `netflow` VGI worker.
//!
//! A standalone binary DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'vgi-netflow' AS netflow (TYPE vgi)`). It decodes captured
//! flow-export datagrams — NetFlow v5/v9, IPFIX, and sFlow v5 — from a BLOB
//! column into normalized flow rows, under the catalog `netflow`, schema `main`:
//!
//! ```sql
//! ATTACH 'netflow' (TYPE vgi, LOCATION './target/release/netflow-worker');
//! LOAD inet;
//! SELECT f.src_addr, f.dst_addr, f.bytes
//! FROM read_blob('caps/*.dat') AS d,
//!      LATERAL netflow.main.flows(d.content, exporter := 'r1') AS f
//! WHERE f.diagnostics IS NULL;
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

use vgi::catalog::{CatSchema, CatalogModel};
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
                 BLOB column into typed, normalized flow rows: src/dst as INET, ports, protocol, \
                 byte/packet counts, TCP flags, resolved flow start/end timestamps, AS numbers, \
                 interfaces, next hop, ToS, sampling, plus a raw_fields MAP of every unmapped \
                 Information Element. The hard part — and the value — is template-stateful v9/IPFIX \
                 decode: a Data Set carries only a template id, and the matching Template Set may \
                 have arrived in a much earlier datagram, so the worker maintains a per-exporter, \
                 per-observation-domain template cache as externalized VGI scan state that survives \
                 batch boundaries and HTTP rehydration. Use it for SQL forensics over captured flow \
                 archives — join flows to geoip/ASN, threat-intel, and asset inventory, at scale, \
                 with no collector. Functions: flows (auto-detect, unified), netflow_decode, \
                 ipfix_decode, sflow_decode, templates (cache introspection), and the scalars \
                 flow_version, header, well_formed, netflow_version."
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
                 never dropped.\n\n**Table functions:** `flows` (auto-detect any version, unified \
                 entry point), `netflow_decode` (v5/v9), `ipfix_decode` (the headline IPFIX \
                 decoder), `sflow_decode` (stateless), and `templates` (introspect the learned \
                 template cache).\n\n**Scalars:** `flow_version`, `header`, `well_formed`, \
                 `netflow_version`.\n\nAddresses are emitted as DuckDB **INET** (`LOAD inet;`), so \
                 `src_addr::INET <<= '10.0.0.0/8'::INET` containment joins to geoip / threat-intel \
                 work directly. The worker decodes captured bytes only — it opens no UDP socket and \
                 makes no egress (collector mode is roadmap)."
                    .to_string(),
            ),
            (
                "vgi.agent_test_tasks".to_string(),
                crate::meta::agent_test_tasks_json(&[
                    (
                        "worker_version",
                        "What version of the netflow worker is currently running? Return a single \
                         row with one column named version.",
                        "SELECT netflow.main.netflow_version() AS version",
                    ),
                    (
                        "probe_unknown",
                        "I have a one-byte blob that is not a flow datagram. Probe its flow-export \
                         version; it should come back NULL. Return a single column named v.",
                        "SELECT netflow.main.flow_version('\\x00'::BLOB) AS v",
                    ),
                    (
                        "validate_garbage",
                        "Classify the garbage two-byte blob 0xDEAD with the validator and return \
                         just the failure kind as a single column named kind.",
                        "SELECT netflow.main.well_formed('\\xde\\xad'::BLOB).kind AS kind",
                    ),
                ]),
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
                    "Flow-export decode functions: flows (unified auto-detect), netflow_decode \
                     (v5/v9), ipfix_decode (IPFIX), sflow_decode (sFlow v5), templates (template \
                     cache introspection), and the scalars flow_version, header, well_formed, \
                     netflow_version. Decoders thread a per-exporter, per-observation-domain \
                     template cache as externalized scan state."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "The single schema for the `netflow` worker — qualify calls as \
                     `netflow.main.<fn>(...)`. Table functions: `flows`, `netflow_decode`, \
                     `ipfix_decode`, `sflow_decode` (BLOB column → normalized flow rows) and \
                     `templates` (learned-template introspection). Scalars: `flow_version`, \
                     `header`, `well_formed`, `netflow_version`."
                        .to_string(),
                ),
                (
                    "vgi.example_queries".to_string(),
                    "SELECT netflow.main.netflow_version();\n\
                     SELECT netflow.main.flow_version(content) FROM read_blob('caps/*.dat');\n\
                     SELECT * FROM read_blob('caps/*.dat') AS d, LATERAL \
                     netflow.main.flows(d.content, exporter := 'r1') AS f WHERE f.diagnostics IS NULL;\n\
                     SELECT * FROM netflow.main.templates();"
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "netflow");
    }
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "netflow".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    table::register(&mut worker);
    table_in_out::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
