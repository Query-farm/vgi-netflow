//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table.
//!
//! Each function/table surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)            — human-friendly display name
//! - `vgi.doc_llm` (VGI112)          — concise prose aimed at LLMs
//! - `vgi.doc_md` (VGI113)           — short Markdown description
//! - `vgi.keywords` (VGI126/VGI138)  — a JSON array of search terms/synonyms
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted here: it belongs on
//! the catalog object only (VGI139), which already points at the repo.

/// Sample flow-export datagrams as hex, built by `netflow-core`'s `fixtures`
/// (the same golden vectors the unit tests + E2E assert). They are embedded
/// inline in the runnable `vgi.executable_examples` so every decode function
/// carries a self-contained example that `vgi-lint --execute` can run against
/// the attached worker with no external files, fixtures, or `LOAD inet`.
///
/// `SAMPLE_V5_HEX`     — NetFlow v5, two records (a TCP + a UDP flow).
/// `SAMPLE_V9_HEX`     — NetFlow v9, template + one data record in one datagram.
/// `SAMPLE_IPFIX_HEX`  — IPFIX (v10), template + one fully-decodable IPv4/TCP flow.
/// `SAMPLE_SFLOW_HEX`  — sFlow v5, one flow sample + one counter sample.
pub const SAMPLE_V5_HEX: &str = "00050002000186a06553f100000000000000000a000100000a0000010a0000020a0000fe000100020000000a000003e800015f900001731804d2005000180600fbf4fbf518180000c0a80101080808080a0000fe0001000200000002000000c800015f900001731814e900350000110000003b4118180000";
pub const SAMPLE_V9_HEX: &str = "00090002000186a06553f1000000001400000001000000240100000700080004000c000400070002000b000200040001000200040001000401000019ac100001ac100002045700160600000003000000b4";
pub const SAMPLE_IPFIX_HEX: &str = "000a006d6553f100000000070000002a0002002c0100000900080004000c000400070002000b0002000400010001000800020008009800080099000801000031cb007105c633640980e801bb06000000000016e36000000000000004b00000018bcfe568000000018bcfe58f10";
pub const SAMPLE_SFLOW_HEX: &str = "00000005000000010a0000090000000000000001000003e8000000020000000100000048000000640000000000001000000000000000000000000005000000060000000100000003000000200000004000000006c000020ac00002140000c738000000500000001800000000000000020000006c000000c80000000000000001000000010000005800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Encode `(description, sql)` pairs as the `vgi.executable_examples` JSON array
/// (VGI906/907). The linter binds and runs each `sql` against the live worker.
pub fn executable_examples_json(examples: &[(&str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = examples
        .iter()
        .map(|(description, sql)| {
            format!(
                "{{\"description\":\"{}\",\"sql\":\"{}\"}}",
                esc(description),
                esc(sql)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Encode `(name, type, description)` triples as the `vgi.result_columns_schema`
/// JSON array (VGI307/VGI321): one object per returned column, **in the exact
/// order the function emits them** (VGI910 also checks column order). Each `type`
/// must be a real DuckDB type that `typeof(NULL::<type>)` canonicalizes to the
/// same string DuckDB's `DESCRIBE` reports for that column, or VGI910 flags a
/// type mismatch under `--execute`.
pub fn result_columns_schema_json(cols: &[(&str, &str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = cols
        .iter()
        .map(|(name, ty, description)| {
            format!(
                "{{\"name\":\"{}\",\"type\":\"{}\",\"description\":\"{}\"}}",
                esc(name),
                esc(ty),
                esc(description)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Encode `(description, sql)` pairs as the `vgi.example_queries` JSON array
/// (VGI502/503): illustrative, catalog-qualified examples that are *shown* (not
/// executed by the example-execution rules, unlike `vgi.executable_examples`).
pub fn example_queries_json(examples: &[(&str, &str)]) -> String {
    // Same `{description, sql}` object shape as executable examples.
    executable_examples_json(examples)
}

/// Encode comma-separated keywords as the JSON array of strings that
/// `vgi.keywords` requires (VGI138).
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<String> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| {
            let escaped = k.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// One `vgi.agent_test_tasks` entry. `vgi-lint simulate` shows only `prompt` to
/// the simulated analyst. The private graders (`reference_sql` — one or more
/// statements run in order, the last statement's output being the graded result —
/// plus the `ignore_column_names` / `unordered` comparison relaxations) live in
/// `vgi-agent-tests.yaml` at the repo root, keyed by `name`, so the agent being
/// graded never sees them (VGI416).
pub struct AgentTask {
    pub name: &'static str,
    pub prompt: String,
}

/// Build the catalog-level `vgi.agent_test_tasks` JSON array from a task suite.
pub fn agent_test_tasks_json(tasks: &[AgentTask]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|t| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\"}}",
                esc(t.name),
                esc(&t.prompt)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the four standard per-object discovery/description tags
/// (`vgi.title`, `vgi.doc_llm`, `vgi.doc_md`, `vgi.keywords`).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
    ]
}

/// `SAMPLE_V5_HEX` cut short mid-record: the header still declares two records
/// but only part of the first survives, so `well_formed` reports `short-record`
/// and the decoder emits a single `truncated` diagnostic row.
pub fn sample_v5_truncated_hex() -> &'static str {
    &SAMPLE_V5_HEX[..120]
}

/// Composed examples: each combines two or more of the worker's own objects in
/// one realistic, offline, deterministic query over the inline sample datagrams.
/// Each is defined once here and referenced from the schema-level
/// `vgi.example_queries`, the driving object's example list, and its
/// `vgi.executable_examples` (they are pinned by `test/sql/composed.test`).
///
/// `flows` + `supported_formats`: decode a mixed batch, roll up per format.
pub fn composed_format_rollup() -> (&'static str, String) {
    (
        "Decode a mixed batch of NetFlow v5, NetFlow v9, IPFIX and sFlow datagrams with flows(), \
         then join each decoded row's flow_version to the supported_formats reference table to \
         count decoded rows and bytes per format and defining spec (sFlow counter samples count \
         as rows but carry no bytes).",
        format!(
            "SELECT s.format, s.rfc, count(*) AS decoded_rows, sum(f.bytes) AS total_bytes \
             FROM netflow.main.flows((SELECT from_hex(h) AS datagram FROM (VALUES \
             ('{SAMPLE_V5_HEX}'), ('{SAMPLE_V9_HEX}'), ('{SAMPLE_IPFIX_HEX}'), \
             ('{SAMPLE_SFLOW_HEX}')) AS t(h))) AS f \
             JOIN netflow.main.supported_formats AS s ON s.flow_version = f.flow_version \
             GROUP BY s.format, s.rfc ORDER BY s.format, s.rfc"
        ),
    )
}

/// `flow_version` + `supported_formats`: route each captured datagram to the
/// decode function that handles it (unrecognized bytes get no decoder).
pub fn composed_route_by_decoder() -> (&'static str, String) {
    (
        "Route a mixed set of captured datagrams: probe each one's wire version with \
         flow_version() and look it up in supported_formats to find the decode function that \
         handles it — the unrecognized junk blob gets a NULL version and no decoder.",
        format!(
            "SELECT c.capture, netflow.main.flow_version(c.datagram) AS version, s.format, \
             s.decoder FROM (VALUES ('router-a', from_hex('{SAMPLE_V5_HEX}')), \
             ('router-b', from_hex('{SAMPLE_IPFIX_HEX}')), \
             ('switch-c', from_hex('{SAMPLE_SFLOW_HEX}')), ('junk', '\\xde\\xad'::BLOB)) \
             AS c(capture, datagram) LEFT JOIN netflow.main.supported_formats AS s \
             ON s.flow_version = netflow.main.flow_version(c.datagram) ORDER BY c.capture"
        ),
    )
}

/// `well_formed` + `flows`: triage a capture, decode only the clean datagrams.
pub fn composed_triage_then_decode() -> (&'static str, String) {
    let truncated = sample_v5_truncated_hex();
    (
        "Triage before decoding: keep only the captures that well_formed() validates (the \
         truncated router-t datagram fails as short-record), decode those with flows(), and \
         total the clean flows and bytes per capture.",
        format!(
            "SELECT f.exporter, count(*) AS flows, sum(f.bytes) AS total_bytes \
             FROM netflow.main.flows((SELECT c.datagram, c.capture AS exporter FROM (VALUES \
             ('router-a', from_hex('{SAMPLE_V5_HEX}')), ('router-t', from_hex('{truncated}')), \
             ('router-9', from_hex('{SAMPLE_V9_HEX}'))) AS c(capture, datagram) \
             WHERE netflow.main.well_formed(c.datagram).ok)) AS f \
             GROUP BY f.exporter ORDER BY f.exporter"
        ),
    )
}

/// `header` + `netflow_decode`: reconcile the record count each NetFlow v5
/// header declares against the clean rows actually decoded (loss detection).
pub fn composed_header_reconcile() -> (&'static str, String) {
    let truncated = sample_v5_truncated_hex();
    (
        "Reconcile NetFlow v5 captures: compare the record count each export header declares \
         (header().count) with the clean rows netflow_decode() actually produced for that \
         capture — the truncated router-b datagram declares 2 records but decodes 0 clean ones.",
        format!(
            "WITH caps AS (SELECT exporter, datagram FROM (VALUES ('router-a', from_hex('{SAMPLE_V5_HEX}')), \
             ('router-b', from_hex('{truncated}'))) AS t(exporter, datagram)) \
             SELECT c.exporter, netflow.main.header(c.datagram).count AS declared_records, \
             coalesce(d.clean_rows, 0) AS clean_rows FROM caps AS c LEFT JOIN \
             (SELECT exporter, count(*) FILTER (WHERE diagnostics IS NULL) AS clean_rows \
             FROM netflow.main.netflow_decode((SELECT datagram, exporter FROM caps)) \
             GROUP BY exporter) AS d ON d.exporter = c.exporter ORDER BY c.exporter"
        ),
    )
}

/// Every composed example, in the order the schema-level list shows them.
pub fn composed_examples() -> Vec<(&'static str, String)> {
    vec![
        composed_format_rollup(),
        composed_route_by_decoder(),
        composed_triage_then_decode(),
        composed_header_reconcile(),
    ]
}
