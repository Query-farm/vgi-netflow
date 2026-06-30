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

/// Build the `vgi.agent_test_tasks` JSON value: a fixed suite of analyst tasks
/// that `vgi-lint simulate` runs. Each `(name, prompt, reference_sql)` triple
/// becomes a task object; the `prompt` is shown to the simulated analyst while
/// `reference_sql` (the canonical solution) is hidden and re-run live to grade.
pub fn agent_test_tasks_json(tasks: &[(&str, &str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|(name, prompt, reference_sql)| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\",\"reference_sql\":\"{}\"}}",
                esc(name),
                esc(prompt),
                esc(reference_sql)
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
