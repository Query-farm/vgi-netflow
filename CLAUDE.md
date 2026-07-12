# CLAUDE.md — vgi-netflow

Guidance for working in this repo. `vgi-netflow` is a VGI worker that decodes
NetFlow v5/v9, IPFIX, and sFlow v5 flow-export datagrams (a `BLOB` column) into
normalized flow rows for DuckDB over Apache Arrow.

## Layout

```
crates/netflow-core/     # pure decoders + template cache — NO arrow / vgi deps
  src/buf.rs             #   panic-free big-endian byte cursor
  src/inet.rs            #   IP → DuckDB physical INET triple (ip_type, addr, mask)
  src/cache.rs           #   TemplateCache / TemplateKey / TemplateEntry (serde scan state)
  src/normalize.rs       #   FlowRecord — the normalized §5 wide row
  src/registry/          #   curated IANA IPFIX IE snapshot + enterprise (PEN) tables
  src/decode/            #   header dispatch, v5, v9, ipfix, sflow, record slicer, orchestration
  src/wellformed.rs      #   structural validation (never panics)
  src/fixtures.rs        #   golden datagram builders (shared by tests + gen_fixtures)
  examples/gen_fixtures.rs  # writes test/data/*.dat for the E2E
  tests/decode.rs        #   golden fixtures, template-state-across-batches, zero-panic proptest
crates/netflow-worker/   # thin Arrow / VGI adapter over netflow-core
  src/main.rs            #   catalog `netflow`, schema `main`; registers everything
  src/arrow_map.rs       #   FlowRecord → Arrow (INET struct, MAP, TIMESTAMPTZ); flow_schema()
  src/state.rs           #   load/store the TemplateCache via VGI storage (scan state)
  src/scalar/            #   netflow_version, flow_version, header, well_formed
  src/table/             #   templates() — cache introspection (producer)
  src/table_in_out/      #   flows, netflow_decode, ipfix_decode, sflow_decode (relation in)
test/sql/*.test          # haybarn SQLLogic E2E
ci/                      # check-version.sh, run-integration.sh, preprocess-require.awk
```

## Architecture invariants

- **netflow-core has no Arrow/VGI/network deps.** All wire correctness, the
  template engine, the IE registry, and the normalized schema live there and are
  unit-tested directly. The worker crate only marshals to Arrow.
- **Scan state = the template cache, and only the template cache** (§3). It is
  plain serde data (no sockets/handles/`dyn`). `cache::to_bytes`/`from_bytes`
  round-trip it (a test asserts losslessness — the HTTP-rehydration proof).
- **Zero panics on untrusted bytes.** Read through `buf::Cursor`; validate any
  declared length against the remaining buffer before slicing/allocating. The
  proptest in `tests/decode.rs` is the gate — keep it green.
- **Template state is the moat.** v9/IPFIX Data Sets are undecodable without the
  cached template. Two-pass within a datagram (templates first), buffer data that
  precedes its template, retry on later datagrams, flush leftovers as
  `missing-template` at end of scan (`flush_pending` via the in-out `finish`).
- **Cache key is `(exporter, obs_domain, template_id)`** — all three. Two
  exporters reuse template id 256 for different layouts; don't let them collide.

## VGI gotchas (learned the hard way)

- **Table functions reject correlated per-row column args.** `LATERAL
  netflow.flows(d.content, …)` does NOT bind. The decode functions are
  **table-in-out**: call `FROM netflow.main.flows((FROM (SELECT content AS
  datagram, filename AS exporter FROM read_blob(...))))` and read input columns
  by name (`find_datagram_col` / `find_named_col`). This also gives per-row
  `exporter`.
- **INET does not round-trip through Arrow.** Emit the physical
  `STRUCT(ip_type UInt8, address FixedSizeBinary(16)→hugeint, mask UInt16)` (see
  `inet.rs` + `arrow_map::build_inet`) and consume via `::INET`. Containment is
  `<<=` / `>>=`, never `&&`. Verify IPv4 *and* IPv6.
- **`templates()` reads a global cache projection** (`state::global_cache`) that
  the decode functions mirror into on every batch; the per-scan cache itself is
  execution-scoped. Filter `templates()` by `exporter` for determinism.

## Gates (all must be green)

```sh
cargo build --release
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
./run_tests.sh                          # haybarn E2E (subprocess); ci/run-integration.sh for unix/http
uvx --prerelease=allow --from vgi-lint-check vgi-lint lint target/release/netflow-worker \
    --execute --fail-on info   # latest linter; executes examples (run mode)
```

Every function carries `vgi.title` / `vgi.doc_llm` / `vgi.doc_md` / `vgi.keywords`
+ per-arg docs (VGI metadata rules). Bump `[workspace.package] version` before a
release tag (`ci/check-version.sh` enforces tag == version).

## Non-goals

No UDP listener / collector, no flow aggregation, no v1/v7/v8, no encode, no pcap.
This worker is the future fold-home for `asn`/`oui` enrichment scalars, but those
are **not** in this catalog — do not add them unless the spec's function catalog
grows.

Copyright 2026 Query Farm LLC — https://query.farm
