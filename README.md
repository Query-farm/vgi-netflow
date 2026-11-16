# vgi-netflow

A [VGI](https://query.farm) worker that decodes raw network **flow-export
datagrams** — NetFlow **v5** (fixed), NetFlow **v9** (RFC 3954, template-based),
**IPFIX** (RFC 7011, template-based, enterprise + variable-length IEs), and
**sFlow v5** — from a `BLOB` column of captured exporter datagrams (or UDP
payloads carved out of pcap) into typed, **normalized** flow rows: src/dst IP+port,
protocol, bytes, packets, TCP flags, flow start/end, interfaces, AS numbers, next
hop, ToS, sampling, and exporter-specific Information Elements.

The moat is correct **template-stateful** v9/IPFIX decode at lake scale: a v9/IPFIX
Data Set carries *no field descriptors* — only a template id — and the matching
**Template Set** that defines the layout may have arrived minutes earlier, in a
different datagram. So the worker maintains a **template cache keyed by
`(exporter, observation domain, template id)`** as serializable VGI **scan
state** that survives scan-batch boundaries and HTTP worker rehydration — a
template seen in datagram 1 decodes data in datagram 10,000. A data record that
arrives *before* its template is buffered and retried, or emitted with
`diagnostics = 'missing-template:…'` — never dropped. Network/security
observability compute, in-engine, no collector stack.

It also enriches the **Layer-2** side: MAC-address scalars resolve a MAC's
IEEE-registered vendor from a bundled registry snapshot, normalize its notation,
flag multicast / randomized (locally administered) / broadcast addresses, and
convert to and from IPv6 modified EUI-64 — directly on the MACs IPFIX exports in
`raw_fields['sourceMacAddress']`.

> **Not a pcap worker.** A NetFlow/IPFIX datagram is an *aggregate report an
> exporter sends about many packets*, not the packets themselves. Carve UDP
> payloads with a pcap reader upstream; vgi-netflow starts at the UDP payload.

## Quick start

Every [GitHub release](https://github.com/Query-farm/vgi-netflow/releases) ships a prebuilt worker binary. The `vgi` extension downloads the one for your platform, checks its SHA-256 and caches it, so there is nothing to install besides DuckDB:

```sql
INSTALL vgi FROM community;
LOAD vgi;

ATTACH 'netflow' AS netflow (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-netflow@v0.4.2');

-- Decode a sample IPFIX capture (pinned to a release tag) as exporter 'edge-1',
-- then inspect the v9/IPFIX templates the worker learned from it.
SELECT count(*) AS flows FROM netflow.main.flows((FROM (SELECT content AS datagram, 'edge-1' AS exporter FROM read_blob('https://raw.githubusercontent.com/Query-farm/vgi-netflow/v0.4.0/test/data/ipfix.dat'))));
SELECT exporter, template_id, kind, field_count FROM netflow.main.templates(exporter => 'edge-1') ORDER BY template_id;

-- List the template-stateful formats (the ones whose decode needs a learned template)
-- and which function decodes each.
SELECT format, version, decoder FROM netflow.main.supported_formats WHERE template_stateful ORDER BY version;
```

`src_addr` / `dst_addr` / `next_hop` are emitted as native `INET`, so also run `LOAD inet;` before decoding flows (see [INET addressing](#inet-addressing)).

Prebuilt binaries cover macOS (Apple silicon), Linux (x86-64 and arm64). `github-auto://` needs an explicit release tag; change `@v0.4.2` to move to a newer release.

### Other ways to run it

- **Docker** (the image bundles the worker; needs a container runtime):

  ```sql
  ATTACH 'netflow' AS netflow (TYPE vgi, LOCATION 'docker://ghcr.io/query-farm/vgi-netflow:0.4.2');
  ```

- **Manual download.** Download the archive for your platform from the [releases page](https://github.com/Query-farm/vgi-netflow/releases), verify it against its `.sha256` file (a cosign `.cosign.bundle` is published alongside), unpack it, and set `LOCATION` to the path of the extracted worker executable.

### Build from source

To build the worker yourself, see [Building & testing](#building--testing).

## SQL surface

Because DuckDB table functions cannot take a correlated per-row column argument,
the decode functions are **table-in-out** functions: pass a **relation** with a
`datagram` BLOB column (and, optionally, a per-row `exporter` / `obs_domain` /
`mode` column). Feed datagrams in **capture order** so a Template Set is seen
before the Data Sets that reference it.

```sql
-- 1. Decode a column of captured flow datagrams to normalized flow rows.
--    flows() auto-detects the version per datagram and threads the template cache.
--    Pass exporter (per row) so template ids never collide across devices.
SELECT f.exporter, f.flow_version, f.src_addr, f.dst_addr, f.src_port, f.dst_port,
       f.protocol, f.bytes, f.packets, f.tcp_flags, f.flow_start, f.flow_end,
       f.src_as, f.dst_as, f.diagnostics
FROM netflow.main.flows((FROM (
       SELECT content AS datagram, filename AS exporter
       FROM read_blob('s3://flowlake/exporter=*/*.dat'))))  AS f
WHERE f.diagnostics IS NULL;        -- only fully-decoded records

-- 2. Enrich: join flows to GeoIP / ASN and threat-intel, all in SQL. Addresses
--    are native INET, so containment / prefix joins work directly (<<= / >>=).
SELECT f.src_addr, g.country, g.asn, t.category AS threat
FROM flow_records f
LEFT JOIN maxmind.city(f.src_addr)             g ON TRUE
LEFT JOIN vgi_threatintel.lookup(f.dst_addr)   t ON TRUE
WHERE f.src_addr::INET <<= '10.0.0.0/8'::INET   -- DuckDB inet uses <<= / >>=
  AND t.category IS NOT NULL;

-- 3. Per-version scalars + exporter-specific IEs via the raw_fields MAP.
--    Decode the relation once and join rows back to their source datagram by
--    exporter (here the file name) — a correlated flows(d.content) per row is not
--    supported (DuckDB 2.0 raises an internal FinalExecute error). These read the
--    repo's sample captures by tag-pinned URL; point read_blob at your own files.
WITH caps AS (SELECT content AS datagram, filename AS exporter
              FROM read_blob(['https://raw.githubusercontent.com/Query-farm/vgi-netflow/v0.4.0/test/data/v5.dat',
                                'https://raw.githubusercontent.com/Query-farm/vgi-netflow/v0.4.0/test/data/v9.dat',
                                'https://raw.githubusercontent.com/Query-farm/vgi-netflow/v0.4.0/test/data/ipfix.dat']))
SELECT c.exporter,
       netflow.main.flow_version(c.datagram)   AS ver,    -- '5' / '9' / '10' / 'sflow5'
       netflow.main.header(c.datagram).sequence AS seq,
       f.raw_fields['natEvent']                AS nat_evt  -- enterprise / unmapped IE
FROM caps AS c
JOIN netflow.main.flows((FROM caps)) AS f ON f.exporter = c.exporter
ORDER BY c.exporter, seq;

-- 4. Loss check: does each NetFlow v5 capture decode as many clean records as
--    its export header declares? (header() + netflow_decode() together.)
--    No rows means no capture lost records.
WITH caps AS (SELECT content AS datagram, filename AS exporter
              FROM read_blob('https://raw.githubusercontent.com/Query-farm/vgi-netflow/v0.4.0/test/data/v5.dat'))
SELECT c.exporter,
       netflow.main.header(c.datagram).count AS declared_records,
       coalesce(d.clean_rows, 0)            AS clean_rows
FROM caps AS c
LEFT JOIN (SELECT exporter, count(*) FILTER (WHERE diagnostics IS NULL) AS clean_rows
           FROM netflow.main.netflow_decode((FROM caps))
           GROUP BY exporter) AS d ON d.exporter = c.exporter
WHERE coalesce(d.clean_rows, 0) < netflow.main.header(c.datagram).count
ORDER BY c.exporter;
```

### Template priming (critical)

v9/IPFIX templates and the data records that use them ride in **separate** Sets
and frequently **separate datagrams**. Feed datagrams to `flows()` in capture
order; the cache survives across rows *and across scan batches* (it is
externalized scan state). A data record that arrives before its template is
buffered (bounded) and retried; if the template never appears within the scan it
is emitted with `diagnostics = 'missing-template:<domain>/<id>'` rather than
dropped silently. For lakes partitioned per exporter, scan each exporter's
datagrams ordered by capture time and pass a per-row `exporter` column so caches
never collide across devices.

## Functions

| Function | Kind | Purpose |
| --- | --- | --- |
| `flows((FROM rel))` | table-in-out + template state | Unified decode (auto-detect v5/v9/IPFIX/sFlow) → normalized schema |
| `netflow_decode((FROM rel))` | table-in-out (+ state for v9) | NetFlow v5 + v9 only |
| `ipfix_decode((FROM rel))` | table-in-out + state | IPFIX (v10) — templates, options, enterprise + variable-length IEs |
| `sflow_decode((FROM rel))` | table-in-out (stateless) | sFlow v5 flow + counter samples |
| `templates([exporter])` | table | Read-only projection of the learned template cache |
| `flow_version(blob)` | scalar | `'5'` / `'9'` / `'10'` / `'sflow5'` / `NULL` |
| `header(blob)` | scalar | `STRUCT(version, count, sys_uptime, export_time, sequence, obs_domain)` |
| `well_formed(blob)` | scalar | `STRUCT(ok, version, error, kind)` — never panics on garbage |
| `oui_vendor(mac)` | scalar | IEEE-registered organization (`VARCHAR`), longest prefix of MA-S / MA-M / MA-L; `NULL` if unassigned |
| `oui_lookup(mac)` | scalar | `STRUCT(prefix, block, organization)` — e.g. `00:1b:63:00:00:00/24`, `MA-L`, `Apple, Inc.` |
| `mac_normalize(mac)` | scalar | Canonical `aa:bb:cc:dd:ee:ff`; `NULL` if not a MAC |
| `mac_is_multicast(mac)` | scalar | I/G bit set (multicast or broadcast) |
| `mac_is_local(mac)` | scalar | U/L bit set — locally administered, e.g. a randomized privacy MAC |
| `mac_is_broadcast(mac)` | scalar | `ff:ff:ff:ff:ff:ff` |
| `eui48_to_eui64(mac)` | scalar | Modified EUI-64 interface ID (RFC 4291 App. A) as hextets, e.g. `021b:63ff:fe84:45e6` |
| `mac_from_ipv6(address)` | scalar | MAC embedded in a SLAAC (modified EUI-64) IPv6 address (`VARCHAR`); `NULL` otherwise |

Input relation columns (read by name, case-insensitive): **`datagram`** (BLOB,
required; also accepts `content` / `blob`, or the first binary column),
**`exporter`** (VARCHAR, optional, per row), **`obs_domain`** (integer, optional),
**`mode`** (VARCHAR, `flows` only: `auto` / `flows-only` / `all`).

`mac` accepts `VARCHAR` in colon, dash, Cisco dotted (`aabb.ccdd.eeff`) or bare
hex notation (any case, 1–2 digits per group), a 6-byte `BLOB` (how IPFIX carries
`sourceMacAddress` / `destinationMacAddress` in `raw_fields`), or an integer
holding the 48-bit address. Anything that is not a MAC yields `NULL`, never an
error.

### MAC enrichment

```sql
-- Attribute decoded L2 flows to hardware vendors and flag randomized MACs.
SELECT netflow.main.mac_normalize(f.raw_fields['sourceMacAddress']) AS src_mac,
       netflow.main.oui_vendor(f.raw_fields['sourceMacAddress'])    AS vendor,
       netflow.main.mac_is_local(f.raw_fields['sourceMacAddress'])  AS randomized,
       sum(f.bytes)                                                 AS bytes
FROM netflow.main.flows((SELECT content AS datagram, filename AS exporter
                         FROM read_blob('captures/*.ipfix'))) AS f
WHERE f.raw_fields['sourceMacAddress'] IS NOT NULL
GROUP BY ALL ORDER BY bytes DESC;

-- SLAAC: link-local address for a MAC, and back to the vendor.
SELECT 'fe80::' || netflow.main.eui48_to_eui64('00:1b:63:84:45:e6') AS link_local,   -- fe80::021b:63ff:fe84:45e6
       netflow.main.oui_vendor(netflow.main.mac_from_ipv6('fe80::21b:63ff:fe84:45e6')) AS vendor;  -- Apple, Inc.
```

Vendor data is a snapshot of the **IEEE Registration Authority** registries —
MA-L (`oui/oui.csv`), MA-M (`oui28/mam.csv`) and MA-S (`oui36/oui36.csv`) from
<https://standards-oui.ieee.org/>, retrieved **2026-11-16** — keeping only each
assignment prefix and organization name (~54k assignments, ~1.1 MB compiled in;
no network at runtime). Provenance (row counts, CSV checksums) is in
`crates/netflow-core/data/oui/SNAPSHOT`; regenerate with `python3 ci/gen-oui.py`.
Randomized MACs (U/L bit set) almost never match a registry entry, so
`oui_vendor` is `NULL` for them — pair it with `mac_is_local`.

### Normalized output schema (`flows()` and the per-version decoders)

`exporter`, `flow_version`, `obs_domain`, `template_id`, `export_time`
(TIMESTAMPTZ), `sequence`, `src_addr`/`dst_addr` (**INET**), `src_port`/`dst_port`,
`protocol`, `tcp_flags`, `bytes`, `packets`, `flow_start`/`flow_end`
(TIMESTAMPTZ), `src_as`/`dst_as`, `input_snmp`/`output_snmp`, `next_hop`
(**INET**), `tos`, `src_mask`/`dst_mask`, `sampling_rate`, `direction`,
`raw_fields` (`MAP(VARCHAR, BLOB)` — every unmapped IE), `diagnostics`.

## INET addressing

`src_addr` / `dst_addr` / `next_hop` are emitted as DuckDB's physical **`INET`**
layout (`STRUCT(ip_type, address HUGEINT, mask)`), so a scanned address is a
zero-cost `::INET` cast from native `INET` and containment / prefix joins work
directly:

```sql
WHERE f.src_addr::INET <<= '10.0.0.0/8'::INET   -- containment is <<= / >>=, NOT &&
```

`LOAD inet;` provides the type. (DuckDB does not round-trip the logical `INET`
type through Arrow, so the worker emits the physical struct that `::INET` accepts
— the same approach `vgi-bgp` uses. Both IPv4 and IPv6 reconstruct correctly.)

## Building & testing

```sh
cargo build --release --bin netflow-worker
cargo test --workspace          # unit + golden fixtures + zero-panic proptest
./run_tests.sh                  # haybarn SQLLogic E2E (needs haybarn-unittest + vgi)
```

The decoders are hand-rolled (`netflow-core`, no Arrow/VGI deps) with strict
untrusted-binary-input discipline: every read is bounds-checked, every declared
length validated before slicing (a hostile 4 GB length allocates nothing), and a
malformed datagram yields a diagnostic row rather than a panic — a proptest
drives arbitrary/truncated bytes through every decoder asserting **zero panics**.

## Licensing

MIT. NetFlow v9 (RFC 3954), IPFIX (RFC 7011/7012), and sFlow v5 (sflow.org) are
open specs; the bundled IANA IPFIX Information-Element registry is a public
protocol registry (curated snapshot in `crates/netflow-core/src/registry/`,
attributed to IANA / RFC 7012). The MAC vendor table is derived directly from the
IEEE Registration Authority's public MA-L / MA-M / MA-S registries (not from
Wireshark's GPL `manuf` file). No GPL/AGPL/copyleft, no commercial data license.

## Non-goals (v1)

No UDP listener / live collector (decodes *captured* bytes only — no socket, no
egress); no flow aggregation/de-dup across exporters (do it in SQL); no NetFlow
v1/v7/v8; no flow export/encode; no pcap parsing.

---

Copyright 2026 Query Farm LLC — https://query.farm

## Executed SQL notebook

[A missing template is not zero traffic](notebooks/README.md) compares complete and template-withheld synthetic NetFlow scans, with diagnostics and unavailable counters kept visible.
