# Flow-export context and counter semantics

Two focused notebooks use the public **VGI NetFlow v0.4.0** native release:

- [01 · A missing template is not zero traffic](01_missing_template_is_not_zero_traffic.ipynb) preserves structurally valid datagrams and missing-template diagnostics, comparing known counters with a complete synthetic reference. It also inspects the learned layout and uses the format reference to explain template dependence. [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-netflow/blob/main/notebooks/01_missing_template_is_not_zero_traffic.ipynb).
- [02 · Sample rows are not packet counts](02_sample_rows_are_not_packet_counts.ipynb) separates IPFIX exported counters, sFlow sample weighting and informational counter-sample rows. Changing the unified decoder's row mode leaves the retained flow's weighted counters intact. [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-netflow/blob/main/notebooks/02_sample_rows_are_not_packet_counts.ipynb).

In Colab choose **Runtime → Run all**. The base shared package preserves compatible
preloaded kernel/data/plotting libraries and retrieves SHA256-verified immutable
companions. The separate local lock includes the publication `[runner]` extra:

```sh
uv sync --locked
uv run --locked vgi-notebooks
uv run --locked vgi-notebooks 01_missing_template_is_not_zero_traffic.ipynb --parameters '{"INCLUDE_TEMPLATE":false}' --output-dir artifacts/without-template
uv run --locked vgi-notebooks 02_sample_rows_are_not_packet_counts.ipynb --parameters '{"SFLOW_MODE":"flows-only"}' --output-dir artifacts/flows-only
```

Run from `notebooks/`; the directory works without the worker checkout. Select
`.venv/bin/python` for interactive Jupyter. The runner uses a temporary kernel,
requires separate destinations for parameter experiments and preserves defaults
when execution fails. Unknown parameters and source-directory overrides are
rejected. If an older bootstrap replaced kernel libraries, save your work and
open the current notebook in a fresh runtime.

Connection SQL remains literal and visible:

```sql
INSTALL vgi FROM community;
LOAD vgi;
INSTALL inet FROM core;
LOAD inet;
ATTACH 'netflow' (TYPE vgi,
 LOCATION 'github-auto://Query-farm/vgi-netflow@v0.4.0');
```

Haybarn/VGI retrieves the native platform release, verifies its SHA256 and caches
it. Initial extension, binary, package and companion setup needs network access.
No Rust compiler, worker build, local source checkout or credentials are required.
The local environment locks Haybarn **2.0.0rc11**; actual execution was validated on
macOS arm64. The INET extension supplies address types. All analysis reads authored
local datagram bytes: there is no collector, socket listener or external network
traffic. Worker and notebook source remain separate.

The [shared v0.3.13 standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.13/docs/standard.md)
provides catalog-derived worker title/subtitle, branding, isolated SQL secrets,
portable companions, SVG output and execution protections. Keep committed `charts/`
with the saved notebooks so GitHub can display the SVG image links. Colab/Jupyter
reruns retain native SVG. Review PNGs and experimental outputs remain ignored.

Coverage is **9 of 9 public named SQL surfaces**: `flow_version`, `header`,
`well_formed`, `flows`, `netflow_decode`, `ipfix_decode`, `sflow_decode`, `templates`,
and the `supported_formats` view. The actual complete catalog contains eight
functions and one view; four relation-input functions were absent from the initial
static candidate extraction. No objects are excluded. `coverage.json` binds full
released/current runtime catalogs, function/view output columns, successful
execution receipts and reviewed narrative/SQL/result mappings. The notebooks run
the release; compatible current mappings do not claim current-main notebook
execution. Release-to-main worker differences add descriptions and composed
examples, with decoding/state/schema code and dependency locks unchanged.

All five `.dat` files are unchanged synthetic golden fixtures from
`crates/netflow-core/src/fixtures.rs`. They were generated in Rust, not captured
from a network. [Provenance](fixtures/provenance.json) records source revision,
sizes and SHA256 hashes. The NetFlow/IPFIX export clock **2023-11-14 22:13:20 UTC**
is invented. sFlow has no export timestamp in this fixture and remains NULL.
Exporter names are notebook scope labels. Addresses and ports establish neither
real devices nor application identities.

In the first notebook, both data datagrams always remain selected.
`INCLUDE_TEMPLATE=True` includes the separate v9 template, while **False** withholds
only that layout from the selected scan. The complete reference uses the unified
`flows` decoder; the selected NetFlow-only scan uses `netflow_decode`. Each scan
owns its template state. The `templates` projection snapshots the reference's
learned exporter/domain/template identity and seven ordered fields before the
selected scan. It is historical introspection, not a guarantee that another scan
received the layout. `supported_formats` explains why v9 is template-stateful
while v5 has fixed records.

With the template, selected known bytes total **2,000** across **three flow rows**.
Without it, **1,200 known bytes** remain in the two v5 rows and one missing-template
diagnostic preserves unknown v9 counters as NULL. The unavailable category remains
in the comparison; it is never converted into zero traffic. Diagnostic rows are
not counts of missing records or network packets. The complete synthetic reference
explains the difference here; a diagnostic alone cannot recover missing traffic.
Eleven checks reconcile structural validity, data selection, scan isolation,
unchanged v5 records, NULL diagnostics and grouped counters.

In the second notebook, the IPFIX fixture contains an exported record with
**1,500,000 bytes** and **1,200 packets**. A NULL sampling-rate field in this fixture
does not establish that arbitrary IPFIX data was unsampled. The sFlow fixture has
one sampled flow plus one informational `counter-sample` row. Its raw fields retain
a **64-byte frame length** and **4,096 sampling weight**, which explain the returned
**262,144 normalized bytes** and **4,096 normalized packets**. Neither normalized
counter is the export datagram's payload size or an output-row count.

`SFLOW_MODE` accepts **"all"** (default) or **"flows-only"**. Only the unified
`flows` decoder honors this optional input column; specialized `sflow_decode`
remains an unchanged reference. Flows-only removes the counter-sample row but
retains the same flow record and weighted counters. A `counter-sample` label is
not a decode error, and its unknown traffic fields stay NULL. Twelve checks
reconcile row categories, retained records, raw-field arithmetic, IPFIX controls
and unavailable sFlow timestamps. The protocols' counter provenance remains
separate; the notebook does not publish an unexplained combined traffic total.

Relation-input decoders accept a table with `datagram` and `exporter` columns;
correlated scalar/LATERAL usage is not supported. Preserve exporter/domain identity
and ordering when working with real archives. These tiny examples do not test
expiration, exporter restarts, packet loss, large-scale buffering, estimator bias,
confidence intervals or sampling-rate changes. Correct arithmetic is not evidence
that a real observation window or sampling design is complete.

Validation covers defaults, one separate parameter experiment per story, four
reviewed SVG figures, runner guards and one fresh preloaded compatible kernel for
the shared helper/fixture path. Hosted Colab was not manually operated. Existing
green [source CI at 032c4e6](https://github.com/Query-farm/vgi-netflow/actions/runs/43575534184)
is reused for these notebook-only changes; no source rebuild, full test repetition
or new worker CI is triggered. Prior gates passed 32 Rust tests, 103 stdio / 111
HTTP / 103 Unix SQL assertions and metadata 100/100 L2 with zero findings.
