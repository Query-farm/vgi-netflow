"""Charts for synthetic flow-export context and counter semantics."""

import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from vgi_notebooks import finish

SOURCE = "Source: unchanged synthetic NetFlow golden fixtures · VGI netflow v0.4.0 · no captured network traffic"
SAMPLE_SOURCE = (
    "Source: unchanged synthetic IPFIX/sFlow golden fixtures · VGI netflow v0.4.0 · counters describe authored samples"
)


def validate_template(value):
    """Check the visible template-presence parameter."""
    if type(value) is not bool:
        raise ValueError("INCLUDE_TEMPLATE must be a Boolean.")


def validate_mode(value):
    """Check the visible unified-decoder mode."""
    if value not in {"all", "flows-only"}:
        raise ValueError('SFLOW_MODE must be "all" or "flows-only".')


def outcomes(totals, INCLUDE_TEMPLATE):
    """Compare decoded and diagnostic row populations."""
    fig, ax = plt.subplots(figsize=(10.5, 5.4))
    x = list(range(len(totals)))
    for col, offset, color, label in [
        ("decoded_flow_rows", -0.18, "#397d8c", "Decoded flow rows"),
        ("diagnostic_rows", 0.18, "#b56a45", "Diagnostic rows"),
    ]:
        bars = ax.bar([v + offset for v in x], totals[col], width=0.32, color=color, label=label)
        ax.bar_label(bars, padding=4, fontsize=11)
    ax.set_xticks(x, totals.scenario)
    ax.set_ylabel("Output rows · different outcome types")
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_ylim(0, max(totals.decoded_flow_rows.max(), totals.diagnostic_rows.max()) + 1)
    ax.grid(axis="x", visible=False)
    fig.legend(*ax.get_legend_handles_labels(), loc="upper center", bbox_to_anchor=(0.55, 0.79), ncol=2, frameon=False)
    finish(
        fig,
        "Valid datagrams can still yield unavailable flow fields",
        f"Selected v9 template: {'included' if INCLUDE_TEMPLATE else 'withheld'} · diagnostic rows stay distinct",
        SOURCE,
        name="01-decode-outcomes",
    )


def traffic(by_port, INCLUDE_TEMPLATE):
    """Retain unavailable reference categories beside known counters."""
    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    y = list(range(len(by_port)))
    ref = ax.barh(
        [v - 0.18 for v in y], by_port.reference_bytes, height=0.3, color="#a5bfb6", label="Complete reference"
    )
    ax.bar_label(ref, labels=[f"{value:,.0f}" for value in by_port.reference_bytes], padding=4, fontsize=10)
    for i, row in enumerate(by_port.itertuples()):
        if row.selected_bytes == row.selected_bytes:
            bar = ax.barh(
                i + 0.18, row.selected_bytes, height=0.3, color="#397d8c", label="Selected stream" if i == 0 else None
            )
            ax.bar_label(bar, labels=[f"{row.selected_bytes:,.0f}"], padding=4, fontsize=10)
        else:
            ax.text(15, i + 0.18, "Unavailable · see diagnostic", va="center", color="#9b5738", fontsize=10)
    ax.set_yticks(y, [f"{r.exporter} · port {r.dst_port}" for r in by_port.itertuples()])
    ax.set_ylim(len(by_port) - 0.5, -0.5)
    ax.set_xlabel("Decoded traffic bytes · sum of fixture counters")
    ax.set_xlim(0, float(by_port.reference_bytes.max()) * 1.22)
    ax.grid(axis="y", visible=False)
    fig.legend(*ax.get_legend_handles_labels(), loc="upper center", bbox_to_anchor=(0.55, 0.79), ncol=2, frameon=False)
    finish(
        fig,
        "A smaller known total can reflect missing decode context",
        "Complete-reference categories retained · unavailable counters are not plotted as zero",
        SOURCE,
        name="02-known-counters",
    )


def row_selection(summary, mode):
    """Keep flow,counter and diagnostic categories distinct."""
    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    colors = {"Flow sample": "#267358", "Counter sample": "#c57b40", "Decode diagnostic": "#7a5a99"}
    scenarios = ["Specialized reference", "Selected unified scan"]
    for kind, offset in [("Flow sample", -0.22), ("Counter sample", 0), ("Decode diagnostic", 0.22)]:
        data = summary[summary.row_kind == kind].set_index("scenario").loc[scenarios]
        bars = ax.bar([i + offset for i in range(2)], data.row_count, width=0.2, color=colors[kind], label=kind)
        ax.bar_label(bars, padding=4)
    ax.set_xticks([0, 1], scenarios)
    ax.set_ylabel("Returned rows (sample categories kept separate)")
    ax.set_ylim(0, 1.5)
    ax.set_yticks([0, 1])
    ax.grid(axis="y")
    fig.legend(*ax.get_legend_handles_labels(), loc="lower center", bbox_to_anchor=(0.55, 0.78), ncol=3)
    finish(
        fig,
        "A counter-sample row is not another flow",
        f"Selected unified mode: {mode} · fixed specialized reference · no decode failures in this fixture",
        SAMPLE_SOURCE,
        name="03-sample-populations",
    )


def sampling_arithmetic(weights):
    """Display raw-field sampling arithmetic without combining protocols."""
    r = weights.iloc[0]
    fig, ax = plt.subplots(figsize=(11, 5.8))
    ax.set_axis_off()
    headers = ["Sampled frame", "Sampling weight", "Normalized counter"]
    for x, label in zip([0.14, 0.49, 0.84], headers, strict=True):
        ax.text(x, 0.94, label, ha="center", va="center", fontsize=12, weight="bold")
    rows = [
        (0.65, [f"{int(r.raw_frame_bytes):,} bytes", f"× {int(r.raw_weight):,}", f"{int(r.scaled_bytes):,} bytes"]),
        (0.25, ["1 sampled frame", f"× {int(r.raw_weight):,}", f"{int(r.scaled_packets):,} packets"]),
    ]
    for y, values in rows:
        for x, value in zip([0.14, 0.49, 0.84], values, strict=True):
            ax.text(
                x,
                y,
                value,
                ha="center",
                va="center",
                fontsize=15,
                weight="bold",
                bbox={"boxstyle": "round,pad=0.55", "facecolor": "#e7efea", "edgecolor": "none"},
            )
        for x1, x2 in [(0.29, 0.35), (0.63, 0.70)]:
            ax.annotate("", xy=(x2, y), xytext=(x1, y), arrowprops={"arrowstyle": "->", "color": "#52665A", "lw": 1.8})
    finish(
        fig,
        "One sampled frame yields weighted counters",
        "Raw fields preserve the frame length and weight · arithmetic is not independent evidence of total traffic",
        SAMPLE_SOURCE,
        name="04-sampling-arithmetic",
    )
