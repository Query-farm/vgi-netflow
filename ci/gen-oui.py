#!/usr/bin/env python3
"""Regenerate the bundled IEEE OUI snapshot used by `oui_vendor` / `oui_lookup`.

Source: the IEEE Registration Authority's public MAC address block registries,
downloaded directly from https://standards-oui.ieee.org/ :

  MA-L (24-bit OUI)  oui/oui.csv
  MA-M (28-bit)      oui28/mam.csv
  MA-S (36-bit)      oui36/oui36.csv

Only the Assignment prefix and Organization Name columns are kept (no addresses).
Wireshark's `manuf` file is deliberately NOT used (GPL-2.0).

Writes, under crates/netflow-core/data/oui/:

  mal.bin    MA-L entries, sorted: [prefix u24 BE][name offset u24 BE]
  mam.bin    MA-M entries, sorted: [prefix u32 BE (low 28 bits)][name offset u24 BE]
  mas.bin    MA-S entries, sorted: [prefix u40 BE (low 36 bits)][name offset u24 BE]
  names.bin  deduplicated organization names: [len u8][UTF-8 bytes] ...
  SNAPSHOT   provenance: source URLs, retrieval date, row counts, sha256 of each CSV

Stdlib only. Usage:

  python3 ci/gen-oui.py                 # download the three CSVs from IEEE
  python3 ci/gen-oui.py --from DIR      # use oui.csv / mam.csv / oui36.csv already in DIR

IEEE's server may reject non-browser user agents, so the download sends a
browser-like User-Agent. Commit the regenerated files and bump the CHANGELOG.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import io
import pathlib
import urllib.request

BASE = "https://standards-oui.ieee.org/"
# (registry, url path, local file name, prefix hex digits, entry key bytes)
REGISTRIES = [
    ("MA-L", "oui/oui.csv", "oui.csv", 6, 3),
    ("MA-M", "oui28/mam.csv", "mam.csv", 7, 4),
    ("MA-S", "oui36/oui36.csv", "oui36.csv", 9, 5),
]
OUT_NAMES = {"MA-L": "mal.bin", "MA-M": "mam.bin", "MA-S": "mas.bin"}
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
)


def fetch(path: str) -> bytes:
    req = urllib.request.Request(BASE + path, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (fixed https URL)
        return resp.read()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", type=pathlib.Path, help="directory with the CSVs")
    ap.add_argument(
        "--out",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent
        / "crates/netflow-core/data/oui",
    )
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    raw: dict[str, bytes] = {}
    for reg, path, local, _, _ in REGISTRIES:
        raw[reg] = (args.src / local).read_bytes() if args.src else fetch(path)

    # registry -> {prefix int: organization}
    tables: dict[str, dict[int, str]] = {}
    for reg, _, _, digits, _ in REGISTRIES:
        rows = csv.DictReader(io.StringIO(raw[reg].decode("utf-8-sig")))
        cands: dict[int, list[str]] = {}
        for row in rows:
            if row["Registry"].strip() != reg:
                raise SystemExit(f"{reg}: unexpected registry {row['Registry']!r}")
            assignment = row["Assignment"].strip()
            if len(assignment) != digits:
                raise SystemExit(f"{reg}: bad assignment {assignment!r}")
            name = " ".join(row["Organization Name"].split())
            if not name:
                continue
            cands.setdefault(int(assignment, 16), []).append(name)
        # A handful of MA-L prefixes are listed twice; pick deterministically.
        tables[reg] = {k: sorted(v)[0] for k, v in cands.items()}

    pool = bytearray()
    offsets: dict[str, int] = {}
    for name in sorted({n for t in tables.values() for n in t.values()}):
        enc = name.encode("utf-8")
        if len(enc) > 255:
            raise SystemExit(f"organization name too long for u8 length: {name!r}")
        offsets[name] = len(pool)
        pool.append(len(enc))
        pool += enc
    if len(pool) >= 1 << 24:
        raise SystemExit("name pool exceeds u24 offsets")
    (args.out / "names.bin").write_bytes(bytes(pool))

    for reg, _, _, _, key_bytes in REGISTRIES:
        buf = bytearray()
        for prefix in sorted(tables[reg]):
            buf += prefix.to_bytes(key_bytes, "big")
            buf += offsets[tables[reg][prefix]].to_bytes(3, "big")
        (args.out / OUT_NAMES[reg]).write_bytes(bytes(buf))

    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    lines = [
        "# IEEE Registration Authority MAC address block snapshot (regenerate: ci/gen-oui.py)",
        f"retrieved={today}",
        f"source={BASE}",
    ]
    for reg, path, _, _, _ in REGISTRIES:
        lines.append(
            f"{reg} {BASE}{path} rows={len(tables[reg])} "
            f"sha256={hashlib.sha256(raw[reg]).hexdigest()}"
        )
    lines.append(f"organizations={len(offsets)} names_bytes={len(pool)}")
    (args.out / "SNAPSHOT").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
