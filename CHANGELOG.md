# Changelog

## 0.4.1 — 2026-11-14

### Fixed

- Schema-level example queries no longer read the placeholder capture glob
  `caps/*.dat`, which exists nowhere, so for every user they returned no rows
  (vgi-lint-check 2.7.0 VGI516/VGI913). The version-routing and
  INET-containment examples now read the committed sample captures
  (`test/data/{v5,v9,ipfix,sflow}.dat`) through release-tag-pinned
  raw.githubusercontent.com URLs and return real rows.
- README: the quick start decodes a sample IPFIX capture before listing the
  learned templates (a bare `templates()` on a fresh worker is empty), and the
  per-version and loss-check SQL examples read the pinned sample captures.
