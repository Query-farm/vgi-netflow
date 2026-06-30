//! The template cache — the worker's externalized VGI scan state (§3).
//!
//! v9/IPFIX Data Sets carry only a template id; the Template Set that defines
//! the field layout arrives out-of-band, often in an earlier datagram. The cache
//! is the durable memory of templates seen so far, keyed
//! `(exporter, obs_domain, template_id)`, plus a bounded buffer of data records
//! that arrived before their template.
//!
//! Everything here is `#[derive(Serialize, Deserialize)]` plain owned data — no
//! sockets, no handles, no `dyn` — so DuckDB can serialize it between scan
//! batches and rehydrate the worker process (HTTP transport) losslessly. A unit
//! test asserts `serialize -> bytes -> deserialize == original`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Default cap on cached template layouts (LRU-evicted past this).
pub const DEFAULT_CAP_ENTRIES: u32 = 100_000;
/// Default cap on buffered pending-record bytes (per cache).
pub const DEFAULT_CAP_PENDING_BYTES: u32 = 4 * 1024 * 1024;

/// Whether a template describes data records or options (exporter metadata).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TemplateKind {
    Data,
    Options,
}

impl TemplateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TemplateKind::Data => "data",
            TemplateKind::Options => "options",
        }
    }
}

/// One field in a template layout (RFC 7011 §3.2 Field Specifier).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpec {
    pub ie_id: u16,
    /// `0` for a standard IANA IE, else the Private Enterprise Number.
    pub enterprise_number: u32,
    /// Declared length in bytes; `0xFFFF` marks a variable-length IPFIX IE.
    pub length: u16,
    /// Resolved IE name (or `e<PEN>id<n>` / `id<n>` when unknown).
    pub name: String,
    /// Resolved abstract-data-type label (or `octetArray` when unknown).
    pub ie_type: String,
}

impl FieldSpec {
    /// `true` when this is a variable-length IPFIX IE (`length == 0xFFFF`).
    pub fn is_variable(&self) -> bool {
        self.length == 0xFFFF
    }
}

/// Cache key: all three components are required — two exporters legitimately
/// reuse template id 256 for different layouts, and one exporter subdivides its
/// template-id space by observation domain.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateKey {
    pub exporter: String,
    pub obs_domain: u32,
    pub template_id: u16,
}

/// A cached template layout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateEntry {
    pub kind: TemplateKind,
    pub fields: Vec<FieldSpec>,
    /// Number of leading scope fields (Options templates); `0` for Data.
    pub scope_field_count: u16,
    pub first_seen: i64,
    pub last_seen: i64,
    pub use_count: u64,
}

/// A Data Set buffered because its template had not yet been seen. Carries the
/// header context needed to decode it once the template arrives in a later
/// datagram or scan batch (the cross-batch retry is the worker's centerpiece).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecord {
    pub export_time: Option<i64>,
    pub sequence: Option<u64>,
    /// `"9"` or `"10"` — selects the time-resolution rule on retry.
    pub version: String,
    /// v9 header sysUptime in milliseconds (None for IPFIX).
    pub sys_uptime_ms: Option<u64>,
    /// The raw Data Set payload region (all records for this set).
    pub bytes: Vec<u8>,
}

/// JSON-friendly flattening of [`TemplateCache`] (struct map keys → pair arrays).
#[derive(Serialize, Deserialize)]
struct CacheDto {
    entries: Vec<(TemplateKey, TemplateEntry)>,
    pending: Vec<(TemplateKey, Vec<PendingRecord>)>,
    cap_entries: u32,
    cap_pending_bytes: u32,
}

/// The serde scan-state struct (§3): the template cache and nothing else.
#[derive(Clone, Debug)]
pub struct TemplateCache {
    pub entries: BTreeMap<TemplateKey, TemplateEntry>,
    pub pending: BTreeMap<TemplateKey, Vec<PendingRecord>>,
    pub cap_entries: u32,
    pub cap_pending_bytes: u32,
    /// Running total of buffered pending-record byte payloads.
    pending_bytes: u32,
}

impl Default for TemplateCache {
    fn default() -> Self {
        TemplateCache {
            entries: BTreeMap::new(),
            pending: BTreeMap::new(),
            cap_entries: DEFAULT_CAP_ENTRIES,
            cap_pending_bytes: DEFAULT_CAP_PENDING_BYTES,
            pending_bytes: 0,
        }
    }
}

impl TemplateCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a template layout. A redefinition of an existing id
    /// replaces the old layout (exporters legitimately redefine ids) and
    /// preserves `first_seen` / `use_count`. Enforces the LRU entry cap.
    pub fn upsert(&mut self, key: TemplateKey, mut entry: TemplateEntry) {
        if let Some(old) = self.entries.get(&key) {
            entry.first_seen = old.first_seen;
            entry.use_count = old.use_count;
        }
        self.entries.insert(key, entry);
        self.evict_if_needed();
    }

    /// Evict the least-recently-seen entries while over the cap.
    fn evict_if_needed(&mut self) {
        while self.entries.len() as u32 > self.cap_entries {
            // Find the entry with the smallest last_seen (oldest touch).
            if let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&victim);
            } else {
                break;
            }
        }
    }

    /// Look up a template layout and bump its `use_count` / `last_seen`.
    pub fn use_template(&mut self, key: &TemplateKey, now: i64) -> Option<TemplateEntry> {
        if let Some(e) = self.entries.get_mut(key) {
            e.use_count += 1;
            e.last_seen = now;
            Some(e.clone())
        } else {
            None
        }
    }

    /// Read a template layout without mutating its stats.
    pub fn peek(&self, key: &TemplateKey) -> Option<&TemplateEntry> {
        self.entries.get(key)
    }

    /// Buffer a data record awaiting its template. Returns `false` (and does not
    /// store) when the bounded pending buffer is full — the caller then emits the
    /// record as a `missing-template` diagnostic immediately rather than dropping
    /// it silently.
    pub fn push_pending(&mut self, key: TemplateKey, rec: PendingRecord) -> bool {
        let cost = rec.bytes.len() as u32;
        if self.pending_bytes.saturating_add(cost) > self.cap_pending_bytes {
            return false;
        }
        self.pending_bytes += cost;
        self.pending.entry(key).or_default().push(rec);
        true
    }

    /// Remove and return any buffered records for a key (called when its template
    /// has just been learned, to retry decode).
    pub fn take_pending(&mut self, key: &TemplateKey) -> Vec<PendingRecord> {
        let recs = self.pending.remove(key).unwrap_or_default();
        let freed: usize = recs.iter().map(|r| r.bytes.len()).sum();
        self.pending_bytes = self.pending_bytes.saturating_sub(freed as u32);
        recs
    }

    /// Keys with at least one buffered pending record (for retry scans).
    pub fn pending_keys(&self) -> Vec<TemplateKey> {
        self.pending.keys().cloned().collect()
    }

    /// Drain every remaining pending record (end-of-scan flush). The caller emits
    /// each as a `missing-template` diagnostic row.
    pub fn drain_pending(&mut self) -> Vec<(TemplateKey, Vec<PendingRecord>)> {
        self.pending_bytes = 0;
        std::mem::take(&mut self.pending).into_iter().collect()
    }

    /// `true` when nothing is buffered.
    pub fn pending_is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Serialize to bytes for VGI scan-state hand-off (JSON — robust + small;
    /// the cache holds template layouts, not flow data).
    ///
    /// The `BTreeMap` keys are structs, which JSON cannot use as object keys, so
    /// the maps are flattened to arrays of `[key, value]` pairs (`CacheDto`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let dto = CacheDto {
            entries: self
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            pending: self
                .pending
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            cap_entries: self.cap_entries,
            cap_pending_bytes: self.cap_pending_bytes,
        };
        serde_json::to_vec(&dto).unwrap_or_default()
    }

    /// Deserialize from scan-state bytes; an empty / corrupt token degrades to a
    /// fresh empty cache rather than erroring.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::new();
        }
        match serde_json::from_slice::<CacheDto>(bytes) {
            Ok(dto) => {
                let mut c = TemplateCache {
                    entries: dto.entries.into_iter().collect(),
                    pending: dto.pending.into_iter().collect(),
                    cap_entries: dto.cap_entries,
                    cap_pending_bytes: dto.cap_pending_bytes,
                    pending_bytes: 0,
                };
                c.pending_bytes = c
                    .pending
                    .values()
                    .flat_map(|v| v.iter())
                    .map(|r| r.bytes.len() as u32)
                    .sum();
                c
            }
            Err(_) => Self::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(exp: &str, dom: u32, tid: u16) -> TemplateKey {
        TemplateKey {
            exporter: exp.to_string(),
            obs_domain: dom,
            template_id: tid,
        }
    }

    fn entry(now: i64) -> TemplateEntry {
        TemplateEntry {
            kind: TemplateKind::Data,
            fields: vec![FieldSpec {
                ie_id: 8,
                enterprise_number: 0,
                length: 4,
                name: "sourceIPv4Address".into(),
                ie_type: "ipv4Address".into(),
            }],
            scope_field_count: 0,
            first_seen: now,
            last_seen: now,
            use_count: 0,
        }
    }

    #[test]
    fn serde_round_trips_losslessly() {
        let mut c = TemplateCache::new();
        c.upsert(key("r1", 0, 256), entry(100));
        c.push_pending(
            key("r1", 0, 300),
            PendingRecord {
                export_time: Some(123),
                sequence: Some(9),
                version: "9".into(),
                sys_uptime_ms: Some(1000),
                bytes: vec![1, 2, 3, 4],
            },
        );
        let bytes = c.to_bytes();
        let back = TemplateCache::from_bytes(&bytes);
        assert_eq!(c.entries, back.entries);
        assert_eq!(c.pending, back.pending);
    }

    #[test]
    fn two_exporters_do_not_collide_on_template_256() {
        let mut c = TemplateCache::new();
        let mut e1 = entry(1);
        e1.fields[0].ie_id = 8;
        let mut e2 = entry(2);
        e2.fields[0].ie_id = 27; // different layout, same template id
        c.upsert(key("routerA", 0, 256), e1);
        c.upsert(key("routerB", 0, 256), e2);
        assert_eq!(c.peek(&key("routerA", 0, 256)).unwrap().fields[0].ie_id, 8);
        assert_eq!(c.peek(&key("routerB", 0, 256)).unwrap().fields[0].ie_id, 27);
    }

    #[test]
    fn redefinition_replaces_layout_keeps_first_seen() {
        let mut c = TemplateCache::new();
        c.upsert(key("r", 0, 256), entry(100));
        let mut redef = entry(200);
        redef.fields[0].ie_id = 12;
        c.upsert(key("r", 0, 256), redef);
        let got = c.peek(&key("r", 0, 256)).unwrap();
        assert_eq!(got.fields[0].ie_id, 12);
        assert_eq!(
            got.first_seen, 100,
            "first_seen preserved across redefinition"
        );
    }

    #[test]
    fn pending_buffer_is_bounded() {
        let mut c = TemplateCache::new();
        c.cap_pending_bytes = 8;
        let pr = || PendingRecord {
            export_time: None,
            sequence: None,
            version: "9".into(),
            sys_uptime_ms: None,
            bytes: vec![0; 6],
        };
        assert!(c.push_pending(key("r", 0, 1), pr()));
        // Second push would exceed the 8-byte cap → refused.
        assert!(!c.push_pending(key("r", 0, 1), pr()));
    }

    #[test]
    fn lru_eviction_drops_oldest() {
        let mut c = TemplateCache::new();
        c.cap_entries = 2;
        c.upsert(key("r", 0, 1), entry(10));
        c.upsert(key("r", 0, 2), entry(20));
        c.upsert(key("r", 0, 3), entry(30)); // evicts the oldest (last_seen=10)
        assert!(c.peek(&key("r", 0, 1)).is_none());
        assert!(c.peek(&key("r", 0, 2)).is_some());
        assert!(c.peek(&key("r", 0, 3)).is_some());
    }
}
