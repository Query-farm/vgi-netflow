//! Externalized scan-state plumbing: load / store the [`TemplateCache`] through
//! the VGI `FunctionStorage` so a template learned in batch 1 decodes data in
//! batch 9,000 — and survives an HTTP worker teardown/rehydration between calls.
//!
//! The cache is threaded per **execution** (scoped by `execution_id`), which is
//! the faithful VGI scan-state model: isolated, deterministic, race-free across a
//! single scan's batches. Each store also mirrors the learned template layouts
//! into a process-global projection so the `templates()` introspection function
//! can report "what have I learned" across statements.

use netflow_core::TemplateCache;
use vgi::storage::SharedStorage;
use vgi::ProcessParams;

/// Per-execution cache key (within `execution_id` scope).
const CACHE_KEY: &[u8] = b"netflow.cache";
/// Global projection scope (for `templates()`).
const GLOBAL_SCOPE: &[u8] = b"netflow:global";

/// Load the cache for this scan (empty on cold start or when storage is absent).
pub fn load_scan_cache(params: &ProcessParams) -> TemplateCache {
    match &params.storage {
        Some(store) => {
            let bytes = store
                .kv_get(&params.execution_id, CACHE_KEY)
                .unwrap_or_default();
            TemplateCache::from_bytes(&bytes)
        }
        None => TemplateCache::new(),
    }
}

/// Persist the cache for this scan and merge its learned templates into the
/// global projection used by `templates()`.
pub fn store_scan_cache(params: &ProcessParams, cache: &TemplateCache) {
    let Some(store) = &params.storage else {
        return;
    };
    store.kv_put(&params.execution_id, CACHE_KEY, &cache.to_bytes());

    // Mirror learned layouts (not the pending buffer) into the global projection.
    let mut global =
        TemplateCache::from_bytes(&store.kv_get(GLOBAL_SCOPE, CACHE_KEY).unwrap_or_default());
    for (k, v) in &cache.entries {
        global.upsert(k.clone(), v.clone());
    }
    store.kv_put(GLOBAL_SCOPE, CACHE_KEY, &global.to_bytes());
}

/// Read the global template projection (for `templates()`).
pub fn global_cache(storage: &Option<SharedStorage>) -> TemplateCache {
    match storage {
        Some(store) => {
            TemplateCache::from_bytes(&store.kv_get(GLOBAL_SCOPE, CACHE_KEY).unwrap_or_default())
        }
        None => TemplateCache::new(),
    }
}
