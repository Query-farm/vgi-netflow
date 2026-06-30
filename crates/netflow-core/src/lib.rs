//! `netflow-core` — pure NetFlow v5 / v9, IPFIX, and sFlow v5 flow-export
//! datagram decoders plus the serde template cache (the VGI scan state).
//!
//! No Arrow / VGI / network dependencies: all wire-format correctness, the
//! template-state engine (§2–3), the bundled IANA / enterprise IE registry (§4),
//! and the normalized cross-version schema (§5) live here and are unit-tested
//! directly. The `netflow-worker` crate is a thin Arrow / VGI adapter over this.
//!
//! ## Robustness
//!
//! Every decoder is fed untrusted bytes; reads are bounds-checked through
//! [`buf::Cursor`], declared lengths are validated before slicing (a hostile
//! "length = 4 GB" allocates nothing), and a malformed datagram yields a row (or
//! [`wellformed::WellFormed`]) with a diagnostic rather than a panic. A proptest
//! drives arbitrary / truncated bytes through every entry point asserting
//! zero panics (see `tests/`).
#![forbid(unsafe_code)]

pub mod buf;
pub mod cache;
pub mod decode;
pub mod fixtures;
pub mod inet;
pub mod normalize;
pub mod registry;
pub mod wellformed;

pub use cache::TemplateCache;
pub use decode::{decode_datagram, flush_pending, retry_pending, DecodeOptions, Mode, Restrict};
pub use inet::InetVal;
pub use normalize::FlowRecord;
pub use wellformed::{well_formed, WellFormed};

/// The worker's build version (the crate's Cargo version), surfaced by the
/// `netflow_version()` scalar.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
