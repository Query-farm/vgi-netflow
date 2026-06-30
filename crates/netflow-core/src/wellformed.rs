//! `well_formed()` validation — structural soundness without full decode.
//!
//! Never panics: a hostile / garbage blob returns `ok = false` with a `kind`
//! rather than crashing the scan.

use crate::buf::Cursor;
use crate::decode::header::{parse_header, probe_version};

/// The result of [`well_formed`].
#[derive(Clone, Debug, PartialEq)]
pub struct WellFormed {
    pub ok: bool,
    /// `"5"`/`"9"`/`"10"`/`"sflow5"`, or `None` for an unrecognized datagram.
    pub version: Option<String>,
    pub error: Option<String>,
    /// `truncated` | `bad-version` | `set-length-overrun` | `bad-ipfix-set` |
    /// `short-record` | `not-a-flow-datagram`, or `None` when `ok`.
    pub kind: Option<String>,
}

impl WellFormed {
    fn ok(version: &str) -> Self {
        WellFormed {
            ok: true,
            version: Some(version.to_string()),
            error: None,
            kind: None,
        }
    }
    fn bad(version: Option<&str>, error: &str, kind: &str) -> Self {
        WellFormed {
            ok: false,
            version: version.map(str::to_string),
            error: Some(error.to_string()),
            kind: Some(kind.to_string()),
        }
    }
}

/// Validate a flow-export datagram's structure.
pub fn well_formed(data: &[u8]) -> WellFormed {
    let Some(version) = probe_version(data) else {
        return WellFormed::bad(
            None,
            "leading bytes match no known flow header",
            "not-a-flow-datagram",
        );
    };
    match version {
        "5" => validate_v5(data),
        "9" => validate_v9(data),
        "10" => validate_ipfix(data),
        "sflow5" => validate_sflow(data),
        _ => WellFormed::bad(None, "unknown version", "bad-version"),
    }
}

fn validate_v5(data: &[u8]) -> WellFormed {
    if data.len() < 24 {
        return WellFormed::bad(Some("5"), "datagram shorter than v5 header", "truncated");
    }
    let Some(hdr) = parse_header(data) else {
        return WellFormed::bad(Some("5"), "v5 header parse failed", "truncated");
    };
    let count = hdr.count.unwrap_or(0) as usize;
    let need = 24 + count * 48;
    if data.len() < need {
        return WellFormed::bad(
            Some("5"),
            "declared record count exceeds datagram length",
            "short-record",
        );
    }
    WellFormed::ok("5")
}

fn validate_v9(data: &[u8]) -> WellFormed {
    if data.len() < 20 {
        return WellFormed::bad(Some("9"), "datagram shorter than v9 header", "truncated");
    }
    validate_sets(&data[20..], "9", "set-length-overrun")
}

fn validate_ipfix(data: &[u8]) -> WellFormed {
    if data.len() < 16 {
        return WellFormed::bad(
            Some("10"),
            "datagram shorter than IPFIX header",
            "truncated",
        );
    }
    // IPFIX header carries a total `length`; validate it against the buffer.
    let declared = u16::from_be_bytes([data[2], data[3]]) as usize;
    if declared < 16 || declared > data.len() {
        return WellFormed::bad(
            Some("10"),
            "IPFIX header length out of range",
            "bad-ipfix-set",
        );
    }
    validate_sets(&data[16..declared], "10", "bad-ipfix-set")
}

/// Walk Set/FlowSet headers, validating each declared length.
fn validate_sets(mut region: &[u8], version: &str, overrun_kind: &str) -> WellFormed {
    while !region.is_empty() {
        if region.len() < 4 {
            return WellFormed::bad(
                Some(version),
                "trailing bytes shorter than a set header",
                "truncated",
            );
        }
        let length = u16::from_be_bytes([region[2], region[3]]) as usize;
        if length < 4 {
            return WellFormed::bad(
                Some(version),
                "set length below the 4-byte minimum",
                overrun_kind,
            );
        }
        if length > region.len() {
            return WellFormed::bad(
                Some(version),
                "set length exceeds remaining datagram",
                overrun_kind,
            );
        }
        region = &region[length..];
    }
    WellFormed::ok(version)
}

fn validate_sflow(data: &[u8]) -> WellFormed {
    let mut c = Cursor::new(data);
    let ok = (|| {
        c.u32()?; // version
        let addr_type = c.u32()?;
        match addr_type {
            1 => c.skip(4),
            2 => c.skip(16),
            _ => return None,
        };
        c.u32()?; // sub_agent_id
        c.u32()?; // sequence
        c.u32()?; // uptime
        c.u32()?; // num_samples
        Some(())
    })();
    match ok {
        Some(()) => WellFormed::ok("sflow5"),
        None => WellFormed::bad(Some("sflow5"), "sFlow header truncated", "truncated"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_not_a_flow_datagram() {
        let r = well_formed(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(!r.ok);
        assert_eq!(r.kind.as_deref(), Some("not-a-flow-datagram"));
    }

    #[test]
    fn truncated_v9_header() {
        let r = well_formed(&[0x00, 0x09, 0x00]);
        assert_eq!(r.kind.as_deref(), Some("truncated"));
    }
}
