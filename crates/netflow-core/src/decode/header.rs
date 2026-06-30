//! Export-header parsing and the cheap version probe.

use crate::buf::Cursor;

/// A decoded export header, normalized across the four formats. Fields that a
/// given format does not carry are `None`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExportHeader {
    pub version: u16,
    pub count: Option<u16>,
    pub sys_uptime: Option<u32>,
    /// Microseconds since the Unix epoch (UTC).
    pub export_time: Option<i64>,
    pub sequence: Option<u64>,
    pub obs_domain: Option<u32>,
}

/// Cheap leading-bytes probe: `"5"`, `"9"`, `"10"`, `"sflow5"`, or `None`.
///
/// NetFlow v5/v9/IPFIX put a 2-byte version first (5 / 9 / 10). sFlow v5 puts a
/// 4-byte version (== 5), so its first two bytes are `0x0000` and the value at
/// offset 0 read as a u32 is `5` — distinguishing it from NetFlow v5.
pub fn probe_version(data: &[u8]) -> Option<&'static str> {
    let mut c = Cursor::new(data);
    let v16 = c.u16()?;
    match v16 {
        5 => Some("5"),
        9 => Some("9"),
        10 => Some("10"),
        0 => {
            // Possible sFlow: u32 version at offset 0 == 5, and a sane agent
            // address type (1 = IPv4, 2 = IPv6) follows.
            let lo = c.u16()?;
            if lo == 5 {
                let addr_type = Cursor::new(data);
                let mut t = addr_type;
                t.skip(4);
                match t.u32() {
                    Some(1) | Some(2) => Some("sflow5"),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Parse the export header for the `header()` scalar (and internal dispatch).
pub fn parse_header(data: &[u8]) -> Option<ExportHeader> {
    match probe_version(data)? {
        "5" => parse_v5(data),
        "9" => parse_v9(data),
        "10" => parse_ipfix(data),
        "sflow5" => parse_sflow(data),
        _ => None,
    }
}

fn parse_v5(data: &[u8]) -> Option<ExportHeader> {
    let mut c = Cursor::new(data);
    let version = c.u16()?;
    let count = c.u16()?;
    let sys_uptime = c.u32()?;
    let unix_secs = c.u32()?;
    let unix_nsecs = c.u32()?;
    let sequence = c.u32()?;
    let _engine_type = c.u8()?;
    let engine_id = c.u8()?;
    let export_time = unix_secs as i64 * 1_000_000 + (unix_nsecs as i64) / 1_000;
    Some(ExportHeader {
        version,
        count: Some(count),
        sys_uptime: Some(sys_uptime),
        export_time: Some(export_time),
        sequence: Some(sequence as u64),
        obs_domain: Some(engine_id as u32),
    })
}

fn parse_v9(data: &[u8]) -> Option<ExportHeader> {
    let mut c = Cursor::new(data);
    let version = c.u16()?;
    let count = c.u16()?;
    let sys_uptime = c.u32()?;
    let unix_secs = c.u32()?;
    let sequence = c.u32()?;
    let source_id = c.u32()?;
    Some(ExportHeader {
        version,
        count: Some(count),
        sys_uptime: Some(sys_uptime),
        export_time: Some(unix_secs as i64 * 1_000_000),
        sequence: Some(sequence as u64),
        obs_domain: Some(source_id),
    })
}

fn parse_ipfix(data: &[u8]) -> Option<ExportHeader> {
    let mut c = Cursor::new(data);
    let version = c.u16()?;
    let _length = c.u16()?;
    let export_secs = c.u32()?;
    let sequence = c.u32()?;
    let obs_domain = c.u32()?;
    Some(ExportHeader {
        version,
        count: None,
        sys_uptime: None,
        export_time: Some(export_secs as i64 * 1_000_000),
        sequence: Some(sequence as u64),
        obs_domain: Some(obs_domain),
    })
}

fn parse_sflow(data: &[u8]) -> Option<ExportHeader> {
    let mut c = Cursor::new(data);
    let _version = c.u32()?; // == 5
    let addr_type = c.u32()?;
    match addr_type {
        1 => {
            c.skip(4);
        }
        2 => {
            c.skip(16);
        }
        _ => return None,
    }
    let sub_agent_id = c.u32()?;
    let sequence = c.u32()?;
    let uptime = c.u32()?;
    let num_samples = c.u32()?;
    Some(ExportHeader {
        version: 5,
        count: Some(num_samples.min(u16::MAX as u32) as u16),
        sys_uptime: Some(uptime),
        export_time: None,
        sequence: Some(sequence as u64),
        obs_domain: Some(sub_agent_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_distinguishes_formats() {
        assert_eq!(probe_version(&[0x00, 0x05]), Some("5"));
        assert_eq!(probe_version(&[0x00, 0x09]), Some("9"));
        assert_eq!(probe_version(&[0x00, 0x0a]), Some("10"));
        // sFlow: version u32 == 5, agent type IPv4.
        assert_eq!(probe_version(&[0, 0, 0, 5, 0, 0, 0, 1]), Some("sflow5"));
        assert_eq!(probe_version(&[0xde, 0xad]), None);
        assert_eq!(probe_version(&[]), None);
    }
}
