//! Integration tests: golden per-version fixtures, the template-state-across-
//! batches centerpiece, normalization rules, and the zero-panic proptest.

use netflow_core::cache::TemplateCache;
use netflow_core::decode::{decode_datagram, flush_pending, DecodeOptions, Mode, Restrict};
use netflow_core::fixtures;
use netflow_core::wellformed::well_formed;

fn opts(exporter: &str) -> DecodeOptions {
    DecodeOptions {
        exporter: exporter.to_string(),
        now_micros: 1_700_000_000_000_000,
        ..Default::default()
    }
}

fn decode(data: &[u8], cache: &mut TemplateCache, exporter: &str) -> Vec<netflow_core::FlowRecord> {
    decode_datagram(data, &opts(exporter), cache, Restrict::Any)
}

// ------------------------------------------------------------------ NetFlow v5

#[test]
fn v5_decodes_two_records() {
    let mut c = TemplateCache::new();
    let rows = decode(&fixtures::netflow_v5(), &mut c, "r1");
    assert_eq!(rows.len(), 2);
    let r0 = &rows[0];
    assert_eq!(r0.flow_version, "5");
    assert_eq!(
        r0.src_addr.map(|a| a.to_ip_string()),
        Some("10.0.0.1".to_string())
    );
    assert_eq!(
        r0.dst_addr.map(|a| a.to_ip_string()),
        Some("10.0.0.2".to_string())
    );
    assert_eq!(r0.src_port, Some(1234));
    assert_eq!(r0.dst_port, Some(80));
    assert_eq!(r0.protocol, Some(6));
    assert_eq!(r0.bytes, Some(1000));
    assert_eq!(r0.packets, Some(10));
    assert_eq!(r0.src_as, Some(64500));
    assert!(r0.diagnostics.is_none());
    // sysUptime-delta time resolution: boot = export - uptime; start = boot + First.
    let export = fixtures::EXPORT_UNIX_SECS as i64 * 1_000_000;
    let boot = export - fixtures::V9_SYS_UPTIME_MS as i64 * 1_000;
    assert_eq!(r0.flow_start, Some(boot + 90_000 * 1_000));
    assert_eq!(r0.flow_end, Some(boot + 95_000 * 1_000));
    assert_eq!(rows[1].protocol, Some(17));
}

// ------------------------------------------------------------------ NetFlow v9

#[test]
fn v9_combined_template_then_data_one_datagram() {
    let mut c = TemplateCache::new();
    let rows = decode(&fixtures::netflow_v9_combined(), &mut c, "r1");
    let flows: Vec<_> = rows
        .iter()
        .filter(|r| r.diagnostics.is_none() && r.src_addr.is_some())
        .collect();
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0].src_addr.map(|a| a.to_ip_string()),
        Some("172.16.0.1".to_string())
    );
    assert_eq!(flows[0].dst_port, Some(22));
    assert_eq!(flows[0].packets, Some(3));
    assert_eq!(flows[0].bytes, Some(180));
}

#[test]
fn v9_template_in_batch_one_data_in_batch_n() {
    // THE centerpiece: template arrives first, data many "batches" later.
    let mut c = TemplateCache::new();
    let primed = decode(&fixtures::netflow_v9_template(), &mut c, "r1");
    assert!(
        primed.iter().all(|r| r.src_addr.is_none()),
        "template datagram yields no flows"
    );
    assert!(c
        .peek(&netflow_core::cache::TemplateKey {
            exporter: "r1".into(),
            obs_domain: fixtures::V9_OBS_DOMAIN,
            template_id: fixtures::V9_TEMPLATE_ID,
        })
        .is_some());

    let rows = decode(&fixtures::netflow_v9_data(), &mut c, "r1");
    let flows: Vec<_> = rows.iter().filter(|r| r.src_addr.is_some()).collect();
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0].src_addr.map(|a| a.to_ip_string()),
        Some("10.1.1.1".to_string())
    );
    assert_eq!(flows[0].dst_port, Some(443));
}

#[test]
fn v9_data_before_template_is_buffered_then_retried() {
    let mut c = TemplateCache::new();
    // Data first: nothing decodable yet, buffered (no missing-template emitted
    // until end of scan because the pending buffer has room).
    let early = decode(&fixtures::netflow_v9_data(), &mut c, "r1");
    assert!(early.iter().all(|r| r.src_addr.is_none()));
    assert!(!c.pending_is_empty());
    // Template arrives: the buffered data is retried and resolves.
    let resolved = decode(&fixtures::netflow_v9_template(), &mut c, "r1");
    let flows: Vec<_> = resolved.iter().filter(|r| r.src_addr.is_some()).collect();
    assert_eq!(
        flows.len(),
        1,
        "buffered data decodes once its template appears"
    );
    assert!(c.pending_is_empty());
}

#[test]
fn missing_template_flushed_as_diagnostic_never_dropped() {
    let mut c = TemplateCache::new();
    let _ = decode(&fixtures::netflow_v9_data(), &mut c, "r1");
    // Template never arrives → flush emits a missing-template row.
    let flushed = flush_pending(&mut c);
    assert_eq!(flushed.len(), 1);
    let diag = flushed[0].diagnostics.as_deref().unwrap();
    assert!(diag.starts_with("missing-template:"), "got {diag}");
    assert!(c.pending_is_empty());
}

#[test]
fn two_exporters_reusing_template_256_do_not_collide() {
    let mut c = TemplateCache::new();
    // routerA learns template 256; routerB's data for 256 must NOT use it.
    let _ = decode(&fixtures::netflow_v9_template(), &mut c, "routerA");
    let b_rows = decode(&fixtures::netflow_v9_data(), &mut c, "routerB");
    assert!(
        b_rows.iter().all(|r| r.src_addr.is_none()),
        "routerB has no template 256 of its own"
    );
    assert!(
        !c.pending_is_empty(),
        "routerB data is buffered, not decoded with routerA's layout"
    );
}

#[test]
fn cache_round_trips_between_datagrams_http_rehydration() {
    // Prime, serialize → bytes → deserialize (simulating HTTP worker teardown),
    // then decode data with the rehydrated cache.
    let mut c = TemplateCache::new();
    let _ = decode(&fixtures::netflow_v9_template(), &mut c, "r1");
    let bytes = c.to_bytes();
    let mut rehydrated = TemplateCache::from_bytes(&bytes);
    let rows = decode(&fixtures::netflow_v9_data(), &mut rehydrated, "r1");
    assert_eq!(rows.iter().filter(|r| r.src_addr.is_some()).count(), 1);
}

// ------------------------------------------------------------------ IPFIX

#[test]
fn ipfix_basic_decodes_with_absolute_timestamps() {
    let mut c = TemplateCache::new();
    let rows = decode(&fixtures::ipfix_basic(), &mut c, "r1");
    let flows: Vec<_> = rows.iter().filter(|r| r.src_addr.is_some()).collect();
    assert_eq!(flows.len(), 1);
    let f = flows[0];
    assert_eq!(f.flow_version, "10");
    assert_eq!(
        f.src_addr.map(|a| a.to_ip_string()),
        Some("203.0.113.5".to_string())
    );
    assert_eq!(
        f.dst_addr.map(|a| a.to_ip_string()),
        Some("198.51.100.9".to_string())
    );
    assert_eq!(f.dst_port, Some(443));
    assert_eq!(f.bytes, Some(1_500_000));
    assert_eq!(f.packets, Some(1_200));
    // flowStartMilliseconds 1_700_000_000_000 ms → micros = ms * 1000.
    assert_eq!(f.flow_start, Some(1_700_000_000_000 * 1_000));
    assert_eq!(f.flow_end, Some(1_700_000_010_000 * 1_000));
}

#[test]
fn ipfix_variable_length_and_enterprise_ies() {
    let mut c = TemplateCache::new();
    let rows = decode(&fixtures::ipfix_variable_enterprise(), &mut c, "r1");
    let f = rows
        .iter()
        .find(|r| r.src_addr.is_some())
        .expect("a flow row");
    assert_eq!(
        f.src_addr.map(|a| a.to_ip_string()),
        Some("10.9.9.1".to_string())
    );
    // Variable-length interfaceName lands in raw_fields with its exact bytes.
    let ifname = f
        .raw_fields
        .iter()
        .find(|(k, _)| k == "interfaceName")
        .map(|(_, v)| v.clone());
    assert_eq!(ifname.as_deref(), Some(b"eth0".as_ref()));
    // Enterprise IE (VMware PEN 6876 id 880) resolves to its vendor name.
    assert!(f
        .raw_fields
        .iter()
        .any(|(k, _)| k == "vmware.tenantProtocol"));
}

#[test]
fn ipfix_options_record_carries_sampling() {
    let mut c = TemplateCache::new();
    let rows = decode(&fixtures::ipfix_options(), &mut c, "r1");
    // Auto mode keeps options records.
    let opt = rows
        .iter()
        .find(|r| r.sampling_rate.is_some())
        .expect("options record");
    assert_eq!(opt.sampling_rate, Some(1000));
    assert_eq!(opt.template_id, Some(fixtures::IPFIX_OPTIONS_TEMPLATE_ID));

    // flows-only mode drops options records.
    let mut c2 = TemplateCache::new();
    let o2 = DecodeOptions {
        mode: Mode::FlowsOnly,
        ..opts("r1")
    };
    let rows2 = decode_datagram(&fixtures::ipfix_options(), &o2, &mut c2, Restrict::Any);
    assert!(rows2.iter().all(|r| r.sampling_rate.is_none()));
}

// ------------------------------------------------------------------ sFlow

#[test]
fn sflow_flow_and_counter_samples() {
    let mut c = TemplateCache::new();
    let rows = decode(&fixtures::sflow_basic(), &mut c, "r1");
    let flow = rows
        .iter()
        .find(|r| r.src_addr.is_some())
        .expect("flow sample");
    assert_eq!(flow.flow_version, "sflow5");
    assert_eq!(
        flow.src_addr.map(|a| a.to_ip_string()),
        Some("192.0.2.10".to_string())
    );
    assert_eq!(flow.dst_port, Some(80));
    assert_eq!(flow.protocol, Some(6));
    assert_eq!(flow.sampling_rate, Some(4096));
    // bytes scaled by sampling rate (64 * 4096); unscaled length preserved.
    assert_eq!(flow.bytes, Some(64 * 4096));
    assert!(flow
        .raw_fields
        .iter()
        .any(|(k, _)| k == "sflow.frame_length"));

    // Counter sample present in auto mode, dropped in flows-only.
    assert!(rows
        .iter()
        .any(|r| r.diagnostics.as_deref() == Some("counter-sample")));
    let o = DecodeOptions {
        mode: Mode::FlowsOnly,
        ..opts("r1")
    };
    let fo = decode_datagram(
        &fixtures::sflow_basic(),
        &o,
        &mut TemplateCache::new(),
        Restrict::Any,
    );
    assert!(fo
        .iter()
        .all(|r| r.diagnostics.as_deref() != Some("counter-sample")));
}

// ------------------------------------------------------------------ restrict

#[test]
fn restrict_rejects_wrong_format_via_diagnostic() {
    let mut c = TemplateCache::new();
    // ipfix_decode (IpfixOnly) on a v5 datagram → decode-error, never a panic.
    let rows = decode_datagram(
        &fixtures::netflow_v5(),
        &opts("r1"),
        &mut c,
        Restrict::IpfixOnly,
    );
    assert!(rows.iter().all(|r| r.diagnostics.is_some()));
    assert!(rows[0]
        .diagnostics
        .as_deref()
        .unwrap()
        .starts_with("decode-error:"));
}

// ------------------------------------------------------------------ well_formed

#[test]
fn well_formed_classifies_inputs() {
    assert!(well_formed(&fixtures::netflow_v5()).ok);
    assert!(well_formed(&fixtures::ipfix_basic()).ok);
    assert!(well_formed(&fixtures::sflow_basic()).ok);
    let g = well_formed(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(!g.ok);
    assert_eq!(g.kind.as_deref(), Some("not-a-flow-datagram"));
}

// ------------------------------------------------------------------ zero-panic

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// No arbitrary byte string may panic any decoder or the validator.
        #[test]
        fn decoders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..600)) {
            let o = opts("fuzz");
            for restrict in [Restrict::Any, Restrict::NetflowOnly, Restrict::IpfixOnly, Restrict::SflowOnly] {
                let mut c = TemplateCache::new();
                let _ = decode_datagram(&data, &o, &mut c, restrict);
                let _ = flush_pending(&mut c);
            }
            let _ = well_formed(&data);
        }

        /// Truncating a valid datagram at any length must never panic.
        #[test]
        fn truncated_valid_datagrams_never_panic(cut in 0usize..400) {
            for full in [fixtures::netflow_v5(), fixtures::netflow_v9_combined(),
                         fixtures::ipfix_basic(), fixtures::sflow_basic()] {
                let n = cut.min(full.len());
                let mut c = TemplateCache::new();
                let _ = decode_datagram(&full[..n], &opts("t"), &mut c, Restrict::Any);
                let _ = well_formed(&full[..n]);
            }
        }
    }
}
