//! Normalized [`FlowRecord`] → Apache Arrow mapping (the §5 wide schema).
//!
//! Column types are chosen so DuckDB sees the intended logical types: unsigned
//! Arrow ints → `U*` DuckDB ints, `Timestamp(µs, "UTC")` → `TIMESTAMPTZ`, the
//! `raw_fields` `Map(Utf8 → Binary)` → `MAP(VARCHAR, BLOB)`, and the address
//! columns → DuckDB's physical `INET` struct.
//!
//! ## INET addressing
//!
//! `src_addr` / `dst_addr` / `next_hop` are emitted as DuckDB's internal `INET`
//! layout — `STRUCT(ip_type UInt8, address FixedSizeBinary(16)→HUGEINT, mask
//! UInt16)` (the `address` child carries the `arrow.opaque`/`hugeint` extension
//! metadata). DuckDB imports an `INET` back as exactly that struct (the logical
//! type does not round-trip through Arrow), so a scanned address is a zero-cost
//! `::INET` cast from native `INET` and containment joins work:
//! `src_addr::INET <<= '10.0.0.0/8'::INET`. (DuckDB's `inet` uses `<<=` / `>>=`
//! for containment — it has no `&&` operator.)

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBufferBuilder, FixedSizeBinaryBuilder, StringBuilder, UInt16Builder,
    UInt8Builder,
};
use arrow_array::{
    ArrayRef, MapArray, RecordBatch, StringArray, StructArray, TimestampMicrosecondArray,
    UInt16Array, UInt32Array, UInt64Array, UInt8Array,
};
use arrow_buffer::{NullBuffer, OffsetBuffer};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef, TimeUnit};
use netflow_core::{FlowRecord, InetVal};
use vgi_rpc::{Result, RpcError};

const UTC: &str = "UTC";

fn ts() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some(UTC.into()))
}

// --------------------------------------------------------------------- INET

/// The metadata DuckDB needs to read a `FixedSizeBinary(16)` as a `HUGEINT`.
fn hugeint_metadata() -> HashMap<String, String> {
    HashMap::from([
        (
            "ARROW:extension:name".to_string(),
            "arrow.opaque".to_string(),
        ),
        (
            "ARROW:extension:metadata".to_string(),
            "{\"type_name\":\"hugeint\",\"vendor_name\":\"DuckDB\"}".to_string(),
        ),
    ])
}

/// The three child fields of the `INET` struct.
fn inet_child_fields() -> Fields {
    Fields::from(vec![
        Field::new("ip_type", DataType::UInt8, false),
        Field::new("address", DataType::FixedSizeBinary(16), false)
            .with_metadata(hugeint_metadata()),
        Field::new("mask", DataType::UInt16, false),
    ])
}

fn inet_type() -> DataType {
    DataType::Struct(inet_child_fields())
}

/// Build the `INET` struct column from per-row optional address values.
fn build_inet(vals: impl Iterator<Item = Option<InetVal>>, n: usize) -> ArrayRef {
    let mut ip_type = UInt8Builder::with_capacity(n);
    let mut address = FixedSizeBinaryBuilder::with_capacity(n, 16);
    let mut mask = UInt16Builder::with_capacity(n);
    let mut validity = BooleanBufferBuilder::new(n);
    for v in vals {
        match v {
            Some(iv) => {
                ip_type.append_value(iv.ip_type);
                address
                    .append_value(iv.address_le)
                    .expect("16-byte address");
                mask.append_value(iv.mask);
                validity.append(true);
            }
            None => {
                ip_type.append_value(0);
                address.append_value([0u8; 16]).expect("16-byte address");
                mask.append_value(0);
                validity.append(false);
            }
        }
    }
    let children: Vec<ArrayRef> = vec![
        Arc::new(ip_type.finish()),
        Arc::new(address.finish()),
        Arc::new(mask.finish()),
    ];
    Arc::new(StructArray::new(
        inet_child_fields(),
        children,
        Some(NullBuffer::new(validity.finish())),
    ))
}

// ------------------------------------------------------------------- raw_fields

/// The `entries` struct field for the `raw_fields` MAP — shared by the schema and
/// the array builder so their types match exactly.
fn map_entries_field() -> Field {
    Field::new(
        "entries",
        DataType::Struct(Fields::from(vec![
            Field::new("key", DataType::Utf8, false),
            Field::new("value", DataType::Binary, true),
        ])),
        false,
    )
}

fn raw_fields_type() -> DataType {
    DataType::Map(Arc::new(map_entries_field()), false)
}

/// A column field carrying a `comment` (surfaced via `duckdb_columns().comment`).
fn col(name: &str, dt: DataType, comment: &str) -> Field {
    Field::new(name, dt, true).with_metadata(HashMap::from([(
        "comment".to_string(),
        comment.to_string(),
    )]))
}

/// The normalized flow output schema (§5). Used by every decode function's
/// `on_bind` and built against in `process`.
pub fn flow_schema() -> SchemaRef {
    use DataType::*;
    Arc::new(Schema::new(vec![
        col(
            "exporter",
            Utf8,
            "Cache key / source device (as supplied via exporter:= or derived).",
        ),
        col(
            "flow_version",
            Utf8,
            "Wire format: '5', '9', '10' (IPFIX), or 'sflow5'.",
        ),
        col(
            "obs_domain",
            UInt32,
            "v9 source-id / IPFIX observation domain (template-id namespace).",
        ),
        col(
            "template_id",
            UInt16,
            "v9/IPFIX template id; NULL for v5 / sFlow.",
        ),
        col(
            "export_time",
            ts(),
            "Datagram export time from the header (TIMESTAMPTZ).",
        ),
        col(
            "sequence",
            UInt64,
            "Export sequence number (gap-detection key).",
        ),
        col(
            "src_addr",
            inet_type(),
            "Source IP as INET (cast ::INET for <<= containment joins).",
        ),
        col(
            "dst_addr",
            inet_type(),
            "Destination IP as INET (cast ::INET for <<= containment joins).",
        ),
        col("src_port", UInt16, "L4 source port."),
        col("dst_port", UInt16, "L4 destination port."),
        col(
            "protocol",
            UInt8,
            "IP protocol number (6=TCP, 17=UDP, ...).",
        ),
        col("tcp_flags", UInt8, "Cumulative TCP control flags."),
        col(
            "bytes",
            UInt64,
            "Octet count (sFlow scaled by sampling_rate).",
        ),
        col("packets", UInt64, "Packet count (sFlow = sampling_rate)."),
        col("flow_start", ts(), "Flow start, resolved to TIMESTAMPTZ."),
        col("flow_end", ts(), "Flow end, resolved to TIMESTAMPTZ."),
        col("src_as", UInt32, "Origin AS number (when exported)."),
        col("dst_as", UInt32, "Peer AS number (when exported)."),
        col("input_snmp", UInt32, "Ingress interface ifIndex."),
        col("output_snmp", UInt32, "Egress interface ifIndex."),
        col("next_hop", inet_type(), "BGP/IP next hop as INET."),
        col("tos", UInt8, "IP ToS / DSCP byte."),
        col("src_mask", UInt8, "Source prefix length (v5/v9)."),
        col("dst_mask", UInt8, "Destination prefix length (v5/v9)."),
        col(
            "sampling_rate",
            UInt32,
            "sFlow sampling N / IPFIX samplingInterval; NULL if none.",
        ),
        col(
            "direction",
            UInt8,
            "flowDirection (0=ingress, 1=egress) when present.",
        ),
        col(
            "raw_fields",
            raw_fields_type(),
            "Every IE not mapped above, keyed by IE name → raw bytes.",
        ),
        col(
            "diagnostics",
            Utf8,
            "NULL on a clean decode; else missing-template/truncated/decode-error/...",
        ),
    ]))
}

/// Build a `RecordBatch` (against `schema`) from decoded rows.
pub fn rows_to_batch(rows: &[FlowRecord], schema: &SchemaRef) -> Result<RecordBatch> {
    let n = rows.len();
    let str_col = |f: &dyn Fn(&FlowRecord) -> Option<String>| -> ArrayRef {
        Arc::new(rows.iter().map(f).collect::<StringArray>())
    };
    let ts_col = |f: &dyn Fn(&FlowRecord) -> Option<i64>| -> ArrayRef {
        Arc::new(
            rows.iter()
                .map(f)
                .collect::<TimestampMicrosecondArray>()
                .with_timezone(UTC),
        )
    };

    let cols: Vec<ArrayRef> = vec![
        str_col(&|r| Some(r.exporter.clone())),
        str_col(&|r| Some(r.flow_version.clone())),
        Arc::new(
            rows.iter()
                .map(|r| Some(r.obs_domain))
                .collect::<UInt32Array>(),
        ),
        Arc::new(rows.iter().map(|r| r.template_id).collect::<UInt16Array>()),
        ts_col(&|r| r.export_time),
        Arc::new(rows.iter().map(|r| r.sequence).collect::<UInt64Array>()),
        build_inet(rows.iter().map(|r| r.src_addr), n),
        build_inet(rows.iter().map(|r| r.dst_addr), n),
        Arc::new(rows.iter().map(|r| r.src_port).collect::<UInt16Array>()),
        Arc::new(rows.iter().map(|r| r.dst_port).collect::<UInt16Array>()),
        Arc::new(rows.iter().map(|r| r.protocol).collect::<UInt8Array>()),
        Arc::new(rows.iter().map(|r| r.tcp_flags).collect::<UInt8Array>()),
        Arc::new(rows.iter().map(|r| r.bytes).collect::<UInt64Array>()),
        Arc::new(rows.iter().map(|r| r.packets).collect::<UInt64Array>()),
        ts_col(&|r| r.flow_start),
        ts_col(&|r| r.flow_end),
        Arc::new(rows.iter().map(|r| r.src_as).collect::<UInt32Array>()),
        Arc::new(rows.iter().map(|r| r.dst_as).collect::<UInt32Array>()),
        Arc::new(rows.iter().map(|r| r.input_snmp).collect::<UInt32Array>()),
        Arc::new(rows.iter().map(|r| r.output_snmp).collect::<UInt32Array>()),
        build_inet(rows.iter().map(|r| r.next_hop), n),
        Arc::new(rows.iter().map(|r| r.tos).collect::<UInt8Array>()),
        Arc::new(rows.iter().map(|r| r.src_mask).collect::<UInt8Array>()),
        Arc::new(rows.iter().map(|r| r.dst_mask).collect::<UInt8Array>()),
        Arc::new(
            rows.iter()
                .map(|r| r.sampling_rate)
                .collect::<UInt32Array>(),
        ),
        Arc::new(rows.iter().map(|r| r.direction).collect::<UInt8Array>()),
        build_raw_fields(rows)?,
        str_col(&|r| r.diagnostics.clone()),
    ];
    RecordBatch::try_new(schema.clone(), cols).map_err(|e| RpcError::runtime_error(e.to_string()))
}

/// Build the `raw_fields` `MapArray` (one map per row).
fn build_raw_fields(rows: &[FlowRecord]) -> Result<ArrayRef> {
    let mut keys = StringBuilder::new();
    let mut vals = BinaryBuilder::new();
    let mut offsets: Vec<i32> = Vec::with_capacity(rows.len() + 1);
    offsets.push(0);
    let mut running: i32 = 0;
    for r in rows {
        for (k, v) in &r.raw_fields {
            keys.append_value(k);
            vals.append_value(v);
        }
        running += r.raw_fields.len() as i32;
        offsets.push(running);
    }

    let entries = StructArray::from(vec![
        (
            Arc::new(Field::new("key", DataType::Utf8, false)),
            Arc::new(keys.finish()) as ArrayRef,
        ),
        (
            Arc::new(Field::new("value", DataType::Binary, true)),
            Arc::new(vals.finish()) as ArrayRef,
        ),
    ]);
    let map = MapArray::new(
        Arc::new(map_entries_field()),
        OffsetBuffer::new(offsets.into()),
        entries,
        None,
        false,
    );
    Ok(Arc::new(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netflow_core::inet::inet4;

    #[test]
    fn batch_round_trip_schema_matches() {
        let mut r = FlowRecord {
            exporter: "r1".into(),
            flow_version: "10".into(),
            obs_domain: 42,
            export_time: Some(1_700_000_000_000_000),
            src_addr: inet4(&[10, 0, 0, 1]),
            ..Default::default()
        };
        r.put_raw("interfaceName", b"eth0".to_vec());
        let schema = flow_schema();
        let batch = rows_to_batch(&[r], &schema).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.schema().fields(), schema.fields());
    }
}
