//! Table-in-out decode functions: `flows`, `netflow_decode`, `ipfix_decode`,
//! `sflow_decode`. Relation in, normalized flow rows out.
//!
//! DuckDB table functions reject correlated/per-row column arguments, so — like
//! `vgi-mft` — these are table-in-out functions: you pass a **relation** whose
//! columns are read by name, e.g.
//! `FROM netflow.main.flows((FROM (SELECT content AS datagram, filename AS exporter
//! FROM read_blob('caps/*.dat'))))`. The `exporter` column may therefore vary
//! per row (per-file cache scoping), which a literal table-function parameter
//! could not express.

mod flows;

use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef};
use arrow_schema::{DataType, Schema};
use vgi::Worker;
use vgi_rpc::{Result, RpcError};

/// Register every decode (table-in-out) function on the worker.
pub fn register(worker: &mut Worker) {
    use netflow_core::Restrict;
    worker.register_table_in_out(flows::FlowDecode::flows());
    worker.register_table_in_out(flows::FlowDecode::new(
        "netflow_decode",
        Restrict::NetflowOnly,
    ));
    worker.register_table_in_out(flows::FlowDecode::new("ipfix_decode", Restrict::IpfixOnly));
    worker.register_table_in_out(flows::FlowDecode::new("sflow_decode", Restrict::SflowOnly));
}

/// Locate the datagram BLOB column (named `datagram` / `content` / `blob`,
/// case-insensitive; else the first binary column).
pub(crate) fn find_datagram_col(schema: &Schema) -> Result<usize> {
    for want in ["datagram", "content", "blob"] {
        if let Some(i) = schema
            .fields()
            .iter()
            .position(|f| f.name().eq_ignore_ascii_case(want))
        {
            return Ok(i);
        }
    }
    schema
        .fields()
        .iter()
        .position(|f| matches!(f.data_type(), DataType::Binary | DataType::LargeBinary))
        .ok_or_else(|| {
            RpcError::value_error(
                "input relation must carry a `datagram` BLOB column of captured flow datagrams",
            )
        })
}

/// Locate an optional column by name (case-insensitive).
pub(crate) fn find_named_col(schema: &Schema, name: &str) -> Option<usize> {
    schema
        .fields()
        .iter()
        .position(|f| f.name().eq_ignore_ascii_case(name))
}

/// Read a VARCHAR cell as an owned string, or `None` if null / not a string col.
pub(crate) fn text_at(col: &ArrayRef, row: usize) -> Option<String> {
    if col.is_null(row) {
        return None;
    }
    match col.data_type() {
        DataType::Utf8 => Some(col.as_string::<i32>().value(row).to_string()),
        DataType::LargeUtf8 => Some(col.as_string::<i64>().value(row).to_string()),
        _ => None,
    }
}

/// Read an integer cell as `u32`, or `None` if null / not an integer col.
pub(crate) fn u32_at(col: &ArrayRef, row: usize) -> Option<u32> {
    use arrow_array::types::{
        Int16Type, Int32Type, Int64Type, Int8Type, UInt16Type, UInt32Type, UInt64Type, UInt8Type,
    };
    if col.is_null(row) {
        return None;
    }
    Some(match col.data_type() {
        DataType::UInt64 => col.as_primitive::<UInt64Type>().value(row) as u32,
        DataType::UInt32 => col.as_primitive::<UInt32Type>().value(row),
        DataType::UInt16 => col.as_primitive::<UInt16Type>().value(row) as u32,
        DataType::UInt8 => col.as_primitive::<UInt8Type>().value(row) as u32,
        DataType::Int64 => col.as_primitive::<Int64Type>().value(row) as u32,
        DataType::Int32 => col.as_primitive::<Int32Type>().value(row) as u32,
        DataType::Int16 => col.as_primitive::<Int16Type>().value(row) as u32,
        DataType::Int8 => col.as_primitive::<Int8Type>().value(row) as u32,
        _ => return None,
    })
}
