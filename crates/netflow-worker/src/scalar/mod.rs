//! Scalar functions: `flow_version`, `header`, `well_formed`.

mod flow_version;
mod header;
mod well_formed;

use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef};
use arrow_schema::DataType;
use vgi::Worker;
use vgi_rpc::{Result, RpcError};

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(flow_version::FlowVersion);
    worker.register_scalar(header::Header);
    worker.register_scalar(well_formed::WellFormed);
}

/// Borrow the bytes of a BLOB (`Binary` / `LargeBinary`) cell, or `None` if null.
/// Errors if the column is not a binary type.
pub(crate) fn blob_bytes(col: &ArrayRef, row: usize) -> Result<Option<&[u8]>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Binary => col.as_binary::<i32>().value(row),
        DataType::LargeBinary => col.as_binary::<i64>().value(row),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a BLOB (binary) argument, got {other:?}"
            )))
        }
    }))
}
