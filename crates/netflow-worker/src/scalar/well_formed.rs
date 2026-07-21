//! `well_formed(blob) -> STRUCT(ok BOOL, version VARCHAR, error VARCHAR, kind
//! VARCHAR)` — validate a datagram's structure without a full decode. Never
//! panics on hostile input.

use std::sync::Arc;

use arrow_array::builder::{BooleanBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_schema::{DataType, Field, Fields};
use netflow_core::well_formed;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::scalar::blob_bytes;

fn struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("ok", DataType::Boolean, true),
        Field::new("version", DataType::Utf8, true),
        Field::new("error", DataType::Utf8, true),
        Field::new("kind", DataType::Utf8, true),
    ])
}

pub struct WellFormed;

impl ScalarFunction for WellFormed {
    fn name(&self) -> &str {
        "well_formed"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Flow Datagram Validation",
            "Validate the structure of a flow-export datagram (`BLOB`) without a full decode, \
             returning `STRUCT(ok BOOL, version VARCHAR, error VARCHAR, kind VARCHAR)`. `kind` is one \
             of truncated, bad-version, set-length-overrun, bad-ipfix-set, short-record, or \
             not-a-flow-datagram. Never panics — a hostile/garbage blob returns ok=false rather \
             than crashing the scan. Use it to triage a capture before decoding.",
            "Validate a flow datagram `BLOB`'s structure → `STRUCT(ok, version, error, kind)`. Never \
             panics on garbage.",
            "well formed, validate, validation, malformed, truncated, triage, netflow, ipfix, sflow",
        );
        tags.push(("vgi.category".into(), "probe".into()));
        tags.push((
            "vgi.executable_examples".into(),
            crate::meta::executable_examples_json(&[
                (
                    "A real NetFlow v5 datagram validates clean (ok = true, version = '5').",
                    &format!(
                        "SELECT netflow.main.well_formed(from_hex('{hex}')::BLOB) AS check",
                        hex = crate::meta::SAMPLE_V5_HEX
                    ),
                ),
                (
                    "Garbage bytes are flagged not-a-flow-datagram (ok = false).",
                    "SELECT netflow.main.well_formed('\\xde\\xad'::BLOB).kind AS kind",
                ),
            ]),
        ));
        // Described illustrative example — byte-identical SQL to the native
        // `Meta.example`, so the merged example set carries a description (VGI515).
        let example_sql = format!(
            "SELECT netflow.main.well_formed(from_hex('{hex}')::BLOB) AS validation",
            hex = crate::meta::SAMPLE_V5_HEX
        );
        tags.push((
            "vgi.example_queries".into(),
            crate::meta::example_queries_json(&[(
                "Triage a captured datagram — STRUCT(ok, version, error, kind) — before decoding.",
                &example_sql,
            )]),
        ));
        FunctionMetadata {
            description: "Validate a flow datagram's structure (never panics)".into(),
            return_type: Some(DataType::Struct(struct_fields())),
            examples: vec![FunctionExample {
                sql: example_sql,
                description: "Triage a captured datagram — STRUCT(ok, version, error, kind) — \
                              before decoding."
                    .into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::column(
            "datagram",
            0,
            "binary",
            "The raw captured bytes to structurally validate as a flow-export datagram.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Struct(struct_fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let n = batch.num_rows();
        let mut ok = BooleanBuilder::with_capacity(n);
        let mut version = StringBuilder::new();
        let mut error = StringBuilder::new();
        let mut kind = StringBuilder::new();
        let mut validity = arrow_array::builder::BooleanBufferBuilder::new(n);

        for row in 0..n {
            match blob_bytes(col, row)? {
                Some(bytes) => {
                    let w = well_formed(bytes);
                    ok.append_value(w.ok);
                    version.append_option(w.version);
                    error.append_option(w.error);
                    kind.append_option(w.kind);
                    validity.append(true);
                }
                None => {
                    ok.append_null();
                    version.append_null();
                    error.append_null();
                    kind.append_null();
                    validity.append(false);
                }
            }
        }
        let children: Vec<ArrayRef> = vec![
            Arc::new(ok.finish()),
            Arc::new(version.finish()),
            Arc::new(error.finish()),
            Arc::new(kind.finish()),
        ];
        let nulls = arrow_buffer::NullBuffer::new(validity.finish());
        let out: ArrayRef = Arc::new(StructArray::new(struct_fields(), children, Some(nulls)));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
