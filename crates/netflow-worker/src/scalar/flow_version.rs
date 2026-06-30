//! `flow_version(blob) -> VARCHAR` — cheap header probe (`'5'`/`'9'`/`'10'`/
//! `'sflow5'`/`NULL`) without decoding the record tree.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::scalar::blob_bytes;

pub struct FlowVersion;

impl ScalarFunction for FlowVersion {
    fn name(&self) -> &str {
        "flow_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Flow Datagram Version Probe",
            "Probe the leading bytes of a captured flow-export datagram (BLOB) and return its wire \
             version: '5' (NetFlow v5), '9' (NetFlow v9), '10' (IPFIX), or 'sflow5' (sFlow v5); \
             NULL when the bytes match no known flow header. Cheap — it reads only the header and \
             allocates no record tree. Use it to route or filter a mixed column of datagrams \
             before calling the decoders.",
            "Return the flow-export version of a datagram BLOB: '5' / '9' / '10' / 'sflow5', or \
             NULL if unrecognized. Header-only, no full decode.",
            "flow version, netflow version, ipfix, sflow, probe, detect, version, datagram, header",
        );
        tags.push((
            "vgi.executable_examples".into(),
            r#"[{"description":"Probe the version of a one-byte non-flow blob (returns NULL).","sql":"SELECT netflow.main.flow_version('\\x00'::BLOB) AS v"}]"#
                .into(),
        ));
        FunctionMetadata {
            description: "Probe a flow-export datagram's wire version".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT netflow.main.flow_version(content) FROM read_blob('s3://flow/*.dat');"
                    .into(),
                description: "Detect each datagram's flow version.".into(),
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
            "A captured flow-export datagram (BLOB).",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let mut b = arrow_array::builder::StringBuilder::new();
        for row in 0..batch.num_rows() {
            match blob_bytes(col, row)? {
                Some(bytes) => match netflow_core::decode::header::probe_version(bytes) {
                    Some(v) => b.append_value(v),
                    None => b.append_null(),
                },
                None => b.append_null(),
            }
        }
        let out: ArrayRef = Arc::new(b.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
