//! `netflow_version()` — return the worker's version string (the catalog
//! `<name>_version()` scalar every fleet worker carries).

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

pub struct NetflowVersion;

impl ScalarFunction for NetflowVersion {
    fn name(&self) -> &str {
        "netflow_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "NetFlow Worker Version",
            "Return the version string of the running netflow worker binary (the worker's own \
             build version — the crate's Cargo version, MAJOR.MINOR.PATCH — not the SDK/protocol \
             version). Argument-free and deterministic: always the same single VARCHAR (never \
             NULL) for a given build. Useful for diagnostics and confirming which build is \
             attached.",
            "Return the netflow worker version string, e.g. `netflow_version()` → '0.1.0'. \
             Argument-free and deterministic; a single semver VARCHAR.",
            "version, build version, netflow_version, diagnostics, worker version, semver",
        );
        tags.push(("vgi.category".into(), "probe".into()));
        tags.push((
            "vgi.executable_examples".into(),
            r#"[{"description":"Return the worker version string.","sql":"SELECT netflow.main.netflow_version() AS version"}]"#
                .into(),
        ));
        FunctionMetadata {
            description: "Returns the netflow worker version string".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT netflow.main.netflow_version();".into(),
                description: "Return the netflow worker version string.".into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let rows = batch.num_rows();
        let out: ArrayRef = Arc::new(StringArray::from(vec![netflow_core::version(); rows]));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
