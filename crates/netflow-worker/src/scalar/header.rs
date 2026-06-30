//! `header(blob) -> STRUCT(version, count, sys_uptime, export_time, sequence,
//! obs_domain)` — decode just the export header (sequence-gap / dedup analysis)
//! without decoding records.

use std::sync::Arc;

use arrow_array::builder::{
    TimestampMicrosecondBuilder, UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow_array::{ArrayRef, RecordBatch, StructArray};
use arrow_schema::{DataType, Field, Fields, TimeUnit};
use netflow_core::decode::header::parse_header;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::scalar::blob_bytes;

const UTC: &str = "UTC";

fn struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("version", DataType::UInt16, true),
        Field::new("count", DataType::UInt16, true),
        Field::new("sys_uptime", DataType::UInt32, true),
        Field::new(
            "export_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some(UTC.into())),
            true,
        ),
        Field::new("sequence", DataType::UInt64, true),
        Field::new("obs_domain", DataType::UInt32, true),
    ])
}

pub struct Header;

impl ScalarFunction for Header {
    fn name(&self) -> &str {
        "header"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Flow Export Header",
            "Decode just the export header of a flow-export datagram (BLOB) without decoding any \
             records: version, record count, sysUptime, export_time (TIMESTAMPTZ), sequence \
             number, and observation domain. Use it for sequence-gap analysis and dedup over a \
             large column of datagrams cheaply. sFlow fields map best-effort (no count/sys_uptime). \
             Returns a STRUCT; NULL on a non-flow datagram.",
            "Decode a flow datagram's export header to a STRUCT(version, count, sys_uptime, \
             export_time, sequence, obs_domain). NULL if not a flow datagram.",
            "header, export header, sequence, gap detection, dedup, version, obs_domain, netflow, ipfix, sflow",
        );
        tags.push((
            "vgi.executable_examples".into(),
            r#"[{"description":"Header of a non-flow blob is NULL.","sql":"SELECT netflow.main.header('\\x00'::BLOB) AS h"}]"#
                .into(),
        ));
        FunctionMetadata {
            description: "Decode a flow datagram's export header".into(),
            return_type: Some(DataType::Struct(struct_fields())),
            examples: vec![FunctionExample {
                sql: "SELECT netflow.main.header(content).sequence FROM read_blob('s3://flow/*.dat');".into(),
                description: "Read each datagram's export sequence number.".into(),
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
        Ok(BindResponse::result(DataType::Struct(struct_fields())))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let col = batch.column(0);
        let n = batch.num_rows();
        let mut version = UInt16Builder::with_capacity(n);
        let mut count = UInt16Builder::with_capacity(n);
        let mut sys_uptime = UInt32Builder::with_capacity(n);
        let mut export_time = TimestampMicrosecondBuilder::with_capacity(n).with_timezone(UTC);
        let mut sequence = UInt64Builder::with_capacity(n);
        let mut obs_domain = UInt32Builder::with_capacity(n);

        let mut validity = arrow_array::builder::BooleanBufferBuilder::new(n);
        for row in 0..n {
            let hdr = match blob_bytes(col, row)? {
                Some(bytes) => parse_header(bytes),
                None => None,
            };
            match hdr {
                Some(h) => {
                    version.append_option(Some(h.version));
                    count.append_option(h.count);
                    sys_uptime.append_option(h.sys_uptime);
                    export_time.append_option(h.export_time);
                    sequence.append_option(h.sequence);
                    obs_domain.append_option(h.obs_domain);
                    validity.append(true);
                }
                None => {
                    version.append_null();
                    count.append_null();
                    sys_uptime.append_null();
                    export_time.append_null();
                    sequence.append_null();
                    obs_domain.append_null();
                    validity.append(false);
                }
            }
        }
        let children: Vec<ArrayRef> = vec![
            Arc::new(version.finish()),
            Arc::new(count.finish()),
            Arc::new(sys_uptime.finish()),
            Arc::new(export_time.finish()),
            Arc::new(sequence.finish()),
            Arc::new(obs_domain.finish()),
        ];
        let nulls = arrow_buffer::NullBuffer::new(validity.finish());
        let out: ArrayRef = Arc::new(StructArray::new(struct_fields(), children, Some(nulls)));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
