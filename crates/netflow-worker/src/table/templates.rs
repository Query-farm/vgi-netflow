//! `templates([exporter]) -> TABLE(...)` — a read-only projection of the live
//! template cache: which templates the worker has learned and what they decode
//! to. Reads the global cache projection that the decode functions maintain.

use std::sync::Arc;

use arrow_array::builder::{StringBuilder, UInt16Builder, UInt32Builder};
use arrow_array::{
    ArrayRef, ListArray, RecordBatch, StructArray, TimestampMicrosecondArray, UInt16Array,
    UInt32Array, UInt64Array,
};
use arrow_buffer::OffsetBuffer;
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef, TimeUnit};
use vgi::table_function::{TableFunction, TableProducer};
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams};
use vgi_rpc::{OutputCollector, Result, RpcError};

use crate::state::global_cache;

const UTC: &str = "UTC";

fn field_struct_fields() -> Fields {
    Fields::from(vec![
        Field::new("ie_id", DataType::UInt16, false),
        Field::new("enterprise", DataType::UInt32, false),
        Field::new("length", DataType::UInt16, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("ie_type", DataType::Utf8, false),
    ])
}

fn fields_list_type() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(field_struct_fields()),
        false,
    )))
}

fn ts() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some(UTC.into()))
}

fn col(name: &str, dt: DataType, comment: &str) -> Field {
    Field::new(name, dt, true).with_metadata(std::collections::HashMap::from([(
        "comment".to_string(),
        comment.to_string(),
    )]))
}

/// The output schema of `templates()`.
pub fn output_schema() -> SchemaRef {
    use DataType::*;
    Arc::new(Schema::new(vec![
        col(
            "exporter",
            Utf8,
            "Source device the template was learned from.",
        ),
        col(
            "obs_domain",
            UInt32,
            "Observation domain (v9 source-id / IPFIX) the template id is scoped to.",
        ),
        col(
            "template_id",
            UInt16,
            "The template id a Data Set references.",
        ),
        col("kind", Utf8, "'data' or 'options'."),
        col(
            "field_count",
            UInt32,
            "Number of field specifiers in the template.",
        ),
        col(
            "fields",
            fields_list_type(),
            "The ordered field specifiers (ie_id, enterprise, length, name, ie_type).",
        ),
        col(
            "scope_field_count",
            UInt16,
            "Leading scope fields (options templates); 0 for data.",
        ),
        col("first_seen", ts(), "When this template id was first seen."),
        col(
            "last_seen",
            ts(),
            "When this template was most recently seen/used.",
        ),
        col(
            "use_count",
            UInt64,
            "How many data records have been decoded against it.",
        ),
    ]))
}

pub struct Templates;

impl TableFunction for Templates {
    fn name(&self) -> &str {
        "templates"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Template Cache Introspection",
            "Project the live v9/IPFIX template cache: one row per learned template, with its \
             exporter, observation domain, template id, kind (data/options), the ordered field \
             specifiers it decodes to, and first/last-seen and use-count stats. The debugging \
             surface for 'which templates have I learned and what do they decode to'. Optionally \
             filter by exporter. Reflects templates learned by prior flows()/netflow_decode()/\
             ipfix_decode() calls in this session.",
            "List the learned v9/IPFIX templates and their field layouts. Optional `exporter` \
             filter.",
            "templates, template cache, introspection, ipfix, netflow, v9, fields, debug, layout",
        );
        tags.push((
            "vgi.result_columns_md".into(),
            "| column | type | description |\n\
             |---|---|---|\n\
             | `exporter` | VARCHAR | Device the template came from. |\n\
             | `obs_domain` | UINTEGER | Observation domain. |\n\
             | `template_id` | USMALLINT | Template id. |\n\
             | `kind` | VARCHAR | 'data' / 'options'. |\n\
             | `field_count` | UINTEGER | Field specifier count. |\n\
             | `fields` | STRUCT[] | Ordered field specifiers. |\n\
             | `first_seen` / `last_seen` | TIMESTAMPTZ | Seen stats. |\n\
             | `use_count` | UBIGINT | Decode count. |"
                .into(),
        ));
        // Runnable example: learn a template by decoding an IPFIX datagram, then
        // introspect it. Two statements on one connection so the global cache
        // projection the decode writes is visible to templates() in the same
        // session (an empty cache on a cold worker would otherwise show 0 rows).
        tags.push((
            "vgi.executable_examples".into(),
            crate::meta::executable_examples_json(&[(
                "Learn an IPFIX template by decoding a datagram, then list it (template id, kind, \
                 field count).",
                &format!(
                    "SELECT count(*) FROM netflow.main.ipfix_decode((SELECT from_hex('{hex}') \
                     AS datagram, 'doc-exporter' AS exporter));\n\
                     SELECT exporter, template_id, kind, field_count \
                     FROM netflow.main.templates(exporter => 'doc-exporter');",
                    hex = crate::meta::SAMPLE_IPFIX_HEX
                ),
            )]),
        ));
        // No native Meta.examples here: a bare `templates()` on a cold worker
        // returns no rows (VGI902), so the runnable demonstration lives in the
        // two-statement vgi.executable_examples above (decode → introspect).
        FunctionMetadata {
            description: "Project the live v9/IPFIX template cache".into(),
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::const_arg(
            "exporter",
            -1,
            "varchar",
            "Filter to templates learned from this exporter (source device id). Omit for all.",
        )]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse {
            output_schema: output_schema(),
            opaque_data: Vec::new(),
        })
    }

    fn producer(&self, params: &ProcessParams) -> Result<Box<dyn TableProducer>> {
        let filter = params.arguments.named_str("exporter");
        let cache = global_cache(&params.storage);
        Ok(Box::new(TemplatesProducer {
            schema: params.output_schema.clone(),
            cache,
            filter,
            done: false,
        }))
    }
}

struct TemplatesProducer {
    schema: SchemaRef,
    cache: netflow_core::TemplateCache,
    filter: Option<String>,
    done: bool,
}

impl TableProducer for TemplatesProducer {
    fn next_batch(&mut self, _out: &mut OutputCollector) -> Result<Option<RecordBatch>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;

        let mut exporter = StringBuilder::new();
        let mut obs_domain = UInt32Array::builder(0);
        let mut template_id = UInt16Array::builder(0);
        let mut kind = StringBuilder::new();
        let mut field_count = UInt32Array::builder(0);
        let mut scope_field_count = UInt16Array::builder(0);
        let mut first_seen: Vec<Option<i64>> = Vec::new();
        let mut last_seen: Vec<Option<i64>> = Vec::new();
        let mut use_count = UInt64Array::builder(0);

        // Flattened child for the `fields` LIST(STRUCT(...)).
        let mut f_ie_id = UInt16Builder::new();
        let mut f_ent = UInt32Builder::new();
        let mut f_len = UInt16Builder::new();
        let mut f_name = StringBuilder::new();
        let mut f_type = StringBuilder::new();
        let mut offsets: Vec<i32> = vec![0];
        let mut running: i32 = 0;

        for (key, entry) in &self.cache.entries {
            if let Some(f) = &self.filter {
                if &key.exporter != f {
                    continue;
                }
            }
            exporter.append_value(&key.exporter);
            obs_domain.append_value(key.obs_domain);
            template_id.append_value(key.template_id);
            kind.append_value(entry.kind.as_str());
            field_count.append_value(entry.fields.len() as u32);
            scope_field_count.append_value(entry.scope_field_count);
            first_seen.push(Some(entry.first_seen));
            last_seen.push(Some(entry.last_seen));
            use_count.append_value(entry.use_count);
            for f in &entry.fields {
                f_ie_id.append_value(f.ie_id);
                f_ent.append_value(f.enterprise_number);
                f_len.append_value(f.length);
                f_name.append_value(&f.name);
                f_type.append_value(&f.ie_type);
            }
            running += entry.fields.len() as i32;
            offsets.push(running);
        }

        let child = StructArray::new(
            field_struct_fields(),
            vec![
                Arc::new(f_ie_id.finish()) as ArrayRef,
                Arc::new(f_ent.finish()),
                Arc::new(f_len.finish()),
                Arc::new(f_name.finish()),
                Arc::new(f_type.finish()),
            ],
            None,
        );
        let fields_list = ListArray::new(
            Arc::new(Field::new(
                "item",
                DataType::Struct(field_struct_fields()),
                false,
            )),
            OffsetBuffer::new(offsets.into()),
            Arc::new(child),
            None,
        );

        let cols: Vec<ArrayRef> = vec![
            Arc::new(exporter.finish()),
            Arc::new(obs_domain.finish()),
            Arc::new(template_id.finish()),
            Arc::new(kind.finish()),
            Arc::new(field_count.finish()),
            Arc::new(fields_list),
            Arc::new(scope_field_count.finish()),
            Arc::new(TimestampMicrosecondArray::from(first_seen).with_timezone(UTC)),
            Arc::new(TimestampMicrosecondArray::from(last_seen).with_timezone(UTC)),
            Arc::new(use_count.finish()),
        ];
        Ok(Some(
            RecordBatch::try_new(self.schema.clone(), cols)
                .map_err(|e| RpcError::runtime_error(e.to_string()))?,
        ))
    }
}
