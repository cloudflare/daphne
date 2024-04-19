// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashMap;

use tracing::Subscriber;
use tracing_subscriber::{layer::Context as LayerContext, registry, Layer};
use worker::console_log;

use super::{shorten_paths, JsonFields, JsonVisitor};

#[derive(serde::Serialize)]
struct LogLine {
    timestamp: u64,
    log_level: &'static str,
    #[serde(flatten)]
    fields: HashMap<String, serde_json::Value>,
}

/// Tracing subscriber layer that writes JSON to Cloudflare Workers console.
///
/// Fields from spans are flattened into the JSON, duplicates are prioritized by their closeness to
/// the leaf (e.g. leaf field overrides root field).
///
/// Timestamps are derived from calling `Date.now()`. In the Workers runtime, time only progresses
/// when IO occurs.
///
/// Logs all messages to `console.log` with their tracing log level in a `level` field of the JSON.
pub struct WorkersJsonLayer;

impl<S> Layer<S> for WorkersJsonLayer
where
    S: Subscriber + for<'a> registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: LayerContext<'_, S>) {
        let timestamp = worker::Date::now().as_millis();

        let mut fields = HashMap::new();
        let mut visitor = JsonVisitor(&mut fields);

        // Prioritize any fields in the message itself over those in the span tree.
        event.record(&mut visitor);

        if let Some(current) = ctx.event_span(event) {
            // current context --> root context
            if let Some(spans) = ctx.span_scope(&current.id()) {
                for span in spans {
                    let ext = span.extensions();
                    let data = ext.get::<JsonFields>();

                    fields
                        .entry("current_span".to_owned())
                        .or_insert(serde_json::json!(span.name()));

                    for f in span.fields() {
                        if let Some(value) = data.and_then(|d| d.get(f.name())) {
                            // As we are going from current span to root, prioritize existing values.
                            fields.entry(f.name().to_owned()).or_insert(value.clone());
                        }
                    }
                }
            }
        }

        let metadata = event.metadata();
        if let (Some(file), Some(line)) = (metadata.file(), metadata.line()) {
            // we need to keep log lines as short as possible otherwise logpush will truncate them.
            let file_parts = shorten_paths(file.trim_start_matches("daphne_").split('/'));
            fields.insert(
                "at".to_owned(),
                format!("{}:{}", file_parts.display(), line).into(),
            );
        }

        // If there is no `message`, repurpose the error meessage is there is one or the
        // `current_span` as the `message`. This helps normalize the `WasmTimingLayer` events.
        const MSG_KEY: &str = "message";
        if !fields.contains_key(MSG_KEY) {
            if let Some(error) = fields.get("error") {
                fields.insert(MSG_KEY.into(), error.clone());
            } else {
                fields.insert(MSG_KEY.to_owned(), "(no message)".into());
            }
        } else if matches!(fields.get(MSG_KEY).unwrap().as_str(), Some(m) if m.trim().is_empty()) {
            fields.insert(MSG_KEY.to_owned(), "(no message)".into());
        }

        let log_line = LogLine {
            timestamp,
            log_level: metadata.level().as_str(),
            fields,
        };

        if let Ok(log) = serde_json::to_string(&log_line) {
            console_log!("{}", log);
        }
    }
}
