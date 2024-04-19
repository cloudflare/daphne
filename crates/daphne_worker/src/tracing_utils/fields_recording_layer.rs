// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashMap;

use tracing::{span::Attributes, Id, Subscriber};
use tracing_subscriber::{layer::Context as LayerContext, registry, Layer};

use super::{JsonFields, JsonVisitor};

/// Tracing subscriber layer that records the fields of the created spans.
///
/// Fields from spans are flattened into the JSON, duplicates are prioritized by their closeness to
/// the leaf (e.g. leaf field overrides root field).
///
/// Timestamps are derived from calling `Date.now()`. In the Workers runtime, time only progresses
/// when IO occurs.
pub(super) struct SpanFieldsRecorderLayer;

impl<S> Layer<S> for SpanFieldsRecorderLayer
where
    S: Subscriber + for<'a> registry::LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: LayerContext<'_, S>) {
        let span = ctx.span(id).expect("span should exist");
        let mut fields = HashMap::new();
        let mut visitor = JsonVisitor(&mut fields);
        attrs.record(&mut visitor);

        let mut extensions = span.extensions_mut();
        if extensions.get_mut::<JsonFields>().is_none() {
            extensions.insert(fields);
        }
    }
}
