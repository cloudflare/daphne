// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::ControlFlow;

use crate::{
    config::DaphneWorkerConfig,
    durable::{create_span_from_request, state_get_or_default, BINDING_DAP_AGGREGATE_STORE},
    initialize_tracing, int_err,
};
use daphne::{messages::Time, vdaf::VdafAggregateShare, DapAggregateShare};
use prio::{
    codec::Encode,
    field::FieldElement,
    vdaf::{AggregateShare, OutputShare},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::Instrument;
use worker::{wasm_bindgen::JsValue, *};

use super::{req_parse, DapDurableObject, GarbageCollectable};

pub(crate) const DURABLE_AGGREGATE_STORE_GET: &str = "/internal/do/aggregate_store/get";
pub(crate) const DURABLE_AGGREGATE_STORE_MERGE: &str = "/internal/do/aggregate_store/merge";
pub(crate) const DURABLE_AGGREGATE_STORE_MARK_COLLECTED: &str =
    "/internal/do/aggregate_store/mark_collected";
pub(crate) const DURABLE_AGGREGATE_STORE_CHECK_COLLECTED: &str =
    "/internal/do/aggregate_store/check_collected";

/// Durable Object (DO) for storing aggregate shares for a bucket of reports.
///
/// This object defines the following API endpoints:
///
/// - `DURABLE_AGGREGATE_STORE_GET`: Return the current value of the aggregate share.
/// - `DURABLE_AGGREGATE_STORE_MERGE`: Update the aggregate share.
/// - `DURABLE_AGGREGATE_STORE_MARK_COLLECTED`: Mark the bucket as having been collected.
/// - `DURABLE_AGGREGATE_STORE_CHECK_COLLECTED`: Return a boolean indicating if the bucket has been
///   collected.
///
/// The schema for the data stored by this DO is as follows:
///
/// ```text
/// [Aggregate share]
///     meta                -> DapAggregateShareMetadata
///     chunk_v2_{000..004} -> slice of VdafAggregateShare
/// [Collected flag]
///     collected -> bool
/// ```
#[durable_object]
pub struct AggregateStore {
    #[allow(dead_code)]
    state: State,
    env: Env,
    config: DaphneWorkerConfig,
    touched: bool,
    collected: Option<bool>,
}

/// Minimum number of chunks needed to store 512K of aggregate share data.
const MAX_CHUNK_KEY_COUNT: usize = 4;

/// The maximum chunk size as documented in:
/// https://developers.cloudflare.com/durable-objects/platform/limits/
const MAX_CHUNK_SIZE: usize = 128_000;

/// Key used to store metadata under.
const METADATA_KEY: &str = "meta";

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum VdafKind {
    Field64,
    Field128,
    FieldPrio2,
}

#[derive(Debug, Serialize, Deserialize)]
struct DapAggregateShareMetadata {
    report_count: u64,
    min_time: Time,
    max_time: Time,
    checksum: [u8; 32],
    kind: Option<VdafKind>,
}

impl DapAggregateShareMetadata {
    fn from_agg_share(
        share: DapAggregateShare,
    ) -> (Self, Option<daphne::vdaf::VdafAggregateShare>) {
        let this = Self {
            report_count: share.report_count,
            min_time: share.min_time,
            max_time: share.max_time,
            checksum: share.checksum,
            kind: share.data.as_ref().map(|data| match data {
                daphne::vdaf::VdafAggregateShare::Field64(_) => VdafKind::Field64,
                daphne::vdaf::VdafAggregateShare::Field128(_) => VdafKind::Field128,
                daphne::vdaf::VdafAggregateShare::FieldPrio2(_) => VdafKind::FieldPrio2,
            }),
        };

        (this, share.data)
    }

    fn into_agg_share_with_data(self, data: daphne::vdaf::VdafAggregateShare) -> DapAggregateShare {
        DapAggregateShare {
            data: Some(data),
            ..self.into_agg_share_without_data()
        }
    }

    fn into_agg_share_without_data(self) -> DapAggregateShare {
        DapAggregateShare {
            report_count: self.report_count,
            min_time: self.min_time,
            max_time: self.max_time,
            checksum: self.checksum,
            data: None,
        }
    }
}

fn js_map_to_chunks<T: DeserializeOwned>(keys: &[String], map: js_sys::Map) -> Vec<T> {
    keys.iter()
        .map(|k| JsValue::from_str(k))
        .filter(|k| map.has(k))
        .map(|k| map.get(&k))
        .flat_map(|js_v| {
            serde_wasm_bindgen::from_value::<Vec<T>>(js_v).expect("expect an array of bytes")
        })
        .collect()
}

impl AggregateStore {
    fn agg_share_shard_keys(&self) -> Vec<String> {
        (0..MAX_CHUNK_KEY_COUNT)
            .map(|n| format!("chunk_v2_{n:03}"))
            .collect()
    }

    async fn get_agg_share(&self, keys: &[String]) -> Result<DapAggregateShare> {
        let all_keys = keys
            .iter()
            .map(String::as_str)
            .chain([METADATA_KEY])
            .collect::<Vec<_>>();
        let values = self.state.storage().get_multiple(all_keys).await?;

        if values.size() == 0 {
            return Ok(DapAggregateShare::default());
        }

        let meta_key = JsValue::from_str("meta");
        let meta =
            serde_wasm_bindgen::from_value::<DapAggregateShareMetadata>(values.get(&meta_key))
                .unwrap_or_else(|e| {
                    tracing::error!("failed to deser DapAggregateShareMeta: {e:?}");
                    panic!("{e}")
                });

        let chunks = js_map_to_chunks(keys, values);

        Ok(if chunks.is_empty() {
            meta.into_agg_share_without_data()
        } else {
            let kind = meta.kind.expect("if there is data there should be a type");

            fn from_slice<T: FieldElement>(chunks: &[u8]) -> Result<AggregateShare<T>> {
                let share = T::byte_slice_into_vec(chunks).map_err(|e| {
                    worker::Error::Internal(
                        serde_wasm_bindgen::to_value(&e.to_string())
                            .expect("string never fails to convert to JsValue"),
                    )
                })?;
                // TODO(mendess): this an abuse of this API, this type should not be constructed this way.
                Ok(AggregateShare::from(OutputShare::from(share)))
            }

            let data = match kind {
                VdafKind::Field64 => VdafAggregateShare::Field64(from_slice(&chunks)?),
                VdafKind::Field128 => VdafAggregateShare::Field128(from_slice(&chunks)?),
                VdafKind::FieldPrio2 => VdafAggregateShare::FieldPrio2(from_slice(&chunks)?),
            };

            meta.into_agg_share_with_data(data)
        })
    }
}

#[durable_object]
impl DurableObject for AggregateStore {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerConfig::from_worker_env(&env).expect("failed to load configuration");
        Self {
            state,
            env,
            config,
            touched: false,
            collected: None,
        }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let span = create_span_from_request(&req);
        self.handle(req).instrument(span).await
    }
}

impl AggregateStore {
    async fn handle(&mut self, req: Request) -> Result<Response> {
        let mut req = match self
            .schedule_for_garbage_collection(req, BINDING_DAP_AGGREGATE_STORE)
            .await?
        {
            ControlFlow::Continue(req) => req,
            // This req was a GC request and as such we must return from this function.
            ControlFlow::Break(_) => return Response::from_json(&()),
        };

        match (req.path().as_ref(), req.method()) {
            // Merge an aggregate share into the stored aggregate.
            //
            // Non-idempotent (do not retry)
            // Input: `agg_share_dellta: DapAggregateShare`
            // Output: `()`
            (DURABLE_AGGREGATE_STORE_MERGE, Method::Post) => {
                let agg_share_delta = req_parse(&mut req).await?;

                let keys = self.agg_share_shard_keys();
                let mut agg_share = self.get_agg_share(&keys).await?;
                agg_share.merge(agg_share_delta).map_err(int_err)?;

                let (meta, data) = DapAggregateShareMetadata::from_agg_share(agg_share);

                // the data needs to be chunked in order to fit inside the limits of durable
                // objects.
                let chunks_map = data
                    .map(|data| {
                        // stolen from
                        // https://doc.rust-lang.org/std/primitive.usize.html#method.div_ceil
                        // because it's nightly only
                        fn div_ceil(lhs: usize, rhs: usize) -> usize {
                            let d = lhs / rhs;
                            let r = lhs % rhs;
                            if r > 0 && rhs > 0 {
                                d + 1
                            } else {
                                d
                            }
                        }

                        let data = data.get_encoded();
                        let num_chunks = div_ceil(data.len(), MAX_CHUNK_SIZE);
                        assert!(
                            num_chunks <= keys.len(),
                            "too many chunks {num_chunks}. max is {}",
                            keys.len()
                        );

                        // This is effectively a map of "chunk_v2_XX" to a byte slice
                        let chunks_map = js_sys::Object::new();

                        let mut base_idx = 0;
                        for key in &keys[..num_chunks] {
                            let end = usize::min(base_idx + MAX_CHUNK_SIZE + 1, data.len());
                            let chunk = &data[base_idx..end];

                            let value = js_sys::Uint8Array::new_with_length(chunk.len() as _);
                            value.copy_from(chunk);

                            js_sys::Reflect::set(
                                &chunks_map,
                                &JsValue::from_str(key.as_str()),
                                &value.into(),
                            )?;

                            base_idx = end;
                        }
                        assert_eq!(
                            base_idx,
                            data.len(),
                            "len: {} chunk_size: {} rem: {}",
                            data.len(),
                            MAX_CHUNK_SIZE,
                            data.len() % keys.len(),
                        );
                        Result::Ok(chunks_map)
                    })
                    .transpose()?
                    .unwrap_or_default();

                js_sys::Reflect::set(
                    &chunks_map,
                    &JsValue::from_str(METADATA_KEY),
                    &serde_wasm_bindgen::to_value(&meta)?,
                )?;

                self.state.storage().put_multiple_raw(chunks_map).await?;

                Response::from_json(&())
            }

            // Get the current aggregate share.
            //
            // Idempotent
            // Output: `DapAggregateShare`
            (DURABLE_AGGREGATE_STORE_GET, Method::Get) => {
                let agg_share = self.get_agg_share(&self.agg_share_shard_keys()).await?;
                Response::from_json(&agg_share)
            }

            // Mark this bucket as collected.
            //
            // Non-idempotent (do not retry)
            // Output: `()`
            (DURABLE_AGGREGATE_STORE_MARK_COLLECTED, Method::Post) => {
                self.state.storage().put("collected", true).await?;
                self.collected = Some(true);
                Response::from_json(&())
            }

            // Get the value of the flag indicating whether this bucket has been collected.
            //
            // Idempotent
            // Output: `bool`
            (DURABLE_AGGREGATE_STORE_CHECK_COLLECTED, Method::Get) => {
                let collected = if let Some(collected) = self.collected {
                    collected
                } else {
                    let collected = state_get_or_default(&self.state, "collected").await?;
                    self.collected = Some(collected);
                    collected
                };
                Response::from_json(&collected)
            }

            _ => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}

impl DapDurableObject for AggregateStore {
    #[inline(always)]
    fn state(&self) -> &State {
        &self.state
    }

    #[inline(always)]
    fn deployment(&self) -> crate::config::DaphneWorkerDeployment {
        self.config.deployment
    }
}

#[async_trait::async_trait(?Send)]
impl GarbageCollectable for AggregateStore {
    #[inline(always)]
    fn touched(&mut self) -> &mut bool {
        &mut self.touched
    }

    #[inline(always)]
    fn env(&self) -> &Env {
        &self.env
    }
}
