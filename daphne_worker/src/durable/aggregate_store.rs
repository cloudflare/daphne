// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::{collections::HashSet, mem::size_of, ops::ControlFlow};

use crate::{
    config::DaphneWorkerDurableConfig,
    durable::{create_span_from_request, state_get_or_default},
    initialize_tracing, int_err,
};
use daphne::{
    messages::{ReportId, Time},
    vdaf::VdafAggregateShare,
    DapAggregateShare,
};
use daphne_service_utils::{
    config::DaphneWorkerDeployment,
    durable_requests::bindings::{
        self, AggregateStoreMergeReq, AggregateStoreMergeResp, DurableMethod,
    },
};
use prio::{
    codec::{Decode, Encode},
    field::FieldElement,
    vdaf::AggregateShare,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::Instrument;
use worker::{
    async_trait, durable_object, js_sys, wasm_bindgen, wasm_bindgen::JsValue, wasm_bindgen_futures,
    worker_sys, Env, Error, Request, Response, Result, State,
};

use super::{req_parse, DapDurableObject, GarbageCollectable};

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
    config: DaphneWorkerDurableConfig,
    touched: bool,
    collected: Option<bool>,
}

/// Minimum number of chunks needed to store 512K of aggregate share data.
const MAX_AGG_SHARE_CHUNK_KEY_COUNT: usize = 4;

/// Minimum number of chunks needed to store `10_000` report ids.
const MAX_REPORT_ID_CHUNK_KEY_COUNT: usize = 2;

/// The maximum chunk size as documented in
/// [the public docs](https://developers.cloudflare.com/durable-objects/platform/limits/)
const MAX_CHUNK_SIZE: usize = 128_000;

/// Key used to store metadata under.
const METADATA_KEY: &str = "meta";

/// Key used to store where this share has been collected
const COLLECTED_KEY: &str = "collected";

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
    fn agg_share_shard_keys() -> Vec<String> {
        (0..MAX_AGG_SHARE_CHUNK_KEY_COUNT)
            .map(|n| format!("chunk_v2_{n:03}"))
            .collect()
    }

    fn aggregated_reports_keys() -> Vec<String> {
        (0..MAX_REPORT_ID_CHUNK_KEY_COUNT)
            .map(|n| format!("aggregated_report_ids_{n:03}"))
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

        let meta_key = JsValue::from_str(METADATA_KEY);
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
                Ok(AggregateShare::from(share))
            }

            let data = match kind {
                VdafKind::Field64 => VdafAggregateShare::Field64(from_slice(&chunks)?),
                VdafKind::Field128 => VdafAggregateShare::Field128(from_slice(&chunks)?),
                VdafKind::FieldPrio2 => VdafAggregateShare::FieldPrio2(from_slice(&chunks)?),
            };

            meta.into_agg_share_with_data(data)
        })
    }

    async fn load_aggregated_report_ids(&self) -> Result<HashSet<ReportId>> {
        let chunks_map = self
            .state
            .storage()
            .get_multiple(Self::aggregated_reports_keys())
            .await?;

        let bytes = js_map_to_chunks::<u8>(&Self::aggregated_reports_keys(), chunks_map);

        assert_eq!(bytes.len() % std::mem::size_of::<ReportId>(), 0);
        let mut ids = HashSet::with_capacity(bytes.len() / size_of::<ReportId>());
        for chunk in bytes.chunks_exact(size_of::<ReportId>()) {
            ids.insert(ReportId::get_decoded(chunk).map_err(|_| Error::BadEncoding)?);
        }
        Ok(ids)
    }
}

fn shard_bytes_to_object(
    keys: &[String],
    bytes: Vec<u8>,
    object_to_fill: &js_sys::Object,
) -> Result<()> {
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

    let num_chunks = div_ceil(bytes.len(), MAX_CHUNK_SIZE);
    if num_chunks > keys.len() {
        return Err(format!("too many chunks {num_chunks}. max is {}", keys.len()).into());
    }

    let mut base_idx = 0;
    for key in &keys[..num_chunks] {
        let end = usize::min(base_idx + MAX_CHUNK_SIZE + 1, bytes.len());
        let chunk = &bytes[base_idx..end];

        // unwrap cannot fail because chunk len is bounded by MAX_CHUNK_SIZE which is smaller than
        // u32::MAX
        let value = js_sys::Uint8Array::new_with_length(u32::try_from(chunk.len()).unwrap());
        value.copy_from(chunk);

        js_sys::Reflect::set(
            object_to_fill,
            &JsValue::from_str(key.as_str()),
            &value.into(),
        )?;

        base_idx = end;
    }
    Ok(())
}

#[durable_object]
impl DurableObject for AggregateStore {
    fn new(state: State, env: Env) -> Self {
        initialize_tracing(&env);
        let config =
            DaphneWorkerDurableConfig::from_worker_env(&env).expect("failed to load configuration");
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
    async fn is_collected(&mut self) -> Result<bool> {
        Ok(if let Some(collected) = self.collected {
            collected
        } else {
            let collected = state_get_or_default(&self.state, COLLECTED_KEY).await?;
            self.collected = Some(collected);
            collected
        })
    }

    async fn handle(&mut self, req: Request) -> Result<Response> {
        let mut req = match self.schedule_for_garbage_collection(req).await? {
            ControlFlow::Continue(req) => req,
            // This req was a GC request and as such we must return from this function.
            ControlFlow::Break(_) => return Response::from_json(&()),
        };

        match bindings::AggregateStore::try_from_uri(&req.path()) {
            Some(bindings::AggregateStore::GetMerged) => {
                Response::from_json(&self.load_aggregated_report_ids().await?)
            }
            // Merge an aggregate share into the stored aggregate.
            //
            // Non-idempotent (do not retry)
            // Input: `agg_share_dellta: DapAggregateShare`
            // Output: `()`
            Some(bindings::AggregateStore::Merge) => {
                let AggregateStoreMergeReq {
                    contained_reports,
                    agg_share_delta,
                } = req_parse(&mut req).await?;

                let chunks_map = js_sys::Object::default();

                if self.is_collected().await? {
                    return Response::from_json(&AggregateStoreMergeResp::AlreadyCollected);
                }

                {
                    // check for replays
                    let mut merged_report_ids = self.load_aggregated_report_ids().await?;
                    let repeat_ids = contained_reports
                        .iter()
                        .filter(|id| merged_report_ids.contains(id))
                        .copied()
                        .collect::<HashSet<_>>();
                    if !repeat_ids.is_empty() {
                        return Response::from_json(&AggregateStoreMergeResp::ReplaysDetected(
                            repeat_ids,
                        ));
                    }
                    merged_report_ids.extend(contained_reports);
                    let mut as_bytes =
                        Vec::with_capacity(merged_report_ids.len() * size_of::<ReportId>());
                    merged_report_ids
                        .into_iter()
                        .for_each(|id| id.encode(&mut as_bytes));
                    shard_bytes_to_object(&Self::aggregated_reports_keys(), as_bytes, &chunks_map)?;
                };

                let keys = Self::agg_share_shard_keys();
                let mut agg_share = self.get_agg_share(&keys).await?;
                agg_share.merge(agg_share_delta).map_err(int_err)?;

                let (meta, data) = DapAggregateShareMetadata::from_agg_share(agg_share);

                data.as_ref()
                    .map(|data| shard_bytes_to_object(&keys, data.get_encoded(), &chunks_map))
                    .transpose()? // Option<Result> -> Result<Option> -> Option
                    .unwrap_or_default();

                js_sys::Reflect::set(
                    &chunks_map,
                    &JsValue::from_str(METADATA_KEY),
                    &serde_wasm_bindgen::to_value(&meta)?,
                )?;

                self.state.storage().put_multiple_raw(chunks_map).await?;

                Response::from_json(&AggregateStoreMergeResp::Ok)
            }

            // Get the current aggregate share.
            //
            // Idempotent
            // Output: `DapAggregateShare`
            Some(bindings::AggregateStore::Get) => {
                let agg_share = self.get_agg_share(&Self::agg_share_shard_keys()).await?;
                Response::from_json(&agg_share)
            }

            // Mark this bucket as collected.
            //
            // Non-idempotent (do not retry)
            // Output: `()`
            Some(bindings::AggregateStore::MarkCollected) => {
                self.state.storage().put(COLLECTED_KEY, true).await?;
                self.collected = Some(true);
                Response::from_json(&())
            }

            // Get the value of the flag indicating whether this bucket has been collected.
            //
            // Idempotent
            // Output: `bool`
            Some(bindings::AggregateStore::CheckCollected) => {
                Response::from_json(&self.is_collected().await?)
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
    type DurableMethod = bindings::AggregateStore;

    #[inline(always)]
    fn state(&self) -> &State {
        &self.state
    }

    #[inline(always)]
    fn deployment(&self) -> DaphneWorkerDeployment {
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
