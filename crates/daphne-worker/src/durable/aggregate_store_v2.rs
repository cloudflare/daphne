// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Durable Object for storing the result of an aggregation job.

use super::{req_parse, GcDurableObject};
use crate::int_err;
use daphne::DapAggregateShare;
use daphne_service_utils::durable_requests::bindings::{
    self, aggregate_store_v2, DurableMethod as _,
};
use futures::{StreamExt, TryStreamExt};
use std::{sync::OnceLock, time::Duration};
use worker::{js_sys, wasm_bindgen::JsValue, Env, Request, Response, Result, ScheduledTime, State};

const AGGREGATION_JOB_IDS_KEY: &str = "agg-job-ids";
const COLLECTED_FLAG_KEY: &str = "collected";

super::mk_durable_object! {
    /// Where the aggregate share is stored. For the binding name see its
    /// [`BINDING`](bindings::AggregateStore::BINDING)
    struct AggregateStoreV2 {
        state: State,
        env: Env,
        collected: Option<bool>,
    }
}

impl AggregateStoreV2 {
    async fn get_agg_share(&self, agg_job_id: &str) -> Result<Option<DapAggregateShare>> {
        self.load_chuncked_value(agg_job_id).await
    }

    fn put_agg_share(
        &mut self,
        agg_job_id: &str,
        share: DapAggregateShare,
        obj: js_sys::Object,
    ) -> Result<js_sys::Object> {
        self.serialize_chunked_value(agg_job_id, &share, obj)
    }

    async fn is_collected(&mut self) -> Result<bool> {
        Ok(if let Some(collected) = self.collected {
            collected
        } else {
            let collected = self.get_or_default(COLLECTED_FLAG_KEY).await?;
            self.collected = Some(collected);
            collected
        })
    }
}

impl GcDurableObject for AggregateStoreV2 {
    type DurableMethod = bindings::AggregateStore;

    fn with_state_and_env(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            collected: None,
        }
    }

    async fn handle(&mut self, mut req: Request) -> Result<Response> {
        match aggregate_store_v2::Command::try_from_uri(&req.path()) {
            // Store an aggregate share and aggregation job response.
            //
            // Idempotent
            // Input: `agg_share_dellta: agg_job_result_store::FinishRequest`
            // Output: `agg_job_result_store::FinishResponse`
            Some(aggregate_store_v2::Command::Put) => {
                let aggregate_store_v2::PutRequest {
                    agg_job_id,
                    agg_share_delta,
                } = req_parse(&mut req).await?;

                let mut agg_job_ids = self
                    .get_or_default::<Vec<String>>(AGGREGATION_JOB_IDS_KEY)
                    .await?;

                let chunks_map = js_sys::Object::default();

                let agg_job_id = agg_job_id.to_string();

                let chunks_map = self.put_agg_share(&agg_job_id, agg_share_delta, chunks_map)?;

                agg_job_ids.push(agg_job_id);
                js_sys::Reflect::set(
                    &chunks_map,
                    &JsValue::from_str(AGGREGATION_JOB_IDS_KEY),
                    &serde_wasm_bindgen::to_value(&agg_job_ids)?,
                )?;

                self.state.storage().put_multiple_raw(chunks_map).await?;

                Response::from_json(&())
            }

            // Get the current aggregate share.
            //
            // Idempotent
            // Output: `DapAggregateShare`
            Some(aggregate_store_v2::Command::Get) => {
                let ids = self
                    .get_or_default::<Vec<String>>(AGGREGATION_JOB_IDS_KEY)
                    .await?;
                let this = &self;
                let share = futures::stream::iter(ids)
                    .map(|id| async move { this.get_agg_share(&id).await })
                    .buffer_unordered(8)
                    .filter_map(|share| async move { share.transpose() })
                    .try_fold(DapAggregateShare::default(), |mut acc, share| async move {
                        acc.merge(share)
                            .map(|()| acc)
                            .map_err(|e| worker::Error::RustError(e.to_string()))
                    })
                    .await?;
                Response::from_json(&share)
            }

            // Mark this bucket as collected.
            //
            // Idempotent
            // Output: `()`
            Some(aggregate_store_v2::Command::MarkCollected) => {
                self.state.storage().put(COLLECTED_FLAG_KEY, true).await?;
                self.collected = Some(true);
                Response::from_json(&())
            }

            // Get the value of the flag indicating whether this bucket has been collected.
            //
            // Idempotent
            // Output: `bool`
            Some(aggregate_store_v2::Command::CheckCollected) => {
                Response::from_json(&self.is_collected().await?)
            }

            // Get the value of the flag indicating whether this bucket has been collected.
            //
            // Idempotent
            // Output: `bool`
            Some(aggregate_store_v2::Command::AggregateShareCount) => Response::from_json(
                &self
                    .get_or_default::<Vec<String>>(AGGREGATION_JOB_IDS_KEY)
                    .await?
                    .len(),
            ),

            None => Err(int_err(format!(
                "AggregatesStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    fn should_cleanup_at(&self) -> Option<ScheduledTime> {
        const VAR_NAME: &str = "DAP_DURABLE_AGGREGATE_STORE_GC_AFTER_SECS";
        static SELF_DELETE_AFTER: OnceLock<Duration> = OnceLock::new();

        let duration = SELF_DELETE_AFTER.get_or_init(|| {
            Duration::from_secs(
                self.env
                    .var(VAR_NAME)
                    .map(|v| {
                        v.to_string().parse().unwrap_or_else(|e| {
                            panic!("{VAR_NAME} could not be parsed as a number of seconds: {e}")
                        })
                    })
                    .unwrap_or(60 * 60 * 24 * 7), // one week
            )
        });

        Some(ScheduledTime::from(*duration))
    }
}
