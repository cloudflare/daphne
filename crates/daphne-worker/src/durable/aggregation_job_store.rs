// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{req_parse, GcDurableObject};
use crate::int_err;
use daphne::messages::AggregationJobId;
use daphne_service_utils::durable_requests::bindings::{
    aggregation_job_store::{self, NewJobResponse},
    DurableMethod,
};
use std::{collections::HashSet, sync::OnceLock, time::Duration};
use worker::{js_sys::Uint8Array, Request, Response};

super::mk_durable_object! {
    struct AggregationJobStore {
        state: State,
        env: Env,
        seen_agg_job_ids: Option<HashSet<AggregationJobId>>,
    }
}

const SEEN_AGG_JOB_IDS_KEY: &str = "agg-job-ids";

impl GcDurableObject for AggregationJobStore {
    type DurableMethod = aggregation_job_store::Command;

    fn with_state_and_env(state: worker::State, env: worker::Env) -> Self {
        Self {
            state,
            env,
            seen_agg_job_ids: None,
        }
    }

    async fn handle(&mut self, mut req: Request) -> worker::Result<Response> {
        match Self::DurableMethod::try_from_uri(&req.path()) {
            Some(aggregation_job_store::Command::NewJob) => {
                let aggregation_job_store::NewJobRequest { id, agg_job_hash } =
                    req_parse(&mut req).await?;

                let key = &id.to_string();
                let response = match self.get::<Vec<u8>>(key).await? {
                    Some(hash) if hash == *agg_job_hash => NewJobResponse::Ok,
                    Some(_) => NewJobResponse::IllegalJobParameters,
                    None => {
                        self.state
                            .storage()
                            .put_raw(key, Uint8Array::from(agg_job_hash.as_ref()))
                            .await?;
                        let seen_agg_job_ids = self.load_seen_agg_job_ids().await?;
                        seen_agg_job_ids.insert(id);
                        self.store_seen_agg_job_ids().await?;
                        NewJobResponse::Ok
                    }
                };

                Response::from_json(&response)
            }
            Some(aggregation_job_store::Command::ListJobIds) => {
                Response::from_json(&self.load_seen_agg_job_ids().await?)
            }
            None => Err(int_err(format!(
                "AggregationJobStore: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }

    fn should_cleanup_at(&self) -> Option<worker::ScheduledTime> {
        const VAR_NAME: &str = "DO_AGGREGATION_JOB_STORE_GC_AFTER_SECS";
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

        Some(worker::ScheduledTime::from(*duration))
    }
}

impl AggregationJobStore {
    async fn load_seen_agg_job_ids(&mut self) -> worker::Result<&mut HashSet<AggregationJobId>> {
        let seen_agg_job_ids = if let Some(seen_agg_job_ids) = self.seen_agg_job_ids.take() {
            seen_agg_job_ids
        } else {
            self.get_or_default(SEEN_AGG_JOB_IDS_KEY).await?
        };

        self.seen_agg_job_ids = Some(seen_agg_job_ids);

        Ok(self.seen_agg_job_ids.as_mut().unwrap())
    }

    async fn store_seen_agg_job_ids(&mut self) -> worker::Result<()> {
        self.put(
            SEEN_AGG_JOB_IDS_KEY,
            self.seen_agg_job_ids.as_ref().unwrap(),
        )
        .await?;
        Ok(())
    }
}
