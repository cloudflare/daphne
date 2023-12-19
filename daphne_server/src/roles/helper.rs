// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use axum::async_trait;
use daphne::{
    error::DapAbort,
    fatal_error,
    messages::TaskId,
    roles::{DapAggregator, DapHelper},
    DapAggregationJobState, DapError, MetaAggregationJobId,
};
use daphne_service_utils::{auth::DaphneAuth, durable_requests::bindings};
use prio::codec::Encode;

#[async_trait]
impl DapHelper<DaphneAuth> for crate::App {
    async fn put_helper_state_if_not_exists<Id>(
        &self,
        task_id: &TaskId,
        agg_job_id: Id,
        helper_state: &DapAggregationJobState,
    ) -> Result<bool, DapError>
    where
        Id: Into<MetaAggregationJobId> + Send,
    {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;
        let helper_state_hex = hex::encode(helper_state.get_encoded());
        Ok(self
            .durable()
            .with_retry()
            .request(
                bindings::HelperState::PutIfNotExists,
                (task_config.as_ref().version, task_id, &agg_job_id.into()),
            )
            .bin_encoding(helper_state_hex)
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))?)
    }

    async fn get_helper_state<Id>(
        &self,
        task_id: &TaskId,
        agg_job_id: Id,
    ) -> Result<Option<DapAggregationJobState>, DapError>
    where
        Id: Into<MetaAggregationJobId> + Send,
    {
        let task_config = self
            .get_task_config_for(task_id)
            .await?
            .ok_or(DapError::Abort(DapAbort::UnrecognizedTask))?;
        // TODO(cjpatton) Figure out if retry is safe, since the request is not actually
        // idempotent. (It removes the helper's state from storage if it exists.)
        let res: Option<String> = self
            .durable()
            .with_retry()
            .request(
                bindings::HelperState::Get,
                (task_config.as_ref().version, task_id, &agg_job_id.into()),
            )
            .send()
            .await
            .map_err(|e| fatal_error!(err = ?e))?;

        match res {
            Some(helper_state_hex) => {
                let data = hex::decode(helper_state_hex)
                    .map_err(|e| DapAbort::from_hex_error(e, *task_id))?;
                let helper_state =
                    DapAggregationJobState::get_decoded(&task_config.as_ref().vdaf, &data)?;
                Ok(Some(helper_state))
            }
            None => Ok(None),
        }
    }
}
