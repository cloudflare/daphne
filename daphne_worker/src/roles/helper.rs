// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of the helper side of the protocol

use crate::{
    auth::DaphneWorkerAuth,
    config::DaphneWorker,
    durable::{
        helper_state_store::{
            durable_helper_state_name, DURABLE_HELPER_STATE_GET,
            DURABLE_HELPER_STATE_PUT_IF_NOT_EXISTS,
        },
        BINDING_DAP_HELPER_STATE_STORE,
    },
};
use async_trait::async_trait;
use daphne::{
    error::DapAbort, fatal_error, messages::TaskId, roles::DapHelper, DapError, DapHelperState,
    MetaAggregationJobId,
};
use prio::codec::Encode;

#[async_trait(?Send)]
impl<'srv> DapHelper<DaphneWorkerAuth> for DaphneWorker<'srv> {
    async fn put_helper_state_if_not_exists(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
        helper_state: &DapHelperState,
    ) -> std::result::Result<bool, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        let helper_state_hex = hex::encode(helper_state.get_encoded());
        Ok(self
            .durable()
            .with_retry()
            .post(
                BINDING_DAP_HELPER_STATE_STORE,
                DURABLE_HELPER_STATE_PUT_IF_NOT_EXISTS,
                durable_helper_state_name(&task_config.as_ref().version, task_id, agg_job_id),
                helper_state_hex,
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?)
    }

    async fn get_helper_state(
        &self,
        task_id: &TaskId,
        agg_job_id: &MetaAggregationJobId,
    ) -> std::result::Result<Option<DapHelperState>, DapError> {
        let task_config = self.try_get_task_config(task_id).await?;
        // TODO(cjpatton) Figure out if retry is safe, since the request is not actually
        // idempotent. (It removes the helper's state from storage if it exists.)
        let res: Option<String> = self
            .durable()
            .with_retry()
            .get(
                BINDING_DAP_HELPER_STATE_STORE,
                DURABLE_HELPER_STATE_GET,
                durable_helper_state_name(&task_config.as_ref().version, task_id, agg_job_id),
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?;

        match res {
            Some(helper_state_hex) => {
                let data = hex::decode(helper_state_hex)
                    .map_err(|e| DapAbort::from_hex_error(e, task_id.clone()))?;
                let helper_state = DapHelperState::get_decoded(&task_config.as_ref().vdaf, &data)?;
                Ok(Some(helper_state))
            }
            None => Ok(None),
        }
    }
}
