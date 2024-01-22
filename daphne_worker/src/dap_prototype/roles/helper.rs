// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of the helper side of the protocol

use crate::dap_prototype::config::DaphneWorker;
use async_trait::async_trait;
use daphne::{
    error::DapAbort, fatal_error, messages::TaskId, roles::DapHelper, DapAggregationJobState,
    DapError, MetaAggregationJobId,
};
use daphne_service_utils::auth::DaphneAuth;
use daphne_service_utils::durable_requests::bindings::{DurableMethod, HelperState};
use prio::codec::Encode;

#[async_trait(?Send)]
impl<'srv> DapHelper<DaphneAuth> for DaphneWorker<'srv> {
    async fn put_helper_state_if_not_exists<Id>(
        &self,
        task_id: &TaskId,
        agg_job_id: Id,
        helper_state: &DapAggregationJobState,
    ) -> std::result::Result<bool, DapError>
    where
        Id: Into<MetaAggregationJobId> + Send,
    {
        let task_config = self.try_get_task_config(task_id).await?;
        let helper_state_hex = hex::encode(helper_state.get_encoded().map_err(DapError::encoding)?);
        let durable_name =
            HelperState::name((task_config.as_ref().version, task_id, &agg_job_id.into()))
                .unwrap_from_name();
        Ok(self
            .durable()
            .with_retry()
            .post(
                HelperState::BINDING,
                HelperState::PutIfNotExists.to_uri(),
                durable_name,
                helper_state_hex,
            )
            .await
            .map_err(|e| fatal_error!(err = ?e))?)
    }

    async fn get_helper_state<Id>(
        &self,
        task_id: &TaskId,
        agg_job_id: Id,
    ) -> std::result::Result<Option<DapAggregationJobState>, DapError>
    where
        Id: Into<MetaAggregationJobId> + Send,
    {
        let task_config = self.try_get_task_config(task_id).await?;
        let durable_name =
            HelperState::name((task_config.as_ref().version, task_id, &agg_job_id.into()))
                .unwrap_from_name();
        // TODO(cjpatton) Figure out if retry is safe, since the request is not actually
        // idempotent. (It removes the helper's state from storage if it exists.)
        let res: Option<String> = self
            .durable()
            .with_retry()
            .get(
                HelperState::BINDING,
                HelperState::Get.to_uri(),
                durable_name,
            )
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
