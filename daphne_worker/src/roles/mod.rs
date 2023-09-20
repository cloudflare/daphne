// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Implementation of DAP Aggregator roles for Daphne-Worker.
//!
//! Daphne-Worker uses bearer tokens for DAP request authorization as specified in
//! draft-ietf-ppm-dap-03.

mod aggregator;
mod helper;
mod leader;

use crate::config::{BearerTokenKvPair, DaphneWorker};
use async_trait::async_trait;
use daphne::{
    auth::BearerTokenProvider,
    fatal_error,
    hpke::{HpkeConfig, HpkeDecrypter},
    messages::{HpkeCiphertext, TaskId, TransitionFailure},
    roles::DapAggregator,
    DapError, DapTaskConfig, DapVersion,
};

#[async_trait(?Send)]
impl<'srv> HpkeDecrypter for DaphneWorker<'srv> {
    type WrappedHpkeConfig<'a> = HpkeConfig
        where Self: 'a;

    async fn get_hpke_config_for<'s>(
        &'s self,
        version: DapVersion,
        _task_id: Option<&TaskId>,
    ) -> std::result::Result<Self::WrappedHpkeConfig<'s>, DapError> {
        self.get_hpke_receiver_config(version, |receiver_config_list| {
            // Assume the first HPKE config in the receiver list has the highest preference.
            //
            // NOTE draft02 compatibility: The spec allows us to return multiple configs, but
            // draft02 does not. In order to keep things imple we preserve the semantics of the old
            // version for now.
            receiver_config_list
                .iter()
                .next()
                .map(|receiver| receiver.config.clone())
        })
        .await
        .map_err(|e| fatal_error!(err = ?e, "failed to get list of hpke key configs in kv"))?
        .ok_or_else(|| fatal_error!(err = "there are no hpke configs in kv!!", %version))
    }

    async fn can_hpke_decrypt(
        &self,
        task_id: &TaskId,
        config_id: u8,
    ) -> std::result::Result<bool, DapError> {
        let version = self.try_get_task_config(task_id).await?.as_ref().version;
        Ok(self
            .get_hpke_receiver_config(version, |config_list| {
                config_list
                    .iter()
                    .find(|receiver| receiver.config.id == config_id)
                    .map(|_| ())
            })
            .await
            .map_err(|e| fatal_error!(err = ?e))?
            .is_some())
    }

    async fn hpke_decrypt(
        &self,
        task_id: &TaskId,
        info: &[u8],
        aad: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> std::result::Result<Vec<u8>, DapError> {
        let version = self.try_get_task_config(task_id).await?.as_ref().version;
        self.get_hpke_receiver_config(version, |config_list| {
            config_list
                .iter()
                .find(|receiver| receiver.config.id == ciphertext.config_id)
                .map(|receiver| receiver.decrypt(info, aad, &ciphertext.enc, &ciphertext.payload))
        })
        .await
        .map_err(|e| fatal_error!(err = ?e))?
        .ok_or_else(|| DapError::Transition(TransitionFailure::HpkeUnknownConfigId))?
    }
}

#[async_trait(?Send)]
impl<'srv> BearerTokenProvider for DaphneWorker<'srv> {
    type WrappedBearerToken<'a> = BearerTokenKvPair<'a>
        where Self: 'a;

    async fn get_leader_bearer_token_for<'s>(
        &'s self,
        task_id: &'s TaskId,
        task_config: &DapTaskConfig,
    ) -> std::result::Result<Option<BearerTokenKvPair<'s>>, DapError> {
        if let Some(ref taskprov_config) = self.config().taskprov {
            if self.get_global_config().allow_taskprov && task_config.taskprov {
                return Ok(Some(BearerTokenKvPair::new(
                    task_id,
                    taskprov_config.leader_auth.as_ref(),
                )));
            }
        }

        self.get_leader_bearer_token(task_id)
            .await
            .map_err(|e| fatal_error!(err = ?e))
    }

    async fn get_collector_bearer_token_for<'s>(
        &'s self,
        task_id: &'s TaskId,
        task_config: &DapTaskConfig,
    ) -> std::result::Result<Option<Self::WrappedBearerToken<'s>>, DapError> {
        if let Some(ref taskprov_config) = self.config().taskprov {
            if self.get_global_config().allow_taskprov && task_config.taskprov {
                return Ok(Some(BearerTokenKvPair::new(
                    task_id,
                    taskprov_config
                        .collector_auth
                        .as_ref()
                        .expect("collector authorization method not set")
                        .as_ref(),
                )));
            }
        }

        self.get_collector_bearer_token(task_id)
            .await
            .map_err(|e| fatal_error!(err = ?e))
    }
}
