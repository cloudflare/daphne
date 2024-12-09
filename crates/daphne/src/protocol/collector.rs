// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(feature = "experimental")]
use crate::vdaf::mastic::mastic_unshard;
use crate::{
    constants::DapAggregatorRole,
    fatal_error,
    hpke::{info_and_aad, HpkeDecrypter},
    messages::{BatchSelector, HpkeCiphertext, TaskId},
    vdaf::{prio2::prio2_unshard, prio3::prio3_unshard, prio3_draft09::prio3_draft09_unshard},
    DapAggregateResult, DapAggregationParam, DapError, DapVersion, VdafConfig,
};

impl VdafConfig {
    /// Decrypt and unshard a sequence of aggregate shares. This method is run by the Collector
    /// after completing a collect request.
    ///
    /// # Inputs
    ///
    /// * `decrypter` is used to decrypt the aggregate shares.
    ///
    /// * `task_id` is the DAP task ID.
    ///
    /// * `batch_interval` is the batch interval for the aggregate share.
    ///
    /// * `encrypted_agg_shares` is the set of encrypted aggregate shares produced by the
    ///   Aggregators. The first encrypted aggregate shares must be the Leader's.
    ///
    /// * `version` is the `DapVersion` to use.
    #[expect(clippy::too_many_arguments)]
    pub fn consume_encrypted_agg_shares(
        &self,
        decrypter: &impl HpkeDecrypter,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
        report_count: u64,
        agg_param: &DapAggregationParam,
        encrypted_agg_shares: Vec<HpkeCiphertext>,
        version: DapVersion,
    ) -> Result<DapAggregateResult, DapError> {
        if encrypted_agg_shares.len() != 2 {
            return Err(fatal_error!(
                err = "unexpected number of encrypted aggregate shares"
            ));
        }

        let mut info = info_and_aad::AggregateShare {
            version,
            sender: DapAggregatorRole::Leader, // placeholder
            task_id,
            agg_param,
            batch_selector: batch_sel,
        };

        let mut agg_shares = Vec::with_capacity(encrypted_agg_shares.len());
        for (i, agg_share_ciphertext) in encrypted_agg_shares.iter().enumerate() {
            info.sender = if i == 0 {
                DapAggregatorRole::Leader
            } else {
                DapAggregatorRole::Helper
            };

            let agg_share_data = decrypter.hpke_decrypt(info, agg_share_ciphertext)?;
            agg_shares.push(agg_share_data);
        }

        if agg_shares.len() != encrypted_agg_shares.len() {
            return Err(fatal_error!(
                err = "one or more HPKE ciphertexts with unrecognized config ID",
            ));
        }

        let num_measurements = usize::try_from(report_count).unwrap();
        match self {
            Self::Prio3Draft09(prio3_config) => {
                prio3_draft09_unshard(prio3_config, num_measurements, agg_shares)
            }
            Self::Prio3(prio3_config) => prio3_unshard(prio3_config, num_measurements, agg_shares),
            Self::Prio2 { dimension } => prio2_unshard(*dimension, num_measurements, agg_shares),
            #[cfg(feature = "experimental")]
            Self::Mastic {
                input_size: _,
                weight_config,
            } => mastic_unshard(*weight_config, agg_param, agg_shares),
            Self::Pine(pine) => pine.unshard(num_measurements, agg_shares),
        }
        .map_err(|e| fatal_error!(err = ?e, "failed to unshard agg_shares"))
    }
}
