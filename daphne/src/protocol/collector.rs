// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    fatal_error,
    hpke::HpkeDecrypter,
    messages::{encode_u32_bytes, BatchSelector, HpkeCiphertext, TaskId},
    vdaf::{prio2::prio2_unshard, prio3::prio3_unshard},
    DapAggregateResult, DapError, DapVersion, VdafConfig,
};
use prio::codec::Encode;

use super::{
    CTX_AGG_SHARE_DRAFT02, CTX_AGG_SHARE_DRAFT_LATEST, CTX_ROLE_COLLECTOR, CTX_ROLE_HELPER,
    CTX_ROLE_LEADER,
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
    /// Aggregators. The first encrypted aggregate shares must be the Leader's.
    ///
    /// * `version` is the `DapVersion` to use.
    #[allow(clippy::too_many_arguments)]
    pub async fn consume_encrypted_agg_shares(
        &self,
        decrypter: &impl HpkeDecrypter,
        task_id: &TaskId,
        batch_sel: &BatchSelector,
        report_count: u64,
        agg_param: &[u8],
        encrypted_agg_shares: Vec<HpkeCiphertext>,
        version: DapVersion,
    ) -> Result<DapAggregateResult, DapError> {
        if encrypted_agg_shares.len() != 2 {
            return Err(fatal_error!(
                err = "unexpected number of encrypted aggregate shares"
            ));
        }

        let agg_share_text = match version {
            DapVersion::Draft02 => CTX_AGG_SHARE_DRAFT02,
            DapVersion::DraftLatest => CTX_AGG_SHARE_DRAFT_LATEST,
        };
        let n: usize = agg_share_text.len();
        let mut info = Vec::with_capacity(n + 2);
        info.extend_from_slice(agg_share_text);
        info.push(CTX_ROLE_LEADER); // Sender role placeholder
        info.push(CTX_ROLE_COLLECTOR); // Receiver role

        let mut aad = Vec::with_capacity(40);
        task_id.encode(&mut aad).map_err(DapError::encoding)?;
        if version != DapVersion::Draft02 {
            encode_u32_bytes(&mut aad, agg_param).map_err(DapError::encoding)?;
        }
        batch_sel.encode(&mut aad).map_err(DapError::encoding)?;

        let mut agg_shares = Vec::with_capacity(encrypted_agg_shares.len());
        for (i, agg_share_ciphertext) in encrypted_agg_shares.iter().enumerate() {
            info[n] = if i == 0 {
                CTX_ROLE_LEADER
            } else {
                CTX_ROLE_HELPER
            };

            let agg_share_data = decrypter
                .hpke_decrypt(task_id, &info, &aad, agg_share_ciphertext)
                .await?;
            agg_shares.push(agg_share_data);
        }

        if agg_shares.len() != encrypted_agg_shares.len() {
            return Err(fatal_error!(
                err = "one or more HPKE ciphertexts with unrecognized config ID",
            ));
        }

        let num_measurements = usize::try_from(report_count).unwrap();
        match self {
            Self::Prio3(prio3_config) => {
                Ok(prio3_unshard(prio3_config, num_measurements, agg_shares)?)
            }
            Self::Prio2 { dimension } => {
                Ok(prio2_unshard(*dimension, num_measurements, agg_shares)?)
            }
        }
    }
}
