// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(any(test, feature = "test-utils"))]
use crate::vdaf::mastic::mastic_shard;
use crate::{
    fatal_error,
    hpke::HpkeConfig,
    messages::{
        encode_u32_bytes, Extension, HpkeCiphertext, PlaintextInputShare, Report, ReportId,
        ReportMetadata, TaskId, Time,
    },
    vdaf::{prio2::prio2_shard, prio3::prio3_shard},
    DapError, DapMeasurement, DapVersion, VdafConfig,
};
use prio::codec::{Encode, ParameterizedEncode};
use rand::prelude::*;

use super::{
    CTX_INPUT_SHARE_DRAFT02, CTX_INPUT_SHARE_DRAFT_LATEST, CTX_ROLE_CLIENT, CTX_ROLE_HELPER,
    CTX_ROLE_LEADER,
};

impl VdafConfig {
    /// Generate a report for a measurement. This method is run by the Client.
    ///
    /// # Inputs
    ///
    /// * `hpke_config_list` is the sequence of HPKE configs, the first belonging to the Leader and the
    /// remainder belonging to the Helpers. Note that the current draft only supports one Helper,
    /// so this method will return an error if `hpke_config_list.len() != 2`.
    ///
    /// * `now` is the number of seconds since the UNIX epoch. It is the caller's responsibility to
    /// ensure this value is truncated to the nearest `min_batch_duration`, as required by the
    /// spec.
    ///
    /// * `task_id` is the DAP task for which this report is being generated.
    ///
    /// * `measurement` is the measurement.
    ///
    /// * `extensions` are the extensions.
    ///
    /// * `version` is the `DapVersion` to use.
    pub fn produce_report_with_extensions(
        &self,
        hpke_config_list: &[HpkeConfig],
        time: Time,
        task_id: &TaskId,
        measurement: DapMeasurement,
        extensions: Vec<Extension>,
        version: DapVersion,
    ) -> Result<Report, DapError> {
        let mut rng = thread_rng();
        let report_id = ReportId(rng.gen());
        let (public_share, input_shares) = self.produce_input_shares(measurement, &report_id.0)?;
        Self::produce_report_with_extensions_for_shares(
            public_share,
            input_shares,
            hpke_config_list,
            time,
            task_id,
            &report_id,
            extensions,
            version,
        )
    }

    /// Generate a report for the given public and input shares with the given extensions.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn produce_report_with_extensions_for_shares(
        public_share: Vec<u8>,
        input_shares: Vec<Vec<u8>>,
        hpke_configs: &[HpkeConfig],
        time: Time,
        task_id: &TaskId,
        report_id: &ReportId,
        extensions: Vec<Extension>,
        version: DapVersion,
    ) -> Result<Report, DapError> {
        if input_shares.len() != 2 {
            return Err(fatal_error!(err = "unexpected number of input shares"));
        }
        if hpke_configs.len() != 2 {
            return Err(fatal_error!(err = "unexpected number of HPKE configs"));
        }

        let (draft02_extensions, mut draft_latest_plaintext_input_share) = match version {
            DapVersion::DraftLatest => (
                None,
                Some(PlaintextInputShare {
                    extensions,
                    payload: Vec::default(),
                }),
            ),
            DapVersion::Draft02 => (Some(extensions), None),
        };

        let metadata = ReportMetadata {
            id: *report_id,
            time,
            draft02_extensions,
        };

        let encoded_input_shares = input_shares.into_iter().map(|input_share| {
            if let Some(ref mut plaintext_input_share) = draft_latest_plaintext_input_share {
                plaintext_input_share.payload = input_share;
                plaintext_input_share.get_encoded_with_param(&version)
            } else {
                Ok(input_share)
            }
        });

        let input_share_text = match version {
            DapVersion::Draft02 => CTX_INPUT_SHARE_DRAFT02,
            DapVersion::DraftLatest => CTX_INPUT_SHARE_DRAFT_LATEST,
        };
        let n: usize = input_share_text.len();
        let mut info = Vec::with_capacity(n + 2);
        info.extend_from_slice(input_share_text);
        info.push(CTX_ROLE_CLIENT); // Sender role
        info.push(CTX_ROLE_LEADER); // Receiver role placeholder; updated below.

        let mut aad = Vec::with_capacity(58);
        task_id.encode(&mut aad).map_err(DapError::encoding)?;
        metadata
            .encode_with_param(&version, &mut aad)
            .map_err(DapError::encoding)?;
        // draft02 compatibility: In draft02, the tag-length prefix is not specified. However, the
        // intent was to include the prefix, and it is specified unambiguoiusly in the latest
        // version. All of our partners for interop have agreed to include the prefix for draft02,
        // so we have hard-coded it here.
        encode_u32_bytes(&mut aad, &public_share).map_err(DapError::encoding)?;

        let mut encrypted_input_shares = Vec::with_capacity(2);
        for (i, (hpke_config, encoded_input_share)) in
            hpke_configs.iter().zip(encoded_input_shares).enumerate()
        {
            info[n + 1] = if i == 0 {
                CTX_ROLE_LEADER
            } else {
                CTX_ROLE_HELPER
            }; // Receiver role
            let (enc, payload) = hpke_config.encrypt(
                &info,
                &aad,
                &encoded_input_share.map_err(DapError::encoding)?,
            )?;

            encrypted_input_shares.push(HpkeCiphertext {
                config_id: hpke_config.id,
                enc,
                payload,
            });
        }

        Ok(Report {
            draft02_task_id: task_id.for_request_payload(&version),
            report_metadata: metadata,
            public_share,
            encrypted_input_shares: encrypted_input_shares.try_into().unwrap(),
        })
    }

    /// Generate shares for a measurement.
    pub(crate) fn produce_input_shares(
        &self,
        measurement: DapMeasurement,
        nonce: &[u8; 16],
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), DapError> {
        match self {
            Self::Prio3(prio3_config) => Ok(prio3_shard(prio3_config, measurement, nonce)?),
            Self::Prio2 { dimension } => Ok(prio2_shard(*dimension, measurement, nonce)?),
            #[cfg(any(test, feature = "test-utils"))]
            VdafConfig::Mastic {
                input_size,
                weight_config,
            } => Ok(mastic_shard(*input_size, *weight_config, measurement)?),
        }
    }

    /// Generate a report for a measurement. This method is run by the Client.
    ///
    /// # Inputs
    ///
    /// * `hpke_config_list` is the sequence of HPKE configs, the first belonging to the Leader and the
    /// remainder belonging to the Helpers. Note that the current draft only supports one Helper,
    /// so this method will return an error if `hpke_config_list.len() != 2`.
    ///
    /// * `time` is the number of seconds since the UNIX epoch. It is the caller's responsibility to
    /// ensure this value is truncated to the nearest `min_batch_duration`, as required by the
    /// spec.
    ///
    /// * `task_id` is the DAP task for which this report is being generated.
    ///
    /// * `measurement` is the measurement.
    ///
    /// * `version` is the `DapVersion` to use.
    pub fn produce_report(
        &self,
        hpke_config_list: &[HpkeConfig],
        time: Time,
        task_id: &TaskId,
        measurement: DapMeasurement,
        version: DapVersion,
    ) -> Result<Report, DapError> {
        self.produce_report_with_extensions(
            hpke_config_list,
            time,
            task_id,
            measurement,
            Vec::new(),
            version,
        )
    }
}
