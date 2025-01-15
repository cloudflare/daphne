// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    constants::DapAggregatorRole,
    fatal_error,
    hpke::{info_and_aad, HpkeConfig},
    messages::{Extension, PlaintextInputShare, Report, ReportId, ReportMetadata, TaskId, Time},
    DapError, DapMeasurement, DapVersion, VdafConfig,
};
use prio::codec::ParameterizedEncode;
use rand::prelude::*;

impl VdafConfig {
    /// Generate a report for a measurement. This method is run by the Client.
    ///
    /// # Inputs
    ///
    /// * `hpke_config_list` is the sequence of HPKE configs, the first belonging to the Leader and
    ///   the remainder belonging to the Helpers. Note that the current draft only supports one
    ///   Helper, so this method will return an error if `hpke_config_list.len() != 2`.
    ///
    /// * `now` is the number of seconds since the UNIX epoch. It is the caller's responsibility to
    ///   ensure this value is truncated to the nearest `min_batch_duration`, as required by the
    ///   spec.
    ///
    /// * `task_id` is the DAP task for which this report is being generated.
    ///
    /// * `measurement` is the measurement.
    ///
    /// * `extensions` are the extensions.
    ///
    /// * `version` is the `DapVersion` to use.
    #[allow(clippy::too_many_arguments)]
    pub fn produce_report_with_extensions(
        &self,
        hpke_config_list: &[HpkeConfig; 2],
        time: Time,
        task_id: &TaskId,
        measurement: DapMeasurement,
        public_extensions: Option<Vec<Extension>>,
        private_extensions: Vec<Extension>,
        version: DapVersion,
    ) -> Result<Report, DapError> {
        let mut rng = thread_rng();
        let report_id = ReportId(rng.gen());
        let (public_share, input_shares) = self
            .shard(measurement, &report_id.0, *task_id, version)
            .map_err(DapError::from_vdaf)?;
        Self::produce_report_with_extensions_for_shares(
            public_share,
            input_shares,
            hpke_config_list,
            time,
            task_id,
            &report_id,
            public_extensions,
            private_extensions,
            version,
        )
    }

    /// Generate a report for the given public and input shares with the given extensions.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn produce_report_with_extensions_for_shares(
        public_share: Vec<u8>,
        input_shares: [Vec<u8>; 2],
        hpke_configs: &[HpkeConfig; 2],
        time: Time,
        task_id: &TaskId,
        report_id: &ReportId,
        public_extensions: Option<Vec<Extension>>,
        private_extensions: Vec<Extension>,
        version: DapVersion,
    ) -> Result<Report, DapError> {
        if let (Some(_), DapVersion::Draft09) | (None, DapVersion::Latest) =
            (&public_extensions, version)
        {
            return Err(fatal_error!(
                err = format!("public extensions not set correctly for {version:?}")
            ));
        }

        let mut plaintext_input_share = PlaintextInputShare {
            private_extensions,
            payload: Vec::default(),
        };

        let metadata = ReportMetadata {
            id: *report_id,
            time,
            public_extensions,
        };

        let encoded_input_shares = input_shares.into_iter().map(|input_share| {
            plaintext_input_share.payload = input_share;
            plaintext_input_share.get_encoded_with_param(&version)
        });

        let mut info = info_and_aad::InputShare {
            version,
            receiver: DapAggregatorRole::Leader, //placeholder; updated below.
            task_id,
            report_metadata: &metadata,
            public_share: &public_share,
        };

        let mut encrypted_input_shares = Vec::with_capacity(2);
        for (i, (hpke_config, encoded_input_share)) in
            hpke_configs.iter().zip(encoded_input_shares).enumerate()
        {
            info.receiver = if i == 0 {
                DapAggregatorRole::Leader
            } else {
                DapAggregatorRole::Helper
            }; // Receiver role
            let ciphertext =
                hpke_config.encrypt(info, &encoded_input_share.map_err(DapError::encoding)?)?;

            encrypted_input_shares.push(ciphertext);
        }

        Ok(Report {
            report_metadata: metadata,
            public_share,
            encrypted_input_shares: encrypted_input_shares.try_into().unwrap(),
        })
    }

    /// Generate a report for a measurement. This method is run by the Client.
    ///
    /// # Inputs
    ///
    /// * `hpke_config_list` is the sequence of HPKE configs, the first belonging to the Leader and
    ///   the remainder belonging to the Helpers. Note that the current draft only supports one
    ///   Helper, so this method will return an error if `hpke_config_list.len() != 2`.
    ///
    /// * `time` is the number of seconds since the UNIX epoch. It is the caller's responsibility
    ///   to ensure this value is truncated to the nearest `min_batch_duration`, as required by the
    ///   spec.
    ///
    /// * `task_id` is the DAP task for which this report is being generated.
    ///
    /// * `measurement` is the measurement.
    ///
    /// * `version` is the `DapVersion` to use.
    pub fn produce_report(
        &self,
        hpke_config_list: &[HpkeConfig; 2],
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
            match version {
                DapVersion::Draft09 => None,
                DapVersion::Latest => Some(Vec::new()),
            },
            Vec::new(),
            version,
        )
    }
}
