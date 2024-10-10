// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::path::Path;

use anyhow::Context as _;
use daphne::{
    hpke::HpkeReceiverConfig,
    messages::{BatchSelector, Collection, TaskId},
    vdaf::VdafConfig,
    DapAggregateResult, DapAggregationParam, DapVersion,
};

pub fn collection(
    task_id: &TaskId,
    hpke_config_path: &Path,
    vdaf_config: &VdafConfig,
    batch_selector: BatchSelector,
    version: DapVersion,
    collection: &Collection,
) -> anyhow::Result<DapAggregateResult> {
    let hpke_config: HpkeReceiverConfig = serde_json::from_reader(
        std::fs::File::open(hpke_config_path)
            .with_context(|| format!("opening {}", hpke_config_path.display()))?,
    )
    .with_context(|| format!("deserializing the config at {}", hpke_config_path.display()))?;
    let agg_shares = vdaf_config.consume_encrypted_agg_shares(
        &hpke_config,
        task_id,
        &batch_selector,
        collection.report_count,
        &DapAggregationParam::Empty,
        collection.encrypted_agg_shares.to_vec(),
        version,
    )?;
    Ok(agg_shares)
}
