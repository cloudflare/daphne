// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::Context;
use daphne::{
    hpke::{HpkeKemId, HpkeReceiverConfig},
    messages::HpkeConfigList,
};
use rand::{thread_rng, Rng};
use url::Url;

use crate::HttpClient;

pub async fn add_hpke_config(
    http_client: &HttpClient,
    aggregator_url: &Url,
    kem_alg: HpkeKemId,
) -> anyhow::Result<()> {
    let mut rng = thread_rng();
    let HpkeConfigList { hpke_configs } =
        match http_client.get_hpke_config(aggregator_url, None).await {
            Ok(configs) => configs,
            Err(_) => HpkeConfigList {
                hpke_configs: vec![],
            },
        };

    let receiver_config = loop {
        let config = HpkeReceiverConfig::gen(rng.gen(), kem_alg)
            .context("failed to generate HPKE receiver config")?;
        if hpke_configs.iter().all(|c| c.id != config.config.id) {
            break config;
        }
    };

    http_client
        .post(
            aggregator_url
                .join("internal/test/add_hpke_config")
                .unwrap(),
        )
        .json(&receiver_config)
        .send()
        .await
        .context("adding the hpke config")?
        .error_for_status()
        .context("adding the hpke config")?;

    println!("config added!");

    Ok(())
}

pub async fn delete_all_storage(
    http_client: &HttpClient,
    aggregator_url: &Url,
    kem_alg: Option<HpkeKemId>,
) -> anyhow::Result<()> {
    http_client
        .post(aggregator_url.join("/internal/delete_all").unwrap())
        .send()
        .await
        .context("deleting storage")?
        .error_for_status()
        .context("deleting storage")?;

    if let Some(kem_alg) = kem_alg {
        add_hpke_config(http_client, aggregator_url, kem_alg).await?;
    }
    Ok(())
}
