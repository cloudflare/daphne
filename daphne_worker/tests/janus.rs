// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Integration tests for [Janus](https://github.com/divviup/janus).

mod test_runner;

use assert_matches::assert_matches;
use daphne::constants;
use daphne_worker::InternalAggregateInfo;
use janus_prio::{codec::Decode, vdaf::prio3::Prio3Aes128Sum};
use rand::prelude::*;
use test_runner::{TestRunner, COLLECTOR_HPKE_SECRET_KEY};

// Test that daphne can aggregate a report from a Janus client.
//
// TODO(MVP) Update Daphne to latest version of the draft to make this test pass.
#[tokio::test]
#[cfg_attr(not(feature = "test_janus"), ignore)]
async fn janus_client() {
    let t = TestRunner::default().await;
    let client = reqwest::Client::new();

    let raw_leader_hpke_config = t.leader_get_raw_hpke_config(&client).await;
    let leader_hpke_config =
        janus::message::HpkeConfig::get_decoded(&raw_leader_hpke_config).unwrap();

    let raw_helper_hpke_config = t.helper_get_raw_hpke_config(&client).await;
    let helper_hpke_config =
        janus::message::HpkeConfig::get_decoded(&raw_helper_hpke_config).unwrap();

    let vdaf = assert_matches!(t.vdaf, daphne::VdafConfig::Prio3(ref prio3_config) => {
        assert_matches!(prio3_config, daphne::Prio3Config::Sum{ bits } =>
            Prio3Aes128Sum::new(2, *bits).unwrap()
        )
    });

    let task_id = janus::message::TaskId::get_decoded(t.task_id.as_ref()).unwrap();

    let janus_client_parameters = janus_server::client::ClientParameters::new(
        task_id,
        vec![t.leader_url.clone(), t.helper_url.clone()],
    );

    let client_clock =
        janus_test_util::MockClock::new(janus::message::Time::from_seconds_since_epoch(t.now));

    let janus_client = janus_server::client::Client::new(
        janus_client_parameters,
        vdaf,
        (),
        client_clock,
        &client,
        leader_hpke_config,
        helper_hpke_config,
    );

    janus_client.upload(&23).await.unwrap();

    let agg_info = InternalAggregateInfo {
        batch_info: t.batch_info(),
        agg_rate: 1,
    };
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_processed, 1);
    assert_eq!(agg_telem.reports_aggregated, 1);
}

// Test that daphne can run the aggregation sub-protocol with a Janus helper.
//
// For tracing, run `cargo test` with RUST_LOG=aggregator=trace,janus=trace,warning.
//
// TODO(MVP) Update Daphne to latest version of the draft to make this test pass.
#[tokio::test]
#[cfg_attr(not(feature = "test_janus"), ignore)]
async fn janus_helper() {
    // TODO Use the same version of prio as Janus.
    use prio::codec::{Decode, Encode};

    janus_server::trace::test_util::install_test_trace_subscriber();
    let (t, janus_helper) = TestRunner::janus_helper().await;
    let client = t.http_client();
    let hpke_config_list = t.get_hpke_configs(&client).await;
    let agg_info = InternalAggregateInfo {
        batch_info: t.batch_info(),
        agg_rate: t.min_batch_size,
    };

    // Upload a number of reports (a few more than the aggregation rate).
    let mut rng = thread_rng();
    let batch_interval = agg_info.batch_info.as_ref().unwrap();
    for _ in 0..agg_info.agg_rate + 3 {
        let now = rng.gen_range(batch_interval.start..batch_interval.end());
        t.leader_post_expect_ok(
            &client,
            "/upload",
            constants::MEDIA_TYPE_REPORT,
            t.vdaf
                .produce_report(
                    &hpke_config_list,
                    now,
                    &t.task_id,
                    daphne::DapMeasurement::U64(1),
                )
                .unwrap()
                .get_encoded(),
        )
        .await;
    }

    // Aggregate first.
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_aggregated, agg_info.agg_rate);
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_aggregated, 3);
    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_aggregated, 0);

    // Get the collect URI.
    let collect_req = daphne::messages::CollectReq {
        task_id: t.task_id.clone(),
        batch_interval: batch_interval.clone(),
        agg_param: Vec::new(),
    };
    let url = t.leader_url.join("/collect").unwrap();
    let resp = client
        .post(url.as_str())
        .body(collect_req.get_encoded())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);

    let agg_telem = t.internal_process(&client, &agg_info).await;
    assert_eq!(agg_telem.reports_collected, 13);

    // Poll the collect URI before the ColleectResp is ready.
    let collect_uri = resp.headers().get("Location").unwrap().to_str().unwrap();
    let resp = client.get(collect_uri).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let decrypter: daphne::hpke::HpkeSecretKey =
        serde_json::from_str(COLLECTOR_HPKE_SECRET_KEY).unwrap();
    let collect_resp =
        daphne::messages::CollectResp::get_decoded(&resp.bytes().await.unwrap()).unwrap();
    let agg_res = t
        .vdaf
        .consume_encrypted_agg_shares(
            &decrypter,
            &t.task_id,
            &batch_interval,
            collect_resp.encrypted_agg_shares,
        )
        .unwrap();
    assert_eq!(agg_res, daphne::DapAggregateResult::U64(13 as u64));

    janus_helper.shutdown().await;
}
