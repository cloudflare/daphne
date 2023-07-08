// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    assert_metrics_include, assert_metrics_include_auxiliary_function, async_test_version,
    async_test_versions,
    error::DapAbort,
    hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId},
    messages::{
        AggregationJobInitReq, BatchSelector, Interval, PartialBatchSelector, Report, ReportId,
        ReportShare, Transition, TransitionFailure, TransitionVar,
    },
    test_version, test_versions,
    testing::AggregationJobTest,
    DapAggregateResult, DapAggregateShare, DapError, DapHelperState, DapHelperTransition,
    DapLeaderState, DapLeaderTransition, DapLeaderUncommitted, DapMeasurement, DapOutputShare,
    DapVersion, Prio3Config, VdafAggregateShare, VdafConfig, VdafPrepMessage, VdafPrepState,
};
use assert_matches::assert_matches;
use hpke_rs::HpkePublicKey;
use paste::paste;
use prio::{
    codec::Encode,
    field::Field64,
    vdaf::{
        prio3::Prio3, Aggregatable, AggregateShare, Aggregator as VdafAggregator,
        Collector as VdafCollector, OutputShare, PrepareTransition,
    },
};
use rand::prelude::*;
use std::{borrow::Cow, fmt::Debug};

use super::{EarlyReportStateConsumed, EarlyReportStateInitialized};

impl<M: Debug> DapLeaderTransition<M> {
    pub(crate) fn unwrap_continue(self) -> (DapLeaderState, M) {
        match self {
            DapLeaderTransition::Continue(state, message) => (state, message),
            _ => {
                panic!("unexpected transition: got {:?}", self);
            }
        }
    }

    pub(crate) fn unwrap_uncommitted(self) -> (DapLeaderUncommitted, M) {
        match self {
            DapLeaderTransition::Uncommitted(uncommitted, message) => (uncommitted, message),
            _ => {
                panic!("unexpected transition: got {:?}", self);
            }
        }
    }
}

impl<M: Debug> DapHelperTransition<M> {
    pub(crate) fn unwrap_continue(self) -> (DapHelperState, M) {
        match self {
            DapHelperTransition::Continue(state, message) => (state, message),
            _ => {
                panic!("unexpected transition: got {:?}", self);
            }
        }
    }

    pub(crate) fn unwrap_finish(self) -> (Vec<DapOutputShare>, M) {
        match self {
            DapHelperTransition::Finish(out_shares, message) => (out_shares, message),
            _ => {
                panic!("unexpected transition: got {:?}", self);
            }
        }
    }
}

// TODO Exercise all of the Prio3 variants and not just Count.
const TEST_VDAF: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Count);

async fn roundtrip_report(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let report = t
        .task_config
        .vdaf
        .produce_report(
            &t.client_hpke_config_list,
            t.now,
            &t.task_id,
            DapMeasurement::U64(1),
            version,
        )
        .unwrap();

    let early_report_state_consumed = EarlyReportStateConsumed::consume(
        &t.leader_hpke_receiver_config,
        true, // is_leader
        &t.task_id,
        &t.task_config,
        Cow::Borrowed(&report.report_metadata),
        Cow::Borrowed(&report.public_share),
        &report.encrypted_input_shares[0],
    )
    .await
    .unwrap();
    let EarlyReportStateInitialized::Ready{ state: leader_step, message: leader_share, .. } =
        EarlyReportStateInitialized::initialize(true, &t.task_config.vdaf_verify_key, &t.task_config.vdaf, early_report_state_consumed).unwrap() else {
        panic!("rejected unexpectedly");
    };

    let early_report_state_consumed = EarlyReportStateConsumed::consume(
        &t.helper_hpke_receiver_config,
        false, // is_helper
        &t.task_id,
        &t.task_config,
        Cow::Borrowed(&report.report_metadata),
        Cow::Borrowed(&report.public_share),
        &report.encrypted_input_shares[1],
    )
    .await
    .unwrap();
    let EarlyReportStateInitialized::Ready{ state: helper_step, message: helper_share, .. } =
        EarlyReportStateInitialized::initialize(false, &t.task_config.vdaf_verify_key, &t.task_config.vdaf, early_report_state_consumed).unwrap() else {
        panic!("rejected unexpectedly");
    };

    match (leader_step, helper_step, leader_share, helper_share) {
        (
            VdafPrepState::Prio3Field64(leader_step),
            VdafPrepState::Prio3Field64(helper_step),
            VdafPrepMessage::Prio3ShareField64(leader_share),
            VdafPrepMessage::Prio3ShareField64(helper_share),
        ) => {
            let vdaf = Prio3::new_count(2).unwrap();
            let message = vdaf
                .prepare_preprocess([leader_share, helper_share])
                .unwrap();

            let leader_out_share = assert_matches!(
                vdaf.prepare_step(leader_step, message.clone()).unwrap(),
                PrepareTransition::Finish(out_share) => out_share
            );
            let leader_agg_share = vdaf.aggregate(&(), [leader_out_share]).unwrap();

            let helper_out_share = assert_matches!(
                vdaf.prepare_step(helper_step, message).unwrap(),
                PrepareTransition::Finish(out_share) => out_share
            );
            let helper_agg_share = vdaf.aggregate(&(), [helper_out_share]).unwrap();

            assert_eq!(
                vdaf.unshard(&(), vec![leader_agg_share, helper_agg_share], 1)
                    .unwrap(),
                1,
            );
        }
        _ => {
            panic!("unexpected output from leader or helper");
        }
    }
}

async_test_versions! { roundtrip_report }

fn roundtrip_report_unsupported_hpke_suite(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);

    // The helper's HPKE config indicates a KEM type no supported by the client.
    let unsupported_hpke_config_list = vec![
        t.client_hpke_config_list[0].clone(),
        HpkeConfig {
            id: thread_rng().gen(),
            kem_id: HpkeKemId::NotImplemented(999),
            kdf_id: HpkeKdfId::HkdfSha256,
            aead_id: HpkeAeadId::Aes128Gcm,
            public_key: HpkePublicKey::from(b"some KEM public key".to_vec()),
        },
    ];

    let res = t.task_config.vdaf.produce_report(
        &unsupported_hpke_config_list,
        t.now,
        &t.task_id,
        DapMeasurement::U64(1),
        version,
    );
    assert_matches!(
        res,
        Err(DapError::Fatal(s)) => assert_eq!(s.to_string(), "HPKE ciphersuite not implemented (999, 1, 1)")
    );
}

test_versions! { roundtrip_report_unsupported_hpke_suite }

async fn produce_agg_job_init_req(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
    ]);

    let (leader_state, agg_job_init_req) = t
        .produce_agg_job_init_req(reports.clone())
        .await
        .unwrap_continue();
    assert_eq!(leader_state.seq.len(), 3);
    assert_eq!(
        agg_job_init_req.draft02_task_id,
        t.task_id.for_request_payload(&version)
    );
    assert_eq!(agg_job_init_req.agg_param.len(), 0);
    assert_eq!(agg_job_init_req.report_shares.len(), 3);
    for (report_shares, report) in agg_job_init_req.report_shares.iter().zip(reports.iter()) {
        assert_eq!(report_shares.report_metadata.id, report.report_metadata.id);
    }

    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();
    assert_eq!(helper_state.seq.len(), 3);
    assert_eq!(agg_job_resp.transitions.len(), 3);
    for (sub, report) in agg_job_resp.transitions.iter().zip(reports.iter()) {
        assert_eq!(sub.report_id, report.report_metadata.id);
    }
}

async_test_versions! { produce_agg_job_init_req }

async fn produce_agg_job_init_req_skip_hpke_decrypt_err(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate HPKE decryption error of leader's report share.
    reports[0].encrypted_input_shares[0].payload[0] ^= 1;

    assert_matches!(
        t.produce_agg_job_init_req(reports).await,
        DapLeaderTransition::Skip
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_leader_report_counter{host="leader.com",status="rejected_hpke_decrypt_error"}"#: 1,
    });
}

async_test_versions! { produce_agg_job_init_req_skip_hpke_decrypt_err }

async fn produce_agg_job_init_req_skip_hpke_unknown_config_id(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Client tries to send Leader encrypted input with incorrect config ID.
    reports[0].encrypted_input_shares[0].config_id ^= 1;

    assert_matches!(
        t.produce_agg_job_init_req(reports).await,
        DapLeaderTransition::Skip
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_leader_report_counter{host="leader.com",status="rejected_hpke_unknown_config_id"}"#: 1,
    });
}

async_test_versions! { produce_agg_job_init_req_skip_hpke_unknown_config_id }

async fn produce_agg_job_init_req_skip_vdaf_prep_error(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = vec![
        t.produce_invalid_report_public_share_decode_failure(DapMeasurement::U64(1), version),
        t.produce_invalid_report_input_share_decode_failure(DapMeasurement::U64(1), version),
    ];

    assert_matches!(
        t.produce_agg_job_init_req(reports).await,
        DapLeaderTransition::Skip
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_leader_report_counter{host="leader.com",status="rejected_vdaf_prep_error"}"#: 2,
    });
}

async_test_versions! { produce_agg_job_init_req_skip_vdaf_prep_error }

async fn handle_agg_job_init_req_hpke_decrypt_err(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate HPKE decryption error of helper's report share.
    reports[0].encrypted_input_shares[1].payload[0] ^= 1;

    let (_, agg_job_init_req) = t
        .produce_agg_job_init_req(reports.clone())
        .await
        .unwrap_continue();
    let (_, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    assert_eq!(agg_job_resp.transitions.len(), 1);
    assert_matches!(
        agg_job_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::HpkeDecryptError)
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_helper_report_counter{host="helper.org",status="rejected_hpke_decrypt_error"}"#: 1,
    });
}

async_test_versions! { handle_agg_job_init_req_hpke_decrypt_err }

async fn handle_agg_job_init_req_hpke_unknown_config_id(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Client tries to send Helper encrypted input with incorrect config ID.
    reports[0].encrypted_input_shares[1].config_id ^= 1;

    let (_, agg_job_init_req) = t
        .produce_agg_job_init_req(reports.clone())
        .await
        .unwrap_continue();
    let (_, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    assert_eq!(agg_job_resp.transitions.len(), 1);
    assert_matches!(
        agg_job_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::HpkeUnknownConfigId)
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_helper_report_counter{host="helper.org",status="rejected_hpke_unknown_config_id"}"#: 1,
    });
}

async_test_versions! { handle_agg_job_init_req_hpke_unknown_config_id }

async fn handle_agg_job_init_req_vdaf_prep_error(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let report0 =
        t.produce_invalid_report_public_share_decode_failure(DapMeasurement::U64(1), version);
    let report1 =
        t.produce_invalid_report_input_share_decode_failure(DapMeasurement::U64(1), version);

    let agg_job_init_req = AggregationJobInitReq {
        draft02_task_id: t.task_id.for_request_payload(&version),
        draft02_agg_job_id: t.agg_job_id.for_request_payload(),
        agg_param: Vec::new(),
        part_batch_sel: PartialBatchSelector::TimeInterval,
        report_shares: vec![
            ReportShare {
                report_metadata: report0.report_metadata,
                public_share: report0.public_share,
                encrypted_input_share: report0.encrypted_input_shares[1].clone(),
            },
            ReportShare {
                report_metadata: report1.report_metadata,
                public_share: report1.public_share,
                encrypted_input_share: report1.encrypted_input_shares[1].clone(),
            },
        ],
    };

    let (_, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    assert_eq!(agg_job_resp.transitions.len(), 2);
    assert_matches!(
        agg_job_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::VdafPrepError)
    );
    assert_matches!(
        agg_job_resp.transitions[1].var,
        TransitionVar::Failed(TransitionFailure::VdafPrepError)
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_helper_report_counter{host="helper.org",status="rejected_vdaf_prep_error"}"#: 2,
    });
}

async_test_versions! { handle_agg_job_init_req_vdaf_prep_error }

async fn agg_job_resp_abort_transition_out_of_order(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (_, mut agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    // Helper sends transitions out of order.
    let tmp = agg_job_resp.transitions[0].clone();
    agg_job_resp.transitions[0] = agg_job_resp.transitions[1].clone();
    agg_job_resp.transitions[1] = tmp;

    assert_matches!(
        t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_job_resp_abort_transition_out_of_order }

async fn agg_job_resp_abort_report_id_repeated(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (_, mut agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    // Helper sends a transition twice.
    let repeated_transition = agg_job_resp.transitions[0].clone();
    agg_job_resp.transitions.push(repeated_transition);

    assert_matches!(
        t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_job_resp_abort_report_id_repeated }

async fn agg_job_resp_abort_unrecognized_report_id(version: DapVersion) {
    let mut rng = thread_rng();
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (_, mut agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    // Helper sent a transition with an unrecognized report ID.
    agg_job_resp.transitions.push(Transition {
        report_id: ReportId(rng.gen()),
        var: TransitionVar::Continued(b"whatever".to_vec()),
    });

    assert_matches!(
        t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_job_resp_abort_unrecognized_report_id }

async fn agg_job_resp_abort_invalid_transition(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (_, mut agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    // Helper sent a transition with an unrecognized report ID.
    agg_job_resp.transitions[0].var = TransitionVar::Finished;

    assert_matches!(
        t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_job_resp_abort_invalid_transition }

async fn agg_job_cont_req(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
        DapMeasurement::U64(1),
    ]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    let (leader_uncommitted, agg_job_cont_req) = t
        .handle_agg_job_resp(leader_state, agg_job_resp)
        .unwrap_uncommitted();

    let (helper_out_shares, agg_job_resp) = t
        .handle_agg_job_cont_req(helper_state, &agg_job_cont_req)
        .unwrap_finish();
    assert_eq!(helper_out_shares.len(), 5);
    assert_eq!(agg_job_resp.transitions.len(), 5);

    let leader_out_shares = t.handle_final_agg_job_resp(leader_uncommitted, agg_job_resp);
    assert_eq!(leader_out_shares.len(), 5);
    let num_measurements = leader_out_shares.len();

    let leader_agg_share = leader_out_shares
        .into_iter()
        .map(|out_share| match out_share.data {
            VdafAggregateShare::Field64(data) => data,
            _ => panic!("unexpected aggregate share varaint"),
        })
        .reduce(|mut left, right| {
            left.merge(&right).unwrap();
            left
        })
        .unwrap();

    let helper_agg_share = helper_out_shares
        .into_iter()
        .map(|out_share| match out_share.data {
            VdafAggregateShare::Field64(data) => data,
            _ => panic!("unexpected aggregate share varaint"),
        })
        .reduce(|mut left, right| {
            left.merge(&right).unwrap();
            left
        })
        .unwrap();

    let vdaf = Prio3::new_count(2).unwrap();
    assert_eq!(
        vdaf.unshard(&(), [leader_agg_share, helper_agg_share], num_measurements,)
            .unwrap(),
        3,
    );
}

async_test_versions! { agg_job_cont_req }

async fn agg_job_cont_req_skip_vdaf_prep_error(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    reports.insert(
        1,
        t.produce_invalid_report_vdaf_prep_failure(DapMeasurement::U64(1), version),
    );

    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    let (_, agg_job_cont_req) = t
        .handle_agg_job_resp(leader_state, agg_job_resp)
        .unwrap_uncommitted();

    let (helper_output_shares, agg_job_resp) = t
        .handle_agg_job_cont_req(helper_state, &agg_job_cont_req)
        .unwrap_finish();

    assert_eq!(2, helper_output_shares.len());
    assert_eq!(2, agg_job_resp.transitions.len());
    assert_eq!(
        agg_job_resp.transitions[0].report_id,
        agg_job_init_req.report_shares[0].report_metadata.id
    );
    assert_eq!(
        agg_job_resp.transitions[1].report_id,
        agg_job_init_req.report_shares[2].report_metadata.id
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_leader_report_counter{host="leader.com",status="rejected_vdaf_prep_error"}"#: 1,
    });
}

async_test_versions! { agg_job_cont_req_skip_vdaf_prep_error }

async fn agg_cont_abort_unrecognized_report_id(version: DapVersion) {
    let mut rng = thread_rng();
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    let (_, mut agg_job_cont_req) = t
        .handle_agg_job_resp(leader_state, agg_job_resp)
        .unwrap_uncommitted();
    // Leader sends a Transition with an unrecognized report_id.
    agg_job_cont_req.transitions.insert(
        1,
        Transition {
            report_id: ReportId(rng.gen()),
            var: TransitionVar::Finished, // Expected transition type for Prio3 at this stage
        },
    );

    assert_matches!(
        t.handle_agg_job_cont_req_expect_err(helper_state, &agg_job_cont_req),
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_cont_abort_unrecognized_report_id }

async fn agg_job_cont_req_abort_transition_out_of_order(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    let (_, mut agg_job_cont_req) = t
        .handle_agg_job_resp(leader_state, agg_job_resp)
        .unwrap_uncommitted();
    // Leader sends transitions out of order.
    let tmp = agg_job_cont_req.transitions[0].clone();
    agg_job_cont_req.transitions[0] = agg_job_cont_req.transitions[1].clone();
    agg_job_cont_req.transitions[1] = tmp;

    assert_matches!(
        t.handle_agg_job_cont_req_expect_err(helper_state, &agg_job_cont_req),
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_job_cont_req_abort_transition_out_of_order }

async fn agg_job_cont_req_abort_report_id_repeated(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    let (_, mut agg_job_cont_req) = t
        .handle_agg_job_resp(leader_state, agg_job_resp)
        .unwrap_uncommitted();
    // Leader sends a transition twice.
    let repeated_transition = agg_job_cont_req.transitions[0].clone();
    agg_job_cont_req.transitions.push(repeated_transition);

    assert_matches!(
        t.handle_agg_job_cont_req_expect_err(helper_state, &agg_job_cont_req),
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_job_cont_req_abort_report_id_repeated }

async fn encrypted_agg_share(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let leader_agg_share = DapAggregateShare {
        report_count: 50,
        min_time: 1637359200,
        max_time: 1637359200,
        checksum: [0; 32],
        data: Some(VdafAggregateShare::Field64(AggregateShare::from(
            OutputShare::from(vec![Field64::from(23)]),
        ))),
    };
    let helper_agg_share = DapAggregateShare {
        report_count: 50,
        min_time: 1637359200,
        max_time: 1637359200,
        checksum: [0; 32],
        data: Some(VdafAggregateShare::Field64(AggregateShare::from(
            OutputShare::from(vec![Field64::from(9)]),
        ))),
    };

    let batch_selector = BatchSelector::TimeInterval {
        batch_interval: Interval {
            start: 1637359200,
            duration: 7200,
        },
    };
    let leader_encrypted_agg_share =
        t.produce_leader_encrypted_agg_share(&batch_selector, &leader_agg_share);
    let helper_encrypted_agg_share =
        t.produce_helper_encrypted_agg_share(&batch_selector, &helper_agg_share);
    let agg_res = t
        .consume_encrypted_agg_shares(
            &batch_selector,
            50,
            vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
        )
        .await;

    assert_eq!(agg_res, DapAggregateResult::U64(32));
}

async_test_versions! { encrypted_agg_share }

async fn helper_state_serialization(version: DapVersion) {
    let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
        DapMeasurement::U64(1),
    ]);
    let (_, agg_job_init_req) = t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (want, _) = t
        .handle_agg_job_init_req(&agg_job_init_req)
        .await
        .unwrap_continue();

    let got = DapHelperState::get_decoded(TEST_VDAF, &want.get_encoded()).unwrap();
    assert_eq!(got, want);

    assert!(DapHelperState::get_decoded(TEST_VDAF, b"invalid helper state").is_err())
}

async_test_versions! { helper_state_serialization }

impl AggregationJobTest {
    // Tweak the Helper's share so that decoding succeeds but preparation fails.
    fn produce_invalid_report_vdaf_prep_failure(
        &self,
        measurement: DapMeasurement,
        version: DapVersion,
    ) -> Report {
        let report_id = ReportId(thread_rng().gen());
        let (invalid_public_share, mut invalid_input_shares) = self
            .task_config
            .vdaf
            .produce_input_shares(measurement, &report_id.0)
            .unwrap();
        invalid_input_shares[1][0] ^= 1; // The first bit is incorrect!
        self.task_config
            .vdaf
            .produce_report_with_extensions_for_shares(
                invalid_public_share,
                invalid_input_shares,
                &self.client_hpke_config_list,
                self.now,
                &self.task_id,
                &report_id,
                Vec::new(), // extensions
                version,
            )
            .unwrap()
    }

    // Tweak the public share so that it can't be decoded.
    fn produce_invalid_report_public_share_decode_failure(
        &self,
        measurement: DapMeasurement,
        version: DapVersion,
    ) -> Report {
        let report_id = ReportId(thread_rng().gen());
        let (mut invalid_public_share, invalid_input_shares) = self
            .task_config
            .vdaf
            .produce_input_shares(measurement, &report_id.0)
            .unwrap();
        invalid_public_share.push(1); // Add spurious byte at the end
        self.task_config
            .vdaf
            .produce_report_with_extensions_for_shares(
                invalid_public_share,
                invalid_input_shares,
                &self.client_hpke_config_list,
                self.now,
                &self.task_id,
                &report_id,
                Vec::new(), // extensions
                version,
            )
            .unwrap()
    }

    // Tweak the input shares so that they can't be decoded.
    fn produce_invalid_report_input_share_decode_failure(
        &self,
        measurement: DapMeasurement,
        version: DapVersion,
    ) -> Report {
        let report_id = ReportId(thread_rng().gen());
        let (invalid_public_share, mut invalid_input_shares) = self
            .task_config
            .vdaf
            .produce_input_shares(measurement, &report_id.0)
            .unwrap();
        invalid_input_shares[0].push(1); // Add a spurious byte to the Leader's share
        invalid_input_shares[1].push(1); // Add a spurious byte to the Helper's share
        self.task_config
            .vdaf
            .produce_report_with_extensions_for_shares(
                invalid_public_share,
                invalid_input_shares,
                &self.client_hpke_config_list,
                self.now,
                &self.task_id,
                &report_id,
                Vec::new(), // extensions
                version,
            )
            .unwrap()
    }
}
