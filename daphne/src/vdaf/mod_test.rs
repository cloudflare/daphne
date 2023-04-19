// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    assert_metrics_include, assert_metrics_include_auxiliary_function, async_test_version,
    async_test_versions,
    error::DapAbort,
    hpke::HpkeReceiverConfig,
    messages::{
        AggregationJobContinueReq, AggregationJobInitReq, AggregationJobResp, BatchSelector,
        HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeKdfId, HpkeKemId, Interval,
        PartialBatchSelector, Report, ReportId, ReportInit, ReportShare, TaskId, Time, Transition,
        TransitionFailure, TransitionVar,
    },
    metrics::DaphneMetrics,
    test_version, test_versions, DapAggregateResult, DapAggregateShare, DapError, DapHelperState,
    DapHelperTransition, DapLeaderState, DapLeaderTransition, DapMeasurement, DapOutputShare,
    DapQueryConfig, DapTaskConfig, DapVersion, MetaAggregationJobId, Prio3Config,
    VdafAggregateShare, VdafConfig, VdafMessage, VdafState,
};
use assert_matches::assert_matches;
use hpke_rs::HpkePublicKey;
use paste::paste;
use prio::{
    field::Field64,
    vdaf::{
        prio3::Prio3, AggregateShare, Aggregator as VdafAggregator, Collector as VdafCollector,
        OutputShare, PrepareTransition,
    },
};
use rand::prelude::*;
use std::{fmt::Debug, time::SystemTime};
use url::Url;

impl<M: Debug> DapLeaderTransition<M> {
    pub(crate) fn unwrap_continue(self) -> (DapLeaderState, M) {
        match self {
            DapLeaderTransition::Continue(state, message) => (state, message),
            _ => {
                panic!("unexpected transition: got {:?}", self);
            }
        }
    }

    pub(crate) fn unwrap_uncommitted(self) -> (Vec<DapOutputShare>, M) {
        match self {
            DapLeaderTransition::Uncommitted(uncommitted, message) => (uncommitted, message),
            _ => {
                panic!("unexpected transition: got {:?}", self);
            }
        }
    }

    pub(crate) fn unwrap_committed(self) -> Vec<DapOutputShare> {
        match self {
            DapLeaderTransition::Committed(out_shares) => out_shares,
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

    pub(crate) fn unwrap_agg_job_resp_for_version(self, version: DapVersion) -> M {
        match (version, self) {
            (DapVersion::Draft02, DapHelperTransition::Continue(_helper_state, agg_job_resp)) => {
                agg_job_resp
            }
            (DapVersion::Draft05, DapHelperTransition::Finish(_out_shares, agg_job_resp)) => {
                agg_job_resp
            }
            (_version, transition) => {
                panic!("unexpected transition for version {version:?}: got {transition:?}")
            }
        }
    }
}

// TODO Exercise all of the Prio3 variants and not just Count.
const TEST_VDAF: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Count);

async fn roundtrip_report(version: DapVersion) {
    let t = Test::new(TEST_VDAF, version);
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

    let (leader_step, leader_share) = TEST_VDAF
        .consume_report_share(
            &t.leader_hpke_receiver_config,
            true, // is_leader
            &t.task_id,
            &t.task_config,
            &report.report_metadata,
            &report.public_share,
            &report.encrypted_input_shares[0],
        )
        .await
        .unwrap();

    let (helper_step, helper_share) = TEST_VDAF
        .consume_report_share(
            &t.helper_hpke_receiver_config,
            false, // is_leader
            &t.task_id,
            &t.task_config,
            &report.report_metadata,
            &report.public_share,
            &report.encrypted_input_shares[1],
        )
        .await
        .unwrap();

    match (leader_step, helper_step, leader_share, helper_share) {
        (
            VdafState::Prio3Field64(leader_step),
            VdafState::Prio3Field64(helper_step),
            VdafMessage::Prio3ShareField64(leader_share),
            VdafMessage::Prio3ShareField64(helper_share),
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
    let t = Test::new(TEST_VDAF, version);

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
    let mut t = Test::new(TEST_VDAF, version);
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
    assert_eq!(agg_job_init_req.report_inits.len(), 3);
    for (report_init, report) in agg_job_init_req.report_inits.iter().zip(reports.iter()) {
        assert_eq!(
            report_init.helper_report_share.report_metadata.id,
            report.report_metadata.id
        );
    }

    let res = t.handle_agg_job_init_req(agg_job_init_req).await;
    let agg_job_resp = match version {
        DapVersion::Draft02 => {
            let (helper_state, agg_job_resp) = res.unwrap_continue();
            assert_eq!(helper_state.seq.len(), 3);
            agg_job_resp
        }
        DapVersion::Draft05 => {
            let (out_shares, agg_job_resp) = res.unwrap_finish();
            assert_eq!(out_shares.len(), 3);
            agg_job_resp
        }
        version => unreachable!("unhandled version {version:?}"),
    };
    assert_eq!(agg_job_resp.transitions.len(), 3);
    for (sub, report) in agg_job_resp.transitions.iter().zip(reports.iter()) {
        assert_eq!(sub.report_id, report.report_metadata.id);
    }
}

async_test_versions! { produce_agg_job_init_req }

async fn produce_agg_job_init_req_skip_hpke_decrypt_err(version: DapVersion) {
    let t = Test::new(TEST_VDAF, version);
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
    let t = Test::new(TEST_VDAF, version);
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
    let t = Test::new(TEST_VDAF, version);
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
    let mut t = Test::new(TEST_VDAF, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate HPKE decryption error of helper's report share.
    reports[0].encrypted_input_shares[1].payload[0] ^= 1;

    let (_, agg_job_init_req) = t
        .produce_agg_job_init_req(reports.clone())
        .await
        .unwrap_continue();
    let agg_job_resp = t
        .handle_agg_job_init_req(agg_job_init_req)
        .await
        .unwrap_agg_job_resp_for_version(version);

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
    let mut t = Test::new(TEST_VDAF, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Client tries to send Helper encrypted input with incorrect config ID.
    reports[0].encrypted_input_shares[1].config_id ^= 1;

    let (_, agg_job_init_req) = t
        .produce_agg_job_init_req(reports.clone())
        .await
        .unwrap_continue();
    let agg_job_resp = t
        .handle_agg_job_init_req(agg_job_init_req)
        .await
        .unwrap_agg_job_resp_for_version(version);

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
    let mut t = Test::new(TEST_VDAF, version);
    let report0 =
        t.produce_invalid_report_public_share_decode_failure(DapMeasurement::U64(1), version);
    let report1 =
        t.produce_invalid_report_input_share_decode_failure(DapMeasurement::U64(1), version);

    let dummy_draft05_leader_prep_share = match version {
        DapVersion::Draft02 => None,
        // Trigger VDAF prep error by sending a malformed prep share.
        DapVersion::Draft05 => Some(b"malformed prep share".to_vec()),
        _ => unreachable!("unhandled version {version:?}"),
    };

    let agg_job_init_req = AggregationJobInitReq {
        draft02_task_id: t.task_id.for_request_payload(&version),
        draft02_agg_job_id: t.agg_job_id.for_request_payload(),
        agg_param: Vec::new(),
        part_batch_sel: PartialBatchSelector::TimeInterval,
        report_inits: vec![
            ReportInit {
                helper_report_share: ReportShare {
                    report_metadata: report0.report_metadata,
                    public_share: report0.public_share,
                    encrypted_input_share: report0.encrypted_input_shares[1].clone(),
                },
                draft05_leader_prep_share: dummy_draft05_leader_prep_share.clone(),
            },
            ReportInit {
                helper_report_share: ReportShare {
                    report_metadata: report1.report_metadata,
                    public_share: report1.public_share,
                    encrypted_input_share: report1.encrypted_input_shares[1].clone(),
                },
                draft05_leader_prep_share: dummy_draft05_leader_prep_share.clone(),
            },
        ],
    };

    let agg_job_resp = t
        .handle_agg_job_init_req(agg_job_init_req)
        .await
        .unwrap_agg_job_resp_for_version(version);

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
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let mut agg_job_resp = t
        .handle_agg_job_init_req(agg_job_init_req)
        .await
        .unwrap_agg_job_resp_for_version(version);

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
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let mut agg_job_resp = t
        .handle_agg_job_init_req(agg_job_init_req)
        .await
        .unwrap_agg_job_resp_for_version(version);

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
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let mut agg_job_resp = t
        .handle_agg_job_init_req(agg_job_init_req)
        .await
        .unwrap_agg_job_resp_for_version(version);

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
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let mut agg_job_resp = t
        .handle_agg_job_init_req(agg_job_init_req)
        .await
        .unwrap_agg_job_resp_for_version(version);

    // Helper sent a transition with an unrecognized report ID.
    agg_job_resp.transitions[0].var = TransitionVar::Finished;

    assert_matches!(
        t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_job_resp_abort_invalid_transition }

/// draft02: Test that VDAF prep failures are handled properly in the AggregateContinueReq.
#[tokio::test]
async fn agg_job_cont_req_skip_vdaf_prep_error_draft02() {
    let mut t = Test::new(TEST_VDAF, DapVersion::Draft02);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    reports.insert(
        1,
        t.produce_invalid_report_vdaf_prep_failure(DapMeasurement::U64(1), t.task_config.version),
    );

    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(agg_job_init_req.clone())
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
        agg_job_init_req.report_inits[0]
            .helper_report_share
            .report_metadata
            .id
    );
    assert_eq!(
        agg_job_resp.transitions[1].report_id,
        agg_job_init_req.report_inits[2]
            .helper_report_share
            .report_metadata
            .id
    );

    assert_metrics_include!(t.prometheus_registry, {
        r#"test_leader_report_counter{host="leader.com",status="rejected_vdaf_prep_error"}"#: 1,
    });
}

/// draft02: Test that Helper aborts if an AggregateContinueReq contains a report that did not
/// appear in the previous AggregateInitializeReq.
#[tokio::test]
async fn agg_cont_abort_unrecognized_report_id_draft02() {
    let mut rng = thread_rng();
    let mut t = Test::new(TEST_VDAF, DapVersion::Draft02);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(agg_job_init_req)
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

/// draft02: Test that the Helper enforces the order of the reports in the AggregateContinueReq
/// (should match the AggregateInitializeReq).
#[tokio::test]
async fn agg_job_cont_req_abort_transition_out_of_order_draft02() {
    let mut t = Test::new(TEST_VDAF, DapVersion::Draft02);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(agg_job_init_req)
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

async fn agg_job_init_req_abort_report_id_repeated(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (_leader_state, mut agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();

    // Leader sends the same report twice.
    let repeated_report_init = agg_job_init_req.report_inits[0].clone();
    agg_job_init_req.report_inits.push(repeated_report_init);

    assert_matches!(
        t.handle_agg_job_init_req_expect_err(agg_job_init_req).await,
        DapAbort::UnrecognizedMessage { .. }
    );
}

async_test_versions! { agg_job_init_req_abort_report_id_repeated }

/// draft02: Check that the Helper aborts if the AggregateContinueReq contains a repeated report.
#[tokio::test]
async fn agg_job_cont_req_abort_report_id_repeated_draft02() {
    let mut t = Test::new(TEST_VDAF, DapVersion::Draft02);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_job_init_req) =
        t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_job_resp) = t
        .handle_agg_job_init_req(agg_job_init_req)
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

async fn encrypted_agg_share(version: DapVersion) {
    let t = Test::new(TEST_VDAF, version);
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

/// draft02: Test Helpr state serialization. This test applies draft02 only; it would apply to the
/// latest version if we supported multi-round VDAFs, but for the moment we only support 1-round
/// VADFs (https://github.com/cloudflare/daphne/issues/306).
#[tokio::test]
async fn helper_state_serialization_draft02() {
    let mut t = Test::new(TEST_VDAF, DapVersion::Draft02);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
        DapMeasurement::U64(1),
    ]);
    let (_, agg_job_init_req) = t.produce_agg_job_init_req(reports).await.unwrap_continue();
    let (want, _) = t
        .handle_agg_job_init_req(agg_job_init_req)
        .await
        .unwrap_continue();

    let got =
        DapHelperState::get_decoded(TEST_VDAF, &want.get_encoded(TEST_VDAF).unwrap()).unwrap();
    assert_eq!(got, want);

    assert!(DapHelperState::get_decoded(TEST_VDAF, b"invalid helper state").is_err())
}

pub(crate) struct Test {
    now: Time,
    task_id: TaskId,
    agg_job_id: MetaAggregationJobId<'static>,
    task_config: DapTaskConfig,
    leader_hpke_receiver_config: HpkeReceiverConfig,
    helper_hpke_receiver_config: HpkeReceiverConfig,
    client_hpke_config_list: Vec<HpkeConfig>,
    collector_hpke_receiver_config: HpkeReceiverConfig,
    prometheus_registry: prometheus::Registry,
    leader_metrics: DaphneMetrics,
    helper_metrics: DaphneMetrics,
}

impl Test {
    pub(crate) fn new(vdaf: &VdafConfig, version: DapVersion) -> Test {
        let mut rng = thread_rng();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let task_id = TaskId(rng.gen());
        let agg_job_id = MetaAggregationJobId::gen_for_version(&version);
        let vdaf_verify_key = vdaf.gen_verify_key();
        let leader_hpke_receiver_config =
            HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256).unwrap();
        let helper_hpke_receiver_config =
            HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256).unwrap();
        let collector_hpke_receiver_config =
            HpkeReceiverConfig::gen(rng.gen(), HpkeKemId::X25519HkdfSha256).unwrap();
        let leader_hpke_config = leader_hpke_receiver_config.clone().config;
        let helper_hpke_config = helper_hpke_receiver_config.clone().config;
        let collector_hpke_config = collector_hpke_receiver_config.clone().config;
        let prometheus_registry = prometheus::Registry::new();
        let leader_metrics =
            DaphneMetrics::register(&prometheus_registry, Some("test_leader")).unwrap();
        let helper_metrics =
            DaphneMetrics::register(&prometheus_registry, Some("test_helper")).unwrap();

        Test {
            now,
            task_id,
            agg_job_id,
            leader_hpke_receiver_config,
            helper_hpke_receiver_config,
            client_hpke_config_list: vec![leader_hpke_config, helper_hpke_config],
            collector_hpke_receiver_config,
            task_config: DapTaskConfig {
                version,
                leader_url: Url::parse("http://leader.com").unwrap(),
                helper_url: Url::parse("https://helper.org").unwrap(),
                time_precision: 500,
                expiration: now + 500,
                min_batch_size: 10,
                query: DapQueryConfig::TimeInterval,
                vdaf: vdaf.clone(),
                vdaf_verify_key,
                collector_hpke_config,
                taskprov: false,
            },
            prometheus_registry,
            leader_metrics,
            helper_metrics,
        }
    }

    fn produce_reports(&self, measurements: Vec<DapMeasurement>) -> Vec<Report> {
        let mut reports = Vec::with_capacity(measurements.len());

        for measurement in measurements.into_iter() {
            reports.push(
                self.task_config
                    .vdaf
                    .produce_report(
                        &self.client_hpke_config_list,
                        self.now,
                        &self.task_id,
                        measurement,
                        self.task_config.version,
                    )
                    .unwrap(),
            );
        }
        reports
    }

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

    async fn produce_agg_job_init_req(
        &self,
        reports: Vec<Report>,
    ) -> DapLeaderTransition<AggregationJobInitReq> {
        let metrics = self
            .leader_metrics
            .with_host(self.task_config.leader_url.host_str().unwrap());
        self.task_config
            .vdaf
            .produce_agg_job_init_req(
                &self.leader_hpke_receiver_config,
                &self.task_id,
                &self.task_config,
                &self.agg_job_id,
                &PartialBatchSelector::TimeInterval,
                reports,
                &metrics,
            )
            .await
            .unwrap()
    }

    async fn handle_agg_job_init_req_with_handler<T: Debug>(
        &mut self,
        agg_job_init_req: AggregationJobInitReq,
        handler: impl FnOnce(Result<DapHelperTransition<AggregationJobResp>, DapAbort>) -> T,
    ) -> T {
        let metrics = self
            .helper_metrics
            .with_host(self.task_config.helper_url.host_str().unwrap());
        handler(
            self.task_config
                .vdaf
                .handle_agg_job_init_req(
                    &self.helper_hpke_receiver_config,
                    &self.task_id,
                    &self.task_config,
                    &agg_job_init_req,
                    &metrics,
                )
                .await,
        )
    }

    async fn handle_agg_job_init_req(
        &mut self,
        agg_job_init_req: AggregationJobInitReq,
    ) -> DapHelperTransition<AggregationJobResp> {
        self.handle_agg_job_init_req_with_handler(agg_job_init_req, |res| res.unwrap())
            .await
    }

    async fn handle_agg_job_init_req_expect_err(
        &mut self,
        agg_job_init_req: AggregationJobInitReq,
    ) -> DapAbort {
        self.handle_agg_job_init_req_with_handler(agg_job_init_req, |res| res.unwrap_err())
            .await
    }

    fn handle_agg_job_resp(
        &self,
        leader_state: DapLeaderState,
        agg_job_resp: AggregationJobResp,
    ) -> DapLeaderTransition<AggregationJobContinueReq> {
        let metrics = self
            .leader_metrics
            .with_host(self.task_config.leader_url.host_str().unwrap());
        self.task_config
            .vdaf
            .handle_agg_job_resp(
                &self.task_id,
                &self.agg_job_id,
                leader_state,
                agg_job_resp,
                self.task_config.version,
                &metrics,
            )
            .unwrap()
    }

    fn handle_agg_job_resp_expect_err(
        &self,
        leader_state: DapLeaderState,
        agg_job_resp: AggregationJobResp,
    ) -> DapAbort {
        let metrics = self
            .leader_metrics
            .with_host(self.task_config.leader_url.host_str().unwrap());
        self.task_config
            .vdaf
            .handle_agg_job_resp(
                &self.task_id,
                &self.agg_job_id,
                leader_state,
                agg_job_resp,
                self.task_config.version,
                &metrics,
            )
            .expect_err("handle_agg_job_resp() succeeded; expected failure")
    }

    fn handle_agg_job_cont_req(
        &self,
        helper_state: DapHelperState,
        agg_job_cont_req: &AggregationJobContinueReq,
    ) -> DapHelperTransition<AggregationJobResp> {
        let metrics = self
            .helper_metrics
            .with_host(self.task_config.helper_url.host_str().unwrap());
        self.task_config
            .vdaf
            .handle_agg_job_cont_req(
                &self.task_id,
                &self.agg_job_id,
                helper_state,
                agg_job_cont_req,
                &metrics,
            )
            .unwrap()
    }

    fn handle_agg_job_cont_req_expect_err(
        &self,
        helper_state: DapHelperState,
        agg_job_cont_req: &AggregationJobContinueReq,
    ) -> DapAbort {
        let metrics = self
            .helper_metrics
            .with_host(self.task_config.helper_url.host_str().unwrap());
        self.task_config
            .vdaf
            .handle_agg_job_cont_req(
                &self.task_id,
                &self.agg_job_id,
                helper_state,
                agg_job_cont_req,
                &metrics,
            )
            .expect_err("handle_agg_job_cont_req() succeeded; expected failure")
    }

    fn handle_final_agg_job_resp(
        &self,
        leader_uncommitted: Vec<DapOutputShare>,
        agg_job_resp: AggregationJobResp,
    ) -> Vec<DapOutputShare> {
        let metrics = self
            .leader_metrics
            .with_host(self.task_config.leader_url.host_str().unwrap());
        self.task_config
            .vdaf
            .handle_final_agg_job_resp(leader_uncommitted, agg_job_resp, &metrics)
            .unwrap()
    }

    fn produce_leader_encrypted_agg_share(
        &self,
        batch_selector: &BatchSelector,
        agg_share: &DapAggregateShare,
    ) -> HpkeCiphertext {
        self.task_config
            .vdaf
            .produce_leader_encrypted_agg_share(
                &self.task_config.collector_hpke_config,
                &self.task_id,
                batch_selector,
                agg_share,
                self.task_config.version,
            )
            .unwrap()
    }

    fn produce_helper_encrypted_agg_share(
        &self,
        batch_selector: &BatchSelector,
        agg_share: &DapAggregateShare,
    ) -> HpkeCiphertext {
        self.task_config
            .vdaf
            .produce_helper_encrypted_agg_share(
                &self.task_config.collector_hpke_config,
                &self.task_id,
                batch_selector,
                agg_share,
                self.task_config.version,
            )
            .unwrap()
    }

    async fn consume_encrypted_agg_shares(
        &self,
        batch_selector: &BatchSelector,
        report_count: u64,
        enc_agg_shares: Vec<HpkeCiphertext>,
    ) -> DapAggregateResult {
        self.task_config
            .vdaf
            .consume_encrypted_agg_shares(
                &self.collector_hpke_receiver_config,
                &self.task_id,
                batch_selector,
                report_count,
                enc_agg_shares,
                self.task_config.version,
            )
            .await
            .unwrap()
    }

    pub(crate) async fn roundtrip(
        &mut self,
        measurements: Vec<DapMeasurement>,
    ) -> DapAggregateResult {
        let batch_selector = BatchSelector::TimeInterval {
            batch_interval: Interval {
                start: self.now,
                duration: 3600,
            },
        };

        let report_count = measurements.len();

        // Clients -> Leader: Upload reports
        let reports = self.produce_reports(measurements);
        assert_eq!(reports.len(), report_count);

        // Leader -> Helper: Initailize aggregation job
        let (leader_state, agg_job_init_req) = self
            .produce_agg_job_init_req(reports)
            .await
            .unwrap_continue();
        assert_eq!(leader_state.seq.len(), report_count);
        assert_eq!(agg_job_init_req.report_inits.len(), report_count);

        let (leader_out_shares, helper_out_shares) = match self.task_config.version {
            DapVersion::Draft02 => {
                let (helper_state, agg_job_resp) = self
                    .handle_agg_job_init_req(agg_job_init_req)
                    .await
                    .unwrap_continue();
                assert_eq!(helper_state.seq.len(), report_count);
                assert_eq!(agg_job_resp.transitions.len(), report_count);

                // Test Helper state serialization.
                let got = DapHelperState::get_decoded(
                    &self.task_config.vdaf,
                    &helper_state
                        .get_encoded(&self.task_config.vdaf)
                        .expect("failed to encode helper state"),
                )
                .expect("failed to decode helper state");
                assert_eq!(got, helper_state);

                let (uncommitted, agg_job_cont_req) = self
                    .handle_agg_job_resp(leader_state, agg_job_resp)
                    .unwrap_uncommitted();
                assert_eq!(uncommitted.len(), report_count);
                assert_eq!(agg_job_cont_req.transitions.len(), report_count);

                let (helper_out_shares, agg_job_resp) = self
                    .handle_agg_job_cont_req(helper_state, &agg_job_cont_req)
                    .unwrap_finish();
                assert_eq!(agg_job_resp.transitions.len(), report_count);

                let leader_out_shares = self.handle_final_agg_job_resp(uncommitted, agg_job_resp);
                (leader_out_shares, helper_out_shares)
            }
            DapVersion::Draft05 => {
                let (helper_out_shares, agg_job_resp) = self
                    .handle_agg_job_init_req(agg_job_init_req)
                    .await
                    .unwrap_finish();
                assert_eq!(agg_job_resp.transitions.len(), report_count);

                let leader_out_shares = self
                    .handle_agg_job_resp(leader_state, agg_job_resp)
                    .unwrap_committed();
                (leader_out_shares, helper_out_shares)
            }
            version => unreachable!("unhandled version {version:?}"),
        };
        assert_eq!(leader_out_shares.len(), report_count);
        assert_eq!(helper_out_shares.len(), report_count);

        // Leader: Aggregation
        let leader_agg_share = DapAggregateShare::try_from_out_shares(leader_out_shares).unwrap();
        let leader_encrypted_agg_share =
            self.produce_leader_encrypted_agg_share(&batch_selector, &leader_agg_share);

        // Helper: Aggregation
        let helper_agg_share = DapAggregateShare::try_from_out_shares(helper_out_shares).unwrap();
        let helper_encrypted_agg_share =
            self.produce_helper_encrypted_agg_share(&batch_selector, &helper_agg_share);

        // Collector: Unshard
        self.consume_encrypted_agg_shares(
            &batch_selector,
            report_count.try_into().unwrap(),
            vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
        )
        .await
    }
}
