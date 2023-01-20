// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    async_test_version, async_test_versions,
    hpke::HpkeReceiverConfig,
    messages::{
        AggregateContinueReq, AggregateInitializeReq, AggregateResp, BatchSelector, HpkeAeadId,
        HpkeCiphertext, HpkeConfig, HpkeKdfId, HpkeKemId, Id, Interval, PartialBatchSelector,
        Report, ReportId, Time, Transition, TransitionFailure, TransitionVar,
    },
    test_version, test_versions, DapAbort, DapAggregateResult, DapAggregateShare, DapError,
    DapHelperState, DapHelperTransition, DapLeaderState, DapLeaderTransition, DapLeaderUncommitted,
    DapMeasurement, DapOutputShare, DapQueryConfig, DapTaskConfig, DapVersion, Prio3Config,
    VdafAggregateShare, VdafConfig, VdafMessage, VdafState,
};
use assert_matches::assert_matches;
use hpke_rs::HpkePublicKey;
use paste::paste;
use prio::vdaf::{
    prio3::Prio3, Aggregatable, Aggregator as VdafAggregator, Collector as VdafCollector,
    PrepareTransition,
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
            &report.metadata,
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
            &report.metadata,
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
            let vdaf = Prio3::new_aes128_count(2).unwrap();
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
    assert_matches!(res, Err(DapError::Fatal(s)) => assert_eq!(s, "HPKE ciphersuite not implemented (999, 1, 1)"));
}

test_versions! { roundtrip_report_unsupported_hpke_suite }

async fn agg_init_req(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
    ]);

    let (leader_state, agg_init_req) = t
        .produce_agg_init_req(reports.clone())
        .await
        .unwrap_continue();
    assert_eq!(leader_state.seq.len(), 3);
    assert_eq!(agg_init_req.task_id, t.task_id);
    assert_eq!(agg_init_req.agg_param.len(), 0);
    assert_eq!(agg_init_req.report_shares.len(), 3);
    for (report_shares, report) in agg_init_req.report_shares.iter().zip(reports.iter()) {
        assert_eq!(report_shares.metadata.id, report.metadata.id);
    }

    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();
    assert_eq!(helper_state.seq.len(), 3);
    assert_eq!(agg_resp.transitions.len(), 3);
    for (sub, report) in agg_resp.transitions.iter().zip(reports.iter()) {
        assert_eq!(sub.report_id, report.metadata.id);
    }
}

async_test_versions! { agg_init_req }

async fn agg_init_req_fail_hpke_decrypt_err(version: DapVersion) {
    let t = Test::new(TEST_VDAF, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate HPKE decryption error of leader's report share.
    reports[0].encrypted_input_shares[0].payload[0] ^= 1;

    assert_matches!(
        t.produce_agg_init_req(reports).await,
        DapLeaderTransition::Skip
    );
}

async_test_versions! { agg_init_req_fail_hpke_decrypt_err }

async fn agg_init_req_fail_hpke_decrypt_err_wrong_config_id(version: DapVersion) {
    let t = Test::new(TEST_VDAF, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Client tries to send Leader encrypted input with incorrect config ID.
    reports[0].encrypted_input_shares[0].config_id ^= 1;

    assert_matches!(
        t.produce_agg_init_req(reports).await,
        DapLeaderTransition::Skip
    );
}

async_test_versions! { agg_init_req_fail_hpke_decrypt_err_wrong_config_id }

async fn agg_resp_fail_hpke_decrypt_err(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate HPKE decryption error of helper's report share.
    reports[0].encrypted_input_shares[1].payload[0] ^= 1;

    let (_, agg_req) = t
        .produce_agg_init_req(reports.clone())
        .await
        .unwrap_continue();
    let (_, agg_resp) = t.handle_agg_init_req(agg_req).await.unwrap_continue();

    assert_eq!(agg_resp.transitions.len(), 1);
    assert_matches!(
        agg_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::HpkeDecryptError)
    );
}

async_test_versions! { agg_resp_fail_hpke_decrypt_err }

async fn agg_resp_fail_hpke_decrypt_err_wrong_id(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Client tries to send Helper encrypted input with incorrect config ID.
    reports[0].encrypted_input_shares[1].config_id ^= 1;

    let (_, agg_req) = t
        .produce_agg_init_req(reports.clone())
        .await
        .unwrap_continue();
    let (_, agg_resp) = t.handle_agg_init_req(agg_req).await.unwrap_continue();

    assert_eq!(agg_resp.transitions.len(), 1);
    assert_matches!(
        agg_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::HpkeUnknownConfigId)
    );
}

async_test_versions! { agg_resp_fail_hpke_decrypt_err_wrong_id }

async fn agg_resp_abort_transition_out_of_order(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (_, mut agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    // Helper sends transitions out of order.
    let tmp = agg_resp.transitions[0].clone();
    agg_resp.transitions[0] = agg_resp.transitions[1].clone();
    agg_resp.transitions[1] = tmp;

    assert_matches!(
        t.handle_agg_resp_expect_err(leader_state, agg_resp),
        DapAbort::UnrecognizedMessage
    );
}

async_test_versions! { agg_resp_abort_transition_out_of_order }

async fn agg_resp_abort_report_id_repeated(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (_, mut agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    // Helper sends a transition twice.
    let repeated_transition = agg_resp.transitions[0].clone();
    agg_resp.transitions.push(repeated_transition);

    assert_matches!(
        t.handle_agg_resp_expect_err(leader_state, agg_resp),
        DapAbort::UnrecognizedMessage
    );
}

async_test_versions! { agg_resp_abort_report_id_repeated }

async fn agg_resp_abort_unrecognized_report_id(version: DapVersion) {
    let mut rng = thread_rng();
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (_, mut agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    // Helper sent a transition with an unrecognized report ID.
    agg_resp.transitions.push(Transition {
        report_id: ReportId(rng.gen()),
        var: TransitionVar::Continued(b"whatever".to_vec()),
    });

    assert_matches!(
        t.handle_agg_resp_expect_err(leader_state, agg_resp),
        DapAbort::UnrecognizedMessage
    );
}

async_test_versions! { agg_resp_abort_unrecognized_report_id }

async fn agg_resp_abort_invalid_transition(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (_, mut agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    // Helper sent a transition with an unrecognized report ID.
    agg_resp.transitions[0].var = TransitionVar::Finished;

    assert_matches!(
        t.handle_agg_resp_expect_err(leader_state, agg_resp),
        DapAbort::UnrecognizedMessage
    );
}

async_test_versions! { agg_resp_abort_invalid_transition }

async fn agg_cont_req(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
        DapMeasurement::U64(1),
    ]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    let (leader_uncommitted, agg_cont_req) = t
        .handle_agg_resp(leader_state, agg_resp)
        .unwrap_uncommitted();

    let (helper_out_shares, agg_resp) = t
        .handle_agg_cont_req(helper_state, &agg_cont_req)
        .unwrap_finish();
    assert_eq!(helper_out_shares.len(), 5);
    assert_eq!(agg_resp.transitions.len(), 5);

    let leader_out_shares = t.handle_final_agg_resp(leader_uncommitted, agg_resp);
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

    let vdaf = Prio3::new_aes128_count(2).unwrap();
    assert_eq!(
        vdaf.unshard(&(), [leader_agg_share, helper_agg_share], num_measurements,)
            .unwrap(),
        3,
    );
}

async_test_versions! { agg_cont_req }

async fn agg_cont_req_skip_vdaf_prep_error(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
    ]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_resp) = t
        .handle_agg_init_req(agg_init_req.clone())
        .await
        .unwrap_continue();

    let (_, mut agg_cont_req) = t
        .handle_agg_resp(leader_state, agg_resp)
        .unwrap_uncommitted();
    // Simulate VDAF preparation error (due to the report being invalid, say). The leader will
    // skip the report without processing it any further.
    agg_cont_req.transitions.remove(1);

    let (helper_output_shares, agg_resp) = t
        .handle_agg_cont_req(helper_state, &agg_cont_req)
        .unwrap_finish();

    assert_eq!(2, helper_output_shares.len());
    assert_eq!(2, agg_resp.transitions.len());
    assert_eq!(
        agg_resp.transitions[0].report_id,
        agg_init_req.report_shares[0].metadata.id
    );
    assert_eq!(
        agg_resp.transitions[1].report_id,
        agg_init_req.report_shares[2].metadata.id
    );
}

async_test_versions! { agg_cont_req_skip_vdaf_prep_error }

async fn agg_cont_abort_unrecognized_report_id(version: DapVersion) {
    let mut rng = thread_rng();
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    let (_, mut agg_cont_req) = t
        .handle_agg_resp(leader_state, agg_resp)
        .unwrap_uncommitted();
    // Leader sends a Transition with an unrecognized report_id.
    agg_cont_req.transitions.insert(
        1,
        Transition {
            report_id: ReportId(rng.gen()),
            var: TransitionVar::Finished, // Expected transition type for Prio3 at this stage
        },
    );

    assert_matches!(
        t.handle_agg_cont_req_expect_err(helper_state, &agg_cont_req),
        DapAbort::UnrecognizedMessage
    );
}

async_test_versions! { agg_cont_abort_unrecognized_report_id }

async fn agg_cont_req_abort_transition_out_of_order(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    let (_, mut agg_cont_req) = t
        .handle_agg_resp(leader_state, agg_resp)
        .unwrap_uncommitted();
    // Leader sends transitions out of order.
    let tmp = agg_cont_req.transitions[0].clone();
    agg_cont_req.transitions[0] = agg_cont_req.transitions[1].clone();
    agg_cont_req.transitions[1] = tmp;

    assert_matches!(
        t.handle_agg_cont_req_expect_err(helper_state, &agg_cont_req),
        DapAbort::UnrecognizedMessage
    );
}

async_test_versions! { agg_cont_req_abort_transition_out_of_order }

async fn agg_cont_req_abort_report_id_repeated(version: DapVersion) {
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    let (_, mut agg_cont_req) = t
        .handle_agg_resp(leader_state, agg_resp)
        .unwrap_uncommitted();
    // Leader sends a transition twice.
    let repeated_transition = agg_cont_req.transitions[0].clone();
    agg_cont_req.transitions.push(repeated_transition);

    assert_matches!(
        t.handle_agg_cont_req_expect_err(helper_state, &agg_cont_req),
        DapAbort::UnrecognizedMessage
    );
}

async_test_versions! { agg_cont_req_abort_report_id_repeated }

async fn encrypted_agg_share(version: DapVersion) {
    let t = Test::new(TEST_VDAF, version);
    let leader_agg_share = DapAggregateShare {
        report_count: 50,
        checksum: [0; 32],
        data: Some(VdafAggregateShare::Field64(vec![23.into()].into())),
    };
    let helper_agg_share = DapAggregateShare {
        report_count: 50,
        checksum: [0; 32],
        data: Some(VdafAggregateShare::Field64(vec![9.into()].into())),
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
    let mut t = Test::new(TEST_VDAF, version);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
        DapMeasurement::U64(1),
    ]);
    let (_, agg_init_req) = t.produce_agg_init_req(reports).await.unwrap_continue();
    let (want, _) = t.handle_agg_init_req(agg_init_req).await.unwrap_continue();

    let got =
        DapHelperState::get_decoded(TEST_VDAF, &want.get_encoded(TEST_VDAF).unwrap()).unwrap();
    assert_eq!(got, want);

    assert!(DapHelperState::get_decoded(TEST_VDAF, b"invalid helper state").is_err())
}

async_test_versions! { helper_state_serialization }

pub(crate) struct Test {
    now: Time,
    task_id: Id,
    agg_job_id: Id,
    task_config: DapTaskConfig,
    leader_hpke_receiver_config: HpkeReceiverConfig,
    helper_hpke_receiver_config: HpkeReceiverConfig,
    client_hpke_config_list: Vec<HpkeConfig>,
    collector_hpke_receiver_config: HpkeReceiverConfig,
}

impl Test {
    pub(crate) fn new(vdaf: &VdafConfig, version: DapVersion) -> Test {
        let mut rng = thread_rng();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let task_id = Id(rng.gen());
        let agg_job_id = Id(rng.gen());
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
                leader_url: Url::parse("http://dummy.url").unwrap(),
                helper_url: Url::parse("http://dummy.url").unwrap(),
                time_precision: 500,
                expiration: now + 500,
                min_batch_size: 10,
                query: DapQueryConfig::TimeInterval,
                vdaf: vdaf.clone(),
                vdaf_verify_key,
                collector_hpke_config,
            },
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

    async fn produce_agg_init_req(
        &self,
        reports: Vec<Report>,
    ) -> DapLeaderTransition<AggregateInitializeReq> {
        self.task_config
            .vdaf
            .produce_agg_init_req(
                &self.leader_hpke_receiver_config,
                &self.task_id,
                &self.task_config,
                &self.agg_job_id,
                &PartialBatchSelector::TimeInterval,
                reports,
            )
            .await
            .unwrap()
    }

    async fn handle_agg_init_req(
        &mut self,
        agg_init_req: AggregateInitializeReq,
    ) -> DapHelperTransition<AggregateResp> {
        let agg_resp = self
            .task_config
            .vdaf
            .handle_agg_init_req(
                &self.helper_hpke_receiver_config,
                &self.task_config,
                &agg_init_req,
            )
            .await
            .unwrap();

        agg_resp
    }

    fn handle_agg_resp(
        &self,
        leader_state: DapLeaderState,
        agg_resp: AggregateResp,
    ) -> DapLeaderTransition<AggregateContinueReq> {
        self.task_config
            .vdaf
            .handle_agg_resp(&self.task_id, &self.agg_job_id, leader_state, agg_resp)
            .unwrap()
    }

    fn handle_agg_resp_expect_err(
        &self,
        leader_state: DapLeaderState,
        agg_resp: AggregateResp,
    ) -> DapAbort {
        self.task_config
            .vdaf
            .handle_agg_resp(&self.task_id, &self.agg_job_id, leader_state, agg_resp)
            .err()
            .expect("handle_agg_resp() succeeded; expected failure")
    }

    fn handle_agg_cont_req(
        &self,
        helper_state: DapHelperState,
        agg_cont_req: &AggregateContinueReq,
    ) -> DapHelperTransition<AggregateResp> {
        self.task_config
            .vdaf
            .handle_agg_cont_req(helper_state, agg_cont_req)
            .unwrap()
    }

    fn handle_agg_cont_req_expect_err(
        &self,
        helper_state: DapHelperState,
        agg_cont_req: &AggregateContinueReq,
    ) -> DapAbort {
        self.task_config
            .vdaf
            .handle_agg_cont_req(helper_state, agg_cont_req)
            .err()
            .expect("handle_agg_cont_req() succeeded; expected failure")
    }

    fn handle_final_agg_resp(
        &self,
        leader_uncommitted: DapLeaderUncommitted,
        agg_resp: AggregateResp,
    ) -> Vec<DapOutputShare> {
        self.task_config
            .vdaf
            .handle_final_agg_resp(leader_uncommitted, agg_resp)
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

        // Clients: Shard
        let reports = self.produce_reports(measurements);

        // Aggregators: Preparation
        let (leader_state, agg_init) = self.produce_agg_init_req(reports).await.unwrap_continue();
        let (helper_state, agg_resp) = self.handle_agg_init_req(agg_init).await.unwrap_continue();
        let got = DapHelperState::get_decoded(
            &self.task_config.vdaf,
            &helper_state
                .get_encoded(&self.task_config.vdaf)
                .expect("failed to encode helper state"),
        )
        .expect("failed to decode helper state");
        assert_eq!(got, helper_state);

        let (uncommitted, agg_cont) = self
            .handle_agg_resp(leader_state, agg_resp)
            .unwrap_uncommitted();
        let (helper_out_shares, agg_resp) = self
            .handle_agg_cont_req(helper_state, &agg_cont)
            .unwrap_finish();
        let leader_out_shares = self.handle_final_agg_resp(uncommitted, agg_resp);
        let report_count = u64::try_from(leader_out_shares.len()).unwrap();

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
            report_count,
            vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
        )
        .await
    }
}
