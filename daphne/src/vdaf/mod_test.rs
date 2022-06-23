// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    hpke::HpkeSecretKey,
    messages::{
        AggregateContinueReq, AggregateInitializeReq, AggregateResp, HpkeAeadId, HpkeCiphertext,
        HpkeConfig, HpkeKdfId, HpkeKemId, Id, Interval, Nonce, Report, Transition,
        TransitionFailure, TransitionVar,
    },
    DapAbort, DapAggregateResult, DapAggregateShare, DapError, DapHelperState, DapHelperTransition,
    DapLeaderState, DapLeaderTransition, DapLeaderUncommitted, DapMeasurement, DapOutputShare,
    Prio3Config, VdafAggregateShare, VdafConfig, VdafMessage, VdafState, VdafVerifyKey,
};
use assert_matches::assert_matches;
use prio::vdaf::{
    prio3::Prio3, Aggregatable, Aggregator as VdafAggregator, Collector as VdafCollector,
    PrepareTransition,
};
use rand::prelude::*;
use std::{collections::HashSet, fmt::Debug, time::SystemTime};

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

#[test]
fn roundtrip_report() {
    let t = Test::new(TEST_VDAF);
    let report = t
        .vdaf
        .produce_report(
            &t.client_hpke_config_list,
            t.now,
            &t.task_id,
            DapMeasurement::U64(1),
        )
        .unwrap();

    let (leader_step, leader_share) = TEST_VDAF
        .consume_report_share(
            &t.leader_hpke_secret_key,
            true, // is_leader
            &t.vdaf_verify_key,
            &t.task_id,
            &report.nonce,
            &report.ignored_extensions,
            &report.encrypted_input_shares[0],
        )
        .unwrap();

    let (helper_step, helper_share) = TEST_VDAF
        .consume_report_share(
            &t.helper_hpke_secret_key,
            false, // is_leader
            &t.vdaf_verify_key,
            &t.task_id,
            &report.nonce,
            &report.ignored_extensions,
            &report.encrypted_input_shares[1],
        )
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
                vdaf.unshard(&(), vec![leader_agg_share, helper_agg_share])
                    .unwrap(),
                1,
            );
        }
        _ => {
            panic!("unexpected output from leader or helper");
        }
    }
}

#[test]
fn roundtrip_report_unsupported_hpke_suite() {
    let t = Test::new(TEST_VDAF);

    // The helper's HPKE config indicates a KEM type no supported by the client.
    let unsupported_hpke_config_list = vec![
        t.client_hpke_config_list[0].clone(),
        HpkeConfig {
            id: thread_rng().gen(),
            kem_id: HpkeKemId::NotImplemented(999),
            kdf_id: HpkeKdfId::HkdfSha256,
            aead_id: HpkeAeadId::Aes128Gcm,
            public_key: b"some KEM public key".to_vec(),
        },
    ];

    let res = t.vdaf.produce_report(
        &unsupported_hpke_config_list,
        t.now,
        &t.task_id,
        DapMeasurement::U64(1),
    );
    assert_matches!(res, Err(DapError::Fatal(s)) => assert_eq!(s, "HPKE ciphersuite not implemented (999, 1, 1)"));
}

#[test]
fn agg_init_req() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
    ]);

    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports.clone()).unwrap_continue();
    assert_eq!(leader_state.seq.len(), 3);
    assert_eq!(agg_init_req.task_id, t.task_id);
    assert_eq!(agg_init_req.agg_param.len(), 0);
    assert_eq!(agg_init_req.report_shares.len(), 3);
    for (report_shares, report) in agg_init_req.report_shares.iter().zip(reports.iter()) {
        assert_eq!(report_shares.nonce, report.nonce);
    }

    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();
    assert_eq!(helper_state.seq.len(), 3);
    assert_eq!(agg_resp.transitions.len(), 3);
    for (sub, report) in agg_resp.transitions.iter().zip(reports.iter()) {
        assert_eq!(sub.nonce, report.nonce);
    }
}

#[test]
fn agg_init_req_fail_hpke_decrypt_err() {
    let t = Test::new(TEST_VDAF);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate HPKE decryption error of leader's report share.
    reports[0].encrypted_input_shares[0].payload[0] ^= 1;

    assert_matches!(t.produce_agg_init_req(reports), DapLeaderTransition::Skip);
}

#[test]
fn agg_resp_fail_hpke_decrypt_err() {
    let mut t = Test::new(TEST_VDAF);
    let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate HPKE decryption error of helper's report share.
    reports[0].encrypted_input_shares[1].payload[0] ^= 1;

    let (_, agg_req) = t.produce_agg_init_req(reports.clone()).unwrap_continue();
    let (_, agg_resp) = t.handle_agg_init_req(agg_req).unwrap_continue();

    assert_eq!(agg_resp.transitions.len(), 1);
    assert_matches!(
        agg_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::HpkeDecryptError)
    );
}

#[test]
fn agg_resp_fail_report_replayed() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate the leader replaying a report.
    t.helper_reports_aggregated.insert(reports[0].nonce.clone());

    let (_, agg_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (_, agg_resp) = t.handle_agg_init_req(agg_req).unwrap_continue();

    assert_eq!(agg_resp.transitions.len(), 1);
    assert_matches!(
        agg_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::ReportReplayed)
    );
}

#[test]
fn agg_resp_fail_batch_collected() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

    // Simulate the leader requesting aggregation of a report for a batch that has already been
    // collected.
    t.helper_batch_collected = true;

    let (_, agg_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (_, agg_resp) = t.handle_agg_init_req(agg_req).unwrap_continue();

    assert_eq!(agg_resp.transitions.len(), 1);
    assert_matches!(
        agg_resp.transitions[0].var,
        TransitionVar::Failed(TransitionFailure::BatchCollected)
    );
}

#[test]
fn agg_resp_abort_transition_out_of_order() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (_, mut agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

    // Helper sends transitions out of order.
    let tmp = agg_resp.transitions[0].clone();
    agg_resp.transitions[0] = agg_resp.transitions[1].clone();
    agg_resp.transitions[1] = tmp;

    assert_matches!(
        t.handle_agg_resp_expect_err(leader_state, agg_resp),
        DapAbort::UnrecognizedMessage
    );
}

#[test]
fn agg_resp_abort_nonce_repeated() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (_, mut agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

    // Helper sends a transition twice.
    let repeated_transition = agg_resp.transitions[0].clone();
    agg_resp.transitions.push(repeated_transition);

    assert_matches!(
        t.handle_agg_resp_expect_err(leader_state, agg_resp),
        DapAbort::UnrecognizedMessage
    );
}

#[test]
fn agg_resp_abort_unrecognized_nonce() {
    let mut rng = thread_rng();
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (_, mut agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

    // Helper sent a transition with an unrecognized Nonce.
    agg_resp.transitions.push(Transition {
        nonce: Nonce {
            time: rng.gen(),
            rand: rng.gen(),
        },
        var: TransitionVar::Continued(b"whatever".to_vec()),
    });

    assert_matches!(
        t.handle_agg_resp_expect_err(leader_state, agg_resp),
        DapAbort::UnrecognizedMessage
    );
}

#[test]
fn agg_resp_abort_invalid_transition() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (_, mut agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

    // Helper sent a transition with an unrecognized Nonce.
    agg_resp.transitions[0].var = TransitionVar::Finished;

    assert_matches!(
        t.handle_agg_resp_expect_err(leader_state, agg_resp),
        DapAbort::UnrecognizedMessage
    );
}

#[test]
fn agg_cont_req() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
        DapMeasurement::U64(1),
    ]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

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
        vdaf.unshard(&(), [leader_agg_share, helper_agg_share])
            .unwrap(),
        3,
    );
}

#[test]
fn agg_cont_req_skip_vdaf_prep_error() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
    ]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (helper_state, agg_resp) = t
        .handle_agg_init_req(agg_init_req.clone())
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
        agg_resp.transitions[0].nonce,
        agg_init_req.report_shares[0].nonce
    );
    assert_eq!(
        agg_resp.transitions[1].nonce,
        agg_init_req.report_shares[2].nonce
    );
}

#[test]
fn agg_cont_abort_unrecognized_nonce() {
    let mut rng = thread_rng();
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

    let (_, mut agg_cont_req) = t
        .handle_agg_resp(leader_state, agg_resp)
        .unwrap_uncommitted();
    // Leader sends a Transition with an unrecognized nonce.
    agg_cont_req.transitions.insert(
        1,
        Transition {
            nonce: Nonce {
                time: rng.gen(),
                rand: rng.gen(),
            },
            var: TransitionVar::Finished, // Expected transition type for Prio3 at this stage
        },
    );

    assert_matches!(
        t.handle_agg_cont_req_expect_err(helper_state, &agg_cont_req),
        DapAbort::UnrecognizedMessage
    );
}

#[test]
fn agg_cont_req_abort_transition_out_of_order() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

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

#[test]
fn agg_cont_req_abort_nonce_repeated() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
    let (leader_state, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (helper_state, agg_resp) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

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

#[test]
fn encrypted_agg_share() {
    let t = Test::new(TEST_VDAF);
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

    let batch_interval = Interval {
        start: 1637359200,
        duration: 7200,
    };
    let leader_encrypted_agg_share =
        t.produce_leader_encrypted_agg_share(&batch_interval, &leader_agg_share);
    let helper_encrypted_agg_share =
        t.produce_helper_encrypted_agg_share(&batch_interval, &helper_agg_share);
    let agg_res = t.consume_encrypted_agg_shares(
        &batch_interval,
        vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
    );

    assert_eq!(agg_res, DapAggregateResult::U64(32));
}

#[test]
fn helper_state_serialization() {
    let mut t = Test::new(TEST_VDAF);
    let reports = t.produce_reports(vec![
        DapMeasurement::U64(1),
        DapMeasurement::U64(1),
        DapMeasurement::U64(0),
        DapMeasurement::U64(0),
        DapMeasurement::U64(1),
    ]);
    let (_, agg_init_req) = t.produce_agg_init_req(reports).unwrap_continue();
    let (want, _) = t.handle_agg_init_req(agg_init_req).unwrap_continue();

    let got =
        DapHelperState::get_decoded(TEST_VDAF, &want.get_encoded(TEST_VDAF).unwrap()).unwrap();
    assert_eq!(got, want);

    assert!(DapHelperState::get_decoded(TEST_VDAF, b"invalid helper state").is_err())
}

struct Test<'a> {
    now: u64,
    vdaf: &'a VdafConfig,
    task_id: Id,
    agg_job_id: Id,
    vdaf_verify_key: VdafVerifyKey,
    leader_hpke_secret_key: HpkeSecretKey,
    helper_hpke_secret_key: HpkeSecretKey,
    helper_reports_aggregated: HashSet<Nonce>,
    helper_batch_collected: bool,
    client_hpke_config_list: Vec<HpkeConfig>,
    collector_hpke_config: HpkeConfig,
    collector_hpke_secret_key: HpkeSecretKey,
}

impl<'a> Test<'a> {
    fn new(vdaf: &'a VdafConfig) -> Test {
        let mut rng = thread_rng();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let task_id = Id(rng.gen());
        let agg_job_id = Id(rng.gen());
        let vdaf_verify_key = vdaf.gen_verify_key();
        let (leader_hpke_config, leader_hpke_secret_key) = HpkeSecretKey::gen(rng.gen());
        let (helper_hpke_config, helper_hpke_secret_key) = HpkeSecretKey::gen(rng.gen());
        let (collector_hpke_config, collector_hpke_secret_key) = HpkeSecretKey::gen(rng.gen());

        Test {
            now,
            vdaf,
            task_id,
            agg_job_id,
            vdaf_verify_key,
            leader_hpke_secret_key,
            helper_hpke_secret_key,
            helper_reports_aggregated: HashSet::new(),
            helper_batch_collected: false,
            client_hpke_config_list: vec![leader_hpke_config, helper_hpke_config],
            collector_hpke_config,
            collector_hpke_secret_key,
        }
    }

    fn produce_reports(&self, measurements: Vec<DapMeasurement>) -> Vec<Report> {
        let mut reports = Vec::with_capacity(measurements.len());

        for measurement in measurements.into_iter() {
            reports.push(
                self.vdaf
                    .produce_report(
                        &self.client_hpke_config_list,
                        self.now,
                        &self.task_id,
                        measurement,
                    )
                    .unwrap(),
            );
        }
        reports
    }

    fn produce_agg_init_req(
        &self,
        reports: Vec<Report>,
    ) -> DapLeaderTransition<AggregateInitializeReq> {
        self.vdaf
            .produce_agg_init_req(
                &self.leader_hpke_secret_key,
                &self.vdaf_verify_key,
                &self.task_id,
                &self.agg_job_id,
                reports,
            )
            .unwrap()
    }

    fn handle_agg_init_req(
        &mut self,
        agg_init_req: AggregateInitializeReq,
    ) -> DapHelperTransition<AggregateResp> {
        let agg_resp = self
            .vdaf
            .handle_agg_init_req(
                &self.helper_hpke_secret_key,
                &self.vdaf_verify_key,
                &agg_init_req,
                |nonce| self.helper_early_tran_fail_for(nonce),
            )
            .unwrap();

        for report_share in agg_init_req.report_shares {
            self.helper_reports_aggregated
                .insert(report_share.nonce.clone());
        }

        agg_resp
    }

    fn handle_agg_resp(
        &self,
        leader_state: DapLeaderState,
        agg_resp: AggregateResp,
    ) -> DapLeaderTransition<AggregateContinueReq> {
        self.vdaf
            .handle_agg_resp(&self.task_id, &self.agg_job_id, leader_state, agg_resp)
            .unwrap()
    }

    fn handle_agg_resp_expect_err(
        &self,
        leader_state: DapLeaderState,
        agg_resp: AggregateResp,
    ) -> DapAbort {
        self.vdaf
            .handle_agg_resp(&self.task_id, &self.agg_job_id, leader_state, agg_resp)
            .err()
            .expect("handle_agg_resp() succeeded; expected failure")
    }

    fn handle_agg_cont_req(
        &self,
        helper_state: DapHelperState,
        agg_cont_req: &AggregateContinueReq,
    ) -> DapHelperTransition<AggregateResp> {
        self.vdaf
            .handle_agg_cont_req(helper_state, agg_cont_req)
            .unwrap()
    }

    fn handle_agg_cont_req_expect_err(
        &self,
        helper_state: DapHelperState,
        agg_cont_req: &AggregateContinueReq,
    ) -> DapAbort {
        self.vdaf
            .handle_agg_cont_req(helper_state, agg_cont_req)
            .err()
            .expect("handle_agg_cont_req() succeeded; expected failure")
    }

    fn handle_final_agg_resp(
        &self,
        leader_uncommitted: DapLeaderUncommitted,
        agg_resp: AggregateResp,
    ) -> Vec<DapOutputShare> {
        self.vdaf
            .handle_final_agg_resp(leader_uncommitted, agg_resp)
            .unwrap()
    }

    fn produce_leader_encrypted_agg_share(
        &self,
        batch_interval: &Interval,
        agg_share: &DapAggregateShare,
    ) -> HpkeCiphertext {
        self.vdaf
            .produce_leader_encrypted_agg_share(
                &self.collector_hpke_config,
                &self.task_id,
                batch_interval,
                agg_share,
            )
            .unwrap()
    }

    fn produce_helper_encrypted_agg_share(
        &self,
        batch_interval: &Interval,
        agg_share: &DapAggregateShare,
    ) -> HpkeCiphertext {
        self.vdaf
            .produce_helper_encrypted_agg_share(
                &self.collector_hpke_config,
                &self.task_id,
                batch_interval,
                agg_share,
            )
            .unwrap()
    }

    fn consume_encrypted_agg_shares(
        &self,
        batch_interval: &Interval,
        enc_agg_shares: Vec<HpkeCiphertext>,
    ) -> DapAggregateResult {
        self.vdaf
            .consume_encrypted_agg_shares(
                &self.collector_hpke_secret_key,
                &self.task_id,
                batch_interval,
                enc_agg_shares,
            )
            .unwrap()
    }

    fn helper_early_tran_fail_for(&self, nonce: &Nonce) -> Option<TransitionFailure> {
        if !self.helper_batch_collected && self.helper_reports_aggregated.contains(nonce) {
            return Some(TransitionFailure::ReportReplayed);
        } else if self.helper_batch_collected && !self.helper_reports_aggregated.contains(nonce) {
            return Some(TransitionFailure::BatchCollected);
        }
        None
    }
}
