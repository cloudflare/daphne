// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub(crate) mod aggregator;
mod client;
mod collector;

const CTX_INPUT_SHARE_DRAFT02: &[u8] = b"dap-02 input share";
const CTX_INPUT_SHARE_DRAFT_LATEST: &[u8] = b"dap-09 input share";
const CTX_AGG_SHARE_DRAFT02: &[u8] = b"dap-02 aggregate share";
const CTX_AGG_SHARE_DRAFT_LATEST: &[u8] = b"dap-09 aggregate share";
const CTX_ROLE_COLLECTOR: u8 = 0;
const CTX_ROLE_CLIENT: u8 = 1;
const CTX_ROLE_LEADER: u8 = 2;
const CTX_ROLE_HELPER: u8 = 3;

#[cfg(test)]
mod test {
    use crate::{
        assert_metrics_include, async_test_versions,
        error::DapAbort,
        hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId},
        messages::{
            AggregationJobInitReq, BatchSelector, Extension, Interval, PartialBatchSelector,
            PrepareInit, Report, ReportId, ReportShare, Transition, TransitionFailure,
            TransitionVar,
        },
        protocol::aggregator::{
            EarlyReportState, EarlyReportStateConsumed, EarlyReportStateInitialized,
        },
        test_versions,
        testing::AggregationJobTest,
        vdaf::{Prio3Config, VdafConfig},
        DapAggregateResult, DapAggregateShare, DapAggregateSpan, DapAggregationJobState,
        DapAggregationJobUncommitted, DapAggregationParam, DapError,
        DapHelperAggregationJobTransition, DapLeaderAggregationJobTransition, DapMeasurement,
        DapVersion, VdafAggregateShare, VdafPrepMessage, VdafPrepState,
    };
    use assert_matches::assert_matches;
    use hpke_rs::HpkePublicKey;
    use prio::{
        codec::Encode,
        field::Field64,
        vdaf::{
            prio3::Prio3, AggregateShare, Aggregator as VdafAggregator, Collector as VdafCollector,
            OutputShare, PrepareTransition,
        },
    };
    use rand::prelude::*;
    use std::fmt::Debug;

    impl<M: Debug> DapLeaderAggregationJobTransition<M> {
        fn unwrap_continued(self) -> (DapAggregationJobState, M) {
            let Self::Continued(state, message) = self else {
                panic!("unexpected transition")
            };
            (state, message)
        }

        fn unwrap_finished(self) -> DapAggregateSpan<DapAggregateShare> {
            let Self::Finished(agg_span) = self else {
                panic!("unexpected transition")
            };
            agg_span
        }

        pub(crate) fn unwrap_uncommitted(self) -> (DapAggregationJobUncommitted, M) {
            let Self::Uncommitted(uncommitted, message) = self else {
                panic!("unexpected transition")
            };
            (uncommitted, message)
        }
    }

    impl<M: Debug> DapHelperAggregationJobTransition<M> {
        fn unwrap_continued(self) -> (DapAggregationJobState, M) {
            let Self::Continued(state, message) = self else {
                panic!("unexpected transition")
            };
            (state, message)
        }

        fn unwrap_finished(self) -> (DapAggregateSpan<DapAggregateShare>, M) {
            let Self::Finished(agg_span, msg) = self else {
                panic!("unexpected transition")
            };
            (agg_span, msg)
        }

        fn into_message(self) -> M {
            match self {
                Self::Continued(_, msg) | Self::Finished(_, msg) => msg,
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
                t.task_config.version,
            )
            .unwrap();

        let early_report_state_consumed = EarlyReportStateConsumed::consume(
            &t.leader_hpke_receiver_config,
            true, // is_leader
            &t.task_id,
            &t.task_config,
            report.report_metadata.clone(),
            report.public_share.clone(),
            &report.encrypted_input_shares[0],
        )
        .await
        .unwrap();
        let EarlyReportStateInitialized::Ready {
            state: leader_step,
            message: leader_share,
            ..
        } = EarlyReportStateInitialized::initialize(
            true,
            &t.task_config.vdaf_verify_key,
            &t.task_config.vdaf,
            &DapAggregationParam::Empty,
            early_report_state_consumed,
        )
        .unwrap()
        else {
            panic!("rejected unexpectedly");
        };

        let early_report_state_consumed = EarlyReportStateConsumed::consume(
            &t.helper_hpke_receiver_config,
            false, // is_helper
            &t.task_id,
            &t.task_config,
            report.report_metadata,
            report.public_share,
            &report.encrypted_input_shares[1],
        )
        .await
        .unwrap();
        let EarlyReportStateInitialized::Ready {
            state: helper_step,
            message: helper_share,
            ..
        } = EarlyReportStateInitialized::initialize(
            false,
            &t.task_config.vdaf_verify_key,
            &t.task_config.vdaf,
            &DapAggregationParam::Empty,
            early_report_state_consumed,
        )
        .unwrap()
        else {
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
                    .prepare_shares_to_prepare_message(&(), [leader_share, helper_share])
                    .unwrap();

                let leader_out_share = assert_matches!(
                    vdaf.prepare_next(leader_step, message.clone()).unwrap(),
                    PrepareTransition::Finish(out_share) => out_share
                );
                let leader_agg_share = vdaf.aggregate(&(), [leader_out_share]).unwrap();

                let helper_out_share = assert_matches!(
                    vdaf.prepare_next(helper_step, message).unwrap(),
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
            t.task_config.version,
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
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports.clone())
            .await
            .unwrap_continued();
        assert_eq!(leader_state.seq.len(), 3);
        assert_eq!(
            agg_job_init_req.draft02_task_id,
            t.task_id.for_request_payload(&version)
        );
        assert_eq!(agg_job_init_req.agg_param.len(), 0);
        assert_eq!(agg_job_init_req.prep_inits.len(), 3);
        for (prep_init, report) in agg_job_init_req.prep_inits.iter().zip(reports.iter()) {
            assert_eq!(
                prep_init.report_share.report_metadata.id,
                report.report_metadata.id
            );
        }

        match t.handle_agg_job_init_req(&agg_job_init_req).await {
            DapHelperAggregationJobTransition::Continued(helper_state, agg_job_resp) => {
                assert_eq!(helper_state.seq.len(), 3);
                assert_eq!(agg_job_resp.transitions.len(), 3);
                for (sub, report) in agg_job_resp.transitions.iter().zip(reports.iter()) {
                    assert_eq!(sub.report_id, report.report_metadata.id);
                }
            }
            DapHelperAggregationJobTransition::Finished(agg_span, agg_job_resp) => {
                assert_eq!(agg_span.report_count(), 3);
                assert_eq!(agg_job_resp.transitions.len(), 3);
            }
        }
    }

    async_test_versions! { produce_agg_job_init_req }

    async fn produce_agg_job_init_req_skip_hpke_decrypt_err(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Simulate HPKE decryption error of leader's report share.
        reports[0].encrypted_input_shares[0].payload[0] ^= 1;

        assert_eq!(
            t.produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
                .await
                .unwrap_finished()
                .report_count(),
            0
        );
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_hpke_decrypt_error"}"#: 1,
        });
    }

    async_test_versions! { produce_agg_job_init_req_skip_hpke_decrypt_err }

    async fn produce_agg_job_init_req_skip_hpke_unknown_config_id(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Client tries to send Leader encrypted input with incorrect config ID.
        reports[0].encrypted_input_shares[0].config_id ^= 1;

        assert_eq!(
            t.produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
                .await
                .unwrap_finished()
                .report_count(),
            0
        );
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_hpke_unknown_config_id"}"#: 1,
        });
    }

    async_test_versions! { produce_agg_job_init_req_skip_hpke_unknown_config_id }

    async fn produce_agg_job_init_req_skip_vdaf_prep_error(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = vec![
            t.produce_invalid_report_public_share_decode_failure(DapMeasurement::U64(1), version),
            t.produce_invalid_report_input_share_decode_failure(DapMeasurement::U64(1), version),
        ];

        assert_eq!(
            t.produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
                .await
                .unwrap_finished()
                .report_count(),
            0
        );
        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_vdaf_prep_error"}"#: 2,
        });
    }

    async_test_versions! { produce_agg_job_init_req_skip_vdaf_prep_error }

    async fn handle_agg_job_init_req_hpke_decrypt_err(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Simulate HPKE decryption error of helper's report share.
        reports[0].encrypted_input_shares[1].payload[0] ^= 1;

        let (_, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports.clone())
            .await
            .unwrap_continued();
        let agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        assert_eq!(agg_job_resp.transitions.len(), 1);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(TransitionFailure::HpkeDecryptError)
        );
    }

    async_test_versions! { handle_agg_job_init_req_hpke_decrypt_err }

    async fn handle_agg_job_init_req_hpke_unknown_config_id(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Client tries to send Helper encrypted input with incorrect config ID.
        reports[0].encrypted_input_shares[1].config_id ^= 1;

        let (_, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports.clone())
            .await
            .unwrap_continued();
        let agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        assert_eq!(agg_job_resp.transitions.len(), 1);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(TransitionFailure::HpkeUnknownConfigId)
        );
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
            prep_inits: vec![
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: report0.report_metadata,
                        public_share: report0.public_share,
                        encrypted_input_share: report0.encrypted_input_shares[1].clone(),
                    },
                    draft_latest_payload: Some(b"malformed payload".to_vec()),
                },
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: report1.report_metadata,
                        public_share: report1.public_share,
                        encrypted_input_share: report1.encrypted_input_shares[1].clone(),
                    },
                    draft_latest_payload: Some(b"malformed payload".to_vec()),
                },
            ],
        };

        let agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        assert_eq!(agg_job_resp.transitions.len(), 2);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(TransitionFailure::VdafPrepError)
        );
        assert_matches!(
            agg_job_resp.transitions[1].var,
            TransitionVar::Failed(TransitionFailure::VdafPrepError)
        );
    }

    async_test_versions! { handle_agg_job_init_req_vdaf_prep_error }

    async fn agg_job_resp_abort_transition_out_of_order(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let mut agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        // Helper sends transitions out of order.
        let tmp = agg_job_resp.transitions[0].clone();
        agg_job_resp.transitions[0] = agg_job_resp.transitions[1].clone();
        agg_job_resp.transitions[1] = tmp;

        assert_matches!(
            t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    async_test_versions! { agg_job_resp_abort_transition_out_of_order }

    async fn agg_job_resp_abort_report_id_repeated(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let mut agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        // Helper sends a transition twice.
        let repeated_transition = agg_job_resp.transitions[0].clone();
        agg_job_resp.transitions.push(repeated_transition);

        assert_matches!(
            t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    async_test_versions! { agg_job_resp_abort_report_id_repeated }

    async fn agg_job_resp_abort_unrecognized_report_id(version: DapVersion) {
        let mut rng = thread_rng();
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let mut agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        // Helper sent a transition with an unrecognized report ID.
        agg_job_resp.transitions.push(Transition {
            report_id: ReportId(rng.gen()),
            var: TransitionVar::Continued(b"whatever".to_vec()),
        });

        assert_matches!(
            t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    async_test_versions! { agg_job_resp_abort_unrecognized_report_id }

    async fn agg_job_resp_abort_invalid_transition(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let mut agg_job_resp = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .into_message();

        // Helper sent a transition with an unrecognized report ID.
        agg_job_resp.transitions[0].var = TransitionVar::Finished;

        assert_matches!(
            t.handle_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapError::Abort(DapAbort::InvalidMessage { .. })
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

        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();

        let (leader_agg_span, helper_agg_span) =
            match t.handle_agg_job_init_req(&agg_job_init_req).await {
                DapHelperAggregationJobTransition::Continued(helper_state, agg_job_resp) => {
                    // draft02
                    let (leader_uncommitted, agg_job_cont_req) = t
                        .handle_agg_job_resp(leader_state, agg_job_resp)
                        .unwrap_uncommitted();

                    let (helper_agg_span, agg_job_resp) =
                        t.handle_agg_job_cont_req(&helper_state, &agg_job_cont_req);
                    assert_eq!(helper_agg_span.report_count(), 5);
                    assert_eq!(agg_job_resp.transitions.len(), 5);

                    let leader_agg_span =
                        t.handle_final_agg_job_resp(leader_uncommitted, agg_job_resp);

                    (leader_agg_span, helper_agg_span)
                }
                DapHelperAggregationJobTransition::Finished(helper_agg_span, agg_job_resp) => {
                    let leader_agg_span = t
                        .handle_agg_job_resp(leader_state, agg_job_resp)
                        .unwrap_finished();

                    (leader_agg_span, helper_agg_span)
                }
            };

        assert_eq!(leader_agg_span.report_count(), 5);
        let num_measurements = leader_agg_span.report_count();

        let VdafAggregateShare::Field64(leader_agg_share) =
            leader_agg_span.collapsed().data.unwrap()
        else {
            panic!("unexpected VdafAggregateShare variant")
        };

        let VdafAggregateShare::Field64(helper_agg_share) =
            helper_agg_span.collapsed().data.unwrap()
        else {
            panic!("unexpected VdafAggregateShare variant")
        };

        let vdaf = Prio3::new_count(2).unwrap();
        assert_eq!(
            vdaf.unshard(&(), [leader_agg_share, helper_agg_share], num_measurements,)
                .unwrap(),
            3,
        );
    }

    async_test_versions! { agg_job_cont_req }

    #[tokio::test]
    async fn agg_job_cont_req_skip_vdaf_prep_error_draft02() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        reports.insert(
            1,
            t.produce_invalid_report_vdaf_prep_failure(DapMeasurement::U64(1), DapVersion::Draft02),
        );

        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let (helper_state, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let (_, agg_job_cont_req) = t
            .handle_agg_job_resp(leader_state, agg_job_resp)
            .unwrap_uncommitted();

        let (helper_agg_span, agg_job_resp) =
            t.handle_agg_job_cont_req(&helper_state, &agg_job_cont_req);

        assert_eq!(2, helper_agg_span.report_count());
        assert_eq!(2, agg_job_resp.transitions.len());
        assert_eq!(
            agg_job_resp.transitions[0].report_id,
            agg_job_init_req.prep_inits[0]
                .report_share
                .report_metadata
                .id
        );
        assert_eq!(
            agg_job_resp.transitions[1].report_id,
            agg_job_init_req.prep_inits[2]
                .report_share
                .report_metadata
                .id
        );

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_vdaf_prep_error"}"#: 1,
        });
    }

    #[tokio::test]
    async fn agg_job_init_req_skip_vdaf_prep_error_draft09() {
        let t = AggregationJobTest::new(
            TEST_VDAF,
            HpkeKemId::X25519HkdfSha256,
            DapVersion::DraftLatest,
        );
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        reports.insert(
            1,
            t.produce_invalid_report_vdaf_prep_failure(
                DapMeasurement::U64(1),
                DapVersion::DraftLatest,
            ),
        );

        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let (helper_agg_span, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_finished();

        assert_eq!(2, helper_agg_span.report_count());
        assert_eq!(3, agg_job_resp.transitions.len());
        for i in 0..3 {
            assert_eq!(
                agg_job_resp.transitions[i].report_id,
                agg_job_init_req.prep_inits[i]
                    .report_share
                    .report_metadata
                    .id
            );
        }

        let DapLeaderAggregationJobTransition::Finished(leader_agg_span) =
            t.handle_agg_job_resp(leader_state, agg_job_resp)
        else {
            panic!("unexpected transition")
        };
        assert_eq!(leader_agg_span.report_count(), 2);
    }

    #[tokio::test]
    async fn agg_cont_abort_unrecognized_report_id_draft02() {
        let mut rng = thread_rng();
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let (helper_state, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

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
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    #[tokio::test]
    async fn agg_job_cont_req_abort_transition_out_of_order_draft02() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let (helper_state, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let (_, mut agg_job_cont_req) = t
            .handle_agg_job_resp(leader_state, agg_job_resp)
            .unwrap_uncommitted();
        // Leader sends transitions out of order.
        let tmp = agg_job_cont_req.transitions[0].clone();
        agg_job_cont_req.transitions[0] = agg_job_cont_req.transitions[1].clone();
        agg_job_cont_req.transitions[1] = tmp;

        assert_matches!(
            t.handle_agg_job_cont_req_expect_err(helper_state, &agg_job_cont_req),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    #[tokio::test]
    async fn agg_job_cont_req_abort_report_id_repeated_draft02() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let (helper_state, agg_job_resp) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let (_, mut agg_job_cont_req) = t
            .handle_agg_job_resp(leader_state, agg_job_resp)
            .unwrap_uncommitted();
        // Leader sends a transition twice.
        let repeated_transition = agg_job_cont_req.transitions[0].clone();
        agg_job_cont_req.transitions.push(repeated_transition);

        assert_matches!(
            t.handle_agg_job_cont_req_expect_err(helper_state, &agg_job_cont_req),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    async fn encrypted_agg_share(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let leader_agg_share = DapAggregateShare {
            report_count: 50,
            min_time: 1_637_359_200,
            max_time: 1_637_359_200,
            checksum: [0; 32],
            data: Some(VdafAggregateShare::Field64(AggregateShare::from(
                OutputShare::from(vec![Field64::from(23)]),
            ))),
        };
        let helper_agg_share = DapAggregateShare {
            report_count: 50,
            min_time: 1_637_359_200,
            max_time: 1_637_359_200,
            checksum: [0; 32],
            data: Some(VdafAggregateShare::Field64(AggregateShare::from(
                OutputShare::from(vec![Field64::from(9)]),
            ))),
        };

        let batch_selector = BatchSelector::TimeInterval {
            batch_interval: Interval {
                start: 1_637_359_200,
                duration: 7200,
            },
        };
        let leader_encrypted_agg_share = t.produce_leader_encrypted_agg_share(
            &batch_selector,
            &DapAggregationParam::Empty,
            &leader_agg_share,
        );
        let helper_encrypted_agg_share = t.produce_helper_encrypted_agg_share(
            &batch_selector,
            &DapAggregationParam::Empty,
            &helper_agg_share,
        );
        let agg_res = t
            .consume_encrypted_agg_shares(
                &batch_selector,
                50,
                &DapAggregationParam::Empty,
                vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
            )
            .await;

        assert_eq!(agg_res, DapAggregateResult::U64(32));
    }

    async_test_versions! { encrypted_agg_share }

    #[tokio::test]
    async fn helper_state_serialization_draft02() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);
        let reports = t.produce_reports(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(0),
            DapMeasurement::U64(1),
        ]);
        let (_, agg_job_init_req) = t
            .produce_agg_job_init_req(&DapAggregationParam::Empty, reports)
            .await
            .unwrap_continued();
        let (want, _) = t
            .handle_agg_job_init_req(&agg_job_init_req)
            .await
            .unwrap_continued();

        let got =
            DapAggregationJobState::get_decoded(TEST_VDAF, &want.get_encoded().unwrap()).unwrap();
        assert_eq!(got.get_encoded().unwrap(), want.get_encoded().unwrap());

        assert!(DapAggregationJobState::get_decoded(TEST_VDAF, b"invalid helper state").is_err());
    }

    async fn handle_unrecognized_report_extensions(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let report = t
            .task_config
            .vdaf
            .produce_report_with_extensions(
                &t.client_hpke_config_list,
                t.now,
                &t.task_id,
                DapMeasurement::U64(1),
                vec![Extension::NotImplemented {
                    typ: 0xffff,
                    payload: b"some extension data".to_vec(),
                }],
                t.task_config.version,
            )
            .unwrap();

        let report_metadata = report.report_metadata.clone();
        let consumed_report = EarlyReportStateConsumed::consume(
            &t.leader_hpke_receiver_config,
            true,
            &t.task_id,
            &t.task_config,
            report.report_metadata,
            report.public_share,
            &report.encrypted_input_shares[0],
        )
        .await
        .unwrap();

        assert_eq!(consumed_report.metadata(), &report_metadata);

        let expect_ready = match version {
            // In draft02 we're meant to ignore extensions we don't recognize.
            DapVersion::Draft02 => true,
            // In the latest version we're meant to reject reports containing unrecognized
            // extensions.
            DapVersion::DraftLatest => false,
        };
        assert_eq!(consumed_report.is_ready(), expect_ready);
    }

    async_test_versions! { handle_unrecognized_report_extensions }

    async fn handle_repeated_report_extensions(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let report = t
            .task_config
            .vdaf
            .produce_report_with_extensions(
                &t.client_hpke_config_list,
                t.now,
                &t.task_id,
                DapMeasurement::U64(1),
                vec![
                    Extension::NotImplemented {
                        typ: 23,
                        payload: b"this payload shouldn't be interpretd yet".to_vec(),
                    },
                    Extension::NotImplemented {
                        typ: 23,
                        payload: b"nor should this payload".to_vec(),
                    },
                ],
                t.task_config.version,
            )
            .unwrap();

        let report_metadata = report.report_metadata.clone();
        let consumed_report = EarlyReportStateConsumed::consume(
            &t.leader_hpke_receiver_config,
            true,
            &t.task_id,
            &t.task_config,
            report.report_metadata,
            report.public_share,
            &report.encrypted_input_shares[0],
        )
        .await
        .unwrap();

        assert_eq!(consumed_report.metadata(), &report_metadata);
        assert!(!consumed_report.is_ready());
    }

    async_test_versions! { handle_repeated_report_extensions }

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
            VdafConfig::produce_report_with_extensions_for_shares(
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
            VdafConfig::produce_report_with_extensions_for_shares(
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
            VdafConfig::produce_report_with_extensions_for_shares(
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
}
