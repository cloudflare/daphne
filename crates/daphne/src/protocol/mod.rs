// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use prio::codec::{CodecError, Decode as _};
use std::{collections::HashSet, io::Cursor};

pub(crate) mod aggregator;
mod client;
mod collector;
pub(crate) mod report_init;

/// checks if an iterator has no duplicate items, returns the ok if there are no dups or an error
/// with the first offending item.
fn no_duplicates<I>(iterator: I) -> Result<(), I::Item>
where
    I: Iterator,
    I::Item: Eq + std::hash::Hash,
{
    let (lower, upper) = iterator.size_hint();
    let mut seen = HashSet::with_capacity(upper.unwrap_or(lower));

    for item in iterator {
        if let Some(repeat) = seen.replace(item) {
            return Err(repeat);
        }
    }
    Ok(())
}

// Ping-pong message framing as defined in draft-irtf-cfrg-vdaf-08, Section 5.8. We do not
// implement the "continue" message type because we only support 1-round VDAFs.
enum PingPongMessageType {
    Initialize = 0,
    Finish = 2,
}

// This is essentially a re-implementation of a method in the `messages` module. However the goal
// here is to make it zero-copy. See https://github.com/cloudflare/daphne/issues/15.
fn decode_ping_pong_framed(
    bytes: &[u8],
    expected_type: PingPongMessageType,
) -> Result<&[u8], CodecError> {
    let mut r = Cursor::new(bytes);

    let message_type = u8::decode(&mut r)?;
    if message_type != expected_type as u8 {
        return Err(CodecError::UnexpectedValue);
    }

    let message_len = u32::decode(&mut r)?.try_into().unwrap();
    let message_start = usize::try_from(r.position()).unwrap();
    if bytes.len() - message_start < message_len {
        return Err(CodecError::LengthPrefixTooBig(message_len));
    }
    if bytes.len() - message_start > message_len {
        return Err(CodecError::BytesLeftOver(message_len));
    }

    Ok(&bytes[message_start..])
}

#[cfg(test)]
mod test {
    use super::{report_init::InitializedReport, PingPongMessageType};
    use crate::{
        assert_metrics_include,
        error::DapAbort,
        hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId},
        messages::{
            AggregationJobInitReq, BatchSelector, Extension, Interval, PartialBatchSelector,
            PrepareInit, Report, ReportError, ReportId, ReportShare, Transition, TransitionVar,
        },
        test_versions,
        testing::AggregationJobTest,
        vdaf::{Prio3Config, VdafConfig},
        DapAggregateResult, DapAggregateShare, DapAggregationParam, DapError, DapMeasurement,
        DapVersion, VdafAggregateShare, VdafPrepShare, VdafPrepState,
    };
    use assert_matches::assert_matches;
    use hpke_rs::HpkePublicKey;
    use prio::{
        codec::encode_u32_items,
        vdaf::{
            prio3::Prio3, Aggregator as VdafAggregator, Collector as VdafCollector,
            PrepareTransition,
        },
    };
    use prio_draft09::{
        field::Field64 as Field64Draft09,
        vdaf::{
            prio3::Prio3 as Prio3Draft09, AggregateShare as AggregateShareDraft09,
            Aggregator as VdafAggregatorDraft09, Collector as VdafCollectorDraft09,
            OutputShare as OutputShareDraft09, PrepareTransition as PrepareTransitionDraft09,
        },
    };
    use rand::prelude::*;
    use std::iter::zip;

    const TEST_VDAF: &VdafConfig = &VdafConfig::Prio3(Prio3Config::Count);
    const TEST_VDAF_DRAFT09: &VdafConfig = &VdafConfig::Prio3Draft09(Prio3Config::Count);

    fn roundtrip_report(version: DapVersion) {
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

        let [leader_share, helper_share] = report.encrypted_input_shares;

        let InitializedReport::Ready {
            prep_share: leader_prep_share,
            prep_state: leader_prep_state,
            ..
        } = InitializedReport::from_client(
            &t.leader_hpke_receiver_config,
            t.valid_report_time_range(),
            &t.task_id,
            &t.task_config,
            ReportShare {
                report_metadata: report.report_metadata.clone(),
                public_share: report.public_share.clone(),
                encrypted_input_share: leader_share,
            },
            &DapAggregationParam::Empty,
        )
        .unwrap()
        else {
            panic!("rejected unexpectedly");
        };

        let InitializedReport::Ready {
            prep_share: helper_prep_share,
            prep_state: helper_prep_state,
            ..
        } = InitializedReport::from_leader(
            &t.helper_hpke_receiver_config,
            t.valid_report_time_range(),
            &t.task_id,
            &t.task_config,
            ReportShare {
                report_metadata: report.report_metadata,
                public_share: report.public_share,
                encrypted_input_share: helper_share,
            },
            {
                let mut outbound = Vec::new();
                outbound.push(PingPongMessageType::Initialize as u8);
                encode_u32_items(&mut outbound, &version, &[leader_prep_share.clone()]).unwrap();
                outbound
            },
            &DapAggregationParam::Empty,
        )
        .unwrap()
        else {
            panic!("rejected unexpectedly");
        };

        match (
            leader_prep_state,
            helper_prep_state,
            leader_prep_share,
            helper_prep_share,
        ) {
            (
                VdafPrepState::Prio3Field64(leader_step),
                VdafPrepState::Prio3Field64(helper_step),
                VdafPrepShare::Prio3Field64(leader_share),
                VdafPrepShare::Prio3Field64(helper_share),
            ) => {
                let ctx = &["dap-13".as_bytes(), &t.task_id.0].concat();
                //let ctx = binding.as_slice();
                let vdaf = Prio3::new_count(2).unwrap();
                let message = vdaf
                    .prepare_shares_to_prepare_message(ctx, &(), [leader_share, helper_share])
                    .unwrap();

                let leader_out_share = assert_matches!(
                    vdaf.prepare_next(ctx, leader_step, message.clone()).unwrap(),
                    PrepareTransition::Finish(out_share) => out_share
                );
                let leader_agg_share = vdaf.aggregate(&(), [leader_out_share]).unwrap();

                let helper_out_share = assert_matches!(
                    vdaf.prepare_next(ctx, helper_step, message).unwrap(),
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

    test_versions! { roundtrip_report }

    #[test]
    fn roundtrip_report_vdaf_draft09() {
        let version = DapVersion::Draft09;
        let t = AggregationJobTest::new(TEST_VDAF_DRAFT09, HpkeKemId::X25519HkdfSha256, version);
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

        let [leader_share, helper_share] = report.encrypted_input_shares;

        let InitializedReport::Ready {
            prep_share: leader_prep_share,
            prep_state: leader_prep_state,
            ..
        } = InitializedReport::from_client(
            &t.leader_hpke_receiver_config,
            t.valid_report_time_range(),
            &t.task_id,
            &t.task_config,
            ReportShare {
                report_metadata: report.report_metadata.clone(),
                public_share: report.public_share.clone(),
                encrypted_input_share: leader_share,
            },
            &DapAggregationParam::Empty,
        )
        .unwrap()
        else {
            panic!("rejected unexpectedly");
        };

        let InitializedReport::Ready {
            prep_share: helper_prep_share,
            prep_state: helper_prep_state,
            ..
        } = InitializedReport::from_leader(
            &t.helper_hpke_receiver_config,
            t.valid_report_time_range(),
            &t.task_id,
            &t.task_config,
            ReportShare {
                report_metadata: report.report_metadata,
                public_share: report.public_share,
                encrypted_input_share: helper_share,
            },
            {
                let mut outbound = Vec::new();
                outbound.push(PingPongMessageType::Initialize as u8);
                encode_u32_items(&mut outbound, &version, &[leader_prep_share.clone()]).unwrap();
                outbound
            },
            &DapAggregationParam::Empty,
        )
        .unwrap()
        else {
            panic!("rejected unexpectedly");
        };

        match (
            leader_prep_state,
            helper_prep_state,
            leader_prep_share,
            helper_prep_share,
        ) {
            (
                VdafPrepState::Prio3Draft09Field64(leader_step),
                VdafPrepState::Prio3Draft09Field64(helper_step),
                VdafPrepShare::Prio3Draft09Field64(leader_share),
                VdafPrepShare::Prio3Draft09Field64(helper_share),
            ) => {
                let vdaf = Prio3Draft09::new_count(2).unwrap();
                let message = vdaf
                    .prepare_shares_to_prepare_message(&(), [leader_share, helper_share])
                    .unwrap();

                let leader_out_share = assert_matches!(
                    vdaf.prepare_next(leader_step, message.clone()).unwrap(),
                    PrepareTransitionDraft09::Finish(out_share) => out_share
                );
                let leader_agg_share = vdaf.aggregate(&(), [leader_out_share]).unwrap();

                let helper_out_share = assert_matches!(
                    vdaf.prepare_next(helper_step, message).unwrap(),
                    PrepareTransitionDraft09::Finish(out_share) => out_share
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

    fn roundtrip_report_unsupported_hpke_suite(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);

        // The helper's HPKE config indicates a KEM type no supported by the client.
        let unsupported_hpke_config_list = [
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

    fn produce_agg_job_req(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(0),
        ]);

        let (agg_job_state, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports.clone());
        assert_eq!(agg_job_state.report_count(), 3);
        assert_eq!(agg_job_init_req.agg_param.len(), 0);
        assert_eq!(agg_job_init_req.prep_inits.len(), 3);
        for (prep_init, report) in agg_job_init_req.prep_inits.iter().zip(reports.iter()) {
            assert_eq!(
                prep_init.report_share.report_metadata.id,
                report.report_metadata.id
            );
        }

        let (agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);
        assert_eq!(agg_span.report_count(), 3);
        assert_eq!(agg_job_resp.transitions.len(), 3);
    }

    test_versions! { produce_agg_job_req }

    fn produce_agg_job_req_skip_hpke_decrypt_err(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Simulate HPKE decryption error of leader's report share.
        reports[0].encrypted_input_shares[0].payload[0] ^= 1;

        let (agg_job_state, _agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        assert_eq!(agg_job_state.report_count(), 0);

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_hpke_decrypt_error"}"#: 1,
        });
    }

    test_versions! { produce_agg_job_req_skip_hpke_decrypt_err }

    fn produce_agg_job_req_skip_time_too_stale(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = vec![t
            .task_config
            .vdaf
            .produce_report(
                &t.client_hpke_config_list,
                t.valid_report_time_range().start - 1,
                &t.task_id,
                DapMeasurement::U64(1),
                t.task_config.version,
            )
            .unwrap()];

        let (agg_job_state, _agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        assert_eq!(agg_job_state.report_count(), 0);

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_report_dropped"}"#: 1,
        });
    }

    test_versions! { produce_agg_job_req_skip_time_too_stale }

    fn produce_agg_job_req_skip_time_too_early(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = vec![t
            .task_config
            .vdaf
            .produce_report(
                &t.client_hpke_config_list,
                t.valid_report_time_range().end + 1,
                &t.task_id,
                DapMeasurement::U64(1),
                t.task_config.version,
            )
            .unwrap()];

        let (agg_job_state, _agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        assert_eq!(agg_job_state.report_count(), 0);

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_report_too_early"}"#: 1,
        });
    }

    test_versions! { produce_agg_job_req_skip_time_too_early }

    fn produce_agg_job_req_skip_hpke_unknown_config_id(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Client tries to send Leader encrypted input with incorrect config ID.
        reports[0].encrypted_input_shares[0].config_id ^= 1;

        let (agg_job_state, _agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        assert_eq!(agg_job_state.report_count(), 0);

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_hpke_unknown_config_id"}"#: 1,
        });
    }

    test_versions! { produce_agg_job_req_skip_hpke_unknown_config_id }

    fn produce_agg_job_req_skip_vdaf_prep_error(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = vec![
            t.produce_invalid_report_public_share_decode_failure(DapMeasurement::U64(1), version),
            t.produce_invalid_report_input_share_decode_failure(DapMeasurement::U64(1), version),
        ];

        let (agg_job_state, _agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        assert_eq!(agg_job_state.report_count(), 0);

        assert_metrics_include!(t.leader_registry, {
            r#"report_counter{env="test_leader",host="leader.com",status="rejected_vdaf_prep_error"}"#: 2,
        });
    }

    test_versions! { produce_agg_job_req_skip_vdaf_prep_error }

    fn handle_agg_job_req_hpke_decrypt_err(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Simulate HPKE decryption error of helper's report share.
        reports[0].encrypted_input_shares[1].payload[0] ^= 1;

        let (_, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports.clone());
        let (_agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        assert_eq!(agg_job_resp.transitions.len(), 1);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(ReportError::HpkeDecryptError)
        );
    }

    test_versions! { handle_agg_job_req_hpke_decrypt_err }

    fn handle_agg_job_req_skip_time_too_stale(version: DapVersion) {
        let mut t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = vec![t
            .task_config
            .vdaf
            .produce_report(
                &t.client_hpke_config_list,
                t.valid_report_time_range().start - 1,
                &t.task_id,
                DapMeasurement::U64(1),
                t.task_config.version,
            )
            .unwrap()];

        let agg_job_init_req = {
            // Temporarily overwrite the valid report time range so that the Leader accepts the
            // out-of-range report and produces the request.
            let tmp = t.valid_report_range.clone();
            t.valid_report_range = 0..u64::MAX;
            let (_, agg_job_init_req) =
                t.produce_agg_job_req(&DapAggregationParam::Empty, reports.clone());
            t.valid_report_range = tmp;
            agg_job_init_req
        };
        let (_agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        assert_eq!(agg_job_resp.transitions.len(), 1);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(ReportError::ReportDropped)
        );
    }

    test_versions! { handle_agg_job_req_skip_time_too_stale }

    fn handle_agg_job_req_skip_time_too_early(version: DapVersion) {
        let mut t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = vec![t
            .task_config
            .vdaf
            .produce_report(
                &t.client_hpke_config_list,
                t.valid_report_time_range().end + 1,
                &t.task_id,
                DapMeasurement::U64(1),
                t.task_config.version,
            )
            .unwrap()];

        let agg_job_init_req = {
            // Temporarily overwrite the valid report time range so that the Leader accepts the
            // out-of-range report and produces the request.
            let tmp = t.valid_report_range.clone();
            t.valid_report_range = 0..u64::MAX;
            let (_, agg_job_init_req) =
                t.produce_agg_job_req(&DapAggregationParam::Empty, reports.clone());
            t.valid_report_range = tmp;
            agg_job_init_req
        };
        let (_agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        assert_eq!(agg_job_resp.transitions.len(), 1);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(ReportError::ReportTooEarly)
        );
    }

    test_versions! { handle_agg_job_req_skip_time_too_early }

    fn handle_agg_job_req_hpke_unknown_config_id(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1)]);

        // Client tries to send Helper encrypted input with incorrect config ID.
        reports[0].encrypted_input_shares[1].config_id ^= 1;

        let (_, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports.clone());
        let (_agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        assert_eq!(agg_job_resp.transitions.len(), 1);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(ReportError::HpkeUnknownConfigId)
        );
    }

    test_versions! { handle_agg_job_req_hpke_unknown_config_id }

    fn handle_agg_job_req_vdaf_prep_error(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let report0 =
            t.produce_invalid_report_public_share_decode_failure(DapMeasurement::U64(1), version);
        let report1 =
            t.produce_invalid_report_input_share_decode_failure(DapMeasurement::U64(1), version);

        let agg_job_init_req = AggregationJobInitReq {
            agg_param: Vec::new(),
            part_batch_sel: PartialBatchSelector::TimeInterval,
            prep_inits: vec![
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: report0.report_metadata,
                        public_share: report0.public_share,
                        encrypted_input_share: report0.encrypted_input_shares[1].clone(),
                    },
                    payload: b"malformed payload".to_vec(),
                },
                PrepareInit {
                    report_share: ReportShare {
                        report_metadata: report1.report_metadata,
                        public_share: report1.public_share,
                        encrypted_input_share: report1.encrypted_input_shares[1].clone(),
                    },
                    payload: b"malformed payload".to_vec(),
                },
            ],
        };

        let (_agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        assert_eq!(agg_job_resp.transitions.len(), 2);
        assert_matches!(
            agg_job_resp.transitions[0].var,
            TransitionVar::Failed(ReportError::VdafPrepError)
        );
        assert_matches!(
            agg_job_resp.transitions[1].var,
            TransitionVar::Failed(ReportError::VdafPrepError)
        );
    }

    test_versions! { handle_agg_job_req_vdaf_prep_error }

    fn agg_job_resp_abort_transition_out_of_order(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        let (_agg_span, mut agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        // Helper sends transitions out of order.
        let tmp = agg_job_resp.transitions[0].clone();
        agg_job_resp.transitions[0] = agg_job_resp.transitions[1].clone();
        agg_job_resp.transitions[1] = tmp;

        assert_matches!(
            t.consume_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    test_versions! { agg_job_resp_abort_transition_out_of_order }

    fn agg_job_resp_abort_report_id_repeated(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        let (_agg_span, mut agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        // Helper sends a transition twice.
        let repeated_transition = agg_job_resp.transitions[0].clone();
        agg_job_resp.transitions.push(repeated_transition);

        assert_matches!(
            t.consume_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    test_versions! { agg_job_resp_abort_report_id_repeated }

    fn agg_job_resp_abort_unrecognized_report_id(version: DapVersion) {
        let mut rng = thread_rng();
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        let (_agg_span, mut agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        // Helper sent a transition with an unrecognized report ID.
        agg_job_resp.transitions.push(Transition {
            report_id: ReportId(rng.gen()),
            var: TransitionVar::Continued(b"whatever".to_vec()),
        });

        assert_matches!(
            t.consume_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    test_versions! { agg_job_resp_abort_unrecognized_report_id }

    fn agg_job_resp_abort_invalid_transition(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![DapMeasurement::U64(1)]);
        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        let (_helper_agg_span, mut agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        // Helper sent a transition with an unrecognized report ID. Simulate this by flipping the
        // first bit of the report ID.
        agg_job_resp.transitions[0].report_id.0[0] ^= 1;

        assert_matches!(
            t.consume_agg_job_resp_expect_err(leader_state, agg_job_resp),
            DapError::Abort(DapAbort::InvalidMessage { .. })
        );
    }

    test_versions! { agg_job_resp_abort_invalid_transition }

    #[test]
    fn finish_agg_job_vdaf_draft09() {
        let version = DapVersion::Draft09;
        let t = AggregationJobTest::new(TEST_VDAF_DRAFT09, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(0),
            DapMeasurement::U64(1),
        ]);

        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);

        let (leader_agg_span, helper_agg_span) = {
            let (helper_agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);
            let leader_agg_span = t.consume_agg_job_resp(leader_state, agg_job_resp);

            (leader_agg_span, helper_agg_span)
        };

        assert_eq!(leader_agg_span.report_count(), 5);
        let num_measurements = leader_agg_span.report_count();

        let VdafAggregateShare::Field64Draft09(leader_agg_share) =
            leader_agg_span.collapsed().data.unwrap()
        else {
            panic!("unexpected VdafAggregateShare variant")
        };

        let VdafAggregateShare::Field64Draft09(helper_agg_share) =
            helper_agg_span.collapsed().data.unwrap()
        else {
            panic!("unexpected VdafAggregateShare variant")
        };

        let vdaf = Prio3Draft09::new_count(2).unwrap();
        assert_eq!(
            vdaf.unshard(&(), [leader_agg_share, helper_agg_share], num_measurements,)
                .unwrap(),
            3,
        );
    }

    fn finish_agg_job(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let reports = t.produce_reports(vec![
            DapMeasurement::U64(1),
            DapMeasurement::U64(1),
            DapMeasurement::U64(0),
            DapMeasurement::U64(0),
            DapMeasurement::U64(1),
        ]);

        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);

        let (leader_agg_span, helper_agg_span) = {
            let (helper_agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);
            let leader_agg_span = t.consume_agg_job_resp(leader_state, agg_job_resp);

            (leader_agg_span, helper_agg_span)
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

    test_versions! { finish_agg_job }

    #[tokio::test]
    async fn agg_job_init_req_skip_vdaf_prep_error_draft09() {
        let t =
            AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, DapVersion::Draft09);
        let mut reports = t.produce_reports(vec![DapMeasurement::U64(1), DapMeasurement::U64(1)]);
        reports.insert(
            1,
            t.produce_invalid_report_vdaf_prep_failure(DapMeasurement::U64(1), DapVersion::Draft09),
        );

        let (leader_state, agg_job_init_req) =
            t.produce_agg_job_req(&DapAggregationParam::Empty, reports);
        let prep_init_ids = agg_job_init_req
            .prep_inits
            .iter()
            .map(|r| r.report_share.report_metadata.id)
            .collect::<Vec<_>>();
        let (helper_agg_span, agg_job_resp) = t.handle_agg_job_req(agg_job_init_req);

        assert_eq!(2, helper_agg_span.report_count());
        assert_eq!(3, agg_job_resp.transitions.len());
        for (transition, prep_init_id) in zip(&agg_job_resp.transitions, prep_init_ids) {
            assert_eq!(transition.report_id, prep_init_id);
        }

        let leader_agg_span = t.consume_agg_job_resp(leader_state, agg_job_resp);
        assert_eq!(leader_agg_span.report_count(), 2);
    }

    fn encrypted_agg_share(version: DapVersion) {
        let t = AggregationJobTest::new(TEST_VDAF, HpkeKemId::X25519HkdfSha256, version);
        let leader_agg_share = DapAggregateShare {
            report_count: 50,
            min_time: 1_637_359_200,
            max_time: 1_637_359_200,
            checksum: [0; 32],
            data: Some(VdafAggregateShare::Field64Draft09(
                AggregateShareDraft09::from(OutputShareDraft09::from(vec![Field64Draft09::from(
                    23,
                )])),
            )),
        };
        let helper_agg_share = DapAggregateShare {
            report_count: 50,
            min_time: 1_637_359_200,
            max_time: 1_637_359_200,
            checksum: [0; 32],
            data: Some(VdafAggregateShare::Field64Draft09(
                AggregateShareDraft09::from(OutputShareDraft09::from(vec![Field64Draft09::from(
                    9,
                )])),
            )),
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
        let agg_res = t.consume_encrypted_agg_shares(
            &batch_selector,
            50,
            &DapAggregationParam::Empty,
            vec![leader_encrypted_agg_share, helper_encrypted_agg_share],
        );

        assert_eq!(agg_res, DapAggregateResult::U64(32));
    }

    test_versions! { encrypted_agg_share }

    fn handle_unrecognized_report_extensions(version: DapVersion) {
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

        let [leader_share, _] = report.encrypted_input_shares;
        let report_metadata = report.report_metadata.clone();
        let initialized_report = InitializedReport::from_client(
            &t.leader_hpke_receiver_config,
            t.valid_report_time_range(),
            &t.task_id,
            &t.task_config,
            ReportShare {
                report_metadata: report.report_metadata,
                public_share: report.public_share,
                encrypted_input_share: leader_share,
            },
            &DapAggregationParam::Empty,
        )
        .unwrap();

        assert_eq!(initialized_report.metadata(), &report_metadata);

        // We're meant to reject reports containing unrecognized extensions.
        assert_matches!(initialized_report, InitializedReport::Rejected { .. });
    }

    test_versions! { handle_unrecognized_report_extensions }

    fn handle_repeated_report_extensions(version: DapVersion) {
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
        let [leader_share, _] = report.encrypted_input_shares;
        let initialized_report = InitializedReport::from_client(
            &t.leader_hpke_receiver_config,
            t.valid_report_time_range(),
            &t.task_id,
            &t.task_config,
            ReportShare {
                report_metadata: report.report_metadata,
                public_share: report.public_share,
                encrypted_input_share: leader_share,
            },
            &DapAggregationParam::Empty,
        )
        .unwrap();

        assert_eq!(initialized_report.metadata(), &report_metadata);
        assert_matches!(initialized_report, InitializedReport::Rejected { .. });
    }

    test_versions! { handle_repeated_report_extensions }

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
                .produce_input_shares(measurement, &report_id.0, &self.task_id)
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
                .produce_input_shares(measurement, &report_id.0, &self.task_id)
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
                .produce_input_shares(measurement, &report_id.0, &self.task_id)
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
