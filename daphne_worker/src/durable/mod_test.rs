// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::durable::{
    durable_name_agg_store, durable_name_queue, durable_name_report_store,
    reports_pending::PendingReport,
};
use daphne::{
    messages::{BatchId, HpkeCiphertext, Report, ReportId, ReportMetadata, TaskId},
    test_version, test_versions, DapBatchBucket, DapVersion,
};
use paste::paste;
use prio::codec::{ParameterizedDecode, ParameterizedEncode};
use rand::prelude::*;

#[test]
fn durable_name() {
    let time = 1664850074;
    let id1 = TaskId([17; 32]);
    let id2 = BatchId([34; 32]);
    let shard = 1234;

    assert_eq!(durable_name_queue(shard), "queue/1234");

    assert_eq!(
        durable_name_report_store(&DapVersion::Draft02, &id1.to_hex(), time, shard),
        "v02/task/1111111111111111111111111111111111111111111111111111111111111111/epoch/00000000001664850074/shard/1234",
    );

    assert_eq!(
        durable_name_agg_store(&DapVersion::Draft02, &id1.to_hex(), &DapBatchBucket::FixedSize{ batch_id: &id2 }),
        "v02/task/1111111111111111111111111111111111111111111111111111111111111111/batch/2222222222222222222222222222222222222222222222222222222222222222",
    );

    assert_eq!(
        durable_name_agg_store(&DapVersion::Draft02, &id1.to_hex(), &DapBatchBucket::TimeInterval{ batch_window: time }),
        "v02/task/1111111111111111111111111111111111111111111111111111111111111111/window/1664850074",
    );
}

// Test that the `PendingReport.report_id_hex()` method properly extracts the report ID from the
// hex-encoded report. This helps ensure that changes to the `Report` wire format don't cause any
// regressions to `ReportStore`.
fn parse_report_id_hex_from_report(version: DapVersion) {
    let mut rng = thread_rng();
    let task_id = TaskId([17; 32]);
    let report = Report {
        draft02_task_id: task_id.for_request_payload(&version),
        report_metadata: ReportMetadata {
            id: ReportId(rng.gen()),
            time: rng.gen(),
            extensions: Vec::default(),
        },
        public_share: Vec::default(),
        encrypted_input_shares: vec![
            HpkeCiphertext {
                config_id: rng.gen(),
                enc: b"encapsulated key".to_vec(),
                payload: b"ciphertext".to_vec(),
            },
            HpkeCiphertext {
                config_id: rng.gen(),
                enc: b"encapsulated key".to_vec(),
                payload: b"ciphertext".to_vec(),
            },
        ],
    };

    let pending_report = PendingReport {
        task_id,
        version,
        report_hex: hex::encode(report.get_encoded_with_param(&version)),
    };

    let got = ReportId::get_decoded_with_param(
        &version,
        &hex::decode(
            pending_report
                .report_id_hex()
                .expect("report_id_hex() failed"),
        )
        .expect("hex::decode() failed"),
    )
    .expect("ReportId::get_decoded_with_param() failed");
    assert_eq!(got, report.report_metadata.id);
}

test_versions! {parse_report_id_hex_from_report}
