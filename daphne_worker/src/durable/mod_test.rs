// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::durable::{
    durable_name_agg_store, durable_name_queue, durable_name_report_store, nonce_hex_from_report,
};
use daphne::{
    messages::{Id, Nonce, Report, ReportMetadata},
    DapBatchBucket, DapVersion,
};
use prio::codec::{Decode, Encode};
use rand::prelude::*;

#[test]
fn durable_name() {
    let time = 1664850074;
    let id1 = Id([17; 32]);
    let id2 = Id([34; 32]);
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

// Test that the `report_id_from_report()` method properly extracts the nonce from the hex-encoded
// report. This helps ensure that changes to the `Report` wire format don't cause any regressions
// to `ReportStore`.
#[test]
fn parse_nonce_hex_from_report() {
    let mut rng = thread_rng();
    let report = Report {
        task_id: Id(rng.gen()),
        metadata: ReportMetadata {
            time: rng.gen(),
            nonce: Nonce(rng.gen()),
            extensions: Vec::default(),
        },
        public_share: Vec::default(),
        encrypted_input_shares: Vec::default(),
    };

    let report_hex = hex::encode(report.get_encoded());
    let key = nonce_hex_from_report(&report_hex).unwrap();
    assert_eq!(
        Nonce::get_decoded(&hex::decode(key).unwrap()).unwrap(),
        report.metadata.nonce
    );
}
