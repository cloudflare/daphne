// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::durable::report_store::nonce_hex_from_report;
use daphne::messages::{Id, Nonce, Report, ReportMetadata};
use prio::codec::{Decode, Encode};
use rand::prelude::*;

// Test that the `nonce_hex_from_report()` method properly extracts the nonce from the hex-encoded
// report. This helps ensure that changes to the `Report` wire format don't cause any regressions
// to `ReportStore`.
#[test]
fn test_nonce_hex_from_report() {
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
