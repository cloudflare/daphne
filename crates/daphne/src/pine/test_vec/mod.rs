// Copyright (c) 2024 Cloudflare, Inc.

//! Tools for evaluating PINE test vectors.

use prio::{
    codec::Encode,
    field::FftFriendlyFieldElement,
    vdaf::{xof::XofTurboShake128, Aggregator, Collector, PrepareTransition},
};
use serde::Deserialize;

use crate::pine::{Pine, ALPHA, NUM_WR_SUCCESSES, NUM_WR_TESTS};

#[derive(Deserialize)]
struct Encoded(#[serde(with = "hex")] Vec<u8>);

impl AsRef<[u8]> for Encoded {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Deserialize)]
struct TestVecPrep {
    rand: Encoded,
    nonce: Encoded,
    measurement: Vec<f64>,
    public_share: Encoded,
    input_shares: Vec<Encoded>,
    prep_shares: Vec<Vec<Encoded>>,
    prep_messages: Vec<Encoded>,
    out_shares: Vec<Vec<Encoded>>,
}

#[derive(Deserialize)]
struct TestVec {
    // Parameters
    num_wr_checks: usize,
    num_wr_successes: usize,
    alpha: f64,
    dimension: usize,
    l2_norm_bound: u64,
    num_frac_bits: usize,
    chunk_length: usize,
    chunk_length_norm_equality: usize,
    shares: usize,
    proofs: usize,

    // Execution
    verify_key: Encoded,
    #[serde(rename = "prep")]
    reports: Vec<TestVecPrep>,
    agg_shares: Vec<Encoded>,
    agg_result: Vec<f64>,
}

impl<F: FftFriendlyFieldElement> Pine<F, XofTurboShake128, 16> {
    fn run_test_vec(&self, test_vec: &TestVec) {
        // Check that the test vector parameters have the values we expect.
        //
        // clippy: These are test vectors, so we expect the value to match precisely.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(test_vec.alpha, ALPHA);
        }
        assert_eq!(test_vec.num_wr_checks, NUM_WR_TESTS);
        assert_eq!(test_vec.num_wr_successes, NUM_WR_SUCCESSES);
        assert_eq!(test_vec.shares, 2);
        assert_eq!(test_vec.proofs, usize::from(self.flp.cfg.num_proofs));

        let mut out_shares_0 = Vec::new();
        let mut out_shares_1 = Vec::new();
        let verify_key = <[u8; 16]>::try_from(test_vec.verify_key.as_ref()).unwrap();
        for report in &test_vec.reports {
            let rand = report
                .rand
                .as_ref()
                .chunks(16)
                .map(|seed| <[u8; 16]>::try_from(seed).unwrap())
                .take(7)
                .collect::<Vec<_>>();
            let nonce = <[u8; 16]>::try_from(report.nonce.as_ref()).unwrap();

            // Sharding
            let (public_share, input_shares) = self
                .shard_with_rand(&report.measurement, &nonce, rand.try_into().unwrap())
                .unwrap();
            assert_eq!(
                public_share.get_encoded().unwrap(),
                report.public_share.as_ref(),
                "public share",
            );
            assert_eq!(
                input_shares[0].get_encoded().unwrap(),
                report.input_shares[0].as_ref(),
                "input share 0",
            );
            assert_eq!(
                input_shares[1].get_encoded().unwrap(),
                report.input_shares[1].as_ref(),
                "input share 1",
            );

            // Preparation
            let (prep_state_0, prep_share_0) = self
                .prepare_init(&verify_key, 0, &(), &nonce, &public_share, &input_shares[0])
                .unwrap();
            assert_eq!(
                prep_share_0.get_encoded().unwrap(),
                report.prep_shares[0][0].as_ref(),
                "prep share 0",
            );

            let (prep_state_1, prep_share_1) = self
                .prepare_init(&verify_key, 1, &(), &nonce, &public_share, &input_shares[1])
                .unwrap();
            assert_eq!(
                prep_share_1.get_encoded().unwrap(),
                report.prep_shares[0][1].as_ref(),
                "prep share 1",
            );

            let prep = self
                .prepare_shares_to_prepare_message(&(), [prep_share_0, prep_share_1])
                .unwrap();
            assert_eq!(
                prep.get_encoded().unwrap(),
                report.prep_messages[0].as_ref(),
                "prep",
            );

            let PrepareTransition::Finish(out_share_0) =
                self.prepare_next(prep_state_0, prep.clone()).unwrap()
            else {
                panic!("unexpected transition");
            };
            assert_eq!(out_share_0.0.len(), report.out_shares[0].len());
            for (got, want) in out_share_0.0.iter().zip(report.out_shares[0].iter()) {
                assert_eq!(got.get_encoded().unwrap(), want.as_ref());
            }
            out_shares_0.push(out_share_0);

            let PrepareTransition::Finish(out_share_1) =
                self.prepare_next(prep_state_1, prep.clone()).unwrap()
            else {
                panic!("unexpected transition");
            };
            assert_eq!(out_share_1.0.len(), report.out_shares[1].len());
            for (got, want) in out_share_1.0.iter().zip(report.out_shares[1].iter()) {
                assert_eq!(got.get_encoded().unwrap(), want.as_ref());
            }
            out_shares_1.push(out_share_1);
        }

        // Aggregation
        let agg_share_0 = self.aggregate(&(), out_shares_0).unwrap();
        assert_eq!(
            agg_share_0.get_encoded().unwrap(),
            test_vec.agg_shares[0].as_ref()
        );

        let agg_share_1 = self.aggregate(&(), out_shares_1).unwrap();
        assert_eq!(
            agg_share_1.get_encoded().unwrap(),
            test_vec.agg_shares[1].as_ref()
        );

        // Unsharding
        let agg_result = self
            .unshard(&(), [agg_share_0, agg_share_1], test_vec.reports.len())
            .unwrap();
        assert_eq!(agg_result, test_vec.agg_result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pine::Pine;

    #[test]
    fn run_64() {
        let test_vec = serde_json::from_str::<TestVec>(include_str!("01/Pine64_0.json")).unwrap();
        Pine::new_64(
            test_vec.l2_norm_bound,
            test_vec.dimension,
            test_vec.num_frac_bits,
            test_vec.chunk_length,
            test_vec.chunk_length_norm_equality,
        )
        .unwrap()
        .run_test_vec(&test_vec);
    }

    #[test]
    fn run_128() {
        let test_vec = serde_json::from_str::<TestVec>(include_str!("01/Pine128_0.json")).unwrap();
        Pine::new_128(
            test_vec.l2_norm_bound,
            test_vec.dimension,
            test_vec.num_frac_bits,
            test_vec.chunk_length,
            test_vec.chunk_length_norm_equality,
        )
        .unwrap()
        .run_test_vec(&test_vec);
    }
}
