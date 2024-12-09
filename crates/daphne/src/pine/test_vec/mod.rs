// Copyright (c) 2024 Cloudflare, Inc.

//! Tools for evaluating PINE test vectors.

use crate::messages::taskprov::{
    VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128, VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128,
};
use crate::pine::{Pine, PineParam, ALPHA};
use prio_09::{
    codec::Encode,
    field::{FftFriendlyFieldElement, Field128, Field64},
    vdaf::{
        xof::{Xof, XofTurboShake128},
        Aggregator, Collector, PrepareTransition,
    },
};
use prio_09::{field::FieldPrio2, vdaf::xof::XofHmacSha256Aes128};
use serde::Deserialize;

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
    proofs: u8,
    proofs_norm_equality: u8,

    // Execution
    verify_key: Encoded,
    #[serde(rename = "prep")]
    reports: Vec<TestVecPrep>,
    agg_shares: Vec<Encoded>,
    agg_result: Vec<f64>,
}

impl TestVec {
    fn from_str(test_vec_str: &str) -> Self {
        serde_json::from_str(test_vec_str).unwrap()
    }

    fn run<F: FftFriendlyFieldElement, X: Xof<SEED_SIZE>, const SEED_SIZE: usize>(
        &self,
        alg_id: u32,
    ) {
        let pine = Pine::<F, X, SEED_SIZE>::new(
            &PineParam {
                norm_bound: self.l2_norm_bound,
                dimension: self.dimension,
                frac_bits: self.num_frac_bits,
                chunk_len: self.chunk_length,
                chunk_len_sq_norm_equal: self.chunk_length_norm_equality,
                num_proofs: self.proofs,
                num_proofs_sq_norm_equal: self.proofs_norm_equality,
                num_wr_tests: self.num_wr_checks,
                num_wr_successes: self.num_wr_successes,
            },
            alg_id,
        )
        .unwrap();

        // Check that the test vector parameters have the values we expect.
        //
        // clippy: These are test vectors, so we expect the value to match precisely.
        #[expect(clippy::float_cmp)]
        {
            assert_eq!(self.alpha, ALPHA);
        }
        assert_eq!(self.shares, 2);

        let mut out_shares_0 = Vec::new();
        let mut out_shares_1 = Vec::new();
        let verify_key = <[u8; SEED_SIZE]>::try_from(self.verify_key.as_ref()).unwrap();
        for report in &self.reports {
            let rand = report
                .rand
                .as_ref()
                .chunks(SEED_SIZE)
                .map(|seed| <[u8; SEED_SIZE]>::try_from(seed).unwrap())
                .take(7)
                .collect::<Vec<_>>();
            let nonce = <[u8; 16]>::try_from(report.nonce.as_ref()).unwrap();

            // Sharding
            let (public_share, input_shares) = pine
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
            let (prep_state_0, prep_share_0) = pine
                .prepare_init(&verify_key, 0, &(), &nonce, &public_share, &input_shares[0])
                .unwrap();
            assert_eq!(
                prep_share_0.get_encoded().unwrap(),
                report.prep_shares[0][0].as_ref(),
                "prep share 0",
            );

            let (prep_state_1, prep_share_1) = pine
                .prepare_init(&verify_key, 1, &(), &nonce, &public_share, &input_shares[1])
                .unwrap();
            assert_eq!(
                prep_share_1.get_encoded().unwrap(),
                report.prep_shares[0][1].as_ref(),
                "prep share 1",
            );

            let prep = pine
                .prepare_shares_to_prepare_message(&(), [prep_share_0, prep_share_1])
                .unwrap();
            assert_eq!(
                prep.get_encoded().unwrap(),
                report.prep_messages[0].as_ref(),
                "prep",
            );

            let PrepareTransition::Finish(out_share_0) =
                pine.prepare_next(prep_state_0, prep.clone()).unwrap()
            else {
                panic!("unexpected transition");
            };
            assert_eq!(out_share_0.0.len(), report.out_shares[0].len());
            for (got, want) in out_share_0.0.iter().zip(report.out_shares[0].iter()) {
                assert_eq!(got.get_encoded().unwrap(), want.as_ref());
            }
            out_shares_0.push(out_share_0);

            let PrepareTransition::Finish(out_share_1) =
                pine.prepare_next(prep_state_1, prep.clone()).unwrap()
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
        let agg_share_0 = pine.aggregate(&(), out_shares_0).unwrap();
        assert_eq!(
            agg_share_0.get_encoded().unwrap(),
            self.agg_shares[0].as_ref()
        );

        let agg_share_1 = pine.aggregate(&(), out_shares_1).unwrap();
        assert_eq!(
            agg_share_1.get_encoded().unwrap(),
            self.agg_shares[1].as_ref()
        );

        // Unsharding
        let agg_result = pine
            .unshard(&(), [agg_share_0, agg_share_1], self.reports.len())
            .unwrap();
        assert_eq!(agg_result, self.agg_result);
    }
}

const PINE_TEST: u32 = 0xffff_ffff;

#[test]
fn pine64_0() {
    TestVec::from_str(include_str!("01/Pine64_0.json"))
        .run::<Field64, XofTurboShake128, 16>(PINE_TEST);
}

#[test]
fn pine64_1() {
    TestVec::from_str(include_str!("01/Pine64_1.json"))
        .run::<Field64, XofTurboShake128, 16>(PINE_TEST);
}

#[test]
fn pine64_2() {
    TestVec::from_str(include_str!("01/Pine64_2.json"))
        .run::<Field64, XofTurboShake128, 16>(PINE_TEST);
}

#[test]
fn pine64_3() {
    TestVec::from_str(include_str!("01/Pine64_3.json"))
        .run::<Field64, XofTurboShake128, 16>(PINE_TEST);
}

#[test]
fn pine128_0() {
    TestVec::from_str(include_str!("01/Pine128_0.json"))
        .run::<Field128, XofTurboShake128, 16>(PINE_TEST);
}

#[test]
fn pine128_1() {
    TestVec::from_str(include_str!("01/Pine128_1.json"))
        .run::<Field128, XofTurboShake128, 16>(PINE_TEST);
}

#[test]
fn pine128_2() {
    TestVec::from_str(include_str!("01/Pine128_2.json"))
        .run::<Field128, XofTurboShake128, 16>(PINE_TEST);
}

#[test]
fn pine128_3() {
    TestVec::from_str(include_str!("01/Pine128_3.json"))
        .run::<Field128, XofTurboShake128, 16>(PINE_TEST);
}

#[test]
fn pine32_hmac_sha256_aes128_0() {
    TestVec::from_str(include_str!("01/Pine32HmacSha256Aes128_0.json"))
        .run::<FieldPrio2, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128);
}

#[test]
fn pine32_hmac_sha256_aes128_1() {
    TestVec::from_str(include_str!("01/Pine32HmacSha256Aes128_1.json"))
        .run::<FieldPrio2, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128);
}

#[test]
fn pine32_hmac_sha256_aes128_2() {
    TestVec::from_str(include_str!("01/Pine32HmacSha256Aes128_2.json"))
        .run::<FieldPrio2, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128);
}

#[test]
fn pine32_hmac_sha256_aes128_3() {
    TestVec::from_str(include_str!("01/Pine32HmacSha256Aes128_3.json"))
        .run::<FieldPrio2, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128);
}

#[test]
fn pine32_hmac_sha256_aes128_4() {
    TestVec::from_str(include_str!("01/Pine32HmacSha256Aes128_4.json"))
        .run::<FieldPrio2, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128);
}

#[test]
fn pine32_hmac_sha256_aes128_5() {
    TestVec::from_str(include_str!("01/Pine32HmacSha256Aes128_5.json"))
        .run::<FieldPrio2, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128);
}

#[test]
fn pine32_hmac_sha256_aes128_6() {
    TestVec::from_str(include_str!("01/Pine32HmacSha256Aes128_6.json"))
        .run::<FieldPrio2, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128);
}

#[test]
fn pine32_hmac_sha256_aes128_7() {
    TestVec::from_str(include_str!("01/Pine32HmacSha256Aes128_7.json"))
        .run::<FieldPrio2, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD32_HMAC_SHA256_AES128);
}

#[test]
fn pine64_hmac_sha256_aes128_0() {
    TestVec::from_str(include_str!("01/Pine64HmacSha256Aes128_0.json"))
        .run::<Field64, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128);
}

#[test]
fn pine64_hmac_sha256_aes128_1() {
    TestVec::from_str(include_str!("01/Pine64HmacSha256Aes128_1.json"))
        .run::<Field64, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128);
}

#[test]
fn pine64_hmac_sha256_aes128_2() {
    TestVec::from_str(include_str!("01/Pine64HmacSha256Aes128_2.json"))
        .run::<Field64, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128);
}

#[test]
fn pine64_hmac_sha256_aes128_3() {
    TestVec::from_str(include_str!("01/Pine64HmacSha256Aes128_3.json"))
        .run::<Field64, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128);
}

#[test]
fn pine64_hmac_sha256_aes128_4() {
    TestVec::from_str(include_str!("01/Pine64HmacSha256Aes128_4.json"))
        .run::<Field64, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128);
}

#[test]
fn pine64_hmac_sha256_aes128_5() {
    TestVec::from_str(include_str!("01/Pine64HmacSha256Aes128_5.json"))
        .run::<Field64, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128);
}

#[test]
fn pine64_hmac_sha256_aes128_6() {
    TestVec::from_str(include_str!("01/Pine64HmacSha256Aes128_6.json"))
        .run::<Field64, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128);
}

#[test]
fn pine64_hmac_sha256_aes128_7() {
    TestVec::from_str(include_str!("01/Pine64HmacSha256Aes128_7.json"))
        .run::<Field64, XofHmacSha256Aes128, 32>(VDAF_TYPE_PINE_FIELD64_HMAC_SHA256_AES128);
}
