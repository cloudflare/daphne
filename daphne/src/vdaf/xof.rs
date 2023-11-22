// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use prio::vdaf::xof::{SeedStreamAes128, Xof};
use ring::hmac;

#[derive(Clone, Debug)]
pub struct XofHmacSha256Aes128(hmac::Context);

impl Xof<32> for XofHmacSha256Aes128 {
    type SeedStream = SeedStreamAes128;

    fn init(seed_bytes: &[u8; 32], dst: &[u8]) -> Self {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, seed_bytes);
        let mut hmac_context = hmac::Context::with_key(&hmac_key);
        hmac_context.update(&[dst.len().try_into().expect("dst must be at most 255 bytes")]);
        hmac_context.update(dst);
        Self(hmac_context)
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn into_seed_stream(self) -> SeedStreamAes128 {
        let hmac_tag = self.0.sign();
        let (key, iv) = hmac_tag.as_ref().split_at(16);
        SeedStreamAes128::new(key, iv)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use prio::{
        codec::Decode,
        field::Field128,
        vdaf::xof::{IntoFieldVec, Seed},
    };
    use rand_core::RngCore;
    use serde::{Deserialize, Serialize};

    // Cribbed from libprio-rs.
    #[derive(Deserialize, Serialize)]
    struct XofTestVector {
        #[serde(with = "hex")]
        seed: Vec<u8>,
        #[serde(with = "hex")]
        dst: Vec<u8>,
        #[serde(with = "hex")]
        binder: Vec<u8>,
        length: usize,
        #[serde(with = "hex")]
        derived_seed: Vec<u8>,
        #[serde(with = "hex")]
        expanded_vec_field128: Vec<u8>,
    }

    fn test_xof<P, const SEED_SIZE: usize>(t: &XofTestVector)
    where
        P: Xof<SEED_SIZE>,
    {
        // Run some basic functionality tests.
        {
            let seed = Seed::generate().unwrap();
            let dst = b"algorithm and usage";
            let binder = b"bind to artifact";

            let mut xof = P::init(seed.as_ref(), dst);
            xof.update(binder);

            let mut want = [0; SEED_SIZE];
            xof.clone().into_seed_stream().fill_bytes(&mut want);
            let got = xof.clone().into_seed();
            assert_eq!(got.as_ref(), &want);

            let mut want = [0; 45];
            xof.clone().into_seed_stream().fill_bytes(&mut want);
            let mut got = [0; 45];
            P::seed_stream(&seed, dst, binder).fill_bytes(&mut got);
            assert_eq!(got, want);
        }

        // Check test vectors.
        {
            let mut xof = P::init(&t.seed.clone().try_into().unwrap(), &t.dst);
            xof.update(&t.binder);
            assert_eq!(&xof.clone().into_seed().as_ref()[..], &t.derived_seed);

            let mut bytes = Cursor::new(t.expanded_vec_field128.as_slice());
            let mut want = Vec::with_capacity(t.length);
            while usize::try_from(bytes.position()).unwrap() < t.expanded_vec_field128.len() {
                want.push(Field128::decode(&mut bytes).unwrap());
            }
            let got: Vec<Field128> = xof.clone().into_seed_stream().into_field_vec(t.length);
            assert_eq!(got, want);
        }
    }

    #[test]
    fn xof_hmac_sha256_aes128() {
        test_xof::<XofHmacSha256Aes128, 32>(
            &serde_json::from_str(include_str!("test_vec/XofHmacSha256Aes128.json")).unwrap(),
        );
    }
}
