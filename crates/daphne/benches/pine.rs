// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use daphne::pine::Pine;
use prio::{
    field::random_vector,
    flp::Type,
    vdaf::{
        xof::{Seed, XofTurboShake128},
        Aggregator, Client,
    },
};

fn pine(c: &mut Criterion) {
    // NOTE We ignore this clippy warning because we may want to benchmark more parameters later.
    #[expect(clippy::single_element_loop)]
    for (dimension, chunk_len, chunk_len_sq_norm_equal) in [(200_000, 150 * 2, 447 * 18)] {
        let pine =
            Pine::new_64(1 << 15, dimension, 15, chunk_len, chunk_len_sq_norm_equal).unwrap();
        let measurement = vec![0.0; dimension];
        let wr_joint_rand_seed = Seed::generate().unwrap();
        let nonce = [0; 16];
        let verify_key = [0; 16];

        c.bench_with_input(
            BenchmarkId::new("pine/encode", dimension),
            &dimension,
            |b, &_d| {
                b.iter(|| {
                    pine.flp
                        .encode_with_wr_joint_rand::<XofTurboShake128, 16>(
                            measurement.iter().copied(),
                            &wr_joint_rand_seed,
                        )
                        .unwrap()
                });
            },
        );

        {
            let (mut input, wr_test_results) = pine
                .flp
                .encode_with_wr_joint_rand::<XofTurboShake128, 16>(
                    measurement.iter().copied(),
                    &wr_joint_rand_seed,
                )
                .unwrap();
            input.extend_from_slice(&wr_test_results);
            let prove_rand = random_vector(pine.flp_sq_norm_equal.prove_rand_len()).unwrap();

            c.bench_with_input(
                BenchmarkId::new("pine/prove", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        pine.flp_sq_norm_equal
                            .prove(&input, &prove_rand, &[])
                            .unwrap()
                    });
                },
            );

            let query_rand = random_vector(pine.flp_sq_norm_equal.query_rand_len()).unwrap();
            let proof = pine
                .flp_sq_norm_equal
                .prove(&input, &prove_rand, &[])
                .unwrap();

            c.bench_with_input(
                BenchmarkId::new("pine/query", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        pine.flp_sq_norm_equal
                            .query(&input, &proof, &query_rand, &[], 1)
                            .unwrap()
                    });
                },
            );
        }

        c.bench_with_input(
            BenchmarkId::new("pine/shard", dimension),
            &dimension,
            |b, &_d| {
                b.iter(|| pine.shard(&measurement, &nonce).unwrap());
            },
        );

        let (public_share, input_shares) = pine.shard(&measurement, &nonce).unwrap();

        c.bench_with_input(
            BenchmarkId::new("pine/prep_init", dimension),
            &dimension,
            |b, &_d| {
                b.iter(|| {
                    pine.prepare_init(&verify_key, 1, &(), &nonce, &public_share, &input_shares[1])
                });
            },
        );
    }
}

criterion_group!(benches, pine);
criterion_main!(benches);
