// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use daphne::pine::Pine;
use prio::{
    field::random_vector,
    flp::Type,
    vdaf::{xof::Seed, Aggregator, Client},
};

fn pine(c: &mut Criterion) {
    for (dimension, chunk_len) in [
        // dimension, sqrt(dimension) * some multiplier
        (200_000, 448),
    ] {
        let pine = Pine::new_32(1 << 15, dimension, 15, chunk_len).unwrap();
        let measurement = vec![0.0; dimension];
        let wr_joint_rand_seed = Seed::generate().unwrap();
        let nonce = [0; 16];
        let verify_key = [0; 32];

        {
            let mut meas = Vec::new();
            pine.flp
                .append_encoded_gradient(&mut meas, measurement.iter().copied())
                .unwrap();
            let wr_joint_rand_seed = Seed::generate().unwrap();

            c.bench_with_input(
                BenchmarkId::new("pine/fast_run_wr_tests", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        pine.flp
                            .fast_run_wr_tests(&meas[..dimension], &wr_joint_rand_seed);
                    });
                },
            );

            c.bench_with_input(
                BenchmarkId::new("pine/run_wr_tests", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        pine.flp
                            .run_wr_tests(&meas[..dimension], &wr_joint_rand_seed);
                    });
                },
            );
        }

        c.bench_with_input(
            BenchmarkId::new("pine/encode", dimension),
            &dimension,
            |b, &_d| {
                b.iter(|| {
                    pine.flp
                        .encode_with_wr_joint_rand(measurement.iter().copied(), &wr_joint_rand_seed)
                        .unwrap()
                });
            },
        );

        {
            let (mut input, wr_test_results) = pine
                .flp
                .encode_with_wr_joint_rand(measurement.iter().copied(), &wr_joint_rand_seed)
                .unwrap();
            input.extend_from_slice(&wr_test_results);
            let joint_rand =
                random_vector(pine.flp_sq_norm_equality_check.joint_rand_len()).unwrap();
            let prove_rand =
                random_vector(pine.flp_sq_norm_equality_check.prove_rand_len()).unwrap();

            c.bench_with_input(
                BenchmarkId::new("pine/prove_sq_norm_equality", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        pine.flp_sq_norm_equality_check
                            .prove(&input, &prove_rand, &joint_rand)
                            .unwrap()
                    });
                },
            );

            let query_rand =
                random_vector(pine.flp_sq_norm_equality_check.query_rand_len()).unwrap();
            let proof = pine
                .flp_sq_norm_equality_check
                .prove(&input, &prove_rand, &joint_rand)
                .unwrap();

            c.bench_with_input(
                BenchmarkId::new("pine/query_sq_norm_equality", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        pine.flp_sq_norm_equality_check
                            .query(&input, &proof, &query_rand, &joint_rand, 1)
                            .unwrap()
                    });
                },
            );
        }

        let (mut input, wr_test_results) = pine
            .flp
            .encode_with_wr_joint_rand(measurement.iter().copied(), &wr_joint_rand_seed)
            .unwrap();
        input.extend_from_slice(&wr_test_results);
        let joint_rand = random_vector(pine.flp.joint_rand_len()).unwrap();
        let prove_rand = random_vector(pine.flp.prove_rand_len()).unwrap();

        c.bench_with_input(
            BenchmarkId::new("pine/prove", dimension),
            &dimension,
            |b, &_d| {
                b.iter(|| pine.flp.prove(&input, &prove_rand, &joint_rand).unwrap());
            },
        );

        let query_rand = random_vector(pine.flp.query_rand_len()).unwrap();
        let proof = pine.flp.prove(&input, &prove_rand, &joint_rand).unwrap();

        c.bench_with_input(
            BenchmarkId::new("pine/query", dimension),
            &dimension,
            |b, &_d| {
                b.iter(|| {
                    pine.flp
                        .query(&input, &proof, &query_rand, &joint_rand, 1)
                        .unwrap()
                });
            },
        );

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
