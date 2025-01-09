// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use prio::{
    field::Field64,
    flp::{
        gadgets::{Mul, ParallelSum},
        types::SumVec,
    },
    vdaf::{prio2::Prio2, prio3::Prio3, xof::XofHmacSha256Aes128, Aggregator, Client},
};

fn count_vec(c: &mut Criterion) {
    for dimension in [100, 1_000, 10_000, 100_000] {
        let nonce = [0; 16];
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        let chunk_length = (dimension as f64).sqrt() as usize; // asymptotically optimal

        // Prio2
        {
            let prio2 = Prio2::new(dimension).unwrap();
            let verify_key = [0; 32];
            let measurement = vec![0; dimension];
            c.bench_with_input(
                BenchmarkId::new("Prio2/shard", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| prio2.shard(&measurement, &nonce).unwrap());
                },
            );

            let (public_share, input_shares) = prio2.shard(&measurement, &nonce).unwrap();

            c.bench_with_input(
                BenchmarkId::new("Prio2/prep_init", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        prio2.prepare_init(
                            &verify_key,
                            1,
                            &(),
                            &nonce,
                            &public_share,
                            &input_shares[1],
                        )
                    });
                },
            );
        }

        // Prio3SumVec
        {
            let prio3 = Prio3::new_sum_vec(2, 1, dimension, chunk_length).unwrap();
            let verify_key = [0; 16];
            let measurement = vec![0; dimension];
            c.bench_with_input(
                BenchmarkId::new("Prio3SumVec/shard", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| prio3.shard(&measurement, &nonce).unwrap());
                },
            );

            let (public_share, input_shares) = prio3.shard(&measurement, &nonce).unwrap();

            c.bench_with_input(
                BenchmarkId::new("Prio3SumVec/prep_init", dimension),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        prio3.prepare_init(
                            &verify_key,
                            1,
                            &(),
                            &nonce,
                            &public_share,
                            &input_shares[1],
                        )
                    });
                },
            );
        }

        // Prio3SumVecField64MultiproofHmacSha256Aes128
        {
            type Prio3SumVecField64MultiproofHmacSha256Aes128 =
                Prio3<SumVec<Field64, ParallelSum<Field64, Mul<Field64>>>, XofHmacSha256Aes128, 32>;
            let typ = SumVec::new(1, dimension, chunk_length).unwrap();
            let alg_id = 0; // arbitrary algorithm ID
            let prio3 =
                Prio3SumVecField64MultiproofHmacSha256Aes128::new(2, 3, alg_id, typ).unwrap();

            let verify_key = [0; 32];
            let measurement = vec![0; dimension];
            c.bench_with_input(
                BenchmarkId::new(
                    "Prio3SumVecField64MultiproofHmacSha256Aes128/shard",
                    dimension,
                ),
                &dimension,
                |b, &_d| {
                    b.iter(|| prio3.shard(&measurement, &nonce).unwrap());
                },
            );

            let (public_share, input_shares) = prio3.shard(&measurement, &nonce).unwrap();

            c.bench_with_input(
                BenchmarkId::new(
                    "Prio3SumVecField64MultiproofHmacSha256Aes128/prep_init",
                    dimension,
                ),
                &dimension,
                |b, &_d| {
                    b.iter(|| {
                        prio3.prepare_init(
                            &verify_key,
                            1,
                            &(),
                            &nonce,
                            &public_share,
                            &input_shares[1],
                        )
                    });
                },
            );
        }
    }
}

criterion_group!(benches, count_vec);
criterion_main!(benches);
