// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(clippy::cast_possible_truncation)]

use std::{
    hint::black_box,
    iter::repeat,
    time::{Duration, Instant},
};

use criterion::{criterion_group, criterion_main, Bencher, BenchmarkId, Criterion, Throughput};
use daphne::{
    hpke::HpkeKemId,
    messages::AggregationJobInitReq,
    testing::AggregationJobTest,
    vdaf::{Prio3Config, VdafConfig},
    DapAggregationParam, DapVersion,
};

macro_rules! function {
    () => {{
        fn f() {}
        let name = std::any::type_name_of_val(&f);

        // Find and cut the rest of the path
        match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        }
    }};
}

fn consume_reports_vary_vdaf_dimension(c: &mut Criterion) {
    const NUM_REPORTS: u64 = 1000;
    let vdaf_lengths = [10, 100, 1_000, 10_000, 100_000];
    let mut test = AggregationJobTest::new(
        &VdafConfig::Prio2 { dimension: 0 },
        HpkeKemId::P256HkdfSha256,
        DapVersion::Latest,
    );
    test.disable_replay_protection();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut g = c.benchmark_group(function!());
    for vdaf_length in vdaf_lengths {
        let vdaf = VdafConfig::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            bits: 1,
            length: vdaf_length,
            chunk_length: 320,
            num_proofs: 2,
        });
        test.change_vdaf(vdaf);
        let reports = test
            .produce_repeated_reports(vdaf.gen_measurement().unwrap())
            .take(NUM_REPORTS as _);

        let (_, init) =
            runtime.block_on(test.produce_agg_job_req(&DapAggregationParam::Empty, reports));

        g.throughput(Throughput::Bytes(vdaf_length as _));
        g.bench_with_input(
            BenchmarkId::new("consume_agg_job_req", vdaf_length),
            &init,
            |b, init| bench(b, &test, init),
        );
    }
}

fn consume_reports_vary_num_reports(c: &mut Criterion) {
    const VDAF: VdafConfig =
        VdafConfig::Prio3(Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            bits: 1,
            length: 1000,
            chunk_length: 320,
            num_proofs: 2,
        });

    let mut test = AggregationJobTest::new(&VDAF, HpkeKemId::P256HkdfSha256, DapVersion::Latest);
    test.disable_replay_protection();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let mut g = c.benchmark_group(function!());
    for report_counts in [10, 100, 1_000, 10_000] {
        let reports = test
            .produce_repeated_reports(VDAF.gen_measurement().unwrap())
            .take(report_counts);

        let (_, init) =
            runtime.block_on(test.produce_agg_job_req(&DapAggregationParam::Empty, reports));

        g.throughput(Throughput::Elements(report_counts as _));
        g.bench_with_input(
            BenchmarkId::new("consume_agg_job_req", report_counts),
            &init,
            |b, init| bench(b, &test, init),
        );
    }
}

fn bench(b: &mut Bencher, test: &AggregationJobTest, init: &AggregationJobInitReq) {
    b.iter_custom(|iters| {
        let mut total = Duration::ZERO;
        for init in repeat(init).take(iters as _).cloned() {
            let now = Instant::now();
            let ret = black_box(test.handle_agg_job_req(init));
            total += now.elapsed();
            drop(ret);
        }
        total
    });
}

criterion_group!(
    benches,
    consume_reports_vary_num_reports,
    consume_reports_vary_vdaf_dimension
);
criterion_main!(benches);
