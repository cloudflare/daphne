// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use daphne::{
    hpke::HpkeKemId, testing::AggregationJobTest, DapLeaderTransition, DapMeasurement, DapVersion,
    Prio3Config, VdafConfig,
};

fn handle_agg_job_init_req(c: &mut Criterion) {
    let batch_size = 10;
    let dimension = 100_000;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    for (vdaf, measurement) in [
        (
            VdafConfig::Prio3(Prio3Config::SumVec {
                bits: 1,
                len: dimension,
            }),
            DapMeasurement::U128Vec(vec![1; dimension]),
        ),
        (
            VdafConfig::Prio2 { dimension },
            DapMeasurement::U32Vec(vec![1; dimension]),
        ),
    ]
    .into_iter()
    {
        let agg_job_test =
            AggregationJobTest::new(&vdaf, HpkeKemId::X25519HkdfSha256, DapVersion::Draft02);

        let agg_job_init_req = rt.block_on(async {
            let reports = agg_job_test.produce_reports(vec![measurement; batch_size]);
            let DapLeaderTransition::Continue(_leader_state, agg_job_init_req) =
                agg_job_test.produce_agg_job_init_req(reports).await
            else {
                panic!("unexpected transition");
            };
            agg_job_init_req
        });

        c.bench_function(&format!("handle_agg_job_init_req {vdaf:?}"), |b| {
            b.to_async(&rt).iter(|| async {
                black_box(agg_job_test.handle_agg_job_init_req(&agg_job_init_req)).await
            })
        });
    }
}

criterion_group!(benches, handle_agg_job_init_req);
criterion_main!(benches);
