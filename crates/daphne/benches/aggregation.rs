// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::time::{Duration, Instant, SystemTime};

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use daphne::{
    auth::BearerToken,
    hpke::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId, HpkeReceiverConfig},
    messages::{BatchId, TaskId},
    roles::{helper, DapAggregator},
    testing::{report_generator::ReportGenerator, InMemoryAggregator},
    vdaf::{VdafConfig, VdafVerifyKey},
    DapRequest, DapTaskConfig, DapVersion,
};
use hpke_rs::HpkePublicKey;
use prio::codec::ParameterizedEncode;
use rand::{thread_rng, Rng};

const VERSION: DapVersion = DapVersion::Draft09;
const VERIFY_KEY: [u8; 32] = [0; 32];

fn aggregate(c: &mut Criterion) {
    let bearer_token = BearerToken::from("the-bearer-token");
    let tasks = make_tasks();
    let aggregator = make_aggregator(tasks.clone().into_iter(), bearer_token.clone());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for (task_id, task) in tasks {
        aggregator.clear_storage();
        let req = runtime.block_on(make_request(
            &aggregator,
            task_id,
            &task,
            bearer_token.clone(),
        ));
        let mut g = c.benchmark_group(vdaf_short_name(&task.vdaf));
        g.throughput(Throughput::Elements(task.min_batch_size));
        g.bench_with_input(format!("{}", task.min_batch_size), &(), |b, ()| {
            b.to_async(&runtime).iter_custom(|iters| {
                let aggregator = &aggregator;
                let req = &req;
                async move {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let now = Instant::now();
                        let ret = black_box(helper::handle_agg_job_req(aggregator, req).await);
                        total += now.elapsed();
                        aggregator.clear_storage();
                        drop(ret.unwrap());
                    }
                    total
                }
            });
        });
    }
}

fn make_tasks() -> Vec<(TaskId, DapTaskConfig)> {
    [1, 10, 100, 1000, 10_000]
        .into_iter()
        .flat_map(|num_reports| {
            [100, 1_000, 10_000, 100_000]
                .into_iter()
                .map(move |dimension| (num_reports, dimension))
        })
        .map(|(num_reports, dimension)| DapTaskConfig {
            version: daphne::DapVersion::Draft09,
            leader_url: "http://1.1.1.1".parse().unwrap(),
            helper_url: "http://1.1.1.1".parse().unwrap(),
            time_precision: 3600,
            min_batch_size: num_reports,
            query: daphne::DapQueryConfig::FixedSize {
                max_batch_size: Some(num_reports),
            },
            vdaf: daphne::vdaf::VdafConfig::Prio3(
                daphne::vdaf::Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
                    bits: 1,
                    length: dimension,
                    chunk_length: 320,
                    num_proofs: 2,
                },
            ),
            expiration: (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                + Duration::from_secs(5000))
            .as_secs(),
            vdaf_verify_key: VdafVerifyKey::L32(VERIFY_KEY),
            collector_hpke_config: HpkeConfig {
                id: 1,
                kem_id: HpkeKemId::P256HkdfSha256,
                kdf_id: HpkeKdfId::HkdfSha256,
                aead_id: HpkeAeadId::Aes128Gcm,
                public_key: HpkePublicKey::new(vec![]),
            },
            method: daphne::DapTaskConfigMethod::Unknown,
        })
        .map(|task| (TaskId(thread_rng().gen()), task))
        .collect()
}

fn make_aggregator(
    tasks: impl Iterator<Item = (TaskId, DapTaskConfig)>,
    token: BearerToken,
) -> InMemoryAggregator {
    let hpke = HpkeReceiverConfig::gen(1, HpkeKemId::P256HkdfSha256).unwrap();
    let collector_hpke = HpkeReceiverConfig::gen(2, HpkeKemId::P256HkdfSha256)
        .unwrap()
        .config;
    InMemoryAggregator::new_helper(
        tasks,
        [hpke],
        daphne::DapGlobalConfig {
            max_batch_duration: u64::MAX,
            min_batch_interval_start: u64::MAX,
            max_batch_interval_end: u64::MAX,
            supported_hpke_kems: vec![HpkeKemId::P256HkdfSha256],
            allow_taskprov: true,
        },
        token.clone(),
        collector_hpke,
        prometheus::default_registry(),
        VERIFY_KEY,
        token,
    )
}

async fn make_request(
    aggregator: &InMemoryAggregator,
    task_id: TaskId,
    task_config: &DapTaskConfig,
    bearer_token: BearerToken,
) -> DapRequest<BearerToken> {
    let batch_id = BatchId(thread_rng().gen());

    let fake_leader_hpke = HpkeReceiverConfig::gen(2, HpkeKemId::P256HkdfSha256).unwrap();

    let hpke_config_list = [
        fake_leader_hpke.config,
        aggregator.hpke_receiver_config_list[0].config.clone(),
    ];

    DapRequest {
        version: daphne::DapVersion::Draft09,
        media_type: Some(daphne::constants::DapMediaType::AggregationJobInitReq),
        task_id: Some(task_id),
        resource: daphne::DapResource::AggregationJob(daphne::messages::AggregationJobId(
            thread_rng().gen(),
        )),
        payload: task_config
            .produce_agg_job_req(
                aggregator,
                aggregator,
                &task_id,
                &daphne::messages::PartialBatchSelector::FixedSizeByBatchId { batch_id },
                &daphne::DapAggregationParam::Empty,
                ReportGenerator::new(
                    &task_config.vdaf,
                    &hpke_config_list,
                    task_id,
                    task_config.min_batch_size.try_into().unwrap(),
                    &task_config.vdaf.gen_measurement().unwrap(),
                    VERSION,
                    task_config.expiration - 10,
                ),
                aggregator.metrics(),
            )
            .await
            .unwrap()
            .1
            .get_encoded_with_param(&VERSION)
            .unwrap(),
        sender_auth: Some(bearer_token),
        taskprov: None,
    }
}

fn vdaf_short_name(vdaf: &VdafConfig) -> String {
    match vdaf {
        VdafConfig::Prio3(daphne::vdaf::Prio3Config::SumVecField64MultiproofHmacSha256Aes128 {
            length,
            ..
        }) => format!("prio3-sum-vec-multiproof-{length}"),
        _ => todo!(),
    }
}

criterion_group!(benches, aggregate);
criterion_main!(benches);
