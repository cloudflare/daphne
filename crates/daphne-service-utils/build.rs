// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

fn main() {
    #[cfg(any(feature = "durable_requests", feature = "compute-offload"))]
    {
        let mut compiler = ::capnpc::CompilerCommand::new();

        compiler.file("./src/capnproto/base.capnp");

        #[cfg(feature = "durable_requests")]
        compiler
            .file("./src/durable_requests/durable_request.capnp")
            .file("./src/durable_requests/bindings/aggregation_job_store.capnp")
            .file("./src/durable_requests/bindings/aggregate_store_v2.capnp")
            .file("./src/durable_requests/bindings/agg_job_response_store.capnp")
            .file("./src/durable_requests/bindings/replay_checker.capnp");

        #[cfg(feature = "compute-offload")]
        compiler.file("./src/compute_offload/compute_offload.capnp");

        compiler.run().expect("compiling schema");
    }
}
