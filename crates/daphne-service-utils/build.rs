// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

fn main() {
    #[cfg(feature = "durable_requests")]
    ::capnpc::CompilerCommand::new()
        .file("./src/capnproto/base.capnp")
        .file("./src/durable_requests/durable_request.capnp")
        .file("./src/durable_requests/bindings/aggregation_job_store.capnp")
        .run()
        .expect("compiling schema");
}
