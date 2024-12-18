// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

fn main() {
    let mut compiler = ::capnpc::CompilerCommand::new();

    #[cfg(feature = "durable_requests")]
    compiler.file("./src/durable_requests/durable_request.capnp");

    compiler
        .file("./src/cpu_offload/cpu_offload.capnp")
        .run()
        .expect("compiling schema");
}
