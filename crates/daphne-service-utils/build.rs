// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

fn main() {
    #[cfg(any(feature = "durable_requests", feature = "cpu_offload"))]
    {
        let mut compiler = ::capnpc::CompilerCommand::new();

        #[cfg(feature = "durable_requests")]
        compiler.file("./src/durable_requests/durable_request.capnp");

        #[cfg(feature = "cpu_offload")]
        compiler.file("./src/cpu_offload/cpu_offload.capnp");

        compiler.run().expect("compiling schema");
    }
}
