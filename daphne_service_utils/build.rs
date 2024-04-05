// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

fn main() {
    #[cfg(feature = "durable_requests")]
    ::capnpc::CompilerCommand::new()
        .file("./src/durable_requests/durable_request.capnp")
        .run()
        .expect("compiling schema");
}
