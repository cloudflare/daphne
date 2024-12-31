// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

fn main() {
    ::capnpc::CompilerCommand::new()
        .import_path("../daphne-service-utils/src")
        .file("./src/aggregator/queues/queue_messages.capnp")
        .run()
        .expect("compiling schema");
}
