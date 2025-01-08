// Copyright (c) 2025 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne_worker::durable::{self, instantiate_durable_object};

instantiate_durable_object! {
    struct AggregateStore < durable::AggregateStore;

    fn init_user_data(_state: State, env: Env) {
        daphne_worker::tracing_utils::initialize_tracing(env);
    }
}

instantiate_durable_object! {
    struct AggregationJobStore < durable::AggregationJobStore;

    fn init_user_data(_state: State, env: Env) {
        daphne_worker::tracing_utils::initialize_tracing(env);
    }
}
