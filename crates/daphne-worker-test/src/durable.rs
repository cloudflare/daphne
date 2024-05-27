// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne_worker::durable::{self, instantiate_durable_object};

instantiate_durable_object! {
    AggregateStore < durable::AggregateStore;

    fn pre_init(_state, env, _name) {
        daphne_worker::tracing_utils::initialize_tracing(env);
    }
}

instantiate_durable_object! {
    HelperStateStore < durable::HelperStateStore;

    fn pre_init(_state, env, _name) {
        daphne_worker::tracing_utils::initialize_tracing(env);
    }
}
