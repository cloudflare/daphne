// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::durable_requests::ObjectIdFrom;

super::define_do_binding! {
    const BINDING = "DAP_TEST_STATE_CLEANER";
    enum TestStateCleaner {
        Put = "/internal/do/test_state_cleaner/put",
        DeleteAll = "/internal/do/delete_all",
    }

    fn name((): ()) -> ObjectIdFrom {
        ObjectIdFrom::Name(Self::NAME_STR.into())
    }
}

impl TestStateCleaner {
    pub const NAME_STR: &'static str = "test_do_cleaner";
}
