// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use cfg_if::cfg_if;
use worker::*;

cfg_if! {
    // https://github.com/rustwasm/console_error_panic_hook#readme
    if #[cfg(feature = "console_error_panic_hook")] {
        extern crate console_error_panic_hook;
        pub use self::console_error_panic_hook::set_once as set_panic_hook;
    } else {
        #[inline]
        pub fn set_panic_hook() {}
    }
}

pub(crate) fn now() -> u64 {
    Date::now().as_millis() / 1000
}

pub(crate) fn int_err<S: ToString>(s: S) -> Error {
    console_error!("internal error: {}", s.to_string());
    Error::RustError("internalError".to_string())
}
