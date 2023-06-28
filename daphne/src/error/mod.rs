// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod aborts;

use std::fmt::{Debug, Display};

use crate::{messages::TransitionFailure, vdaf::VdafError};
pub use aborts::DapAbort;

/// DAP errors.
#[derive(Debug, thiserror::Error)]
pub enum DapError {
    /// Fatal error. If this triggers an abort, then treat this as an internal error.
    ///
    /// To create an instance of this variant the [`fatal_error`] must be used. This ensures that
    /// all fatal errors are logged with tracing when created.
    #[error("fatal error: {0}")]
    Fatal(#[from] FatalDapError),

    /// Error triggered by peer, resulting in an abort.
    #[error("abort: {0}")]
    Abort(#[from] DapAbort),

    /// Transition failure. This error blocks processing of a paritcular report and may, under
    /// certain conditions, trigger an abort.
    #[error("transition error: {0}")]
    Transition(#[from] TransitionFailure),
}

impl FatalDapError {
    #[doc(hidden)]
    pub fn __use_the_macro(s: String) -> Self {
        FatalDapError(s)
    }
}

impl From<VdafError> for DapError {
    fn from(e: VdafError) -> Self {
        match e {
            VdafError::Codec(..) | VdafError::Vdaf(..) => {
                Self::Transition(TransitionFailure::VdafPrepError)
            }
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct FatalDapError(String);

impl std::error::Error for FatalDapError {}

impl Display for FatalDapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for FatalDapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// This macro is to be used when constructing fatal errors ([`DapError::Fatal`]).
///
/// It follows the exact same syntax as
/// [tracing](https://docs.rs/tracing/latest/tracing/index.html#using-the-macros) macros with one
/// added thing: You must always have an `err` field at the start, like so:
///
/// ```
/// # use daphne::fatal_error;
/// fatal_error!(err = "the error");
/// ```
/// After this field you can do all the same things as tracing, use the `%` sign sintax to use the
/// display implementation of a type, the `?` sigil for the debug representation of a type, etc.
/// ```
/// # use daphne::fatal_error;
/// let some_id = 1;
///
/// fatal_error!(err = "the error", id = %some_id);
/// ```
/// ```
/// # use daphne::fatal_error;
/// use std::io::{Error, ErrorKind};
///
/// let some_id = 1;
/// let e = Error::new(ErrorKind::Other, "the error");
/// fatal_error!(err = e, id = %some_id, "operation failed");
/// ```
///
/// # Note
/// If you have an error that caused the fatal error, it should be passed in the `err` field of the
/// macro, pass a string only when there is no error value you can use.
#[macro_export]
macro_rules! fatal_error {
    (err = $e:expr) => {
        $crate::fatal_error!(@@@ err = $e)
    };
    (err = $e:expr, $($rest:tt)*) => {
        $crate::fatal_error!(@@@ err = $e, $($rest)*)
    };
    (@@@ err = $e:expr $(, $($rest:tt)*)?) => {{
        let error = &$e;
        ::tracing::error!(?error, $($($rest)*)*);
        $crate::error::DapError::Fatal(
            $crate::error::FatalDapError::__use_the_macro(::std::format!("{error}"))
        )
    }};
}
