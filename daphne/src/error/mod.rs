// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod aborts;

use std::fmt::{Debug, Display};

use crate::{messages::TransitionFailure, vdaf::VdafError};
pub use aborts::DapAbort;
use prio::codec::CodecError;

use self::aborts::ProblemDetails;

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

impl DapError {
    pub fn into_problem_details(self) -> ProblemDetails {
        if let Self::Abort(a) = self {
            return a.into_problem_details();
        }

        ProblemDetails {
            typ: None,
            title: "Internal server error".into(),
            agg_job_id: None,
            task_id: None,
            instance: None,
            detail: None,
        }
    }

    /// Construct a fatal encoding error.
    pub fn encoding(e: CodecError) -> DapError {
        DapError::Fatal(FatalDapError(format!(
            "encountered fatal error during encoding: {e}"
        )))
    }
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
            VdafError::Codec(..) | VdafError::Vdaf(..) | VdafError::Uncategorized(..) => {
                Self::Transition(TransitionFailure::VdafPrepError)
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FatalDapError(pub(crate) String);

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
/// fatal_error!(err = ?e, id = %some_id, "operation failed");
/// ```
///
/// # Note
/// If you have an error that caused the fatal error, it should be passed in the `err` field of the
/// macro, pass a string only when there is no error value you can use.
#[macro_export]
macro_rules! fatal_error {
    (err = ?$e:expr) => {
        $crate::__fatal_error_impl!(@@ err = ?$e)
    };
    (err = %$e:expr) => {
        $crate::__fatal_error_impl!(@@ err = %$e)
    };
    (err = $e:expr) => {
        $crate::__fatal_error_impl!(@@ err = $e)
    };
    (err = ?$e:expr, $($rest:tt)*) => {
        $crate::__fatal_error_impl!(@@ err = ?$e, $($rest)*)
    };
    (err = %$e:expr, $($rest:tt)*) => {
        $crate::__fatal_error_impl!(@@ err = %$e, $($rest)*)
    };
    (err = $e:expr, $($rest:tt)*) => {
        $crate::__fatal_error_impl!(@@ err = $e, $($rest)*)
    };

}

#[macro_export]
#[doc(hidden)]
macro_rules! __fatal_error_impl {
    (@@ err = ?$e:expr $(, $($rest:tt)*)?) => {{
        let error = &$e;
        $crate::error::tracing::error!(?error, $($($rest)*)*);
        $crate::__fatal_error_impl!(@@@ error)
    }};
    (@@ err = %$e:expr $(, $($rest:tt)*)?) => {{
        let error = &$e;
        $crate::error::tracing::error!(%error, $($($rest)*)*);
        $crate::__fatal_error_impl!(@@@ error)
    }};
    (@@ err = $e:expr $(, $($rest:tt)*)?) => {{
        let error = &$e;
        $crate::error::tracing::error!(error, $($($rest)*)*);
        $crate::__fatal_error_impl!(@@@ error)
    }};
    (@@@ $error:expr) => {{
        let error = $error;
        $crate::error::DapError::Fatal(
            $crate::error::FatalDapError::__use_the_macro(::std::format!("{error}"))
        )
    }}
}

// re-export tracing to make sure users of the macro can call it even if they don't depend on
// tracing directly
#[doc(hidden)]
pub use tracing;
