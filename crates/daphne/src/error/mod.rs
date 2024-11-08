// Copyright (c) 2023 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod aborts;

use std::fmt::{Debug, Display};

use crate::{messages::TransitionFailure, vdaf::VdafError};
pub use aborts::DapAbort;
use prio::codec::CodecError;

use self::aborts::ProblemDetails;

/// DAP errors.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DapError {
    /// Fatal error. If this triggers an abort, then treat this as an internal error.
    ///
    /// To create an instance of this variant the [`fatal_error`](crate::fatal_error) macro must be
    /// used. This ensures that all fatal errors are logged with tracing when created.
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
    /// Construct a fatal encoding error.
    pub fn encoding(e: CodecError) -> DapError {
        DapError::Fatal(FatalDapError(format!(
            "encountered fatal error during encoding: {e}"
        )))
    }

    pub(crate) fn from_vdaf(e: VdafError) -> Self {
        match e {
            VdafError::Codec(..) | VdafError::Vdaf(..) => {
                tracing::warn!(error = ?e, "rejecting report");
                Self::Transition(TransitionFailure::VdafPrepError)
            }
            VdafError::Dap(e) => e,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FatalDapError(pub(crate) String);

impl FatalDapError {
    pub fn into_problem_details(self) -> ProblemDetails {
        ProblemDetails {
            typ: None,
            title: "Internal server error".into(),
            agg_job_id: None,
            task_id: None,
            instance: "/problem-details/internal-server-error".into(),
            detail: None,
        }
    }
}

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

impl FatalDapError {
    #[doc(hidden)]
    pub fn __use_the_macro(s: String) -> Self {
        FatalDapError(s)
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
/// fatal_error!(err = "the error", id = %some_id, "something bad happened");
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
///
/// # Note
/// A handwriten message must always be present, this requirement can be fulfilled in one of three
/// ways:
///
/// ```
/// # use daphne::fatal_error;
/// # let field1 = 1; let field2 = 2;
/// use std::io::{Error, ErrorKind};
///
/// fatal_error!(err = "a string literal in the err field");
/// fatal_error!(err = format!("a formatted string literal {field1} {}", field2));
///
/// let error = Error::new(ErrorKind::Other, "the error");
/// fatal_error!(err = ?error, "some trailing text after the other attributes");
/// ```
#[macro_export]
macro_rules! fatal_error {
    (err = $e:literal) => {
        $crate::__fatal_error_impl!(@@ err = $e, $e)
    };
    (err = format!($($arg:tt)*)) => {{
        let err = ::std::format!($($arg)*);
        $crate::__fatal_error_impl!(@@ err = err, err)
    }};
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
