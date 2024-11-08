// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! This module provides a means to coalesce arbitrary requets to KV.
//!
//! When issuing multiple identical requests, these can be coalesced into one single network
//! request.
//!
//! The way this is done is by assigning one of the callers as the `executor` of the request and
//! the other callers as `waiters` of the request. The first caller is given the `executor` role.
//!
//! In case the `executor` is canceled for any reason, one of the `waiters` must be promoted to
//! `executor`, this is done by instructing the callers to retry the coalesced request. **This
//! means that the request must be idempotent or retrying might be unsafe.**

use mappable_rc::Marc;
use operation_id::OpId;
use std::{
    any::Any,
    collections::{hash_map::Entry, HashMap},
    future::Future,
    marker::PhantomData,
    sync::Mutex,
};
use tokio::sync::watch::{self, Receiver, Sender};

/// For coalescing to work correctly the key we use for lookup has to be simultaneously:
/// - very unique: distinct code can't have the same key
/// - very duplicated: the same code must use the same key
///
/// To achieve this we use a key pair:
/// - `key` is the KV key, obviously distinct keys must originate distinct requests.
/// - `op_id` is the [`TypeId`] of the [monomorphisation][mono] of the [`coalesce`][coalesce]
///     function. No two closures or futures have the same [`TypeId`], hence, no two
///     monomorphisations of the [`coalesce`] method can have the same id. Thus, using the
///     [`TypeId`] we can guarantee that even if two operations try to work on the same `key`, they
///     won't clober each other since they are produced by different closures.
///
/// mono: <https://en.wikipedia.org/wiki/Monomorphization>
/// coalesce: [`RequestCoalescer::coalesce`]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct OperationKey {
    key: String,
    op_id: OpId,
}

/// The state of the coalesced calls.
#[derive(Default)]
pub struct RequestCoalescer {
    inflight: Mutex<HashMap<OperationKey, Receiver<Option<CoalescedValue>>>>,
    #[cfg(feature = "test-utils")]
    shutting_down: std::sync::atomic::AtomicBool,
}

impl RequestCoalescer {
    #[cfg(feature = "test-utils")]
    pub async fn reset(&self) {
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let receivers = self
            .inflight
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();

        for mut recv in receivers {
            let _ = recv.wait_for(|x| x.is_some()).await;
        }

        self.inflight.lock().unwrap().clear();
        self.shutting_down
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub async fn coalesce<F, Fut, R, E>(
        &self,
        key: String,
        executor: F,
    ) -> Result<Option<Marc<R>>, Marc<E>>
    where
        R: Send + Sync + 'static,
        E: Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<Marc<R>>, E>>,
    {
        let result = loop {
            #[cfg(feature = "test-utils")]
            assert!(
                !self.shutting_down.load(std::sync::atomic::Ordering::SeqCst),
                "RequestCoalescer is shutting down"
            );

            let op_key = OperationKey {
                op_id: operation_id::of::<F, Fut, R, E>(),
                key: key.clone(),
            };
            let role = match self.inflight.lock().unwrap().entry(op_key.clone()) {
                Entry::Occupied(receiver) => {
                    CoalescingRole::Wait(ResponseReceiver::new(receiver.get().clone()))
                }
                Entry::Vacant(slot) => {
                    let (tx, rx) = watch::channel(None);
                    slot.insert(rx);
                    CoalescingRole::Execute(ResponseSender::new(tx, op_key, self))
                }
            };
            break match role {
                CoalescingRole::Wait(receiver) => match receiver.wait().await {
                    Ok(v) => Ok(v),
                    Err(CoalesceError::Canceled) => continue,
                    Err(CoalesceError::Error(e)) => Err(e),
                },
                CoalescingRole::Execute(sender) => {
                    let result = executor().await.map_err(Marc::new);
                    sender.send(result.clone());
                    result
                }
            };
        };
        result
    }
}

/// An error that can occur while executing a coalesced request.
enum CoalesceError<E: ?Sized + 'static> {
    /// The `executor` task that is executing has been cancelled and the waiting tasks that receive
    /// this error should retry the operation.
    Canceled,
    /// An error that occurred during execution of the coalesced operation.
    ///
    /// This error is behind an [`Arc`] because it will be shared between all `waiters`. This is
    /// needed to avoid useless deep [`Clone`]s but also because most errors don't implement
    /// [`Clone`].
    Error(Marc<E>),
}

impl<E: ?Sized> Clone for CoalesceError<E> {
    fn clone(&self) -> Self {
        match self {
            Self::Canceled => Self::Canceled,
            Self::Error(e) => Self::Error(e.clone()),
        }
    }
}

type CoalescedValue =
    Result<Option<Marc<dyn Any + Send + Sync>>, CoalesceError<dyn Any + Send + Sync>>;

/// The send half to be used by the `executor` to send the result of it's computation to the
/// `waiters`.
///
/// Upon being [`Drop`]ed this type will check to see if [`send`](Self::send) was called. If it
/// wasn't called then it is assumed that the `executor` was cancelled, and thus a
/// [`CoalesceError::Canceled`] is sent.
struct ResponseSender<'c, R, E> {
    sender: Sender<Option<CoalescedValue>>,
    key: OperationKey,
    coalescer: &'c RequestCoalescer,
    _marker: PhantomData<(R, E)>,
}

impl<'c, R, E> ResponseSender<'c, R, E>
where
    E: Send + Sync + 'static,
    R: Send + Sync + 'static,
{
    fn new(
        sender: Sender<Option<CoalescedValue>>,
        key: OperationKey,
        coalescer: &'c RequestCoalescer,
    ) -> Self {
        Self {
            sender,
            key,
            coalescer,
            _marker: PhantomData,
        }
    }

    /// Send a value to the other `waiters`.
    fn send(self, v: Result<Option<Marc<R>>, Marc<E>>) {
        // we don't care if every receiver has been dropped, so we ignore the error
        let _ = self.sender.send(Some(
            v.map(|opt_v| opt_v.map(type_erase))
                .map_err(|e| CoalesceError::Error(type_erase(e))),
        ));

        fn type_erase<T: Send + Sync>(m: Marc<T>) -> Marc<dyn Any + Send + Sync> {
            Marc::map(m, |t| t as &(dyn Any + Send + Sync))
        }
    }
}

impl<R, E> Drop for ResponseSender<'_, R, E> {
    fn drop(&mut self) {
        self.coalescer.inflight.lock().unwrap().remove(&self.key);
        self.sender.send_if_modified(|current| {
            if current.is_none() {
                *current = Some(Err(CoalesceError::Canceled));
                true
            } else {
                false
            }
        });
    }
}

/// The receive half to be used by the `waiters` to receive the result of the `executor`'s
/// computation.
struct ResponseReceiver<R, E>(Receiver<Option<CoalescedValue>>, PhantomData<(R, E)>);

impl<R, E> ResponseReceiver<R, E>
where
    E: 'static,
    R: 'static,
{
    fn new(r: Receiver<Option<CoalescedValue>>) -> Self {
        Self(r, PhantomData)
    }

    /// Wait for the `executor` to finish processing and return the result.
    ///
    /// # Cancellation safety
    /// This method is cancel safe.
    async fn wait(mut self) -> Result<Option<Marc<R>>, CoalesceError<E>> {
        fn downcast<T>(m: Marc<dyn Any + Send + Sync>) -> Marc<T> {
            Marc::map(m, |any| any.downcast_ref::<T>().unwrap())
        }

        self.0
            .wait_for(|v| v.is_some())
            .await
            .map_err(|_| CoalesceError::Canceled)?
            .clone()
            // this unwrap can't fail as we rely on `wait_for` to only return when the inner value
            // is_some
            .unwrap()
            // these unwraped downcasts can never fail as self is generic over R and E
            .map(|opt_any| opt_any.map(downcast))
            .map_err(|e| match e {
                CoalesceError::Canceled => CoalesceError::Canceled,
                CoalesceError::Error(e) => CoalesceError::Error(downcast(e)),
            })
    }
}

/// The role assign to a coalescing task.
enum CoalescingRole<'c, R, E> {
    /// Should execute the operation and share it's result with the `waiters`.
    Execute(ResponseSender<'c, R, E>),
    /// Should wait the operation to be completed by the `executor`.
    Wait(ResponseReceiver<R, E>),
}

mod operation_id {
    use mappable_rc::Marc;
    use std::{any::TypeId, future::Future};

    /// A type id that is unique to a coalesce operation. This type id cannot be used to downcast
    /// between types.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OpId(TypeId);

    #[inline]
    pub fn of<F, Fut, R, E>() -> OpId
    where
        R: Send + Sync + 'static,
        E: Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<Marc<R>>, E>>,
    {
        trait NonStaticAny {
            fn type_id(&self) -> TypeId
            where
                Self: 'static,
            {
                TypeId::of::<Self>()
            }
        }
        impl<T> NonStaticAny for T {}

        let fun = super::RequestCoalescer::coalesce::<F, Fut, R, E>;
        let tid = unsafe {
            // SAFETY:
            // This only casts the lifetime away but we don't store this value anywhere, we just
            // call a method on it, thus we can't have a use after free.
            //
            // This type id cannot be used for downcasting for as long as the constructor of `OpId`
            // remains private to this module.
            core::mem::transmute::<&dyn NonStaticAny, &'static dyn NonStaticAny>(&fun).type_id()
        };
        OpId(tid)
    }
}

#[cfg(test)]
mod test {
    use super::RequestCoalescer;
    use assert_matches::assert_matches;
    use futures::StreamExt;
    use mappable_rc::Marc;
    use std::{
        convert::Infallible,
        future::Future,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::task::JoinError;

    fn test_key() -> String {
        "test-key".into()
    }

    const TEST_RESPONSE: &str = "response";

    #[tokio::test]
    async fn multiple_requests_are_coalesced() {
        let counter = Arc::new(AtomicUsize::new(0));
        let tasks = spawn_100_tasks(counter.clone(), |counter, coalescer, _| async move {
            coalescer
                .test_coalesce(test_key(), || async {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    TEST_RESPONSE
                })
                .await
        })
        .await;

        for t in tasks {
            assert_matches!(t, Ok(TEST_RESPONSE));
        }

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // this tests the operation_id module is working.
    #[tokio::test]
    async fn distinct_requests_dont_overlap() {
        let counter1 = Arc::new(AtomicUsize::new(0));
        let counter2 = Arc::new(AtomicUsize::new(0));

        let tasks = spawn_100_tasks(
            (counter1.clone(), counter2.clone()),
            |(counter1, counter2), coalescer, i| async move {
                if i % 2 == 0 {
                    coalescer
                        .test_coalesce(test_key(), || async {
                            counter1.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            TEST_RESPONSE
                        })
                        .await
                } else {
                    coalescer
                        .test_coalesce(test_key(), || async {
                            counter2.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            TEST_RESPONSE
                        })
                        .await
                }
            },
        )
        .await;

        for t in tasks {
            assert_matches!(t, Ok(TEST_RESPONSE));
        }

        assert_eq!(counter1.load(Ordering::SeqCst), 1);
        assert_eq!(counter2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn executor_panicking_doesnt_block_waiters() {
        let tasks = spawn_100_tasks((), |(), coalescer, _| async move {
            coalescer
                .test_coalesce(test_key(), || async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    panic!("oh no")
                })
                .await;
        })
        .await;

        for t in tasks {
            assert!(t.is_err());
        }
    }

    #[tokio::test]
    async fn one_executor_panicking_doesnt_prevent_request_from_succeding() {
        let counter = Arc::new(AtomicUsize::new(0));
        let tasks = spawn_100_tasks(counter.clone(), |counter, coalescer, _| async move {
            coalescer
                .test_coalesce(test_key(), || async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    match counter.fetch_add(1, Ordering::SeqCst) {
                        0 => panic!("I'm the bad actor"),
                        _ => TEST_RESPONSE,
                    }
                })
                .await
        })
        .await;

        let mut number_of_panics = 0;
        let mut number_of_correct_outputs = 0;
        for t in tasks {
            match t {
                Ok(TEST_RESPONSE) => number_of_correct_outputs += 1,
                Ok(invalid) => panic!("invalid response: {invalid}"),
                Err(_panic) => number_of_panics += 1,
            }
        }

        assert_eq!(number_of_correct_outputs, 100 - 1);
        assert_eq!(number_of_panics, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn one_executor_being_canceled_doesnt_prevent_request_from_succeding() {
        let counter = Arc::new(AtomicUsize::new(0));
        let tasks = spawn_100_tasks(counter.clone(), |counter, coalescer, i| async move {
            let fut = coalescer.test_coalesce(test_key(), || async {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
                TEST_RESPONSE
            });
            if i == 0 {
                tokio::time::timeout(Duration::from_millis(10), fut).await
            } else {
                Ok(fut.await)
            }
        })
        .await;

        let mut number_of_timeouts = 0;
        let mut number_of_correct_outputs = 0;
        for t in tasks {
            match t.unwrap() {
                Ok(TEST_RESPONSE) => number_of_correct_outputs += 1,
                Ok(invalid) => panic!("invalid response: {invalid}"),
                Err(_timedout) => number_of_timeouts += 1,
            }
        }

        assert_eq!(number_of_correct_outputs, 100 - 1);
        assert_eq!(number_of_timeouts, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    async fn spawn_100_tasks<C, F, Fut, R>(ctx: C, mut f: F) -> Vec<Result<R, JoinError>>
    where
        F: FnMut(C, Arc<RequestCoalescer>, usize) -> Fut,
        Fut: Future<Output = R> + Send + 'static,
        R: Send + 'static,
        C: Clone,
    {
        let coalescer = Arc::new(RequestCoalescer::default());
        futures::stream::iter((0..100).map(|i| {
            let fut = f(ctx.clone(), coalescer.clone(), i);
            tokio::spawn(fut)
        }))
        .buffer_unordered(usize::MAX)
        .collect::<Vec<_>>()
        .await
    }

    impl RequestCoalescer {
        async fn test_coalesce<F, Fut, R>(&self, key: String, executor: F) -> R
        where
            R: Send + Sync + Copy + 'static,
            F: FnOnce() -> Fut,
            Fut: Future<Output = R>,
        {
            let fut = executor();
            let result =
                self.coalesce::<_, _, _, Infallible>(key, || async move {
                    Ok(Some(Marc::new(fut.await)))
                })
                .await;
            let Ok(s) = result.map(|opt| *opt.unwrap()).map_err(|e| *e);
            s
        }
    }
}
