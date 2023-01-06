// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{int_err, now};
use daphne::{messages::Id, DapBatchBucket, DapVersion};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use worker::*;

pub(crate) const DURABLE_DELETE_ALL: &str = "/internal/do/delete_all";

pub(crate) const BINDING_DAP_REPORTS_PENDING: &str = "DAP_REPORTS_PENDING";
pub(crate) const BINDING_DAP_REPORTS_PROCESSED: &str = "DAP_REPORTS_PROCESSED";
pub(crate) const BINDING_DAP_AGGREGATE_STORE: &str = "DAP_AGGREGATE_STORE";
pub(crate) const BINDING_DAP_LEADER_AGG_JOB_QUEUE: &str = "DAP_LEADER_AGG_JOB_QUEUE";
pub(crate) const BINDING_DAP_LEADER_BATCH_QUEUE: &str = "DAP_LEADER_BATCH_QUEUE";
pub(crate) const BINDING_DAP_LEADER_COL_JOB_QUEUE: &str = "DAP_LEADER_COL_JOB_QUEUE";
pub(crate) const BINDING_DAP_HELPER_STATE_STORE: &str = "DAP_HELPER_STATE_STORE";
pub(crate) const BINDING_DAP_GARBAGE_COLLECTOR: &str = "DAP_GARBAGE_COLLECTOR";

const ERR_NO_VALUE: &str = "No such value in storage.";

/// Used to send HTTP requests to a durable object (DO) instance.
pub(crate) struct DurableConnector<'a> {
    env: &'a Env,
}

impl<'a> DurableConnector<'a> {
    pub(crate) fn new(env: &'a Env) -> Self {
        DurableConnector { env }
    }

    /// Send a GET request with the given path to the DO instance with the given binding and name.
    /// The response is expected to be a JSON object.
    pub(crate) async fn get<O: for<'b> Deserialize<'b>>(
        &self,
        durable_binding: &str,
        durable_path: &'static str,
        durable_name: String,
    ) -> Result<O> {
        let namespace = self.env.durable_object(durable_binding)?;
        let stub = namespace.id_from_name(&durable_name)?.get_stub()?;
        durable_request(stub, durable_path, Method::Get, None::<()>).await
    }

    /// Send a POST request with the given path to the DO instance with the given binding and name.
    /// The body of the request is a JSON object. The response is expected to be a JSON object.
    pub(crate) async fn post<I: Serialize, O: for<'b> Deserialize<'b>>(
        &self,
        durable_binding: &str,
        durable_path: &'static str,
        durable_name: String,
        data: I,
    ) -> Result<O> {
        let namespace = self.env.durable_object(durable_binding)?;
        let stub = namespace.id_from_name(&durable_name)?.get_stub()?;
        durable_request(stub, durable_path, Method::Post, Some(data)).await
    }

    /// Send a POST request with the given path to the DO instance with the given binding and hex
    /// identifier. The body of the request is a JSON object. The response is expected to be a JSON
    /// object.
    pub(crate) async fn post_by_id_hex<I: Serialize, O: for<'b> Deserialize<'b>>(
        &self,
        durable_binding: &str,
        durable_path: &'static str,
        durable_id_hex: String,
        data: I,
    ) -> Result<O> {
        let namespace = self.env.durable_object(durable_binding)?;
        let stub = namespace.id_from_string(&durable_id_hex)?.get_stub()?;
        durable_request(stub, durable_path, Method::Post, Some(data)).await
    }
}

async fn durable_request<I: Serialize, O: for<'a> Deserialize<'a>>(
    durable_stub: Stub,
    durable_path: &'static str,
    method: Method,
    data: Option<I>,
) -> Result<O> {
    let req = match (&method, data) {
        (Method::Post, Some(data)) => Request::new_with_init(
            &format!("https://fake-host{}", durable_path),
            RequestInit::new().with_method(Method::Post).with_body(Some(
                wasm_bindgen::JsValue::from_str(&serde_json::to_string(&data)?),
            )),
        )?,
        (Method::Get, None) => Request::new_with_init(
            &format!("https://fake-host{}", durable_path),
            RequestInit::new().with_method(Method::Get),
        )?,
        _ => {
            return Err(Error::RustError(format!(
                "durable_request: Unrecognized method: {:?}",
                method
            )));
        }
    };

    let mut resp = durable_stub.fetch_with_request(req).await?;
    resp.json().await
}

macro_rules! ensure_garbage_collected {
    ($req:expr, $object:expr, $id:expr, $binding:expr) => {{
        if $req.path() == crate::durable::DURABLE_DELETE_ALL && $req.method() == Method::Post {
            $object.state.storage().delete_all().await?;
            $object.touched = false;
            return Response::from_json(&());
        } else if !$object.touched {
            // The GarbageCollector should only be used when running tests. In production, the DO->DO
            // communication overhead adds unacceptable latency, and there's no need to do the
            // bulk deletes of state that test suites require.
            if matches!($object.config.deployment, crate::config::DaphneWorkerDeployment::Dev) {
                let touched: bool =
                    crate::durable::state_set_if_not_exists(&$object.state, "touched", &true)
                        .await?
                        .unwrap_or(false);
                if !touched {
                    let durable = crate::durable::DurableConnector::new(&$object.env);
                    durable
                        .post(
                            crate::durable::BINDING_DAP_GARBAGE_COLLECTOR,
                            crate::durable::garbage_collector::DURABLE_GARBAGE_COLLECTOR_PUT,
                            "garbage_collector".to_string(),
                            &crate::durable::DurableReference {
                                binding: $binding.to_string(),
                                id_hex: $id,
                                task_id: None,
                            },
                        )
                        .await?;
                }
            }
            $object.touched = true;
        }
    }};
}

macro_rules! ensure_alarmed {
    ($object:expr, $lifetime:expr) => {{
        if !$object.alarmed {
            if $object.state.storage().get_alarm().await?.is_none() {
                $object.state.storage().set_alarm($lifetime).await?;
            }
            $object.alarmed = true;
        }
    }};
}

/// Fetch the value associated with the given key from durable storage. If the key/value pair does
/// not exist, then return the default value.
pub(crate) async fn state_get_or_default<T: Default + for<'a> Deserialize<'a>>(
    state: &State,
    key: &str,
) -> Result<T> {
    state.storage().get(key).await.or_else(|e| {
        if matches!(e, Error::JsError(ref s) if s == ERR_NO_VALUE) {
            Ok(T::default())
        } else {
            Err(e)
        }
    })
}

pub(crate) async fn state_get<T: for<'a> Deserialize<'a>>(
    state: &State,
    key: &str,
) -> Result<Option<T>> {
    state.storage().get(key).await.or_else(|e| {
        if matches!(e, Error::JsError(ref s) if s == ERR_NO_VALUE) {
            Ok(None)
        } else {
            Err(e)
        }
    })
}

/// Set a key/value pair unless the key already exists. If the key exists, then return the current
/// value. Otherwise return nothing.
pub(crate) async fn state_set_if_not_exists<T: for<'a> Deserialize<'a> + Serialize>(
    state: &State,
    key: &str,
    val: &T,
) -> Result<Option<T>> {
    let curr_val: Option<T> = state_get(state, key).await?;
    if curr_val.is_some() {
        return Ok(curr_val);
    }

    state.storage().put(key, val).await?;
    Ok(None)
}

pub(crate) fn durable_name_queue(shard: u64) -> String {
    format!("queue/{}", shard)
}

pub(crate) fn durable_name_report_store(
    version: &DapVersion,
    task_id_hex: &str,
    epoch: u64,
    shard: u64,
) -> String {
    format!(
        "{}/epoch/{:020}/shard/{}",
        durable_name_task(version, task_id_hex),
        epoch,
        shard
    )
}

pub(crate) fn durable_name_agg_store(
    version: &DapVersion,
    task_id_hex: &str,
    bucket: &DapBatchBucket<'_>,
) -> String {
    format!(
        "{}/{}",
        durable_name_task(version, task_id_hex),
        durable_name_bucket(bucket),
    )
}

pub(crate) fn durable_name_task(version: &DapVersion, task_id_hex: &str) -> String {
    format!("{}/task/{}", version.as_ref(), task_id_hex)
}

fn durable_name_bucket(bucket: &DapBatchBucket<'_>) -> String {
    match bucket {
        DapBatchBucket::TimeInterval { batch_window } => {
            format!("window/{}", batch_window)
        }
        DapBatchBucket::FixedSize { batch_id } => {
            format!("batch/{}", batch_id.to_hex())
        }
    }
}

pub(crate) fn report_id_hex_from_report(report_hex: &str) -> Option<&str> {
    // task_id (32 bytes)
    if report_hex.len() < 64 {
        return None;
    }
    let report_hex = &report_hex[64..];

    // metadata.id
    if report_hex.len() < 32 {
        return None;
    }
    Some(&report_hex[..32])
}

/// Reference to a DO instance, used by the garbage collector.
#[derive(Deserialize, Serialize)]
pub(crate) struct DurableReference {
    /// The DO binding, e.g., "DAP_REPORT_STORE".
    pub(crate) binding: String,

    /// Unique ID assigned to the DO instance by the Workers runtime.
    pub(crate) id_hex: String,

    /// If applicable, the DAP task ID to which the DO instance is associated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) task_id: Option<Id>,
}

/// An element of a queue stored in a DO instance.
#[derive(Deserialize, Serialize)]
pub(crate) struct DurableOrdered<T> {
    item: T,
    prefix: String,
    ordinal: String,
}

impl<T: for<'a> Deserialize<'a> + Serialize> DurableOrdered<T> {
    /// Return the front of a queue stored in the provided DO state. The string `prefix` defines
    /// the queue's namespace, i.e., the prefix of each key for each key/value pair in the queue.
    /// At most `limit` queue elements are returned.
    pub(crate) async fn get_front(state: &State, prefix: &str, limit: usize) -> Result<Vec<Self>> {
        get_front(state, prefix, Some(limit)).await
    }

    /// Return all elements in the queue.
    ///
    /// WARNING: If the queue is too long, then this action is likely to cause the Workers runtime
    /// to start rate limiting the Worker. This should only be used when the size of the queue is
    /// strictly controlled.
    async fn get_all(state: &State, prefix: &str) -> Result<Vec<Self>> {
        get_front(state, prefix, None).await
    }

    /// Create a new element for a roughly ordered queue. (Use `put()` to store it.)
    ///
    /// Items in this queue are handled roughly in order of creation (oldest elements first).
    /// Specifically, the ordinal is the UNIX time (in seconds) at which this method was called.
    /// Ties are broken by a random nonce tacked on to the key. The format of the ordinal is:
    ///
    /// ```text
    ///     time/<time>/nonce/<nonce>
    /// ```
    ///
    /// where <time> is the timestamp and <nonce> is a random nonce.
    pub(crate) fn new_roughly_ordered(item: T, prefix: &str) -> Self {
        let mut rng = thread_rng();
        let time = now();
        let nonce = rng.gen::<[u8; 16]>();

        // Pad the timestamp with 0s to the length of the longest 64-bit integer encoded in
        // decimal. This ensures that queue elements stay ordered.
        let ordinal = format!("time/{:020}/nonce/{}", time, hex::encode(nonce));

        Self {
            item,
            prefix: prefix.to_string(),
            ordinal,
        }
    }

    /// Create a new element for a strictly ordered queue. (Use `put()` to store it.)
    ///
    /// Items in this queue are handled in order of creation (i.e., the time at which this method
    /// was evaluated.) The order of the item is determined a counter stored in the provided DO
    /// state. (The element must, in turn, be stored in the same state.) This counter is stored
    /// under the following key:
    ///
    /// ```text
    ///     <prefix>/next_ordinal
    /// ```
    ///
    /// where `<prefix>` is the provided prefix. The format of each ordinal is:
    ///
    /// ```text
    ///     order/<ordinal>
    /// ```
    ///
    /// where `<ordinal>` is the value of the counter at the time of creation.
    pub(crate) async fn new_strictly_ordered(state: &State, item: T, prefix: &str) -> Result<Self> {
        // Get the next ordinal.
        let next_ordinal_key = format!("{}/next_ordinal", prefix);
        let mut next_ordinal: u64 = state_get_or_default(state, &next_ordinal_key).await?;
        let ordinal = format!("order/{}", next_ordinal);

        // Update the next ordinal.
        next_ordinal += 1;
        state
            .storage()
            .put(&next_ordinal_key, &next_ordinal)
            .await?;

        Ok(Self {
            item,
            prefix: prefix.to_string(),
            ordinal,
        })
    }

    /// Store the item in the provided DO state.
    pub(crate) async fn put(&self, state: &State) -> Result<()> {
        state.storage().put(&self.key(), &self.item).await
    }

    /// Delete the item from the provided DO state.
    pub(crate) async fn delete(&self, state: &State) -> Result<bool> {
        state.storage().delete(&self.key()).await
    }

    /// Compute the key used to store store the item. The key format is:
    ///
    /// ```text
    ///     <prefix>/item/<ordinal>
    /// ```
    ///
    /// where `<prefix>` is the indicated namespace and `<ordinal>` is the item's ordinal.
    pub(crate) fn key(&self) -> String {
        format!("{}/item/{}", self.prefix, self.ordinal)
    }

    pub(crate) fn into_item(self) -> T {
        self.item
    }
}

impl<T> AsRef<T> for DurableOrdered<T> {
    fn as_ref(&self) -> &T {
        &self.item
    }
}

async fn get_front<T: for<'a> Deserialize<'a> + Serialize>(
    state: &State,
    prefix: &str,
    limit: Option<usize>,
) -> Result<Vec<DurableOrdered<T>>> {
    let key_prefix = format!("{}/item/", prefix);
    let mut opt = ListOptions::new().prefix(&key_prefix);
    if let Some(limit) = limit {
        opt = opt.limit(limit);
    }
    let iter = state.storage().list_with_options(opt).await?.entries();
    let mut js_item = iter.next()?;
    let mut res = Vec::new();
    while !js_item.done() {
        // TODO(issue #118) Remove this deprecated dependency.
        #[allow(deprecated)]
        let (key, item): (String, T) = js_item.value().into_serde()?;
        if key[..key_prefix.len()] != key_prefix {
            return Err(int_err("queue element key is improperly formatted"));
        }
        let ordinal = &key[key_prefix.len()..];
        res.push(DurableOrdered {
            item,
            prefix: prefix.to_string(),
            ordinal: ordinal.to_string(),
        });
        js_item = iter.next()?;
    }
    Ok(res)
}

pub(crate) mod aggregate_store;
pub(crate) mod garbage_collector;
pub(crate) mod helper_state_store;
pub(crate) mod leader_agg_job_queue;
pub(crate) mod leader_batch_queue;
pub(crate) mod leader_col_job_queue;
#[cfg(test)]
pub(crate) mod mod_test;
pub(crate) mod reports_pending;
pub(crate) mod reports_processed;
