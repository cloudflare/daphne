// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use daphne::messages::Id;
use serde::{Deserialize, Serialize};
use worker::*;

pub(crate) const DURABLE_DELETE_ALL: &str = "/internal/do/delete_all";

pub(crate) const BINDING_DAP_REPORT_STORE: &str = "DAP_REPORT_STORE";
pub(crate) const BINDING_DAP_AGGREGATE_STORE: &str = "DAP_AGGREGATE_STORE";
pub(crate) const BINDING_DAP_LEADER_AGG_JOB_QUEUE: &str = "DAP_LEADER_AGG_JOB_QUEUE";
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
                $object.touched = true;
            }
        }
    }};
}

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

pub(crate) fn durable_queue_name(queue_num: usize) -> String {
    format!("queue/{}", queue_num)
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

pub(crate) mod aggregate_store;
pub(crate) mod garbage_collector;
pub(crate) mod helper_state_store;
pub(crate) mod leader_agg_job_queue;
pub(crate) mod leader_col_job_queue;
pub(crate) mod report_store;
#[cfg(test)]
pub(crate) mod report_store_test;
