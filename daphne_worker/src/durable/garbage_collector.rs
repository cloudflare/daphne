// Copyright (c) 2022 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{durable, int_err, now};
use rand::prelude::*;
use worker::*;

pub(crate) const DURABLE_GARBAGE_COLLECTOR_PUT: &str = "/internal/do/garbage_collector/put";

/// Durable Object (DO) for keeping track of all persistent DO storage.
#[durable_object]
pub struct GarbageCollector {
    #[allow(dead_code)]
    state: State,
    env: Env,
}

#[durable_object]
impl DurableObject for GarbageCollector {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        let durable = durable::DurableConnector::new(&self.env);
        let mut rng = thread_rng();
        match (req.path().as_ref(), req.method()) {
            // Schedule a durable object (DO) instance for deletion.
            (DURABLE_GARBAGE_COLLECTOR_PUT, Method::Post) => {
                let durable_ref: durable::DurableReference = req.json().await?;
                match durable_ref.binding.as_ref() {
                    durable::BINDING_DAP_REPORT_STORE
                    | durable::BINDING_DAP_AGGREGATE_STORE
                    | durable::BINDING_DAP_LEADER_AGG_JOB_QUEUE
                    | durable::BINDING_DAP_LEADER_COL_JOB_QUEUE
                    | durable::BINDING_DAP_HELPER_STATE_STORE => (),
                    s => {
                        return Err(int_err(format!(
                            "GarbageCollector: unrecognized binding: {}",
                            s
                        )))
                    }
                };

                // Reference handle encodes the current time and a random nonce in order to deal
                // with collisions. This time goes first in order to ensure we can delete the
                // oldest objects first.
                let mut rand = [0; 16];
                rng.fill(&mut rand);
                let durable_handle = format!(
                    "object/{}/time/{:020}/rand/{}",
                    durable_ref.binding,
                    now(),
                    hex::encode(rand)
                );
                self.state
                    .storage()
                    .put(&durable_handle, &durable_ref)
                    .await?;
                console_debug!(
                    "GarbageCollector: scheduled {} instance {} for deletion",
                    durable_ref.binding,
                    durable_ref.id_hex
                );
                Response::from_json(&())
            }

            // Delete all DO instances.
            //
            // NOTE This method is likely to hit memory and/or time limits when run in a production
            // deployment. This method is not intended for production use. If deleting all memory
            // for a deployment is needed, then the proper way is to do a Workers migration that
            // deletes each of the DO classes.
            //
            //   TODO Add a method for deleting all instances scheduled before a given time. This
            //   will allow us to prune storage we're not likely to need anymore, e.g., for
            //   replay protection. However, for replay protection in particular, it'll be
            //   important to make sure the Leader rejects reports with old timestamps.
            (durable::DURABLE_DELETE_ALL, Method::Post) => {
                let opt = ListOptions::new().prefix("object/");
                let iter = self.state.storage().list_with_options(opt).await?.entries();
                let mut item = iter.next()?;
                while !item.done() {
                    let (_durable_handle, durable_ref): (String, durable::DurableReference) =
                        item.value().into_serde()?;
                    durable
                        .post_by_id_hex(
                            &durable_ref.binding,
                            durable::DURABLE_DELETE_ALL,
                            durable_ref.id_hex.clone(),
                            &(),
                        )
                        .await?;
                    console_debug!(
                        "GarbageCollector: deleted {} instance {}",
                        durable_ref.binding,
                        durable_ref.id_hex
                    );
                    item = iter.next()?;
                }

                self.state.storage().delete_all().await?;
                Response::from_json(&())
            }

            _ => Err(int_err(format!(
                "GarbageCollector: unexpected request: method={:?}; path={:?}",
                req.method(),
                req.path()
            ))),
        }
    }
}
