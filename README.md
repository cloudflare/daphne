# Daphne

Daphne is a Rust implementation of the Distributed Aggregation Protocol
([DAP](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)) standard. DAP is
under active development in the PPM working group of the IETF.

Daphne currently implements:

* draft-ietf-ppm-dap-09
    * Prio3: draft-irtf-cfrg-vdaf-08
    * Taskprov extension: draft-wang-ppm-dap-taskprov-06
    * Interop test API: draft-dcook-ppm-dap-interop-test-design-07

The [repository](https://github.com/cloudflare/daphne) contains a number of
crates. The main one, `daphne`, implements the core DAP protocol logic for
Clients, Aggregators, and Collectors. This crate does not provide the complete,
end-to-end functionality of any party. Instead, it defines traits for the
functionalities that a concrete instantiation of the protocol is required to
implement. We call these functionalities "roles".

The remaining crates are not intended for general use:

* `daphne-server`, `daphne-worker`, `daphne-service-utils` -- Components of
  Cloudflare's backend for its DAP deployments. These crates are not intended
  for general use.

* `daphne-worker-test` -- Integration tests for `daphne` and Cloudflare's
  backend.

* `dapf` (short for "DAP Functions") -- CLI for interacting with DAP
  deployments. Some of its features are specific to Cloudflare's own
  deployment.


## Requirements

[Cap'n Proto](https://capnproto.org/) is required to build DAP.

```sh
# debian
apt install capnproto

# macos
brew install capnp
```

## Testing

The `daphne` crate relies on unit tests. To test integration with Cloudflare's
backend, run `make e2e`.
