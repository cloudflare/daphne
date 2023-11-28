# Daphne

Daphne is a Rust implementation of the Distributed Aggregation Protocol
([DAP](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/)) standard. DAP is
under active development in the PPM working group of the IETF.

Daphne currently implements:

* draft-ietf-ppm-dap-02
    * VDAF: draft-irtf-cfrg-vdaf-03
    * Taskprov extension: draft-wang-ppm-dap-taskprov-02
* draft-ietf-ppm-dap-09
    * VDAF: draft-irtf-cfrg-vdaf-08
    * Taskprov extension: draft-wang-ppm-dap-taskprov-06

This software is intended to support experimental DAP deployments and is not yet
suitable for use in production. Daphne will evolve along with the DAP draft:
Backwards compatibility with previous drafts won't be guaranteed until the draft
itself begins to stabilize. API-breaking changes between releases should also be
expected.

The [repository](https://github.com/cloudflare/daphne) contains three crates:

* `daphne` (aka "Daphne") -- Implementation of the core DAP protocol logic for
  Clients, Aggregators, and Collectors. This crate does not provide the
  complete, end-to-end functionality of any party. Instead, it defines traits
  for the functionalities that a concrete instantantiation of the protocol is
  required to implement. We call these functionalities "roles".

* `daphne_worker` (aka "Daphne-Worker") -- Implements a backend for the
  Aggregator roles based on [Cloudflare
  Workers](https://workers.cloudflare.com/). This crate also implements the
  various HTTP endpoints defined in the DAP spec.

* `daphne_worker_test` -- Defines a deployment of Daphne-Worker for testing
  changes locally. It also implements integration tests for Daphne and
  Daphne-Worker.

## Testing

The `daphne` crate relies on unit tests. The `daphne_worker` crate relies mostly
on integration tests implemented in `daphne_worker_test`. See the README in that
directory for instructions on running Daphne-Worker locally.

Integration tests can be run via docker-compose.

```
docker-compose up --build --abort-on-container-exit --exit-code-from test
```

For integration tests with [Janus](https://github.com/divviup/janus), see the
[DAP Interop Test Runner](https://github.com/divergentdave/dap-interop-test-runner).

## Acknowledgements

Thanks to Yoshimichi Nakatsuka who contributed significantly to Daphne during
his internship at Cloudflare Research. Thanks to Brandon Pitman and David Cook
for testing, reporting bugs, and sending patches.

The name "Daphne" is credited to Cloudflare Research interns Tim Alberdingk
Thijm and James Larisch, who came up with the name independently.
