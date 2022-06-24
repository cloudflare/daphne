# Daphne

Daphne is a Rust implementation of the Distributed Aggregation Protocol
([DAP](https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap)) standard. DAP is
under active development in the PPM working group of the IETF.

This software is intended to support experimental DAP deployments and is not yet
suitable for use in production. Daphne will evolve along with the DAP draft:
Backwards compatibility with previous drafts won't be guaranteed until the draft
itself begins to stabilize. API-breaking changes between releases should also be
expected.

This repository contains two crates:

* `daphne` (aka "Daphne") -- Implementation of the core DAP protocol logic for
  Clients, Aggregators, and Collectors. This crate does not provide the
  complete, end-to-end functionality of any party. Instead, it defines traits
  for the functionalities that a concrete instantantiation of the protocol is
  required to implement. We call these functionalities "roles".

* `daphne_worker` (aka "Daphne-Worker") -- Implements a backend for the
  Aggregator roles based on [Cloudflare
  Workers](https://workers.cloudflare.com/). This crate also implements the
  various HTTP endpoints defined in the DAP spec.

## Testing

> NOTE These instructions will be changed as part of a planned refactor of
> Daphne-Worker and the tests. See issue
> [#1](https://github.com/cloudflare/daphne/issues/1) for details.

The `daphne` crate relies on unit tests. The `daphne_worker` crate contains a
number of integration and end-to-end tests that use
[miniflare](https://miniflare.dev/) to mock the Cloudflare Workers platform.
These can via docker-compose:

```
docker-compose up --build --abort-on-container-exit --exit-code-from test
```

However for development it's often more convenient to run miniflare directly.
Prerequisites:

* miniflare>=2.5.1

    ```
    nvm use 18.4.0 && npm install -g miniflare
    ```

* wrangler>=1.19.12

    ```
    npm install -g @cloudflare/wrangler
    ```

To run the Leader, first navigate to the `daphne_worker` directory. Then run

```
miniflare -p 8787 --env=tests/backend/leader.env --binding=DAP_ENV=dev
```

To run the Helper, in a separate terminal do

```
miniflare -p 8788 --env=tests/backend/helper.env --binding=DAP_ENV=dev
```

You can now `curl` the Leader or the Helper, or run the end-to-end tests via

```
DAP_ENV=dev cargo test --features=test_e2e -- --test-threads 1
```

The `daphne_worker` crate also has integration tests for
[Janus](https://github.com/divviup/janus). To run these, do

```
DAP_ENV=dev cargo test --features=test_janus -- --test-threads 1
```

## Acknowledgements

The name "Daphne" is credited to Cloudflare Research interns Tim Alberdingk
Thijm and James Larisch, who came up with the mame independently.
