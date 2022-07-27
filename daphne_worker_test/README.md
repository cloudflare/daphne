# Daphne-Worker Tests

This directory defines a deployment of Daphne-Worker for testing changes
locally. It also implements integration tests between Daphne and and
Daphne-Worker and interop tests with [Janus](https://github.com/divviup/janus).

[miniflare](https://miniflare.dev/) is used to mock the Cloudflare Workers
platform. For development it's often more convenient to run miniflare directly.
Prerequisites:

* miniflare>=2.5.1

    ```
    nvm use 18.4.0 && npm install -g miniflare
    ```

* wrangler>=1.19.12

    ```
    npm install -g @cloudflare/wrangler
    ```

To run the Leader, run

```
miniflare --port=8787 --env=leader.env --binding=DAP_DEPLOYMENT=dev
```

To run the Helper, in a separate terminal do

```
miniflare --port=8788 --env=helper.env --binding=DAP_DEPLOYMENT=dev
```

You can now `curl` the Leader or the Helper, or run the end-to-end tests via

```
DAP_DEPLOYMENT=dev cargo test --features=test_e2e -- --test-threads 1
```

The `daphne_worker` crate also has integration tests for
[Janus](https://github.com/divviup/janus). To run these, make sure that your
Docker environment is running and then do

```
DAP_DEPLOYMENT=dev cargo test --features=test_janus -- --test-threads 1
```
