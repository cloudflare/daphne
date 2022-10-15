# Daphne-Worker Tests

This directory defines a deployment of Daphne-Worker for testing changes
locally. It also implements integration tests between Daphne and and
Daphne-Worker and interop tests with [Janus](https://github.com/divviup/janus).

[Wrangler](https://github.com/cloudflare/wrangler2) (>=2.1.11) is used to mock
the Cloudflare Workers platform for local testing. Wrangler is available from
npm. To run the Leader, do

```
npx wrangler dev -e leader --port 8787 --local
```

To run the Helper, in a separate terminal do

```
npx wrangler dev -e helper --port 8788 --local
```

You can now `curl` the Leader or the Helper, or run the end-to-end tests via

```
DAP_DEPLOYMENT=dev cargo test --features=test_e2e -- --test-threads 1
```

The `daphne_worker` crate also has integration tests for
[Janus](https://github.com/divviup/janus). To run these, make sure that your
Docker environment is running and then do

> TODO(issue #138) Re-enable the Janus interop tests. Daphne implements DAP-02,
> but Janus implements DAP-01. These tests are expected to fail until Janus is
> upgraded.

```
DAP_DEPLOYMENT=dev cargo test --features=test_janus -- --test-threads 1
```
