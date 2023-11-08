# Daphne-Worker Tests

This directory defines a deployment of Daphne-Worker for testing changes
locally. It also implements integration tests between Daphne and
Daphne-Worker.

[Wrangler](https://github.com/cloudflare/wrangler2) (>=2.6.2) is used to mock
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

For integration tests with [Janus](https://github.com/divviup/janus), see the
[DAP Interop Test Runner](https://github.com/divergentdave/dap-interop-test-runner).
