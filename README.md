# Daphne

## Integration tests

[miniflare](https://miniflare.dev/) is used to test integration of Daphne-Worker
with Daphne. These tests can be run from Docker:

```
docker-compose up --build --abort-on-container-exit --exit-code-from test
```

## Development environment

During development it is convenient to run miniflare locally.

> NOTE: In order to run `miniflare` you also need to install the proper version
> of `worker-build`. See TODO in tests/backend/miniflare.Dockerfile. Note that
> this is a temporary workaround.

While iterating on the code it's often helpful to bypass docker-compose so that
you don't have to wait for Docker containers to rebuild. Here are instructions
for getting the Leader and Helper running without Docker.

The Worker is built on [workers-rs](https://github.com/cloudflare/workers-rs).
You'll need wrangler >= 1.19.5 in order to build it. We mock the Workers
platform locally using [miniflare](https://github.com/cloudflare/miniflare). To
get it to work you'll also need to upgrade node to the latest version.

```
$ nvm use 18.4.0 && npm install -g miniflare@2.5.1
```

To run the Leader: from the `daphne_worker` directory, do

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

To run [Janus](https://github.com/divviup/janus) interop tests, do

```
DAP_ENV=dev cargo test --features=test_janus -- --test-threads 1
```
