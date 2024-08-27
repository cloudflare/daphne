# The implementation of the DAP server

## Running the server locally

All of these commands are run from the root of the repo.

### Starting the storage layer

```sh
make storage
```

This should start the storage for both the leader and the helper, exposed at
ports 4000 and 4001 respectively.


### Running the leader/helper

**Leader**:
```sh
make leader
```
The leader listens on port `8787`

**Helper**:
```sh
make helper
```
The leader listens on port `8788`

### Adding an hpke config

The hpke config must be added everytime the storage layer is started as no state
is persisted across runs.

**Leader:**
```
cargo run --bin dapf -- test-routes add-hpke-config http://localhost:8787/v09/ --kem-alg x25519_hkdf_sha256
```

**Helper:**
```
cargo run --bin dapf -- test-routes add-hpke-config http://localhost:8788/v09/ --kem-alg x25519_hkdf_sha256
```

### Clearing all of storage without restaring docker

```
cargo run --bin dapf -- test-routes clear-storage --help
```
