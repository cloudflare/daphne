# dapf (DAP functions)

This binary provides various functions that can be called to interact with DAP
deployments.

Its subcommands and their functionality can be consulted with the built in
help pages the CLI provides.


## Examples

Here are some examples of common functionality of dapf. To avoid installing the
tool replace all instances of `dapf` with `cargo run --bin dapf`.

### Generate an hpke config

With the default algorithm:
```sh
dapf hpke generate
```

With a specific algorithm:
```sh
dapf hpke generate x25519_hkdf_sha256
```

This will output the config twice.

First the receiver config JSON:
```json
{
  "config": {
    "id": 155,
    "kem_id": "x25519_hkdf_sha256",
    "kdf_id": "hkdf_sha256",
    "aead_id": "aes128_gcm",
    "public_key": "a63dd7e6bbfc68d54e8b25e39ceb826cdf5101592a026590cb935d754e4f210d"
  },
  "private_key": "a5adeefcb0e09053e6ebded53277b65c81412c8eafadfe5706aef3453d45b05c"
}
```

Second as a [DAP encoded][hpke-config-encoding] + base64 encoded string which can be
used when issuing requests to `internal/test/add_task`:
```
DAP and base64 encoded hpke config: mwAgAAEAAQAgpj3X5rv8aNVOiyXjnOuCbN9RAVkqAmWQy5NddU5PIQ0
```

### Using the interop api defined by draft-dcook-ppm-dap-interop-test-design-07

Draft: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-07

#### Generating the requert payload for `internal/test/add_task`

Using `dapf test-routes create-add-task-json` the json used for adding a new
testing task can be easily created.

All the parameters of this task can be passed through commandline options, the
parameters that aren't passed in are then asked interactively.

```sh
Options:
      --task-id <TASK_ID>
      --leader-url <LEADER_URL>
      --helper-url <HELPER_URL>
      --vdaf <VDAF>
      --leader-auth-token <LEADER_AUTH_TOKEN>
      --collector-authentication-token <COLLECTOR_AUTHENTICATION_TOKEN>
      --role <ROLE>
      --query <QUERY>
      --min-batch-size <MIN_BATCH_SIZE>
      --collector-hpke-config <COLLECTOR_HPKE_CONFIG>
      --time-precision <TIME_PRECISION>
      --expires-in-seconds <EXPIRES_IN_SECONDS>
```

Using this command should output something like this, which you can then use to
issue requests to `internal/test/add_task`
```json
{
  "task_id": "QXI0XDeCY06OtcHMWxwEyuLwe-MzUWQvBTlFXNl-H4U",
  "leader": "http://leader/",
  "helper": "http://helper/",
  "vdaf": {
    "type": "Prio3SumVecField64MultiproofHmacSha256Aes128",
    "bits": "1",
    "length": "100000",
    "chunk_length": "320"
  },
  "leader_authentication_token": "I-am-the-leader",
  "role": "helper",
  "vdaf_verify_key": "dJXXtUfRAdIJ7z87revcZpqXZ16nbF9HB9OyZ1CMHxM",
  "query_type": 2,
  "min_batch_size": 10,
  "time_precision": 3600,
  "collector_hpke_config": "gwAgAAEAAQAgPMw62iLcCzNn0DHqSwKHanelnvMrWhwGEJVSpRpzmhM",
  "task_expiration": 1729263391
}
```

### Decoding responses from aggregators


#### Decoding aggregate shares

Once you've collected from the leader you may want to see what the result of the
aggregation was, for that you can use the `decode` subcommand:

```sh
dapf decode ./aggregate_share collection \
    --vdaf-config '{"prio3": { "sum": { "bits": 8 } } }' \
    --task-id "8TuT5Z5fAuutsX9DZWSqkUw6pzDl96d3tdsDJgWH2VY" \
    --hpke-config-path ./hpke-config.json
```

[hpke-config-encoding]: https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-09#section-4.4.1-6
