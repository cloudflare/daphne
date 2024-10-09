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
```
dapf hpke generate
```

With a specific algorithm:
```
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
