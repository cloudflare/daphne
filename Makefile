# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

.PHONY: accept acceptance e2e load

leader:
	RUST_LOG=hyper=off,debug cargo run \
		--profile release-symbols \
		--features test-utils \
		--example service \
		-- \
		-c ./crates/daphne-server/examples/configuration-leader.toml
l: leader

helper:
	RUST_LOG=hyper=off,debug cargo run \
		--profile release-symbols \
		--features test-utils \
		--example service \
		-- \
		-c ./crates/daphne-server/examples/configuration-helper.toml
h: helper

storage-proxy:
	docker compose -f ./crates/daphne-worker-test/docker-compose-storage-proxy.yaml up --build
s: storage-proxy

e2e: /tmp/private-key /tmp/certificate
	export HPKE_SIGNING_KEY="$$(cat /tmp/private-key)"; \
	export E2E_TEST_HPKE_SIGNING_CERTIFICATE="$$(cat /tmp/certificate)"; \
	docker compose -f ./crates/daphne-server/docker-compose-e2e.yaml up \
		--no-attach leader_storage \
		--no-attach helper_storage \
		--build \
		--abort-on-container-exit \
		--exit-code-from test

build_interop:
	docker build . -f ./interop/Dockerfile.interop_helper --tag daphne-interop

run_interop:
	docker run -it -p 8788:8788 -P daphne-interop --name daphne-interop

/tmp/private-key:
	openssl ecparam -name prime256v1 -genkey -noout -out $@

/tmp/certificate:
	openssl req -key /tmp/private-key -new -x509 -days 1 -out /tmp/certificate -subj '/C=US/L=Palo Alto/O=Cloudflare Lda/CN=dap.cloudflare.com'

reset-storage:
	-cargo run --bin dapf -- test-routes clear-storage -s p256_hkdf_sha256 http://localhost:8787/v09/
	-cargo run --bin dapf -- test-routes clear-storage -s p256_hkdf_sha256 http://localhost:8788/v09/
