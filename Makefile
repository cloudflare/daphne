# Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

.PHONY: accept acceptance e2e load

leader:
	cargo run --features test-utils --example service -- -c ./daphne_server/examples/configuration-leader.toml

helper:
	cargo run --features test-utils --example service -- -c ./daphne_server/examples/configuration-helper.toml

storage_proxy:
	docker-compose -f ./daphne_worker_test/docker-compose-storage-proxy.yaml up --build

e2e: /tmp/private-key /tmp/certificate
	export HPKE_SIGNING_KEY="$$(cat /tmp/private-key)"; \
	export E2E_TEST_HPKE_SIGNING_CERTIFICATE="$$(cat /tmp/certificate)"; \
	docker-compose -f daphne_server/docker-compose-e2e.yaml up --build --abort-on-container-exit --exit-code-from test

build_interop:
	docker build . -f ./interop/Dockerfile.interop_helper --tag daphne_interop

run_interop:
	docker run -it -p 8788:8788 -P daphne_interop --name daphne_interop

/tmp/private-key:
	openssl ecparam -name prime256v1 -genkey -noout -out $@

/tmp/certificate:
	openssl req -key /tmp/private-key -new -x509 -days 1 -out /tmp/certificate -subj '/C=US/L=Palo Alto/O=Cloudflare Lda/CN=dap.cloudflare.com'
