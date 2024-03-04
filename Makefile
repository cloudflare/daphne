e2e: /tmp/private-key /tmp/certificate
	export HPKE_SIGNING_KEY="$$(cat /tmp/private-key)"; \
	export E2E_TEST_HPKE_SIGNING_CERTIFICATE="$$(cat /tmp/certificate)"; \
	docker-compose -f daphne_server/docker-compose-e2e.yaml up --build --abort-on-container-exit --exit-code-from test

/tmp/private-key:
	openssl ecparam -name prime256v1 -genkey -noout -out $@

/tmp/certificate:
	openssl req -key /tmp/private-key -new -x509 -days 1 -out /tmp/certificate -subj '/C=US/L=Palo Alto/O=Cloudflare Lda/CN=dap.cloudflare.com'
