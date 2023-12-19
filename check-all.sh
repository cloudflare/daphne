#!/bin/bash

r() {
    echo "🔄 '$*'"
    if "$@"; then
        echo "✅ '$*'"
    else
        echo "❌ '$*'"
        exit 1
    fi
}

mode=${1:-lint}

case "$mode" in
    lint)
        r cargo clippy -p daphne --tests
        r cargo clippy -p daphne --features send-traits --tests
        r cargo clippy --bin dapf
        r cargo clippy -p daphne_worker --tests
        r cargo clippy -p daphne-worker-test --tests
        r cargo clippy -p daphne-worker-test --tests --features test_e2e
        r cargo clippy -p daphne_server --tests
        r cargo clippy --example service
        ;;

    test)
        r cargo test -p daphne
        r cargo test -p daphne --features send-traits
        r cargo test -p daphne_service_utils
        r cargo test -p daphne_worker
        r cargo test -p daphne-worker-test
        r cargo test -p daphne_server
        ;;
esac

