#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROUTER="$SCRIPT_DIR/test-changed.sh"

expect_gate() {
    local expected="$1"
    shift
    local actual
    actual="$($ROUTER --print -- "$@")"
    [ "$actual" = "$expected" ] || {
        echo "gate routing: expected $expected, got $actual for: $*" >&2
        exit 1
    }
}

expect_gate none src/bin/lorry/AGENTS.md
expect_gate none src/bin/lorry/make-it-faster.md
expect_gate none src/bin/lorry/docs/example.md
expect_gate fast src/bin/lorry/src/engine.rs
expect_gate fast src/bin/lorry/step-8-review.md src/bin/lorry/src/engine.rs
expect_gate acceptance src/bin/lorry/src/archive.rs
expect_gate exhaustive src/bin/lorry/src/cache.rs
expect_gate exhaustive src/bin/lorry/src/identity.rs
expect_gate exhaustive src/bin/lorry/src/native_tool.rs
expect_gate exhaustive src/bin/lorry/bootstrap/stage2-seed.toml
expect_gate exhaustive src/bin/lorry/tests/test-fast.sh
expect_gate exhaustive src/tests/lorry-native-integration.sh
expect_gate full-test src/sys/lib/moto-rt/src/lib.rs
expect_gate full-test src/bin/lorry/src/engine.rs src/tests/full-test.sh

echo "PASS: Lorry changed-path gate routing"
