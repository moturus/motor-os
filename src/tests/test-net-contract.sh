#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# Networking remains async-first; blocking policy belongs to the VDSO.
if matches=$(grep -RnE --include='*.rs' \
    'SysCpu::spawn|block_on_sync|SyncWaiter|thread::sleep|sched_yield' \
    "$ROOT_DIR/src/sys/lib/moto-sdk/src/io/net" | \
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*//'); then
  echo "moto-sdk networking contains blocking operations:" >&2
  echo "$matches" >&2
  exit 1
fi

feature_graph() {
  cargo tree --manifest-path "$1" --target "$2" --locked --offline -p "$3" \
    -e normal,build --prefix none --format '{p} features=[{f}]'
}

no_test_support() {
  local graph matches
  graph=$(feature_graph "$@")
  if matches=$(printf '%s\n' "$graph" | \
      grep -E 'features=\[([^]]*,)?test-support(,|\])'); then
    echo "$3 enables test-support in production:" >&2
    echo "$matches" >&2
    exit 1
  fi
}

# Each production package builds independently, just as in the Makefile.
# Including systest here would unify its test features into the services.
MOTOR=x86_64-unknown-motor
for package in rt sys-io sys-init sys-tty strobe dns-resolver sysbox; do
  no_test_support "$ROOT_DIR/src/sys/Cargo.toml" "$MOTOR" "$package"
done
# Programs outside src/sys take the same SDK.
HOST="$(rustc -vV | sed -n 's/^host: //p')"
no_test_support "$ROOT_DIR/src/bin/russhd/Cargo.toml" "$MOTOR" russhd
no_test_support "$ROOT_DIR/src/bin/rmux/Cargo.toml" "$MOTOR" rmux
no_test_support "$ROOT_DIR/src/imager/Cargo.toml" "$HOST" imager

# rt.vdso builds with core and alloc only, so nothing may turn on the SDK's std.
if feature_graph "$ROOT_DIR/src/sys/Cargo.toml" "$MOTOR" rt | \
    grep -E '^moto-sdk .*features=\[([^]]*,)?std(,|\])' >&2; then
  echo "rt.vdso enables moto-sdk's std" >&2
  exit 1
fi
# The SDK's Unix slice takes no Motor OS crates.
if feature_graph "$ROOT_DIR/src/imager/Cargo.toml" "$HOST" imager | \
    grep -E '^moto-(rt|sys) ' >&2; then
  echo "the imager's SDK pulls in Motor OS crates on $HOST" >&2
  exit 1
fi

graph=$(feature_graph "$ROOT_DIR/src/sys/Cargo.toml" "$MOTOR" systest)
printf '%s\n' "$graph" | \
  grep -E '^moto-sdk .*features=\[([^]]*,)?test-support(,|\])' >/dev/null
echo "network async and production feature contracts PASS"
