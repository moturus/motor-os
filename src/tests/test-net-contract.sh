#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# Networking remains async-first; blocking policy belongs to the VDSO.
if matches=$(grep -RnE --include='*.rs' \
    'SysCpu::spawn|block_on_sync|SyncWaiter|thread::sleep|sched_yield' \
    "$ROOT_DIR/src/sys/lib/moto-io/src/net" | \
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*//'); then
  echo "moto-io networking contains blocking operations:" >&2
  echo "$matches" >&2
  exit 1
fi

feature_graph() {
  cargo tree --manifest-path "$ROOT_DIR/src/sys/Cargo.toml" \
    --target x86_64-unknown-motor --locked --offline -p "$1" \
    -e normal,build --prefix none --format '{p} features=[{f}]'
}

# Each production package builds independently, just as in the Makefile.
# Including systest here would unify its test features into the services.
for package in rt sys-io sys-init sys-tty strobe dns-resolver sysbox; do
  graph=$(feature_graph "$package")
  if matches=$(printf '%s\n' "$graph" | \
      grep -E 'features=\[([^]]*,)?test-support(,|\])'); then
    echo "$package enables test-support in production:" >&2
    echo "$matches" >&2
    exit 1
  fi
done

graph=$(feature_graph systest)
printf '%s\n' "$graph" | \
  grep -E '^moto-io .*features=\[([^]]*,)?test-support(,|\])' >/dev/null
echo "network async and production feature contracts PASS"
