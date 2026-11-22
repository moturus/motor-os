#!/bin/sh
# Run on the machine being tested. Motor invokes this script with Rush.
set -eu

case "$0" in */*) script_dir="${0%/*}" ;; *) script_dir=. ;; esac
ROOT_DIR="$(cd "$script_dir/../.." && pwd)"
BUILD=debug
RELEASE=
FULL=0
CORE=0
core_entry=0
LIST=0
OS=linux
[ ! -x /user/bin/rush ] || OS=motor
for option in "$@"; do
  case "$option" in
    --release) BUILD=release; RELEASE=--release ;;
    --full) FULL=1 ;;
    --core) CORE=1 ;;
    --list) LIST=1 ;;
    *) echo "usage: $0 [--release] [--full | --core] [--list]" >&2; exit 2 ;;
  esac
done
if [ "$FULL" = 1 ] && [ "$CORE" = 1 ]; then
  echo "usage: $0 [--release] [--full | --core] [--list]" >&2; exit 2
fi

fail() { echo "full-native-test: $*" >&2; exit 1; }

run_lorry() {
  if [ "$OS" = linux ]; then
    env HOME="$ROOT_DIR/build/native-test-inputs/home" "$LORRY" "$@"
  elif [ "${native_cxx_unwind:-0}" = 1 ]; then
    # Rush subshells do not isolate exports. Keep C-runtime linking on these
    # external commands so subsequent Rust-only suites use their own settings.
    if [ -n "${NATIVE_TEST_CAPS:-}" ]; then
      MOTOR_OS_CAPS="$NATIVE_TEST_CAPS" \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER=/user/bin/dev/cc \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS='-C link-self-contained=no -C default-linker-libraries=yes -L native=/user/lib/llvm/lib' \
        "$LORRY" "$@"
    else
      CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER=/user/bin/dev/cc \
        CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS='-C link-self-contained=no -C default-linker-libraries=yes -L native=/user/lib/llvm/lib' \
        "$LORRY" "$@"
    fi
  elif [ -n "${NATIVE_TEST_CAPS:-}" ]; then
    # The VM gate delegates the caller's test capabilities explicitly; the
    # runtime otherwise drops logging and detached-spawn authority on spawn.
    MOTOR_OS_CAPS="$NATIVE_TEST_CAPS" "$LORRY" "$@"
  else
    "$LORRY" "$@"
  fi
}

admit_crate() (
  features=
  all=
  no_default=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --features) features="${features:+$features,}$2"; shift ;;
      --all-features) all=--all-features ;;
      --no-default-features) no_default=--no-default-features ;;
      --) break ;;
    esac
    shift
  done
  # Explicit workspace selection also resets a prior variant's review scope.
  set -- vendor --locked --offline --accept-all --workspace $all $no_default
  [ -z "$features" ] || set -- "$@" --features "$features"
  run_lorry "$@"
)

# Run from the crate directory so both tools read its Cargo configuration.
# The list also supplies the workspaces whose sources the host must prepare.
test_crate() (
  crate="$1"
  shift
  subcommand="${crate_command:-test}"
  # --core runs only the crates listed through core_crate.
  if [ "$CORE" = 1 ] && [ "$core_entry" != 1 ]; then exit 0; fi
  profile="$RELEASE"
  for argument in "$@"; do
    [ "$argument" != --profile ] || profile=
  done
  if [ "$LIST" = 1 ]; then
    printf '%s' "$crate"
    printf ' %s' "$@"
    printf '\n'
    exit
  fi
  cd "$ROOT_DIR/$crate"
  echo "full-native-test: $OS $crate $* ($BUILD)"
  if [ "$OS" = linux ]; then
    cargo "$subcommand" --locked --offline $profile "$@"
    # The core gate tests the OS crates; Lorry on Linux is not part of it.
    [ "$CORE" = 0 ] || exit 0
    if [ "$crate" = src/sys/tools/wg ]; then
      # Linux cdylib support in Lorry is outside the image-layout migration.
      echo 'full-native-test: WireGuard uses Cargo only on Linux'
      exit
    fi
  fi
  admit_crate "$@"
  run_lorry "$subcommand" --locked --offline $profile "$@"
)

# Builds a test program and runs it directly, as `lorry run`.
run_crate() (
  crate_command=run
  test_crate "$@"
)

test_cxx_unwind() (
  native_cxx_unwind=1
  test_crate src/sys/tests/unwind --features cxx "$@"
)

# A crate that src/tests/core-test.sh also runs.
core_crate() {
  core_entry=1
  test_crate "$@"
  core_entry=0
}

native_crates() {
  if [ "$OS" = linux ]; then
    # Colored's ANSI round-trip assertions depend on color being enabled.
    NO_COLOR= test_crate build/crossterm-host/source --lib --no-default-features --features events
    NO_COLOR= test_crate build/crossterm-host/source --lib --no-default-features --features events,use-dev-tty
    test_crate src/sys/tests/cross-peer
    test_crate src/bin/gix --test https-server
  fi
  test_crate src/sys/tests/rust-analyzer
  for crate in red rmux rush russhd curl lorry; do
    test_crate "src/bin/$crate"
  done
  test_crate src/bin/httpd-axum --tests
  test_crate src/bin/gix --features native-test-support --lib --test native-port --test cli
  test_crate src/bin/rnetbench
  test_crate src/sys/tools/wg
  core_crate src/sys/sys-init --lib
  core_crate src/sys/lib/moto-rt
  core_crate src/sys/lib/moto-sys
  core_crate src/sys/lib/moto-sdk
  core_crate src/sys/lib/moto-sdk --no-default-features
  core_crate src/sys/lib/frusa
  core_crate src/sys/lib/memfs
  core_crate src/sys/tests/unwind
  test_cxx_unwind
  test_crate src/sys/tests/unwind --profile release-lto
  test_cxx_unwind --profile release-lto
  test_crate src/sys/tests/unwind --profile release-abort
  test_cxx_unwind --profile release-abort
  test_crate src/sys/tests/wasm-smoke-suite
  if [ "$OS" = linux ]; then
    core_crate src/sys/lib/motor-fs --features image-admin
    test_crate src/bin/rush --features dev-tty --test phase8
  else
    if [ "$LIST" != 1 ]; then
      echo 'SKIP Motor motor-fs unit tests: they need tokio and a file-backed device; see docs/plans/future-work.md'
    fi
    core_crate src/sys/tools/sysbox
    run_crate src/sys/tests/systest
    # The stdlib Command formatting tests live next to systest.
    test_crate src/sys/tests/systest --test command_debug
    run_crate src/sys/tests/mio-test
    run_crate src/sys/tests/tokio-tests
    test_crate src/sys/tests/crossterm-smoke
    test_crate src/sys/tests/toolchain
    test_crate src/sys/tests/javy-smoke --test installed
    test_crate src/sys/tests/wasmtime-smoke --test installed
  fi
  net_features=async,assembler-max-segment-count-32,fragmentation-buffer-size-65536,iface-neighbor-cache-count-64,medium-ethernet,medium-ip,proto-ipv4,proto-ipv4-fragmentation,proto-ipv6,proto-ipv6-fragmentation,reassembly-buffer-count-4,reassembly-buffer-size-65536,socket-dhcpv4,socket-icmp,socket-tcp,socket-udp
  # On Motor these run in debug only: Lorry needs 3.5 minutes there to build
  # them in release, and Linux runs them in both profiles.
  if [ "$OS" = linux ] || [ "$BUILD" = debug ]; then
    core_crate src/sys/sys-io/netstack --no-default-features --features "$net_features"
    core_crate src/sys/sys-io/netstack --no-default-features --features "$net_features,proto-ipv6-slaac" --lib iface::
  elif [ "$LIST" != 1 ]; then
    echo 'SKIP Motor netstack unit tests in release: they run in debug; see docs/plans/future-work.md'
  fi
}

if [ "$LIST" = 1 ]; then
  native_crates
  exit
fi

export CARGO_NET_OFFLINE=true
unset MOTOR_TEST_RELEASE
if [ "$BUILD" = release ]; then export MOTOR_TEST_RELEASE=1; fi
if [ "$OS" = linux ]; then
  # Pin subprocesses too: tests create workspaces outside the checkout.
  RUSTC="$(cd "$ROOT_DIR" && rustup which rustc)"
  export RUSTC
  export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
  [ -f "$ROOT_DIR/build/native-test-inputs/home/.config/lorry/lorry.toml" ] ||
    fail 'prepare locked sources with src/build-scripts/native-test-inputs.sh first'
  if [ -z "${LORRY:-}" ]; then
    (cd "$ROOT_DIR/src/bin/lorry" && cargo build --locked --offline --release)
    LORRY="$ROOT_DIR/src/bin/lorry/target/release/lorry"
  fi
else
  LORRY="${LORRY:-/user/bin/dev/lorry}"
fi
[ -x "$LORRY" ] || fail "Lorry is not executable: $LORRY"
export LORRY

if [ "$CORE" = 1 ]; then
  native_crates
  echo "full-native-test: PASS ($OS, $BUILD, core)"
  exit
fi

# Give the curl harness a fresh output directory so an old test executable
# cannot be mistaken for the one built from the current working tree.
curl_target="$ROOT_DIR/target/native-curl-$BUILD-$$"
if [ "$OS" = motor ]; then
  MOTOR_OS_CAPS=0x204 mkdir -p "$curl_target"
else
  mkdir -p "$curl_target"
fi
trap 'rm -r "$curl_target"' EXIT
(
  cd "$ROOT_DIR/src/bin/curl"
  if [ "$OS" = linux ]; then
    cargo test --locked --offline $RELEASE --no-run --test https --target-dir "$curl_target"
  else
    admit_crate
    run_lorry test --locked --offline $RELEASE --no-run --test https --target-dir "$curl_target"
  fi
)
curl_output="$curl_target/$BUILD"
[ "$OS" != motor ] || curl_output="$curl_target/lorry/$BUILD"
LORRY_TEST_CURL="$curl_output/curl"
LORRY_TEST_TLS_SERVER=
for candidate in "$curl_output"/build/curl/*/*/https-*; do
  # None-created dependency files can retain execute access for Interactive.
  case "$candidate" in *.d) continue ;; esac
  [ -f "$candidate" ] && [ -x "$candidate" ] || continue
  [ -z "$LORRY_TEST_TLS_SERVER" ] || fail 'multiple HTTPS harnesses in fresh curl output'
  LORRY_TEST_TLS_SERVER="$candidate"
done
[ -x "$LORRY_TEST_CURL" ] || fail 'curl fixture executable was not built'
[ -n "$LORRY_TEST_TLS_SERVER" ] || fail 'curl HTTPS harness was not built'
LORRY_TEST_CA="$ROOT_DIR/src/bin/curl/tests/test-ca.pem"
LORRY_TEST_HOSTNAME_CA="$ROOT_DIR/src/bin/curl/tests/hostname-ca.pem"
LORRY_TEST_UNTRUSTED_CA="$ROOT_DIR/img_files/motor-os-base/system/cfg/ssl/ssl-cert.pem"
export LORRY_TEST_CURL LORRY_TEST_TLS_SERVER LORRY_TEST_CA
export LORRY_TEST_HOSTNAME_CA LORRY_TEST_UNTRUSTED_CA

native_crates
test_crate src/bin/lorry --bin lorry 'curl::tests::' -- --ignored
if [ "$FULL" = 1 ]; then
  test_crate src/bin/lorry --test native_helix native_helix -- --ignored
fi
echo "full-native-test: PASS ($OS, $BUILD)"
