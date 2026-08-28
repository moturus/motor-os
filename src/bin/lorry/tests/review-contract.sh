#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: review-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${LORRY_TEST_RUSTC:-}" ]; then
    # shellcheck source=current-toolchain.sh
    source "$SCRIPT_DIR/current-toolchain.sh"
    lorry_load_current_toolchain
fi
export RUSTC
RUSTC="$LORRY_TEST_RUSTC"
WORK="$(mktemp -d /tmp/lorry-review-contract-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PROJECT="$WORK/project"
HOME_DIR="$WORK/home"
REPOSITORY="$HOME_DIR/.config/lorry/vendor"
mkdir -p "$PROJECT/src" "$PROJECT/helper/src" \
    "$HOME_DIR/.config/lorry" "$REPOSITORY"

cat >"$PROJECT/Cargo.toml" <<'EOF'
[package]
name = "review-fixture"
version = "0.1.0"
edition = "2024"
license = "MIT"

[dependencies]
review-helper = { path = "helper" }
EOF
cat >"$PROJECT/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "review-fixture"
version = "0.1.0"
dependencies = ["review-helper"]

[[package]]
name = "review-helper"
version = "0.1.0"
EOF
cat >"$PROJECT/src/main.rs" <<'EOF'
fn main() {
    println!("{}", review_helper::answer());
}
EOF
cat >"$PROJECT/helper/Cargo.toml" <<'EOF'
[package]
name = "review-helper"
version = "0.1.0"
edition = "2024"
license = "MIT"
EOF
cat >"$PROJECT/helper/src/lib.rs" <<'EOF'
pub fn answer() -> u32 { 42 }
EOF
cat >"$HOME_DIR/.config/lorry/lorry.toml" <<EOF
config-version = 1

[repositories]
user = "$REPOSITORY"

[policy]
default = "allow"
EOF
cat >"$REPOSITORY/repository.toml" <<'EOF'
format-version = 1
object-hash = "sha256"
EOF

expect_failure() {
    local label="$1"
    local pattern="$2"
    shift 2
    if (cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" "$@") \
        >"$WORK/$label.stdout" 2>"$WORK/$label.stderr"; then
        echo "review-contract: $label unexpectedly succeeded" >&2
        exit 1
    fi
    grep -F "$pattern" "$WORK/$label.stderr" >/dev/null || {
        cat "$WORK/$label.stderr" >&2
        echo "review-contract: $label did not report '$pattern'" >&2
        exit 1
    }
}

echo "== Creating deterministic local dependency state =="
(cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" vendor --accept-all >/dev/null)

echo "== Proving review is read-only and committed =="
before="$(find "$PROJECT" "$REPOSITORY" -printf '%y %p %s %T@\n' | sort | sha256sum)"
(cd "$PROJECT" && HOME="$HOME_DIR" "$LORRY" review) >"$WORK/review.toml"
after="$(find "$PROJECT" "$REPOSITORY" -printf '%y %p %s %T@\n' | sort | sha256sum)"
[ "$before" = "$after" ] || {
    echo "review-contract: review changed project or repository state" >&2
    exit 1
}
commitment="$(sed -n 's/^review-sha256 = "\([0-9a-f]*\)"/\1/p' \
    "$PROJECT/.lorry/dependencies-v2.toml")"
[ "$(sha256sum "$WORK/review.toml" | cut -d' ' -f1)" = "$commitment" ] || {
    echo "review-contract: stdout does not match the committed review" >&2
    exit 1
}
expect_failure cargo-registry 'cannot be combined with `review`' \
    --use-cargo-registry review
sed -i 's/^review-sha256 = ".*"/review-sha256 = "0000000000000000000000000000000000000000000000000000000000000000"/' \
    "$PROJECT/.lorry/dependencies-v2.toml"
expect_failure stale-commitment "dependency state commitment does not match" review

echo "PASS: offline review contract"
