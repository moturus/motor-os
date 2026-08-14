#!/usr/bin/env bash
set -euo pipefail
export CARGO_NET_OFFLINE=true

if [ "$#" -ne 1 ]; then
    echo "usage: review-contract.sh LORRY" >&2
    exit 1
fi

LORRY="$(realpath "$1")"
LORRY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROOT_DIR="$(cd "$LORRY_DIR/../../.." && pwd)"
TOOLCHAIN="nightly-2026-06-19"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export TMPDIR="$WORK/tmp"
mkdir "$TMPDIR"

unset CARGO_TARGET_DIR RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
export LORRY_REVIEW_REAL_RUSTC
LORRY_REVIEW_REAL_RUSTC="$(rustup which rustc --toolchain "$TOOLCHAIN")"

SOURCE="$WORK/source"
PROJECT="$SOURCE/src/bin/lorry"
LOCAL_REPOSITORY="$WORK/local-repository"
mkdir -p "$PROJECT" "$SOURCE/src/sys/lib" \
    "$LOCAL_REPOSITORY/objects/crates-io/sha256" \
    "$LOCAL_REPOSITORY/objects/seeded-git/sha256"
cp "$LORRY_DIR/Cargo.toml" "$LORRY_DIR/Cargo.lock" "$PROJECT/"
cp -R "$LORRY_DIR/src" "$LORRY_DIR/.lorry" "$PROJECT/"
cp -R "$ROOT_DIR/src/sys/lib/moto-rt" "$SOURCE/src/sys/lib/"
cp "$HOME/.config/lorry/system/vendor/repository.toml" "$LOCAL_REPOSITORY/"

FAKE_RUSTC="$WORK/rustc-inspection-host"
cat > "$FAKE_RUSTC" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -eq 2 ] && [ "$1" = "--version" ] && [ "$2" = "--verbose" ]; then
    "$LORRY_REVIEW_REAL_RUSTC" "$@" |
        sed 's/^host: .*/host: aarch64-unknown-linux-gnu/'
else
    exec "$LORRY_REVIEW_REAL_RUSTC" "$@"
fi
EOF
chmod 0700 "$FAKE_RUSTC"
cat > "$PROJECT/lorry.toml" <<EOF
config-version = 1

[toolchain]
rustc = "$FAKE_RUSTC"

[repositories]
local = "$LOCAL_REPOSITORY"
EOF

snapshot() {
    local output="$1"
    shift
    : > "$output"
    for root in "$@"; do
        if [ -e "$root" ]; then
            find "$root" -printf '%y %P %s %m %T@\n' | sort >> "$output"
            find "$root" -type f -print0 | sort -z | xargs -0 sha256sum >> "$output"
        fi
    done
}

expect_failure() {
    local label="$1"
    local pattern="$2"
    local project="$3"
    shift 3
    if (cd "$project" && "$LORRY" "$@") \
        > "$WORK/$label.stdout" 2> "$WORK/$label.stderr"; then
        echo "review-contract: $label unexpectedly succeeded" >&2
        exit 1
    fi
    if [ -s "$WORK/$label.stdout" ]; then
        echo "review-contract: $label wrote partial stdout" >&2
        exit 1
    fi
    if ! grep -Fq "$pattern" "$WORK/$label.stderr"; then
        echo "review-contract: $label did not report '$pattern'" >&2
        cat "$WORK/$label.stderr" >&2
        exit 1
    fi
}

REPOSITORIES=(
    "$HOME/.config/lorry/system/vendor"
    "$HOME/.config/lorry/vendor"
    "$LOCAL_REPOSITORY"
)
snapshot "$WORK/before.snapshot" "$SOURCE" "${REPOSITORIES[@]}"
(cd "$PROJECT" && "$LORRY" review) > "$WORK/review.toml"
(cd "$PROJECT" && "$LORRY" \
    +"$TOOLCHAIN" --verbose --color=always review) > "$WORK/review-globals.toml"
cmp "$WORK/review.toml" "$WORK/review-globals.toml"

commitment="$(sed -n 's/^review-sha256 = "\([0-9a-f]*\)"/\1/p' \
    "$PROJECT/.lorry/dependencies-v2.toml")"
actual="$(sha256sum "$WORK/review.toml" | cut -d' ' -f1)"
if [ "$actual" != "$commitment" ]; then
    echo "review-contract: stdout does not match the committed review" >&2
    exit 1
fi
if [ -e "$PROJECT/target" ]; then
    echo "review-contract: review created a project target directory" >&2
    exit 1
fi
snapshot "$WORK/after.snapshot" "$SOURCE" "${REPOSITORIES[@]}"
cmp "$WORK/before.snapshot" "$WORK/after.snapshot"

expect_failure cargo-registry 'cannot be combined with `review`' "$PROJECT" \
    --use-cargo-registry review

STALE_PROJECT="$SOURCE/src/bin/lorry-stale"
cp -R "$PROJECT" "$STALE_PROJECT"
sed -i 's/^review-sha256 = ".*"/review-sha256 = "0000000000000000000000000000000000000000000000000000000000000000"/' \
    "$STALE_PROJECT/.lorry/dependencies-v2.toml"
expect_failure stale-commitment "dependency state commitment does not match" \
    "$STALE_PROJECT" review

MISSING_PROJECT="$SOURCE/src/bin/lorry-missing"
cp -R "$PROJECT" "$MISSING_PROJECT"
rm "$MISSING_PROJECT/.lorry/dependencies-v2.toml"
expect_failure missing-state "requires generated Lorry dependency state" \
    "$MISSING_PROJECT" review

CHECKSUM="9481c1c90cbf2ac953f07c8d4a58aa3945c425b7185c9154d67a65e4230da511"
mkdir -p "$LOCAL_REPOSITORY/objects/crates-io/sha256/${CHECKSUM:0:2}/$CHECKSUM"
expect_failure missing-evidence "corrupt object in local repository" "$PROJECT" review
if find "$TMPDIR" -mindepth 1 -print -quit | grep -q .; then
    echo "review-contract: review left temporary inspection data" >&2
    exit 1
fi

echo "PASS: offline review contract"
