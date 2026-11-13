#!/usr/bin/env bash
# Offline contracts for collecting and repackaging native development payloads.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/src/build-scripts/toolchain-overlays.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "test-toolchain-archive: $*" >&2; exit 1; }
defaults="$WORK/repo/img_files/motor-os-dev"
mkdir -p "$defaults/user/bin/dev" "$defaults/user/lib/www" \
    "$defaults/user/cfg/cargo" "$defaults/none/cfg" "$WORK/bin"
for command in lorry gix mdbg imager; do
    printf '%s\n' "$command" > "$WORK/bin/$command"
done
printf 'launcher\n' > "$defaults/user/bin/dev/www"
printf 'documentation\n' > "$defaults/user/lib/www/index.html"
printf 'Cargo defaults\n' > "$defaults/user/cfg/cargo/config.toml"
printf 'user PATH\n' > "$defaults/user/cfg/rush.cfg"
printf 'SSH PATH\n' > "$defaults/user/cfg/sshd.toml"
printf 'None defaults\n' > "$defaults/none/cfg/lorry.toml"
for overlay in "${MOTOR_TOOLCHAIN_OVERLAYS[@]}"; do
    [ "$overlay" != motor ] || continue
    mkdir -p "$WORK/assembly/$overlay/user/lib/$overlay"
    printf '%s\n' "$overlay" > "$WORK/assembly/$overlay/user/lib/$overlay/payload"
done
toolchain_collect_overlays "$WORK/repo" "$WORK/bin" "$WORK/assembly" \
    "$WORK/bin/imager" "$WORK/current"
for path in user/bin/dev/lorry user/bin/dev/gix user/bin/dev/mdbg user/bin/dev/www \
    user/lib/www/index.html user/lib/imager/imager user/cfg/cargo/config.toml \
    none/cfg/lorry.toml; do
    [ -f "$WORK/current/motor/$path" ] || fail "missing $path"
done
for path in user/bin/dev/ar user/cfg/rush.cfg user/cfg/sshd.toml; do
    [ ! -e "$WORK/current/motor/$path" ] || fail "unexpected replacement of $path"
done
# Exercise the shared packager with real tar archives, including its standalone
# entry point. The fixture tools are inert files: no compiler or network is used.
toolchain_source="${MOTOR_TOOLCHAIN_SOURCE:-$ROOT/../motor-os-toolchain}"
package_script="$toolchain_source/lib/toolchain-package.sh"
images="$WORK/current"
mkdir -p "$images/libc/system/cfg/libc" "$WORK/host/bin"
for path in llvm/user/lib/llvm/bin/llvm rustc/user/lib/rust/bin/rustc \
    rustc/user/lib/rust/bin/rustfmt rustc/user/lib/rust/bin/clippy-driver \
    rust-analyzer/user/lib/rust/bin/rust-analyzer helix/user/lib/helix/hx \
    sed/user/bin/dev/sed lua/user/bin/dev/lua quickjs/user/bin/dev/qjs \
    quickjs/user/bin/dev/qjsc javy/user/bin/dev/javy javy/user/bin/dev/wasmi \
    wasmtime/user/bin/dev/wasmtime wasmtime/user/bin/dev/wasmtime-rt; do
    mkdir -p "$images/${path%/*}"
    printf '#!/user/bin/rush\nexit 0\n' > "$images/$path"
    chmod 755 "$images/$path"
done
printf 'host compiler\n' > "$WORK/host/bin/rustc"
# LLVM's Android linker names are unrelated to the retired Motor layout.
printf '/system/bin/linker64\0' >> "$images/llvm/user/lib/llvm/bin/llvm"
name=x86_64-unknown-motor-1.99.1-3
package="motor-toolchain-$name"
cp -a "$images" "$WORK/expected-images"
bash "$package_script" "$(command -v tar)" "$WORK/output" "$name" "$images" "$WORK/host"
(cd "$WORK/output" && sha256sum -c "$package.tar.zst.sha256" "$package-x86_64-linux.tar.zst.sha256")
mkdir "$WORK/extracted"
tar -xaf "$WORK/output/$package.tar.zst" -C "$WORK/extracted"
tar -xaf "$WORK/output/$package-x86_64-linux.tar.zst" -C "$WORK/extracted"
diff -r "$WORK/expected-images" "$WORK/extracted/$package/images"
[ "$(cat "$WORK/extracted/$package-x86_64-linux/toolchain/bin/rustc")" = 'host compiler' ] ||
    fail 'host payload changed'
grep -qx '#!/user/bin/rush' "$WORK/extracted/$package/install.sh" || fail 'wrong installer shell'
if grep -Eq '/devtools|/system/bin' "$WORK/extracted/$package/install.sh"; then
    fail 'installer contains an obsolete path'
fi
[ ! -e "$images" ] && [ ! -e "$WORK/host" ] || fail 'packaging did not consume its input trees'

# A failed validation leaves the previous archive intact.
before="$(sha256sum "$WORK/output/$package.tar.zst")"
cp -a "$WORK/extracted/$package/images" "$images"
ln -s payload "$images/quickjs/user/lib/quickjs/link"
if bash "$package_script" "$(command -v tar)" "$WORK/output" "$name" "$images" > "$WORK/error" 2>&1; then
    fail 'packager accepted a symlink'
fi
grep -q 'unsupported archive member' "$WORK/error" || fail 'wrong symlink diagnostic'
[ "$(sha256sum "$WORK/output/$package.tar.zst")" = "$before" ] || fail 'failed packaging changed the archive'
rm "$images/quickjs/user/lib/quickjs/link"
printf '/system/bin/sh\0' >> "$images/llvm/user/lib/llvm/bin/llvm"
if bash "$package_script" "$(command -v tar)" "$WORK/output" "$name" "$images" > "$WORK/error" 2>&1; then
    fail 'packager accepted an obsolete compiled shell path'
fi
grep -q 'obsolete compiled path' "$WORK/error" || fail 'wrong compiled-path diagnostic'
cp -a "$WORK/extracted/$package/images/llvm/user/lib/llvm/bin/llvm" "$images/llvm/user/lib/llvm/bin/llvm"
mkdir "$images/llvm/devtools"
if bash "$package_script" "$(command -v tar)" "$WORK/output" "$name" "$images" > "$WORK/error" 2>&1; then
    fail 'packager accepted the obsolete layout'
fi
grep -q 'obsolete image layout' "$WORK/error" || fail 'wrong legacy-layout diagnostic'

# Always repackage, including unchanged payloads, without modifying the release.
repo="$WORK/repo"
mkdir -p "$repo/src/build-scripts" "$repo/build/bin" "$repo/build/assembly/build/motor-os-tar-linux/release"
cp "$ROOT/src/build-scripts/"toolchain-{archive,overlays}.sh "$repo/src/build-scripts/"
cp -a "$WORK/bin" "$repo/build/bin/release"
cp -a "$WORK/extracted/$package/images" "$repo/build/assembly/"
ln -s "$(command -v tar)" "$repo/build/assembly/build/motor-os-tar-linux/release/tar"
printf '[toolchain]\nchannel = "%s"\n' "$name" > "$repo/rust-toolchain.toml"
repackage() {
    MOTORH="$WORK/output" MOTOR_TOOLCHAIN_SOURCE="$toolchain_source" \
        bash "$repo/src/build-scripts/toolchain-archive.sh" release
}
original="$WORK/output/$package.tar.zst"
[ "$(repackage)" = "$repo/build/toolchain/release/$package.tar.zst" ] ||
    fail 'unchanged payloads did not produce a local archive'
printf 'new host imager\n' >> "$repo/build/bin/release/imager"
printf 'new Lorry\n' >> "$repo/build/bin/release/lorry"
repacked="$(repackage)"
[ "$repacked" = "$repo/build/toolchain/release/$package.tar.zst" ] || fail 'repackaged archive is outside build/'
tar -xOf "$repacked" "$package/images/motor/user/bin/dev/lorry" > "$WORK/lorry"
cmp "$repo/build/bin/release/lorry" "$WORK/lorry" || fail 'repackaged archive has stale guest bytes'
tar -xOf "$repacked" "$package/images/motor/user/lib/imager/imager" > "$WORK/imager"
cmp "$repo/build/bin/release/imager" "$WORK/imager" || fail 'repackaged archive has a stale host imager'
[ "$(sha256sum "$original")" = "$before" ] || fail 'repackaging changed the original release'
echo 'test-toolchain-archive PASS'
