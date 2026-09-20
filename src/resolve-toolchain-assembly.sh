#!/usr/bin/env bash
# Resolve the assembly consumed by ordinary Motor OS builds. Nothing is chosen
# or stored: the selected Rust toolchain and the declared assembly inputs name
# exactly one assembly, which lives beside that toolchain.

set -euo pipefail

RESOLVER_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
. "$RESOLVER_DIR/toolchain-versions.sh"
. "$RESOLVER_DIR/toolchain-lib.sh"
. "$RESOLVER_DIR/toolchain-sources.sh"
. "$RESOLVER_DIR/toolchain-assembly.sh"

resolver_die() {
	echo "assembly-resolver: $*" >&2
	return 1
}

resolver_usage() {
	cat <<'EOF'
Usage: src/resolve-toolchain-assembly.sh --resolve
       src/resolve-toolchain-assembly.sh --show
EOF
}

# The producer installs into $MOTORH/toolchains/<name> and
# $MOTORH/assemblies/<key>, so the toolchain's own location finds the assembly.
resolver_initialize_identity() {
	local sysroot stamp key
	sysroot="$(rustc --print sysroot)" || return
	sysroot="$(readlink -f "$sysroot")" || return
	stamp="$sysroot/lib/rustlib/MOTOR-TOOLCHAIN-KEY"
	[ -f "$stamp" ] && [ ! -L "$stamp" ] ||
		resolver_die "selected Rust toolchain has no immutable key stamp: $stamp" || return
	key="$(cat "$stamp")"
	[[ "$key" =~ ^[0-9a-f]{64}$ ]] && [ "$(wc -l < "$stamp")" -eq 1 ] ||
		resolver_die "selected Rust toolchain has an invalid key stamp: $stamp" || return
	toolchain_derive_consumed_assembly_identity "$key" || return
	RESOLVED_ASSEMBLY_ROOT="$(dirname "$(dirname "$sysroot")")/assemblies/$MOTOR_ASSEMBLY_KEY"
}

resolver_validate() {
	[ -d "$RESOLVED_ASSEMBLY_ROOT" ] || resolver_die \
		"no assembly $MOTOR_ASSEMBLY_KEY exists for toolchain $MOTOR_TOOLCHAIN_KEY" \
		"($RESOLVED_ASSEMBLY_ROOT); run src/build-motor-os.sh" || return
	toolchain_validate_consumed_assembly "$RESOLVED_ASSEMBLY_ROOT"
}

resolver_describe() {
	local manifest="$RESOLVED_ASSEMBLY_ROOT/MOTOR-ASSEMBLY-MANIFEST" mode state revision
	mode="$(toolchain_manifest_value "$manifest" source_mode)" || return
	state="$(toolchain_manifest_value "$manifest" assembly_state)" || return
	revision="$(toolchain_manifest_value "$manifest" motor_os_rev)" || return
	printf '%s  %s/%s  motor-os=%s\n' "$MOTOR_ASSEMBLY_KEY" "$mode" "$state" "$revision"
}

resolver_main() (
	[ "$#" -eq 1 ] || { resolver_usage >&2; return 1; }
	case "$1" in
		-h|--help) resolver_usage; return ;;
		--resolve|--show) ;;
		*) resolver_usage >&2; return 1 ;;
	esac
	resolver_initialize_identity || return
	resolver_validate || return
	case "$1" in
		--resolve) printf '%s/images\n' "$RESOLVED_ASSEMBLY_ROOT" ;;
		--show) resolver_describe ;;
	esac
)

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	resolver_main "$@"
fi
