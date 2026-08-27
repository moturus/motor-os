#!/usr/bin/env bash
# Resolve and persist the assembly consumed by ordinary Motor OS builds.

set -euo pipefail

SELECTOR_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
ROOT_DIR="$(cd "$SELECTOR_DIR/.." && pwd)"
. "$SELECTOR_DIR/toolchain-versions.sh"
. "$SELECTOR_DIR/toolchain-lib.sh"
. "$SELECTOR_DIR/toolchain-sources.sh"
. "$SELECTOR_DIR/toolchain-assembly.sh"

selector_die() {
	echo "assembly-selector: $*" >&2
	return 1
}

selector_usage() {
	cat <<'EOF'
Usage: src/select-toolchain-assembly.sh --resolve
       src/select-toolchain-assembly.sh --show
       src/select-toolchain-assembly.sh --list
       src/select-toolchain-assembly.sh --pin ASSEMBLY_KEY_OR_ABSOLUTE_ROOT
       src/select-toolchain-assembly.sh --clear
EOF
}

selector_initialize_identity() {
	local sysroot stamp key
	sysroot="$(rustc --print sysroot)" || return
	stamp="$sysroot/lib/rustlib/MOTOR-TOOLCHAIN-KEY"
	[ -f "$stamp" ] && [ ! -L "$stamp" ] ||
		selector_die "selected Rust toolchain has no immutable key stamp: $stamp" || return
	key="$(cat "$stamp")"
	[[ "$key" =~ ^[0-9a-f]{64}$ ]] && [ "$(wc -l < "$stamp")" -eq 1 ] ||
		selector_die "selected Rust toolchain has an invalid key stamp: $stamp" || return
	MOTORH="$(realpath -m "${MOTORH:-$ROOT_DIR/..}")"
	ASSEMBLIES_DIR="$MOTORH/assemblies"
	PIN_ROOT="$ROOT_DIR/.motor-os/assembly-pins"
	PIN_PATH="$PIN_ROOT/$key"
	SELECTED_TOOLCHAIN_KEY="$key"
	toolchain_derive_consumed_assembly_identity \
		"$ROOT_DIR" "$(command -v cargo)" "$SELECTED_TOOLCHAIN_KEY"
}

selector_prepare_state() {
	local state="$ROOT_DIR/.motor-os"
	[ ! -L "$state" ] && [ ! -L "$PIN_ROOT" ] ||
		selector_die "assembly selection state must not use symlinked directories" || return
	mkdir -p "$PIN_ROOT"
	exec 9> "$state/assembly-selection.lock"
	flock 9
}

selector_read_pin() {
	local pin="$1"
	local -a lines
	[ -f "$pin" ] && [ ! -L "$pin" ] ||
		selector_die "assembly pin is absent or linked: $pin" || return
	mapfile -t lines < "$pin"
	[ "${#lines[@]}" -eq 4 ] &&
		[ "${lines[0]}" = schema=motor-assembly-pin-v1 ] &&
		[[ "${lines[1]}" =~ ^toolchain_key=([0-9a-f]{64})$ ]] &&
		[[ "${lines[2]}" =~ ^assembly_key=([0-9a-f]{64})$ ]] &&
		[[ "${lines[3]}" == assembly_root=/* ]] ||
		selector_die "assembly pin is malformed: $pin" || return
	PIN_TOOLCHAIN_KEY="${lines[1]#toolchain_key=}"
	PIN_ASSEMBLY_KEY="${lines[2]#assembly_key=}"
	PIN_ASSEMBLY_ROOT="${lines[3]#assembly_root=}"
	[ "$PIN_TOOLCHAIN_KEY" = "$SELECTED_TOOLCHAIN_KEY" ] ||
		selector_die "assembly pin belongs to another toolchain: $pin" || return
	[ "$PIN_ASSEMBLY_KEY" = "$MOTOR_ASSEMBLY_KEY" ] ||
		selector_die "pinned assembly is stale for the current runtime inputs: $PIN_ASSEMBLY_KEY" || return
	[ "${PIN_ASSEMBLY_ROOT##*/}" = "$PIN_ASSEMBLY_KEY" ] ||
		selector_die "assembly pin root and key disagree: $pin" || return
}

selector_validate_root() {
	local root="$1"
	toolchain_validate_consumed_assembly "$root"
}

selector_write_pin() {
	local root="$1" temporary
	selector_validate_root "$root" || return
	if [ -e "$PIN_PATH" ] || [ -L "$PIN_PATH" ]; then
		[ -f "$PIN_PATH" ] && [ ! -L "$PIN_PATH" ] ||
			selector_die "refusing to replace a non-regular assembly pin: $PIN_PATH" || return
	fi
	temporary="$(mktemp "$PIN_ROOT/.pin.XXXXXX")"
	{
		printf 'schema=motor-assembly-pin-v1\n'
		printf 'toolchain_key=%s\n' "$SELECTED_TOOLCHAIN_KEY"
		printf 'assembly_key=%s\n' "$MOTOR_ASSEMBLY_KEY"
		printf 'assembly_root=%s\n' "$root"
	} > "$temporary"
	chmod 0600 "$temporary"
	mv "$temporary" "$PIN_PATH"
}

selector_candidate_matches_toolchain() {
	local root="$1" manifest key schema assembly_key
	manifest="$root/MOTOR-ASSEMBLY-MANIFEST"
	[ -d "$root" ] && [ ! -L "$root" ] && [ ! -e "${root}.building" ] &&
		[ ! -e "$root/MOTOR-ASSEMBLY-REJECTED" ] &&
		[ -f "$manifest" ] && [ ! -L "$manifest" ] || return 1
	schema="$(toolchain_manifest_value "$manifest" schema 2>/dev/null)" || return 1
	key="$(toolchain_manifest_value "$manifest" toolchain_key 2>/dev/null)" || return 1
	assembly_key="$(toolchain_manifest_value "$manifest" assembly_key 2>/dev/null)" || return 1
	[ "$schema" = "$MOTOR_GENERATED_MANIFEST_SCHEMA" ] &&
		[ "$key" = "$SELECTED_TOOLCHAIN_KEY" ] &&
		[[ "$assembly_key" =~ ^[0-9a-f]{64}$ ]] &&
		[ "${root##*/}" = "$assembly_key" ] && [ "$(stat -c %a "$manifest")" = 444 ]
}

selector_find_candidates() {
	local root
	SELECTOR_CANDIDATES=()
	[ -d "$ASSEMBLIES_DIR" ] || return 0
	while IFS= read -r -d '' root; do
		selector_candidate_matches_toolchain "$root" &&
			SELECTOR_CANDIDATES+=("$root")
	done < <(find "$ASSEMBLIES_DIR" -mindepth 1 -maxdepth 1 -type d \
		-print0 | LC_ALL=C sort -z)
}

selector_describe() {
	local root="$1" manifest
	local key mode state revision compatibility=incompatible
	manifest="$root/MOTOR-ASSEMBLY-MANIFEST"
	key="$(toolchain_manifest_value "$manifest" assembly_key)" || return
	mode="$(toolchain_manifest_value "$manifest" source_mode)" || return
	state="$(toolchain_manifest_value "$manifest" assembly_state)" || return
	revision="$(toolchain_manifest_value "$manifest" motor_os_rev)" || return
	if [ "$key" = "$MOTOR_ASSEMBLY_KEY" ]; then
		if selector_validate_root "$root" >/dev/null 2>&1; then
			compatibility=compatible
		else
			compatibility=invalid
		fi
	fi
	printf '%s  %s  %s/%s  motor-os=%s\n' \
		"$key" "$compatibility" "$mode" "$state" "$revision"
}

selector_pin_argument() {
	local argument="$1" root
	case "$argument" in
		/*) root="$(realpath -m "$argument")" ;;
		*)
			[[ "$argument" =~ ^[0-9a-f]{64}$ ]] ||
				selector_die "assembly selection must be a key or absolute root" || return
			root="$ASSEMBLIES_DIR/$argument"
			;;
	esac
	selector_write_pin "$root" || return
	printf 'pinned assembly %s for toolchain %s\n' \
		"${root##*/}" "$SELECTED_TOOLCHAIN_KEY"
}

selector_resolve() {
	local root choice index
	if [ -e "$PIN_PATH" ]; then
		selector_read_pin "$PIN_PATH" || return
		selector_validate_root "$PIN_ASSEMBLY_ROOT" || return
		printf '%s/images\n' "$PIN_ASSEMBLY_ROOT"
		return
	fi
	selector_find_candidates
	case "${#SELECTOR_CANDIDATES[@]}" in
		0)
			selector_die "no completed assembly exists for toolchain $SELECTED_TOOLCHAIN_KEY; run src/build-motor-os.sh"
			return 1
			;;
		1) root="${SELECTOR_CANDIDATES[0]}" ;;
		*)
			echo "assembly-selector: multiple assemblies are available:" >&2
			for ((index = 0; index < ${#SELECTOR_CANDIDATES[@]}; index++)); do
				printf '  %d) ' "$((index + 1))" >&2
				selector_describe "${SELECTOR_CANDIDATES[$index]}" >&2
			done
			if [ ! -t 0 ]; then
				selector_die "select one with src/select-toolchain-assembly.sh --pin ASSEMBLY_KEY"
				return 1
			fi
			printf 'Select an assembly [1-%d]: ' "${#SELECTOR_CANDIDATES[@]}" >&2
			IFS= read -r choice
			[[ "$choice" =~ ^[0-9]+$ ]] &&
				[ "$choice" -ge 1 ] && [ "$choice" -le "${#SELECTOR_CANDIDATES[@]}" ] ||
				selector_die "invalid assembly selection" || return
			root="${SELECTOR_CANDIDATES[$((choice - 1))]}"
			;;
	esac
	selector_write_pin "$root" || return
	printf '%s/images\n' "$root"
}

selector_main() (
	[ "$#" -ge 1 ] || { selector_usage >&2; return 1; }
	local command="$1"
	shift
	case "$command" in
		-h|--help) [ "$#" -eq 0 ] || return 1; selector_usage; return ;;
	esac
	selector_initialize_identity || return
	selector_prepare_state || return
	case "$command" in
		--resolve) [ "$#" -eq 0 ] || { selector_usage >&2; return 1; }; selector_resolve ;;
		--show)
			[ "$#" -eq 0 ] || { selector_usage >&2; return 1; }
			selector_read_pin "$PIN_PATH" || return
			selector_validate_root "$PIN_ASSEMBLY_ROOT" || return
			selector_describe "$PIN_ASSEMBLY_ROOT"
			;;
		--list)
			[ "$#" -eq 0 ] || { selector_usage >&2; return 1; }
			selector_find_candidates
			for root in "${SELECTOR_CANDIDATES[@]}"; do selector_describe "$root"; done
			;;
		--pin) [ "$#" -eq 1 ] || { selector_usage >&2; return 1; }; selector_pin_argument "$1" ;;
		--clear)
			[ "$#" -eq 0 ] || { selector_usage >&2; return 1; }
			rm -f "$PIN_PATH"
			printf 'cleared assembly pin for toolchain %s\n' "$SELECTED_TOOLCHAIN_KEY"
			;;
		*) selector_usage >&2; return 1 ;;
	esac
)

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	selector_main "$@"
fi
