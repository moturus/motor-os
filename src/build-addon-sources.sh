#!/usr/bin/env bash
# Shared source and workspace inventory for add-on builds and merge validation.

JAVY_SOURCES=(javy:motor-9.1.0 wasmi:motor-1.1.0 wasmtime:motor-48.0.1)
WASMTIME_SOURCES=(wasmtime:motor-48.0.1 target-lexicon:motor-0.13.5 tokio:motor-1.51.1 mio:motor-1.2.0)

select_addon_workspaces() {
	local selection="$1" spec repo
	local -A seen=()
	ADDON_SOURCES=()
	ADDON_WORKSPACES=()
	if [ "$selection" = all ]; then
		ADDON_SOURCES+=("ripgrep:$RIPGREP_BRANCH" "helix:$HELIX_BRANCH" "sed:$SED_BRANCH")
		ADDON_WORKSPACES+=(ripgrep helix sed)
	fi
	if [ "$selection" != wasmtime ]; then
		ADDON_SOURCES+=("${JAVY_SOURCES[@]}")
		ADDON_WORKSPACES+=(javy javy/motor-tests wasmi
			motor-os/src/tests/javy-smoke motor-os/src/tests/javy-smoke/plugins)
	fi
	if [ "$selection" != javy ]; then
		ADDON_SOURCES+=("${WASMTIME_SOURCES[@]}")
		ADDON_WORKSPACES+=(wasmtime wasmtime/motor-runtime wasmtime/motor-tests
			wasmtime/motor-host-tests motor-os/src/tests/wasmtime-smoke)
	fi
	local sources=("${ADDON_SOURCES[@]}")
	ADDON_SOURCES=()
	for spec in "${sources[@]}"; do
		repo=${spec%%:*}
		[ -z "${seen[$repo]:-}" ] || continue
		seen[$repo]=1
		ADDON_SOURCES+=("$spec")
	done
}

prepare_addon_sources() {
	local spec repo branch
	for spec in "${ADDON_SOURCES[@]}"; do
		repo=${spec%%:*}; branch=${spec#*:}
		update_addon_source "$repo" "$MOTORH/$repo" "https://github.com/moturus/$repo.git" "$branch"
	done
}

report_addon_lockfiles() {
	local spec repo workspace root output
	local failed=()
	[ "$(readlink -f "$MOTORH/motor-os")" = "$MOTOR" ] || {
		printf 'ERROR: sibling motor-os must resolve to the checkout being validated: %s\n' "$MOTOR"
		return 1
	}
	output="$(cargo --version)" || return 1
	printf 'Add-on lockfile validation: %s\n' "$output"
	printf 'Rust toolchain: %s\n' "$RUSTUP_TOOLCHAIN"
	for spec in motor-os "${ADDON_SOURCES[@]}"; do
		repo=${spec%%:*}
		if output="$(git -C "$MOTORH/$repo" rev-parse HEAD 2>&1)"; then
			printf 'Source: %s %s\n' "$repo" "$output"
			git -C "$MOTORH/$repo" status --short || return 1
		else
			printf 'Source unavailable: %s\n%s\n' "$repo" "$output"
			failed+=("$repo (source unavailable)")
		fi
	done
	for workspace in "${ADDON_WORKSPACES[@]}"; do
		root="$MOTORH/$workspace"
		printf '\nChecking %s\n  Manifest: %s/Cargo.toml\n  Lockfile: %s/Cargo.lock\n' \
			"$workspace" "$root" "$root"
		if [ ! -f "$root/Cargo.toml" ] || [ ! -f "$root/Cargo.lock" ]; then
			printf 'ERROR: required manifest or checked-in lockfile is missing.\n'
			failed+=("$workspace (missing files)")
			continue
		fi
		# Unlike fetch, update prints the required changes before --locked rejects
		# them. --workspace retains dependency selections wherever still valid.
		if output="$(cd "$root" && cargo update --workspace --locked "$@" 2>&1)"; then
			printf 'OK: lockfile matches the selected sources.\n'
		else
			printf '%s\n' "$output"
			if [[ "$output" == *'cannot update the lock file'* ]]; then
				failed+=("$workspace (stale lockfile)")
			else
				failed+=("$workspace (validation could not complete)")
			fi
		fi
	done
	if [ "${#failed[@]}" -ne 0 ]; then
		printf '\nAdd-on lockfile validation failed:\n'
		printf '  %s\n' "${failed[@]}"
		printf '%s\n' 'Review and update stale lockfiles in their owning repositories.' \
			'For incomplete validation, resolve the source/cache errors reported above.' \
			'No lockfiles were modified; add-on downloads and compilation have not started.'
		return 1
	fi
	printf '\nAll selected add-on lockfiles are consistent.\n'
}

check_addon_lockfiles() {
	mkdir -p "$MOTOR/build" || return 1
	report_addon_lockfiles "$@" 2>&1 | tee "$MOTOR/build/addon-lockfiles.log"
}
