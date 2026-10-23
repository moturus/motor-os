#!/usr/bin/env bash
# Shared source and workspace inventory for add-on builds and merge validation.

# Each wasm add-on is built from one Motor branch of its fork at the exact
# revision declared here, so every Motor OS branch names the fork revisions it
# was gated with. To take new fork work: push the fork, then set its revision
# (an exported MOTOR_<ADDON>_REV wins, for a build before the pin is committed).
# What the forks depend on — Tokio, Mio, target-lexicon, Wasmi and Wizer by git,
# the Motor OS crates from crates.io — is pinned by
# the add-ons' lockfiles; the tree keeps no sibling checkout of them.
MOTOR_JAVY_BRANCH=motor-9.1.0
MOTOR_JAVY_REV="${MOTOR_JAVY_REV:-12a6c52d7dbd62056ead74d8ddea3f8a235f278f}"
MOTOR_WASMTIME_BRANCH=motor-48.0.1
MOTOR_WASMTIME_REV="${MOTOR_WASMTIME_REV:-633e7de368b913a696e7e15d4f546c55fc2eadaf}"

# "repo:branch" follows the branch head; "repo:branch:revision" builds that
# revision of the branch.
JAVY_SOURCES=("javy:$MOTOR_JAVY_BRANCH:$MOTOR_JAVY_REV")
WASMTIME_SOURCES=("wasmtime:$MOTOR_WASMTIME_BRANCH:$MOTOR_WASMTIME_REV")

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
		ADDON_WORKSPACES+=(javy javy/motor-tests
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
	local spec repo branch revision
	for spec in "${ADDON_SOURCES[@]}"; do
		IFS=: read -r repo branch revision <<< "$spec"
		update_addon_source "$repo" "$MOTORH/$repo" "https://github.com/moturus/$repo.git" \
			"$branch" "$revision"
	done
}

report_addon_lockfiles() {
	local spec repo workspace root output
	local failed=()
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
