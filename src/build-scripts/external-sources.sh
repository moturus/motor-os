#!/usr/bin/env bash
# Shared inventory of the external sources and their workspaces, for the build
# and its lockfile validation.

# Javy and Wasmtime are built from one Motor branch of their forks at the exact
# revision declared here, so every Motor OS branch names the fork revisions it
# was gated with. To take new fork work: push the fork, then set its revision
# (an exported MOTOR_JAVY_REV or MOTOR_WASMTIME_REV wins, for a build before
# the pin is committed). What the forks depend on — Tokio, Mio,
# target-lexicon, Wasmi and Wizer by git, the Motor OS crates from crates.io —
# is pinned by the forks' lockfiles; external-sources/ keeps no checkout of
# them.
MOTOR_JAVY_BRANCH=motor-9.1.0
MOTOR_JAVY_REV="${MOTOR_JAVY_REV:-e307323d448470f9925f5a05e8ae4e160074c059}"
MOTOR_WASMTIME_BRANCH=motor-50.0.0
MOTOR_WASMTIME_REV="${MOTOR_WASMTIME_REV:-b5581cade5626f050e6f9002f522b76187b6cf56}"

# "repo:branch" follows the branch head; "repo:branch:revision" builds that
# revision of the branch.
JAVY_SOURCES=("javy:$MOTOR_JAVY_BRANCH:$MOTOR_JAVY_REV")
WASMTIME_SOURCES=("wasmtime:$MOTOR_WASMTIME_BRANCH:$MOTOR_WASMTIME_REV")

select_external_sources() {
	local selection="$1" spec repo
	local -A seen=()
	EXTERNAL_REPOS=()
	EXTERNAL_WORKSPACES=()
	if [ "$selection" = all ]; then
		EXTERNAL_REPOS+=("ripgrep:$RIPGREP_BRANCH" "helix:$HELIX_BRANCH" "sed:$SED_BRANCH"
			"motor-os-tar:$MOTOR_OS_TAR_BRANCH")
		EXTERNAL_WORKSPACES+=("$RIPGREP" "$HELIX" "$SED" "$MOTOR_OS_TAR")
	fi
	if [ "$selection" != wasmtime ]; then
		EXTERNAL_REPOS+=("${JAVY_SOURCES[@]}")
		EXTERNAL_WORKSPACES+=("$EXTERNAL_SOURCES/javy" "$EXTERNAL_SOURCES/javy/motor-tests"
			"$MOTOR/src/tests/javy-smoke" "$MOTOR/src/tests/javy-smoke/plugins")
	fi
	if [ "$selection" != javy ]; then
		EXTERNAL_REPOS+=("${WASMTIME_SOURCES[@]}")
		EXTERNAL_WORKSPACES+=("$EXTERNAL_SOURCES/wasmtime"
			"$EXTERNAL_SOURCES/wasmtime/motor-tests"
			"$MOTOR/src/tests/wasmtime-smoke")
	fi
	local repos=("${EXTERNAL_REPOS[@]}")
	EXTERNAL_REPOS=()
	for spec in "${repos[@]}"; do
		repo=${spec%%:*}
		[ -z "${seen[$repo]:-}" ] || continue
		seen[$repo]=1
		EXTERNAL_REPOS+=("$spec")
	done
}

prepare_external_sources() {
	local spec repo branch revision
	for spec in "${EXTERNAL_REPOS[@]}"; do
		IFS=: read -r repo branch revision <<< "$spec"
		update_external_source "$repo" "$EXTERNAL_SOURCES/$repo" "https://github.com/moturus/$repo.git" \
			"$branch" "$revision"
	done
}

report_external_lockfiles() {
	local spec repo checkout workspace root output
	local failed=()
	output="$(cargo --version)" || return 1
	printf 'Lockfile validation of the external sources: %s\n' "$output"
	printf 'Rust toolchain: %s\n' "$RUSTUP_TOOLCHAIN"
	for spec in motor-os "${EXTERNAL_REPOS[@]}"; do
		repo=${spec%%:*}
		checkout="$EXTERNAL_SOURCES/$repo"
		[ "$repo" != motor-os ] || checkout="$MOTOR"
		if output="$(git -C "$checkout" rev-parse HEAD 2>&1)"; then
			printf 'Source: %s %s\n' "$repo" "$output"
			git -C "$checkout" status --short || return 1
		else
			printf 'Source unavailable: %s\n%s\n' "$repo" "$output"
			failed+=("$repo (source unavailable)")
		fi
	done
	for root in "${EXTERNAL_WORKSPACES[@]}"; do
		workspace="${root#"$MOTOR/"}"
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
		printf '\nLockfile validation of the external sources failed:\n'
		printf '  %s\n' "${failed[@]}"
		printf '%s\n' 'Review and update stale lockfiles in their owning repositories.' \
			'For incomplete validation, resolve the source/cache errors reported above.' \
			'No lockfiles were modified; the external sources have not been built.'
		return 1
	fi
	printf '\nAll selected lockfiles of the external sources are consistent.\n'
}

check_external_lockfiles() {
	mkdir -p "$MOTOR/build" || return 1
	report_external_lockfiles "$@" 2>&1 | tee "$MOTOR/build/external-lockfiles.log"
}
