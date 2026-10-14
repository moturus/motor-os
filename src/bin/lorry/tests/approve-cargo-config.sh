#!/usr/bin/env bash
# Approves a repository Cargo configuration file for a workspace, as an
# interactive `lorry vendor` review records it. Approve again after an edit.
set -euo pipefail
home="${1:?usage: approve-cargo-config.sh HOME WORKSPACE_ROOT FILE}"
root="$(realpath "${2:?}")"
file="$(realpath "${3:?}")"
decisions="$home/.config/lorry/workspaces/$(printf '%s' "$root" | sha256sum | cut -c1-32).toml"
digest="$(sha256sum "$file" | cut -d' ' -f1)"
mkdir -p "${decisions%/*}"
[ -f "$decisions" ] || printf 'format-version = 1\nworkspace = "%s"\n' "$root" >"$decisions"
printf '\n[[cargo-config]]\nfile = "%s"\nsha256 = "%s"\n' "$file" "$digest" >>"$decisions"
