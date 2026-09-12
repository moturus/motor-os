#!/usr/bin/env bash
# Run the top-level make goals in one logged sub-make and end a failed build
# with a loud summary: the failed recipes, the output that preceded the first
# failure, the log path, and a final BUILD FAILED line. The Makefile invokes
# this for every top-level goal, so parallel builds cannot bury a failure.
set -uo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Dry runs only print recipes; leave their output untouched and unlogged.
if [[ "${MAKEFLAGS%% *}" =~ ^[A-Za-z]*n[A-Za-z]*$ ]]; then
	exec "$@"
fi

# The combined log keeps everything; the stderr log is where recipe errors and
# make's own failure markers land, free of the recipe commands make echoes.
log="${MOTOR_MAKE_LOG:-$ROOT_DIR/build/make-last.log}"
errors="$log.stderr"
mkdir -p "$(dirname "$log")"
: > "$log"
: > "$errors"
"$@" > >(tee -a "$log") 2> >(tee -a "$log" "$errors" >&2)
status=$?
wait
[ "$status" -ne 0 ] || exit 0

color=0
if [ -n "${FORCE_COLOR-}" ]; then
	color=1
elif [ -z "${NO_COLOR-}" ] && [ -t 2 ]; then
	color=1
fi
shown=()
for argument in "${@:2}"; do
	[ "$argument" = --no-print-directory ] || shown+=("$argument")
done

# Make's "***" markers name each failed recipe; the stderr lines before the
# first marker are normally that recipe's error output, though other parallel
# jobs can interleave with them. Cargo's progress lines are dropped from that
# window so a failure is not buried under lock-wait chatter.
{
	echo
	echo '---- make failure diagnostics ----'
	awk -v tail=25 '
		/Waiting for unfinished jobs/ { next }
		/^(make(\[[0-9]+\])?|[^ \t]+:[0-9]+): \*\*\* / {
			markers[++m] = $0
			if (m == 1) first = c
			next
		}
		/^make(\[[0-9]+\])?: / { next }
		/^[ \t]*$/ { next }
		/^[ \t]*(Blocking waiting for file lock|Compiling|Checking|Downloading|Downloaded|Fresh|Locking|Updating|Finished|Running) / { next }
		{ line[++c] = $0 }
		END {
			print "Failed recipes:"
			if (m == 0) print "  (make reported no failed recipe; see the log)"
			for (i = 1; i <= m; i++) print "  " markers[i]
			print "Error output before the first failure (last " tail " lines; parallel jobs may interleave):"
			from = first - tail + 1
			if (from < 1) from = 1
			if (first == 0) print "  (none)"
			for (i = from; i <= first; i++) print "  " line[i]
		}' "$errors"
	echo "Full log: $log"
	if [ "$color" = 1 ]; then
		printf '\033[1;31mBUILD FAILED\033[0m: make %s (exit status %s)\n' "${shown[*]}" "$status"
	else
		printf 'BUILD FAILED: make %s (exit status %s)\n' "${shown[*]}" "$status"
	fi
} >&2
exit "$status"
