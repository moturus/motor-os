#!/usr/bin/env bash

# Shared phase timing for the Lorry-owned test harnesses.

LORRY_TIMING_LOG=""
LORRY_TIMING_ACTIVE_PHASE=""
LORRY_TIMING_ACTIVE_START_MS=0

timing_now_ms() {
    local seconds
    local nanoseconds
    read -r seconds nanoseconds < <(date '+%s %N')
    printf '%s\n' "$((seconds * 1000 + 10#$nanoseconds / 1000000))"
}

timing_format_ms() {
    local milliseconds="$1"
    printf '%d.%03ds\n' "$((milliseconds / 1000))" \
        "$((milliseconds % 1000))"
}

timing_init() {
    LORRY_TIMING_LOG="${1:-}"
    LORRY_TIMING_ACTIVE_PHASE=""
    LORRY_TIMING_ACTIVE_START_MS=0
    if [ -n "$LORRY_TIMING_LOG" ]; then
        printf 'phase\tstatus\tmilliseconds\n' >"$LORRY_TIMING_LOG"
    fi
}

timing_start() {
    local phase="$1"
    if [ -n "$LORRY_TIMING_ACTIVE_PHASE" ]; then
        echo "timing: phase '$LORRY_TIMING_ACTIVE_PHASE' is still active" >&2
        return 1
    fi
    LORRY_TIMING_ACTIVE_PHASE="$phase"
    LORRY_TIMING_ACTIVE_START_MS="$(timing_now_ms)"
}

timing_finish() {
    local status="${1:-0}"
    local elapsed_ms
    local result="PASS"

    [ -n "$LORRY_TIMING_ACTIVE_PHASE" ] || return 0
    elapsed_ms=$(($(timing_now_ms) - LORRY_TIMING_ACTIVE_START_MS))
    [ "$status" -eq 0 ] || result="FAIL($status)"
    printf 'timing: %s: %s (%s)\n' "$LORRY_TIMING_ACTIVE_PHASE" \
        "$(timing_format_ms "$elapsed_ms")" "$result"
    if [ -n "$LORRY_TIMING_LOG" ]; then
        printf '%s\t%s\t%s\n' "$LORRY_TIMING_ACTIVE_PHASE" "$status" \
            "$elapsed_ms" >>"$LORRY_TIMING_LOG"
    fi
    LORRY_TIMING_ACTIVE_PHASE=""
    LORRY_TIMING_ACTIVE_START_MS=0
}

timing_run() {
    local phase="$1"
    local status=0
    shift

    timing_start "$phase"
    "$@" || status=$?
    timing_finish "$status"
    return "$status"
}
