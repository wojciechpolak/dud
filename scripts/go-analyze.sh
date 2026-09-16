#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
#
# Run the Go static analyzers over every module in this repository.
#
# An analyzer belongs to one of two sets. A gating analyzer reports nothing on
# this tree and fails the run on any new finding. `npm run check` calls that
# set through --gate. A pending analyzer still has findings left to fix, so it
# reports without failing. To promote an analyzer, move its name from
# PENDING_TOOLS to GATING_TOOLS. The two lists say which set each one is in.
#
# Every analyzer runs even after an earlier one reports, so a single run
# reports every problem instead of stopping at the first.
#
# Usage: scripts/go-analyze.sh [--gate | --pending | --strict] [tool ...]
set -uo pipefail

cd "$(dirname "$0")/.."

ROOT="$PWD"
BIN="$ROOT/bin"
export GOCACHE="${GOCACHE:-/tmp/dud-go-build-cache}"

# The Go modules in this repository. client ships; the other two are the
# protocol vector generator and the analyzers themselves.
MODULES="client tests/vectors/protocol-v2 tools"

# staticcheck, errcheck, and the analyze vettool type-check one platform at a
# time, so they never examine a file that a build constraint excludes. The
# client has separate terminal, process, and filesystem sources for each
# platform, and a run on the developer's GOOS alone would skip the rest.
PLATFORMS="linux darwin windows"

# The most complex function in the tree is validateV2PeerDeliveryState at 184
# (client/cmd/dud/v2_peer_state.go). 30 is the limit this repository intends to
# hold, not the limit it meets, so the report lists every function above 30.
# Split those functions to bring the number down.
GOCYCLO_OVER="${GOCYCLO_OVER:-30}"

# Analyzers that report nothing on this tree. They block, so a change that
# introduces a finding fails instead of adding to a backlog.
GATING_TOOLS="analyze deadcode errcheck govulncheck staticcheck"

# Analyzers with findings left to fix. Once one reports nothing, move it into
# GATING_TOOLS.
PENDING_TOOLS="gocyclo"

ALL_TOOLS="$GATING_TOOLS $PENDING_TOOLS"

strict=0
selection="$ALL_TOOLS"
case "${1:-}" in
    --gate)
        strict=1
        selection="$GATING_TOOLS"
        shift
        ;;
    --pending)
        selection="$PENDING_TOOLS"
        shift
        ;;
    --strict)
        strict=1
        shift
        ;;
esac

tools=("$@")
if [ "${#tools[@]}" -eq 0 ]; then
    read -r -a tools <<<"$selection"
fi

"$ROOT/scripts/go-tools.sh" || exit 1

status=0
declare -a clean_tools=()
declare -a dirty_tools=()

# report <tool> <exit-code> records the outcome. A non-zero code fails the run
# only under --strict. Otherwise the script prints it and carries on.
report() {
    local tool="$1" code="$2"
    if [ "$code" -eq 0 ]; then
        clean_tools+=("$tool")
        return
    fi
    dirty_tools+=("$tool")
    if [ "$strict" -eq 1 ]; then
        status=1
    fi
}

# run_per_platform <tool> <command...> runs one analyzer over every module and
# every platform. It returns non-zero if any of those runs reported.
run_per_platform() {
    local tool="$1"
    shift
    local code=0 module platform
    for module in $MODULES; do
        for platform in $PLATFORMS; do
            echo "--- $tool: $module (GOOS=$platform)"
            (cd "$module" && GOOS="$platform" "$@") || code=1
        done
    done
    report "$tool" "$code"
}

for tool in "${tools[@]}"; do
    case "$tool" in
        analyze)
            run_per_platform analyze go vet -vettool="$BIN/analyze" ./...
            ;;
        staticcheck)
            run_per_platform staticcheck "$BIN/staticcheck" ./...
            ;;
        errcheck)
            # This omits -blank and -asserts. A `_ =` in this repository marks
            # a discard the author chose, so -blank reports every one of them.
            # A bare type assertion reads a field from a CBOR map that a
            # validator has already checked for type and length, or reads the
            # return of ed25519.PrivateKey.Public(), whose type the standard
            # library documents. -asserts reports both, where the type is
            # established rather than assumed.
            run_per_platform errcheck "$BIN/errcheck" \
                -exclude "$ROOT/scripts/errcheck-excludes.txt" ./...
            ;;
        gocyclo)
            echo "--- gocyclo: over $GOCYCLO_OVER"
            code=0
            "$BIN/gocyclo" -over "$GOCYCLO_OVER" \
                client/cmd/dud tests/vectors/protocol-v2 tools || code=1
            report gocyclo "$code"
            ;;
        deadcode)
            # The client is one package main whose tests sit beside the
            # sources. Without -test, every helper that only a test calls
            # reports as unreachable.
            echo "--- deadcode: client/cmd/dud"
            code=0
            output="$(cd client && "$BIN/deadcode" -test ./cmd/dud)" || code=1
            if [ -n "$output" ]; then
                echo "$output"
                code=1
            fi
            report deadcode "$code"
            ;;
        govulncheck)
            echo "--- govulncheck: client"
            code=0
            (cd client && "$BIN/govulncheck" ./...) || code=1
            report govulncheck "$code"
            ;;
        *)
            echo "unknown tool '$tool'; known tools are: $ALL_TOOLS" >&2
            exit 1
            ;;
    esac
done

echo
echo "================ go static analysis ================"
[ "${#clean_tools[@]}" -gt 0 ] && echo "clean:    ${clean_tools[*]}"
[ "${#dirty_tools[@]}" -gt 0 ] && echo "reported: ${dirty_tools[*]}"
if [ "${#dirty_tools[@]}" -eq 0 ]; then
    echo "every analyzer is clean"
elif [ "$strict" -eq 0 ]; then
    echo "advisory run: findings above do not fail this command"
fi
exit "$status"
