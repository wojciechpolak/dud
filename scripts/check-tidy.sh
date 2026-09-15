#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
#
# Fail if "go mod tidy" would change any module in this repository.
#
# A dependency that is present but unrecorded, or recorded but unused, makes
# the vulnerability scan report on a set that differs from what the build uses.
# The tools module needs this for a second reason. This repository builds the
# analyzer binaries from tools/go.mod, so if go.sum no longer describes that
# set, the analyzer that runs is not the one under review.
#
# The check runs tidy against a copy and restores the originals, so a failing
# run leaves the working tree unchanged.
set -uo pipefail

cd "$(dirname "$0")/.."

export GOCACHE="${GOCACHE:-/tmp/dud-go-build-cache}"

MODULES="client tests/vectors/protocol-v2 tools"

status=0

check_module() {
    local dir="$1"
    local work
    work="$(mktemp -d)"
    cp "$dir/go.mod" "$work/"
    [ -f "$dir/go.sum" ] && cp "$dir/go.sum" "$work/"

    if ! go -C "$dir" mod tidy; then
        echo "$dir: go mod tidy failed" >&2
        rm -rf "$work"
        status=1
        return
    fi

    local dirty=0
    diff -q "$work/go.mod" "$dir/go.mod" >/dev/null || dirty=1
    if [ -f "$work/go.sum" ] || [ -f "$dir/go.sum" ]; then
        diff -q "$work/go.sum" "$dir/go.sum" >/dev/null 2>&1 || dirty=1
    fi

    if [ "$dirty" -ne 0 ]; then
        echo "$dir is not tidy (run 'go -C $dir mod tidy' and commit the result):" >&2
        diff -u "$work/go.mod" "$dir/go.mod" >&2
        # Restore what the check rewrote so a failing run leaves no changes.
        cp "$work/go.mod" "$dir/go.mod"
        [ -f "$work/go.sum" ] && cp "$work/go.sum" "$dir/go.sum"
        status=1
    fi
    rm -rf "$work"
}

for module in $MODULES; do
    check_module "$module"
done

if [ "$status" -eq 0 ]; then
    echo "modules: tidy"
fi
exit "$status"
