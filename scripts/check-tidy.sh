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
# The -diff flag reports changes without writing go.mod or go.sum, including
# when dependency resolution fails or the command is interrupted.
set -uo pipefail

cd "$(dirname "$0")/.."

export GOCACHE="${GOCACHE:-/tmp/dud-go-build-cache}"

MODULES="client tests/vectors/protocol-v2 tools"

status=0

check_module() {
    local dir="$1"
    if ! go -C "$dir" mod tidy -diff; then
        echo "$dir: tidy check failed; resolve any errors and run 'go -C $dir mod tidy'" >&2
        status=1
    fi
}

for module in $MODULES; do
    check_module "$module"
done

if [ "$status" -eq 0 ]; then
    echo "modules: tidy"
fi
exit "$status"
