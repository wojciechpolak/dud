#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
#
# Build the Go static-analysis binaries from the tools module into bin/.
#
# The analyzers live in tools/, a module separate from the two that ship, so
# nothing an analyzer depends on can appear in the dependency graph of the
# client binary or the protocol vector generator. This builds each tool to a
# binary instead of running it through "go tool", so the version that runs is
# the one tools/go.sum hashes, and running one resolves no modules.
#
# Usage: scripts/go-tools.sh [name ...]   (default: every tool)
set -euo pipefail

cd "$(dirname "$0")/.."

export GOCACHE="${GOCACHE:-/tmp/dud-go-build-cache}"

# Maps a tool name to the package that provides it. analyze is this
# repository's own program. The rest are third-party commands that the tool
# directives in tools/go.mod name.
tool_package() {
    case "$1" in
        analyze) echo "./analyze" ;;
        deadcode) echo "golang.org/x/tools/cmd/deadcode" ;;
        errcheck) echo "github.com/kisielk/errcheck" ;;
        gocyclo) echo "github.com/fzipp/gocyclo/cmd/gocyclo" ;;
        goimports) echo "golang.org/x/tools/cmd/goimports" ;;
        govulncheck) echo "golang.org/x/vuln/cmd/govulncheck" ;;
        staticcheck) echo "honnef.co/go/tools/cmd/staticcheck" ;;
        *) return 1 ;;
    esac
}

ALL_TOOLS="analyze deadcode errcheck gocyclo goimports govulncheck staticcheck"

tools=("$@")
if [ "${#tools[@]}" -eq 0 ]; then
    read -r -a tools <<<"$ALL_TOOLS"
fi

mkdir -p bin

for tool in "${tools[@]}"; do
    package="$(tool_package "$tool")" || {
        echo "unknown tool '$tool'; known tools are: $ALL_TOOLS" >&2
        exit 1
    }

    # Rebuild when the pinned set moves, or when this repository's own tool
    # source changes. Anything newer than both inputs is already current.
    if [ -x "bin/$tool" ] &&
        [ "bin/$tool" -nt tools/go.mod ] &&
        [ "bin/$tool" -nt tools/go.sum ] &&
        { [ "$tool" != analyze ] || [ "bin/$tool" -nt tools/analyze/main.go ]; }; then
        continue
    fi

    echo "building bin/$tool"
    go -C tools build -o "../bin/$tool" "$package"
done
