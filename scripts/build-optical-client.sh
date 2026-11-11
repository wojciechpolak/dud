#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
# Build a local window-capable client and its sibling renderer for this host.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-/tmp/dud-optical-client}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cd "$ROOT/client"
export GOCACHE="${GOCACHE:-/tmp/dud-go-build-cache}"
go build -trimpath -tags nativewindow -o "$OUT/dud" ./cmd/dud
go build -trimpath -tags nativewindow -o "$OUT/dud-optical-window" ./cmd/dud-optical-window
