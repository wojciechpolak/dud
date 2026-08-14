#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
#
# Build the native `dud` client for every published platform, twice, and fail if
# the two builds differ. A release artifact whose bytes depend on when or where
# it was built cannot be verified against its own source, so reproducibility is
# checked here rather than asserted in the release notes.
#
# Output:
#   dist/release/dud-<os>-<arch>[.exe]
#   dist/release/SHA256SUMS
#
# Usage:
#   ./scripts/build-release-binaries.sh [version]
#
# Requires: go, and one of sha256sum or shasum.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/release"
VERSION="${1:-$(node -p "require('$ROOT/package.json').version")}"

PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

build_one() {
  # $1 GOOS, $2 GOARCH, $3 output path
  # -trimpath removes build paths, CGO_ENABLED=0 removes the host toolchain, and
  # a fixed ldflags string removes the only remaining variable input.
  (
    cd "$ROOT/client"
    CGO_ENABLED=0 GOOS="$1" GOARCH="$2" GOFLAGS=-mod=readonly \
      go build -trimpath \
        -ldflags "-s -w -buildid= -X main.version=$VERSION" \
        -o "$3" ./cmd/dud
  )
}

rm -rf "$OUT"
mkdir -p "$OUT"
VERIFY="$(mktemp -d)"
trap 'rm -rf "$VERIFY"' EXIT HUP INT TERM

printf 'Building dud %s for: %s\n' "$VERSION" "$PLATFORMS"

for platform in $PLATFORMS; do
  goos="${platform%/*}"
  goarch="${platform#*/}"
  name="dud-$goos-$goarch"
  [ "$goos" = "windows" ] && name="$name.exe"

  build_one "$goos" "$goarch" "$OUT/$name"
  build_one "$goos" "$goarch" "$VERIFY/$name"

  first="$(sha256_of "$OUT/$name")"
  second="$(sha256_of "$VERIFY/$name")"
  if [ "$first" != "$second" ]; then
    printf '%s is not reproducible: %s != %s\n' "$name" "$first" "$second" >&2
    exit 1
  fi
  printf '  %s  %s\n' "$first" "$name"
done

(
  cd "$OUT"
  : > SHA256SUMS
  for file in dud-*; do
    printf '%s  %s\n' "$(sha256_of "$file")" "$file" >> SHA256SUMS
  done
)

printf '\nReproducible. Checksums in %s/SHA256SUMS\n' "$OUT"
