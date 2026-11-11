#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TAPE=${1:-docs/demos/tui-overview.tape}
if [ $# -gt 1 ]; then
  echo "Usage: $0 [docs/demos/tui-overview.tape]" >&2
  exit 2
fi
case "$TAPE" in
  docs/demos/tui-overview.tape) ;;
  *) echo "Choose the local TUI overview tape." >&2; exit 2 ;;
esac

for program in go vhs; do
  command -v "$program" >/dev/null 2>&1 || {
    echo "$program is required to record the local demo." >&2
    exit 1
  }
done

FIXTURE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dud-local-demo.XXXXXX")
trap 'rm -rf "$FIXTURE_ROOT"' EXIT HUP INT TERM
mkdir -p "$FIXTURE_ROOT/bin" "$FIXTURE_ROOT/work" "$FIXTURE_ROOT/tmp"
GOCACHE=/tmp/dud-go-build-cache go -C "$REPO_ROOT/client" build -o "$FIXTURE_ROOT/bin/dud" ./cmd/dud
printf 'Encrypted briefing for the demo.\n' > "$FIXTURE_ROOT/work/briefing.txt"

# Local recordings use disposable state independently of the operator's setup.
for variable in $(env | sed -n 's/^\(DUD_[A-Za-z0-9_]*\)=.*/\1/p'); do
  unset "$variable"
done
export PATH="$FIXTURE_ROOT/bin:$PATH"
export DUD_HOME="$FIXTURE_ROOT/state"
export DUD_DEMO_WORK="$FIXTURE_ROOT/work"
export TMPDIR="$FIXTURE_ROOT/tmp"

cd "$REPO_ROOT"
mkdir -p docs/assets
OUTPUT="docs/assets/$(basename "$TAPE" .tape).gif"
vhs "$TAPE"
GIF_BYTES=$(wc -c < "$OUTPUT")
if [ "$GIF_BYTES" -gt 10485760 ]; then
  echo "The GIF exceeds GitHub's 10485760-byte image limit: $OUTPUT" >&2
  exit 1
fi
echo "Recorded $OUTPUT (${GIF_BYTES} bytes)."
