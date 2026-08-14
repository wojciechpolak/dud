#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
#
# Update the commit SHA and image digest pins in client/Dockerfile.
#
# Usage:
#   ./scripts/update-docker-pins.sh          # re-pin the current tag
#   ./scripts/update-docker-pins.sh v1.3.2   # upgrade age
#
# Pin comments in the Dockerfile (# pin: <lib> <tag>) record the current tag
# names and are updated alongside the SHAs when tags change.
#
# Requires: git, docker (with buildx), python3

set -eu

DOCKERFILE="$(cd "$(dirname "$0")/.." && pwd)/client/Dockerfile"

die() { printf '%s\n' "$*" >&2; exit 1; }

pin_tag() {
  # Read the current tag for a library from the Dockerfile's # pin: comments
  grep -E "^# pin: $1 " "$DOCKERFILE" | awk '{print $4}'
}

# --- resolve tags -----------------------------------------------------------

if [ $# -ge 1 ]; then
  AGE_TAG="$1"
else
  AGE_TAG="$(pin_tag age)"
  [ -n "$AGE_TAG" ] || die "No '# pin: age <tag>' comment found in Dockerfile"
fi

# --- fetch new SHAs ---------------------------------------------------------

printf 'Fetching age tag %s...\n' "$AGE_TAG"
AGE_NEW=$(git ls-remote https://github.com/FiloSottile/age.git \
  "refs/tags/${AGE_TAG}^{}" | cut -f1)
[ -n "$AGE_NEW" ] || die "Tag $AGE_TAG not found in FiloSottile/age"

printf 'Fetching debian:stable-slim multi-arch digest...\n'
DEBIAN_NEW=$(docker buildx imagetools inspect debian:stable-slim 2>/dev/null | \
  awk '/^Digest:/{print $2}')
[ -n "$DEBIAN_NEW" ] || die "Failed to fetch Debian image digest (is Docker running?)"

# --- read current values from Dockerfile ------------------------------------

AGE_OLD_TAG="$(pin_tag age)"

AGE_OLD=$(grep -oE 'age fetch --depth 1 origin [0-9a-f]{40}' "$DOCKERFILE" | \
  grep -oE '[0-9a-f]{40}')
DEBIAN_OLD=$(grep -oE 'DEBIAN_DIGEST=sha256:[0-9a-f]+' "$DOCKERFILE" | \
  grep -oE 'sha256:[0-9a-f]+')

[ -n "$AGE_OLD" ]    || die "Could not find current age SHA in Dockerfile"
[ -n "$DEBIAN_OLD" ] || die "Could not find current Debian digest in Dockerfile"

# --- patch Dockerfile -------------------------------------------------------

python3 - <<PYEOF
import pathlib

path = pathlib.Path("$DOCKERFILE")
text = path.read_text()

# Update SHAs
text = text.replace("$AGE_OLD",     "$AGE_NEW")
text = text.replace("$DEBIAN_OLD",  "$DEBIAN_NEW")

# Update pin comments if tags changed
text = text.replace(
    "# pin: age $AGE_OLD_TAG\n",
    "# pin: age $AGE_TAG\n",
)

path.write_text(text)
PYEOF

# --- report -----------------------------------------------------------------

printf '\nPin updates:\n'

if [ "$AGE_OLD_TAG $AGE_OLD" = "$AGE_TAG $AGE_NEW" ]; then
  printf '  age      %s %s  (unchanged)\n' "$AGE_TAG" "$AGE_NEW"
else
  printf '  age      %s %s -> %s %s\n' \
    "$AGE_OLD_TAG" "$AGE_OLD" "$AGE_TAG" "$AGE_NEW"
fi

if [ "$DEBIAN_OLD" = "$DEBIAN_NEW" ]; then
  printf '  debian   %s  (unchanged)\n' "$DEBIAN_NEW"
else
  printf '  debian   %s -> %s\n' "$DEBIAN_OLD" "$DEBIAN_NEW"
fi

printf '\nReview the diff, then commit:\n'
printf '  git diff client/Dockerfile\n'
printf '  git add client/Dockerfile && git commit -m "chore: update docker pins"\n'
