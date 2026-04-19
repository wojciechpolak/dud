#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
#
# Update the commit SHA and image digest pins in client/Dockerfile.
#
# Usage:
#   ./scripts/update-docker-pins.sh                          # re-pin current tags
#   ./scripts/update-docker-pins.sh openssl-4.0.1            # upgrade OpenSSL
#   ./scripts/update-docker-pins.sh openssl-4.0.1 curl-8_20_0  # upgrade both
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
  OPENSSL_TAG="$1"
else
  OPENSSL_TAG="$(pin_tag openssl)"
  [ -n "$OPENSSL_TAG" ] || die "No '# pin: openssl <tag>' comment found in Dockerfile"
fi

if [ $# -ge 2 ]; then
  CURL_TAG="$2"
else
  CURL_TAG="$(pin_tag curl)"
  [ -n "$CURL_TAG" ] || die "No '# pin: curl <tag>' comment found in Dockerfile"
fi

# --- fetch new SHAs ---------------------------------------------------------

printf 'Fetching openssl tag %s...\n' "$OPENSSL_TAG"
OPENSSL_NEW=$(git ls-remote https://github.com/openssl/openssl.git \
  "refs/tags/${OPENSSL_TAG}^{}" | cut -f1)
[ -n "$OPENSSL_NEW" ] || die "Tag $OPENSSL_TAG not found in openssl/openssl"

printf 'Fetching curl tag %s...\n' "$CURL_TAG"
CURL_NEW=$(git ls-remote https://github.com/curl/curl.git \
  "refs/tags/${CURL_TAG}^{}" | cut -f1)
[ -n "$CURL_NEW" ] || die "Tag $CURL_TAG not found in curl/curl"

printf 'Fetching debian:stable-slim multi-arch digest...\n'
DEBIAN_NEW=$(docker buildx imagetools inspect debian:stable-slim 2>/dev/null | \
  awk '/^Digest:/{print $2}')
[ -n "$DEBIAN_NEW" ] || die "Failed to fetch Debian image digest (is Docker running?)"

# --- read current values from Dockerfile ------------------------------------

OPENSSL_OLD_TAG="$(pin_tag openssl)"
CURL_OLD_TAG="$(pin_tag curl)"

OPENSSL_OLD=$(grep -oE 'openssl fetch --depth 1 origin [0-9a-f]{40}' "$DOCKERFILE" | \
  grep -oE '[0-9a-f]{40}')
CURL_OLD=$(grep -oE 'curl fetch --depth 1 origin [0-9a-f]{40}' "$DOCKERFILE" | \
  grep -oE '[0-9a-f]{40}')
DEBIAN_OLD=$(grep -oE 'DEBIAN_DIGEST=sha256:[0-9a-f]+' "$DOCKERFILE" | \
  grep -oE 'sha256:[0-9a-f]+')

[ -n "$OPENSSL_OLD" ] || die "Could not find current OpenSSL SHA in Dockerfile"
[ -n "$CURL_OLD" ]   || die "Could not find current curl SHA in Dockerfile"
[ -n "$DEBIAN_OLD" ] || die "Could not find current Debian digest in Dockerfile"

# --- patch Dockerfile -------------------------------------------------------

python3 - <<PYEOF
import pathlib

path = pathlib.Path("$DOCKERFILE")
text = path.read_text()

# Update SHAs
text = text.replace("$OPENSSL_OLD", "$OPENSSL_NEW")
text = text.replace("$CURL_OLD",    "$CURL_NEW")
text = text.replace("$DEBIAN_OLD",  "$DEBIAN_NEW")

# Update pin comments if tags changed
text = text.replace(
    "# pin: openssl $OPENSSL_OLD_TAG\n",
    "# pin: openssl $OPENSSL_TAG\n",
)
text = text.replace(
    "# pin: curl $CURL_OLD_TAG\n",
    "# pin: curl $CURL_TAG\n",
)

path.write_text(text)
PYEOF

# --- report -----------------------------------------------------------------

printf '\nPin updates:\n'

if [ "$OPENSSL_OLD_TAG $OPENSSL_OLD" = "$OPENSSL_TAG $OPENSSL_NEW" ]; then
  printf '  openssl  %s %s  (unchanged)\n' "$OPENSSL_TAG" "$OPENSSL_NEW"
else
  printf '  openssl  %s %s -> %s %s\n' \
    "$OPENSSL_OLD_TAG" "$OPENSSL_OLD" "$OPENSSL_TAG" "$OPENSSL_NEW"
fi

if [ "$CURL_OLD_TAG $CURL_OLD" = "$CURL_TAG $CURL_NEW" ]; then
  printf '  curl     %s %s  (unchanged)\n' "$CURL_TAG" "$CURL_NEW"
else
  printf '  curl     %s %s -> %s %s\n' \
    "$CURL_OLD_TAG" "$CURL_OLD" "$CURL_TAG" "$CURL_NEW"
fi

if [ "$DEBIAN_OLD" = "$DEBIAN_NEW" ]; then
  printf '  debian   %s  (unchanged)\n' "$DEBIAN_NEW"
else
  printf '  debian   %s -> %s\n' "$DEBIAN_OLD" "$DEBIAN_NEW"
fi

printf '\nReview the diff, then commit:\n'
printf '  git diff client/Dockerfile\n'
printf '  git add client/Dockerfile && git commit -m "chore: update docker pins"\n'
