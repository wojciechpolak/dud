#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

COMPONENT=${COMPONENT:-client}
IMAGE_NAME=${IMAGE_NAME:-}
IMAGE_TAG=${IMAGE_TAG:-latest}
PLATFORM_ARG=""
LOAD_FLAG=${LOAD_FLAG:---load}
PUSH_FLAG=""
CUSTOM_OUTPUT=0

usage() {
  cat <<'EOF'
Usage: docker-build.sh [options]

Options:
  --component NAME      Build component: client or server. Default: client
  --image NAME          Docker image name. Default: dud-client or dud-server
  --tag TAG             Docker image tag. Default: latest
  --platform PLATFORM   Buildx platform, for example linux/amd64
  --push                Push the built image instead of loading it locally
  --output type=...     Forward a custom --output value to docker buildx build
  -h, --help            Show this help text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --component)
      [ $# -ge 2 ] || {
        echo "Missing value for --component" >&2
        exit 1
      }
      COMPONENT=$2
      shift 2
      ;;
    --image)
      [ $# -ge 2 ] || {
        echo "Missing value for --image" >&2
        exit 1
      }
      IMAGE_NAME=$2
      shift 2
      ;;
    --tag)
      [ $# -ge 2 ] || {
        echo "Missing value for --tag" >&2
        exit 1
      }
      IMAGE_TAG=$2
      shift 2
      ;;
    --platform)
      [ $# -ge 2 ] || {
        echo "Missing value for --platform" >&2
        exit 1
      }
      PLATFORM_ARG="--platform $2"
      shift 2
      ;;
    --push)
      PUSH_FLAG="--push"
      LOAD_FLAG=""
      shift 1
      ;;
    --output)
      [ $# -ge 2 ] || {
        echo "Missing value for --output" >&2
        exit 1
      }
      LOAD_FLAG="--output $2"
      CUSTOM_OUTPUT=1
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

DOCKERFILE=""
BUILD_CONTEXT=""
VERSION_BUILD_ARG=""

package_version() {
  sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$REPO_ROOT/package.json" | head -n 1
}

case "$COMPONENT" in
  client)
    DOCKERFILE="$REPO_ROOT/client/Dockerfile"
    BUILD_CONTEXT="$REPO_ROOT/client"
    IMAGE_NAME=${IMAGE_NAME:-dud-client}
    VERSION_BUILD_ARG="DUD_VERSION=$(package_version)"
    ;;
  server)
    DOCKERFILE="$REPO_ROOT/server/Dockerfile"
    BUILD_CONTEXT="$REPO_ROOT"
    IMAGE_NAME=${IMAGE_NAME:-dud-server}
    ;;
  *)
    echo "Unknown component: $COMPONENT" >&2
    usage >&2
    exit 1
    ;;
esac

can_fallback_to_legacy_build() {
  [ -z "$PUSH_FLAG" ] \
    && [ "$CUSTOM_OUTPUT" -eq 0 ] \
    && [ "$LOAD_FLAG" = "--load" ] \
    && [ -z "$PLATFORM_ARG" ]
}

set -- docker buildx build

if [ -n "$PLATFORM_ARG" ]; then
  # shellcheck disable=SC2086
  set -- "$@" $PLATFORM_ARG
fi

if [ -n "$LOAD_FLAG" ]; then
  # shellcheck disable=SC2086
  set -- "$@" $LOAD_FLAG
fi

if [ -n "$PUSH_FLAG" ]; then
  set -- "$@" "$PUSH_FLAG"
fi

if [ -n "$VERSION_BUILD_ARG" ]; then
  set -- "$@" --build-arg "$VERSION_BUILD_ARG"
fi

set -- "$@" \
  --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
  --file "$DOCKERFILE" \
  "$BUILD_CONTEXT"

if can_fallback_to_legacy_build; then
  BUILD_LOG=$(mktemp "${TMPDIR:-/tmp}/dud-docker-build.XXXXXX")
  TAIL_PID=""
  cleanup_build_log() {
    if [ -n "$TAIL_PID" ]; then
      kill "$TAIL_PID" 2>/dev/null || true
      wait "$TAIL_PID" 2>/dev/null || true
    fi
    rm -f "$BUILD_LOG"
  }
  trap cleanup_build_log EXIT HUP INT TERM

  tail -n +1 -f "$BUILD_LOG" &
  TAIL_PID=$!

  set +e
  "$@" >"$BUILD_LOG" 2>&1
  BUILD_STATUS=$?
  kill "$TAIL_PID" 2>/dev/null || true
  wait "$TAIL_PID" 2>/dev/null || true
  TAIL_PID=""
  set -e

  if [ "$BUILD_STATUS" -eq 0 ]; then
    exit 0
  fi

  if grep -q 'failed to create snapshot: missing parent' "$BUILD_LOG" \
    || grep -q 'bucket: not found' "$BUILD_LOG"; then
    cat >&2 <<'EOF'

Docker BuildKit appears to have a corrupted local snapshot cache.
Retrying this local image build with the legacy Docker builder.
EOF
    set -- env DOCKER_BUILDKIT=0 docker build
    if [ -n "$VERSION_BUILD_ARG" ]; then
      set -- "$@" --build-arg "$VERSION_BUILD_ARG"
    fi
    exec "$@" \
      --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
      --file "$DOCKERFILE" \
      "$BUILD_CONTEXT"
  fi

  exit "$BUILD_STATUS"
fi

exec "$@"
