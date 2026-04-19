#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

IMAGE_NAME=${IMAGE_NAME:-dud-client}
IMAGE_TAG=${IMAGE_TAG:-latest}
PLATFORM_ARG=""
LOAD_FLAG=${LOAD_FLAG:---load}
PUSH_FLAG=""

usage() {
  cat <<'EOF'
Usage: docker-build.sh [options]

Options:
  --image NAME          Docker image name. Default: dud-client
  --tag TAG             Docker image tag. Default: latest
  --platform PLATFORM   Buildx platform, for example linux/amd64
  --push                Push the built image instead of loading it locally
  --output type=...     Forward a custom --output value to docker buildx build
  -h, --help            Show this help text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
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

set -- "$@" \
  --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
  --file "$REPO_ROOT/client/Dockerfile" \
  "$REPO_ROOT/client"

exec "$@"

