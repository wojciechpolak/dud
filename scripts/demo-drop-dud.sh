#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
set -eu

: "${DUD_DEMO_NETWORK:?record-peer-transfer-demo.sh did not define DUD_DEMO_NETWORK}"
: "${DUD_DEMO_CADDY_IP:?record-peer-transfer-demo.sh did not define DUD_DEMO_CADDY_IP}"
: "${DUD_DEMO_ROOT_CERT:?record-peer-transfer-demo.sh did not define DUD_DEMO_ROOT_CERT}"
: "${DUD_DEMO_CLIENT_IMAGE:?record-peer-transfer-demo.sh did not define DUD_DEMO_CLIENT_IMAGE}"
: "${DUD_DEMO_DESKTOP_WORK:?record-peer-transfer-demo.sh did not define DUD_DEMO_DESKTOP_WORK}"
: "${DUD_DEMO_LAPTOP_WORK:?record-peer-transfer-demo.sh did not define DUD_DEMO_LAPTOP_WORK}"
: "${DUD_DEMO_DROP_SECRET:?record-peer-transfer-demo.sh did not define DUD_DEMO_DROP_SECRET}"
: "${DUD_DEMO_SIDE:?set DUD_DEMO_SIDE to desktop or laptop}"

case "$DUD_DEMO_SIDE" in
  desktop)
    work_dir=$DUD_DEMO_DESKTOP_WORK
    ;;
  laptop)
    work_dir=$DUD_DEMO_LAPTOP_WORK
    ;;
  *)
    echo "The dead-drop demo recognizes only the desktop and laptop sides." >&2
    exit 2
    ;;
esac

exec docker run --rm \
  --network "$DUD_DEMO_NETWORK" \
  --add-host "dud.local.test:$DUD_DEMO_CADDY_IP" \
  --add-host "doh.local.test:$DUD_DEMO_CADDY_IP" \
  -e "DUD_DROP_SECRET=$DUD_DEMO_DROP_SECRET" \
  -e DUD_BASE_URL=https://dud.local.test \
  -e DUD_DOH_URL=https://doh.local.test/dns-query \
  -e DUD_ECH_MODE=off \
  -e DUD_CA_BUNDLE=/cert/root.crt \
  -v "$DUD_DEMO_ROOT_CERT:/cert/root.crt:ro" \
  -v "$work_dir:/work" \
  "$DUD_DEMO_CLIENT_IMAGE" "$@"
