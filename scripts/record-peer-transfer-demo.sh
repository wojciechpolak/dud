#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TAPE=${1:-docs/demos/peer-transfer.tape}
if [ $# -gt 1 ]; then
  echo "Usage: $0 [docs/demos/recording.tape]" >&2
  exit 2
fi
case "$TAPE" in
  docs/demos/*.tape)
    ;;
  *)
    echo "The recording tape must be under docs/demos." >&2
    exit 2
    ;;
esac
[ -f "$REPO_ROOT/$TAPE" ] || {
  echo "Recording tape not found: $TAPE" >&2
  exit 2
}
CLIENT_IMAGE=${DUD_DEMO_CLIENT_IMAGE:-dud-client:latest}
SERVER_IMAGE=${DUD_DEMO_SERVER_IMAGE:-dud-server:latest}
CADDY_IMAGE=${DUD_DEMO_CADDY_IMAGE:-caddy:2}
RUN_ID="dud-peer-demo-$$"
NETWORK="$RUN_ID"
SERVER="$RUN_ID-server"
CADDY="$RUN_ID-caddy"
DOH="$RUN_ID-doh"
INVITER="$RUN_ID-inviter"
FIXTURE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dud-peer-demo.XXXXXX")
STATE_ROOT="$FIXTURE_ROOT/state"
CADDY_STATE="$FIXTURE_ROOT/caddy"
WORK_ROOT="$FIXTURE_ROOT/work"
DESKTOP_WORK="$WORK_ROOT/desktop"
LAPTOP_WORK="$WORK_ROOT/laptop"
SHARED_WORK="$WORK_ROOT/shared"
OUTPUT=$(sed -n 's/^Output //p' "$REPO_ROOT/$TAPE" | head -n 1)
case "$OUTPUT" in
  docs/assets/*.gif)
    OUTPUT="$REPO_ROOT/$OUTPUT"
    ;;
  *)
    echo "$TAPE must write a GIF under docs/assets." >&2
    exit 2
    ;;
esac
ORIGIN=https://dud.local.test
DOH_URL=https://doh.local.test/dns-query
DEPLOYMENT_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ENROLLMENT_SECRET=squid-lantern-rotate-9-mango
ENROLLMENT_KEY=dud2-enroll-key:_3iJ1c59CVqmBr68qGBeriqPHt5kLWa5j19Ql0PO31E
DROP_SECRET=peer-demo-drop-secret
E2E_SUBNET=${DUD_DEMO_SUBNET:-11.253.0.0/24}

cleanup() {
  docker rm -f "$INVITER" "$DOH" "$CADDY" "$SERVER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -rf "$FIXTURE_ROOT"
}
trap cleanup EXIT HUP INT TERM

require_program() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 is required to record the peer transfer demo." >&2
    exit 1
  }
}

for program in docker expect tmux vhs; do
  require_program "$program"
done

build_image() {
  component=$1
  image=$2
  override=$3
  if [ -n "$override" ]; then
    docker image inspect "$image" >/dev/null 2>&1 || {
      echo "$image is not present locally; build or pull it before recording." >&2
      exit 1
    }
    return
  fi
  "$SCRIPT_DIR/docker-build.sh" --component "$component" --image "${image%:*}" --tag "${image##*:}"
}

if [ "${DUD_DEMO_SKIP_BUILD:-0}" = 1 ]; then
  for image in "$CLIENT_IMAGE" "$SERVER_IMAGE"; do
    docker image inspect "$image" >/dev/null 2>&1 || {
      echo "$image is not present locally; build it or leave DUD_DEMO_SKIP_BUILD unset." >&2
      exit 1
    }
  done
else
  build_image server "$SERVER_IMAGE" "${DUD_DEMO_SERVER_IMAGE:-}"
  build_image client "$CLIENT_IMAGE" "${DUD_DEMO_CLIENT_IMAGE:-}"
fi

mkdir -p "$STATE_ROOT/dud/desktop" "$STATE_ROOT/dud/laptop" "$CADDY_STATE" "$FIXTURE_ROOT/tmux" "$DESKTOP_WORK" "$LAPTOP_WORK" "$SHARED_WORK" "$(dirname -- "$OUTPUT")"
printf 'Encrypted briefing for the demo.\n' > "$DESKTOP_WORK/briefing.txt"
printf '# Shared project\n\nA complete Git checkpoint travels through the paired relationship.\n' > "$DESKTOP_WORK/README.md"
chmod 700 "$CADDY_STATE"
chmod 700 "$FIXTURE_ROOT/tmux"
docker run --rm --user 0 --entrypoint /bin/chown \
  -v "$STATE_ROOT:/state" "$CLIENT_IMAGE" -R 1000:1000 /state
docker run --rm --user 0 --entrypoint /bin/chown \
  -v "$WORK_ROOT:/work" "$CLIENT_IMAGE" -R 1000:1000 /work
docker run --rm --entrypoint /bin/sh \
  -v "$WORK_ROOT:/work" "$CLIENT_IMAGE" -c '
    cd /work/desktop
    git init -q -b main
    git config user.name "DUD Demo"
    git config user.email dud-demo@example.invalid
    git add README.md
    git commit -qm "Share the project"
    git -C /work/laptop init -q -b main
  '
docker run --rm --entrypoint /bin/sh \
  -v "$LAPTOP_WORK:/work" "$CLIENT_IMAGE" -c \
  'age-keygen -o /work/recipient.key && age-keygen -y /work/recipient.key > /work/recipient.txt'
cp "$LAPTOP_WORK/recipient.txt" "$DESKTOP_WORK/recipient.txt"
cp "$DESKTOP_WORK/briefing.txt" "$LAPTOP_WORK/recipient.txt" "$LAPTOP_WORK/recipient.key" "$SHARED_WORK/"
docker network create --subnet "$E2E_SUBNET" "$NETWORK" >/dev/null

docker run -d --name "$SERVER" --network "$NETWORK" \
  -e DUD_DROP_SECRET="$DROP_SECRET" \
  -e DUD_DROP_ENABLED=true \
  -e DUD_PEER_ENABLED=true \
  -e DUD_PEER_DEPLOYMENT_KEY="$DEPLOYMENT_KEY" \
  -e DUD_PEER_SECRET="$ENROLLMENT_KEY" \
  -e DUD_PUBLIC_BASE_URL="$ORIGIN" \
  -e DUD_LOG_MODE=minimal \
  "$SERVER_IMAGE" >/dev/null

sleep 1
if [ "$(docker inspect -f '{{.State.Running}}' "$SERVER" 2>/dev/null)" != true ]; then
  docker logs "$SERVER" >&2 || true
  echo "dud-server exited during demo setup." >&2
  exit 1
fi

docker run -d --name "$CADDY" --network "$NETWORK" \
  -e DUD_HOSTNAME=dud.local.test \
  -e DUD_UPSTREAM="$SERVER:8787" \
  -e DUD_DOH_HOSTNAME=doh.local.test \
  -e DUD_DOH_UPSTREAM="$DOH:8053" \
  -v "$REPO_ROOT/tests/Caddyfile.v2-e2e:/etc/caddy/Caddyfile:ro" \
  -v "$CADDY_STATE:/data" \
  "$CADDY_IMAGE" >/dev/null

ROOT_CERT="$CADDY_STATE/caddy/pki/authorities/local/root.crt"
attempt=0
while [ ! -s "$ROOT_CERT" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    docker logs "$CADDY" >&2 || true
    echo "Caddy did not create its root certificate." >&2
    exit 1
  fi
  sleep 1
done
docker run --rm --user 0 --entrypoint /bin/chmod \
  -v "$CADDY_STATE:/state" "$CLIENT_IMAGE" 644 \
  /state/caddy/pki/authorities/local/root.crt
CADDY_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$CADDY")

docker run -d --name "$DOH" --network "$NETWORK" \
  -e DUD_E2E_TARGET_IP="$CADDY_IP" \
  -v "$REPO_ROOT/tests/v2-doh-server.mjs:/app/v2-doh-server.mjs:ro" \
  -w /app node:24.15-slim node v2-doh-server.mjs >/dev/null

run_client() {
  profile=$1
  shift
  docker run --rm --network "$NETWORK" \
    --add-host "dud.local.test:$CADDY_IP" \
    --add-host "doh.local.test:$CADDY_IP" \
    -e DUD_HOME=/state/dud \
    -e "DUD_PROFILE=$profile" \
    -e DUD_CA_BUNDLE=/cert/root.crt \
    -v "$STATE_ROOT:/state" \
    -v "$ROOT_CERT:/cert/root.crt:ro" \
    "$CLIENT_IMAGE" "$@"
}

if [ "$TAPE" != docs/demos/peer-pairing.tape ]; then
  run_client desktop init --device desktop --url "$ORIGIN" --doh-url "$DOH_URL" --ech-mode off
  run_client laptop init --device laptop --url "$ORIGIN" --doh-url "$DOH_URL" --ech-mode off
  for profile in desktop laptop; do
    docker run --rm --user 1000 --entrypoint /bin/sh \
      -e CADDY_IP="$CADDY_IP" \
      -v "$STATE_ROOT:/state" "$CLIENT_IMAGE" -c \
      "sed -i \"/^doh_url =/a doh_bootstrap = [\\\"$CADDY_IP\\\"]\" /state/dud/$profile/config/config.toml"
  done

  docker run -d -t --name "$INVITER" --network "$NETWORK" \
    --add-host "dud.local.test:$CADDY_IP" \
    -e DUD_HOME=/state/dud \
    -e DUD_PROFILE=desktop \
    -e DUD_CA_BUNDLE=/cert/root.crt \
    -e DUD_PEER_SECRET="$ENROLLMENT_SECRET" \
    -v "$STATE_ROOT:/state" \
    -v "$ROOT_CERT:/cert/root.crt:ro" \
    "$CLIENT_IMAGE" peer invite laptop >/dev/null

  attempt=0
  PAIRING_CODE=""
  while [ -z "$PAIRING_CODE" ]; do
    PAIRING_CODE=$(docker logs "$INVITER" 2>&1 | tr -d '\r' | sed -n 's/^Pairing code: \([0-9a-f-]*\)$/\1/p' | tail -n 1)
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
      docker logs "$INVITER" >&2 || true
      echo "The inviter did not display a pairing code." >&2
      exit 1
    fi
    [ -n "$PAIRING_CODE" ] || sleep 1
  done

  export CLIENT_IMAGE NETWORK CADDY_IP STATE_ROOT ROOT_CERT PAIRING_CODE
  expect <<'EXPECT_EOF'
set timeout 90
spawn docker run --rm -it --network $env(NETWORK) \
  --add-host dud.local.test:$env(CADDY_IP) \
  -e DUD_HOME=/state/dud \
  -e DUD_PROFILE=laptop \
  -e DUD_CA_BUNDLE=/cert/root.crt \
  -v $env(STATE_ROOT):/state \
  -v $env(ROOT_CERT):/cert/root.crt:ro \
  $env(CLIENT_IMAGE) peer accept desktop
expect "Pairing code: "
send -- "$env(PAIRING_CODE)\r"
expect eof
catch wait result
exit [lindex $result 3]
EXPECT_EOF

  INVITER_STATUS=$(docker wait "$INVITER")
  if [ "$INVITER_STATUS" -ne 0 ]; then
    docker logs "$INVITER" >&2 || true
    exit "$INVITER_STATUS"
  fi
fi

export DUD_DEMO_NETWORK="$NETWORK"
export DUD_DEMO_CADDY_IP="$CADDY_IP"
export DUD_DEMO_STATE="$STATE_ROOT"
export DUD_DEMO_ROOT_CERT="$ROOT_CERT"
export DUD_DEMO_CLIENT_IMAGE="$CLIENT_IMAGE"
export DUD_DEMO_DESKTOP_WORK="$DESKTOP_WORK"
export DUD_DEMO_LAPTOP_WORK="$LAPTOP_WORK"
export DUD_DEMO_SHARED_WORK="$SHARED_WORK"
export DUD_DEMO_DROP_SECRET="$DROP_SECRET"
export DUD_DEMO_ENROLLMENT_SECRET="$ENROLLMENT_SECRET"
export DUD_DEMO_SHIM="$SCRIPT_DIR/demo-peer-dud.sh"
export DUD_DEMO_DROP_SHIM="$SCRIPT_DIR/demo-drop-dud.sh"
export TMUX_TMPDIR="$FIXTURE_ROOT/tmux"
unset TMUX

cd "$REPO_ROOT"
rm -f "$OUTPUT"
vhs "$TAPE"

GIF_BYTES=$(wc -c < "$OUTPUT")
if [ "$GIF_BYTES" -gt 10485760 ]; then
  echo "The peer transfer GIF is ${GIF_BYTES} bytes; GitHub image uploads allow at most 10485760 bytes." >&2
  exit 1
fi

echo "Recorded $OUTPUT (${GIF_BYTES} bytes)."
