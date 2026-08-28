#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CLIENT_IMAGE=${DUD_E2E_CLIENT_IMAGE:-dud-client:latest}
SERVER_IMAGE=${DUD_E2E_SERVER_IMAGE:-dud-server:latest}
CADDY_IMAGE=${DUD_E2E_CADDY_IMAGE:-caddy:2}
RUN_ID="dud-v2-e2e-$$"
NETWORK="$RUN_ID"
SERVER="$RUN_ID-server"
CADDY="$RUN_ID-caddy"
DOH="$RUN_ID-doh"
INVITER="$RUN_ID-inviter"
TEMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dud-v2-e2e.XXXXXX")
DESKTOP_STATE="$TEMP_ROOT/desktop"
LAPTOP_STATE="$TEMP_ROOT/laptop"
CADDY_STATE="$TEMP_ROOT/caddy"
DROP_STATE="$TEMP_ROOT/drop"
ORIGIN=https://dud.local.test
DOH_URL=https://doh.local.test/dns-query
DEPLOYMENT_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ENROLLMENT_SECRET=squid-lantern-rotate-9-mango
# The derived key for the passphrase above, frozen in the wire vectors. The
# server runs on this form and the clients on the passphrase, so every run
# proves the two interoperate — which is what lets a deployment with too little
# CPU for the key derivation still gate enrollment.
ENROLLMENT_KEY=dud2-enroll-key:_3iJ1c59CVqmBr68qGBeriqPHt5kLWa5j19Ql0PO31E
DROP_SECRET=v2-e2e-drop-secret
E2E_SUBNET=${DUD_E2E_SUBNET:-11.254.0.0/24}

cleanup() {
  docker rm -f "$INVITER" "$DOH" "$CADDY" "$SERVER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true

  # Caddy owns its private PKI directory, so restore the invoking user's
  # ownership before removing the host-mounted test state.
  docker run --rm --user 0 --entrypoint /bin/chown \
    -v "$TEMP_ROOT:/state" "$CLIENT_IMAGE" -R "$(id -u):$(id -g)" /state \
    >/dev/null 2>&1 || true
  rm -rf "$TEMP_ROOT"
}
trap cleanup EXIT HUP INT TERM

command -v docker >/dev/null 2>&1 || {
  echo "docker is required" >&2
  exit 1
}
command -v expect >/dev/null 2>&1 || {
  echo "expect is required to exercise the controlling-TTY prompt" >&2
  exit 1
}

# Build before running, so the suite cannot report a pass for source it never
# executed. This is not a slow path: an unchanged context is a BuildKit cache
# hit of about a second, and the cache compares the build inputs themselves
# rather than the image timestamp, which is the only comparison that stays
# honest when a change is still uncommitted.
#
# Skipping it has cost a real verification: an enrollment change once "passed"
# here against images built before that change existed, and the stale server
# surfaced the next genuine failure as an unrelated missing pairing code.
build_image() {
  component=$1
  image=$2
  override=$3
  if [ -n "$override" ]; then
    # A named image is something this script did not build and cannot judge.
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      echo "$image is not present locally; build or pull it first." >&2
      exit 1
    fi
    echo "Using $image as given; its freshness is not checked." >&2
    return 0
  fi
  echo "Building $image ..." >&2
  if ! "$SCRIPT_DIR/docker-build.sh" --component "$component" >/dev/null; then
    echo "Failed to build $image; rerun ./scripts/docker-build.sh --component $component to see why." >&2
    exit 1
  fi
}

if [ "${DUD_E2E_SKIP_BUILD:-0}" = "1" ]; then
  echo "DUD_E2E_SKIP_BUILD=1: running against whatever $CLIENT_IMAGE and $SERVER_IMAGE already contain." >&2
  echo "A pass proves nothing about source built after those images." >&2
  for image in "$CLIENT_IMAGE" "$SERVER_IMAGE"; do
    docker image inspect "$image" >/dev/null 2>&1 || {
      echo "$image is not present locally." >&2
      exit 1
    }
  done
else
  build_image server "$SERVER_IMAGE" "${DUD_E2E_SERVER_IMAGE:-}"
  build_image client "$CLIENT_IMAGE" "${DUD_E2E_CLIENT_IMAGE:-}"
fi

mkdir -p "$DESKTOP_STATE" "$LAPTOP_STATE" "$CADDY_STATE"
chmod 700 "$CADDY_STATE"
docker run --rm --user 0 --entrypoint /bin/chown \
  -v "$DESKTOP_STATE:/state" "$CLIENT_IMAGE" -R 1000:1000 /state
docker run --rm --user 0 --entrypoint /bin/chown \
  -v "$LAPTOP_STATE:/state" "$CLIENT_IMAGE" -R 1000:1000 /state
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

# A configuration error makes the server exit within milliseconds. Every wait
# after this point is a 60-second timeout, so without this check that failure
# surfaces a minute later as an unrelated "inviter did not display a pairing
# code", and the log explaining it is deleted along with the container.
sleep 1
if [ "$(docker inspect -f '{{.State.Running}}' "$SERVER" 2>/dev/null)" != true ]; then
  docker logs "$SERVER" >&2 || true
  echo "dud-server exited during startup; its log above says why." >&2
  echo "The image was built from this working tree, so a credential it rejects is one this script sets." >&2
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
while ! docker exec "$CADDY" test -s /data/caddy/pki/authorities/local/root.crt; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    docker logs "$CADDY" >&2 || true
    echo "Caddy root certificate was not created" >&2
    exit 1
  fi
  sleep 1
done

# Caddy keeps the CA private by default, while clients run as the unprivileged
# image user. The public root certificate alone is readable by the clients.
docker run --rm --user 0 --entrypoint /bin/chmod \
  -v "$CADDY_STATE:/state" "$CLIENT_IMAGE" 644 \
  /state/caddy/pki/authorities/local/root.crt
CADDY_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$CADDY")

docker run -d --name "$DOH" --network "$NETWORK" \
  -e DUD_E2E_TARGET_IP="$CADDY_IP" \
  -v "$REPO_ROOT/tests/v2-doh-server.mjs:/app/v2-doh-server.mjs:ro" \
  -w /app node:24.15-slim node v2-doh-server.mjs >/dev/null

run_client() {
  state=$1
  shift
  docker run --rm --network "$NETWORK" \
    --add-host "dud.local.test:$CADDY_IP" \
    --add-host "doh.local.test:$CADDY_IP" \
    -e DUD_HOME=/state/dud \
    -e DUD_CA_BUNDLE=/cert/root.crt \
    -v "$state:/state" \
    -v "$ROOT_CERT:/cert/root.crt:ro" \
    "$CLIENT_IMAGE" "$@"
}

# Client state is private to the image user. Read assertions through that user
# so they exercise the same permissions as a client instead of the host's UID.
state_file_matches() {
  state=$1
  path=$2
  pattern=$3
  docker run --rm --user 1000 --entrypoint /bin/grep \
    -v "$state:/state" "$CLIENT_IMAGE" -q "$pattern" "$path"
}

run_client "$DESKTOP_STATE" init --device desktop --url "$ORIGIN" --doh-url "$DOH_URL" --ech-mode off
run_client "$LAPTOP_STATE" init --device laptop --url "$ORIGIN" --doh-url "$DOH_URL" --ech-mode off
for state in "$DESKTOP_STATE" "$LAPTOP_STATE"; do
  docker run --rm --user 1000 --entrypoint /bin/sh \
    -e CADDY_IP="$CADDY_IP" \
    -v "$state:/state" "$CLIENT_IMAGE" -c \
    'sed -i "/^doh_url =/a doh_bootstrap = [\"$CADDY_IP\"]" /state/dud/default/config/config.toml'
done

docker run -d -t --name "$INVITER" --network "$NETWORK" \
  --add-host "dud.local.test:$CADDY_IP" \
  -e DUD_HOME=/state/dud \
  -e DUD_CA_BUNDLE=/cert/root.crt \
  -e DUD_PEER_SECRET="$ENROLLMENT_SECRET" \
  -v "$DESKTOP_STATE:/state" \
  -v "$ROOT_CERT:/cert/root.crt:ro" \
  "$CLIENT_IMAGE" peer invite laptop >/dev/null

attempt=0
PAIRING_CODE=""
while [ -z "$PAIRING_CODE" ]; do
  PAIRING_CODE=$(docker logs "$INVITER" 2>&1 | tr -d '\r' | sed -n 's/^Pairing code: \([0-9a-f-]*\)$/\1/p' | tail -n 1)
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    docker logs "$INVITER" >&2 || true
    echo "inviter did not display a pairing code" >&2
    exit 1
  fi
  [ -n "$PAIRING_CODE" ] || sleep 1
done

# The image must render the code as a real terminal QR code, not merely print
# it: the invitee below types exactly the displayed string, which is what a
# scanner reads from those graphics.
INVITER_OUTPUT=$(docker logs "$INVITER" 2>&1 | tr -d '\r')
printf '%s\n' "$INVITER_OUTPUT" | grep -q '^QR Code:$' || {
  printf '%s\n' "$INVITER_OUTPUT" >&2
  echo "inviter did not render a QR code" >&2
  exit 1
}
QR_ROWS=$(printf '%s\n' "$INVITER_OUTPUT" | sed -n '/^QR Code:$/,/^Waiting for the peer to accept/p' | grep -c '█')
[ "$QR_ROWS" -ge 10 ] || {
  printf '%s\n' "$INVITER_OUTPUT" >&2
  echo "terminal QR code has only $QR_ROWS rendered rows" >&2
  exit 1
}
docker run --rm --entrypoint qrencode "$CLIENT_IMAGE" \
  -t ansiutf8 "$PAIRING_CODE" | tr -d '\r' | grep '█' >"$TEMP_ROOT/expected-qr"
printf '%s\n' "$INVITER_OUTPUT" | sed -n '/^QR Code:$/,/^Waiting for the peer to accept/p' |
  grep '█' >"$TEMP_ROOT/displayed-qr"
diff "$TEMP_ROOT/expected-qr" "$TEMP_ROOT/displayed-qr" >/dev/null || {
  echo "displayed QR code does not encode the displayed pairing code" >&2
  exit 1
}

export CLIENT_IMAGE NETWORK CADDY_IP LAPTOP_STATE ROOT_CERT PAIRING_CODE
expect <<'EXPECT_EOF'
set timeout 90
spawn docker run --rm -it --network $env(NETWORK) \
  --add-host dud.local.test:$env(CADDY_IP) \
  -e DUD_HOME=/state/dud \
  -e DUD_CA_BUNDLE=/cert/root.crt \
  -v $env(LAPTOP_STATE):/state \
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

run_client "$DESKTOP_STATE" send laptop -m desktop-to-laptop
LAPTOP_RECEIVED=$(run_client "$LAPTOP_STATE" receive desktop --wait 30s)
printf '%s\n' "$LAPTOP_RECEIVED" | grep -q '^desktop-to-laptop$'

run_client "$LAPTOP_STATE" send desktop -m laptop-to-desktop
DESKTOP_RECEIVED=$(run_client "$DESKTOP_STATE" receive laptop --wait 30s)
printf '%s\n' "$DESKTOP_RECEIVED" | grep -q '^laptop-to-desktop$'

# A file send takes the collection path, not the message path.
docker run --rm --user 1000 --entrypoint /bin/sh \
  -v "$LAPTOP_STATE:/state" "$CLIENT_IMAGE" -c \
  'printf "file-payload\n" > /state/send-file.txt'
run_client "$LAPTOP_STATE" send desktop --file /state/send-file.txt
run_client "$DESKTOP_STATE" receive laptop --wait 30s --out-dir /state/received
state_file_matches "$DESKTOP_STATE" /state/received/send-file.txt '^file-payload$' || {
  echo "peer file send did not round-trip" >&2
  exit 1
}

# The same file again, into an output that already holds those exact bytes.
# Writing it is a no-op, so it must be accepted on the first invocation rather
# than refused once and accepted on the retry.
run_client "$LAPTOP_STATE" send desktop --file /state/send-file.txt
run_client "$DESKTOP_STATE" receive laptop --wait 30s --out-dir /state/received

# Two sends, then one receive. Draining the whole queue in a single invocation
# is the behaviour operators actually depend on, and it cannot be observed from
# the one-delivery-at-a-time path the checks above take.
docker run --rm --user 1000 --entrypoint /bin/sh \
  -v "$LAPTOP_STATE:/state" "$CLIENT_IMAGE" -c \
  'printf "first-of-two\n" > /state/drain-one.txt'
docker run --rm --user 1000 --entrypoint /bin/sh \
  -v "$LAPTOP_STATE:/state" "$CLIENT_IMAGE" -c \
  'printf "second-of-two\n" > /state/drain-two.txt'
run_client "$LAPTOP_STATE" send desktop --file /state/drain-one.txt
run_client "$LAPTOP_STATE" send desktop --file /state/drain-two.txt

# The inbox preview reports the head without committing it, so the receive
# below must still find both deliveries.
INBOX_PREVIEW=$(run_client "$DESKTOP_STATE" inbox laptop)
printf '%s\n' "$INBOX_PREVIEW"
printf '%s\n' "$INBOX_PREVIEW" | grep -q 'drain-one.txt' || {
  echo "inbox did not preview the waiting delivery" >&2
  exit 1
}

DRAINED=$(run_client "$DESKTOP_STATE" receive laptop --wait 30s --out-dir /state/received)
printf '%s\n' "$DRAINED"
printf '%s\n' "$DRAINED" | grep -q 'Received 2 deliveries from laptop' || {
  echo "one receive did not drain both deliveries" >&2
  exit 1
}
state_file_matches "$DESKTOP_STATE" /state/received/drain-one.txt '^first-of-two$' &&
  state_file_matches "$DESKTOP_STATE" /state/received/drain-two.txt '^second-of-two$' || {
  echo "drained deliveries did not both land" >&2
  exit 1
}

# The queue is empty now, so a further receive reports exactly that.
EMPTIED=$(run_client "$DESKTOP_STATE" receive laptop)
printf '%s\n' "$EMPTIED"
printf '%s\n' "$EMPTIED" | grep -q '^No pending delivery from laptop.$' || {
  echo "receive did not report an empty queue" >&2
  exit 1
}

# Git synchronization starts with a complete checkpoint. Once the receiver's
# signed acknowledgement reaches the sender, automatic mode uses that exact
# checkpoint as the base for a non-thin incremental pack.
for state in "$DESKTOP_STATE" "$LAPTOP_STATE"; do
  docker run --rm --user 1000 --entrypoint /bin/sh \
    -v "$state:/state" "$CLIENT_IMAGE" -c \
    'git init -b main /state/repo >/dev/null && git -C /state/repo config user.name "DUD E2E" && git -C /state/repo config user.email dud@example.test'
done
docker run --rm --user 1000 --entrypoint /bin/sh \
  -v "$DESKTOP_STATE:/state" "$CLIENT_IMAGE" -c \
  'printf "base\n" > /state/repo/README.md && git -C /state/repo add README.md && git -C /state/repo commit -m base >/dev/null'

run_git_client_at() {
  state=$1
  workdir=$2
  shift 2
  docker run --rm --network "$NETWORK" \
    --add-host "dud.local.test:$CADDY_IP" \
    --add-host "doh.local.test:$CADDY_IP" \
    -e DUD_HOME=/state/dud \
    -e DUD_CA_BUNDLE=/cert/root.crt \
    -v "$state:/state" \
    -v "$ROOT_CERT:/cert/root.crt:ro" \
    -w "$workdir" \
    "$CLIENT_IMAGE" "$@"
}

run_git_client() {
  state=$1
  shift
  run_git_client_at "$state" /state/repo "$@"
}

FULL_PUSH=$(run_git_client "$DESKTOP_STATE" git push laptop --full --json)
printf '%s\n' "$FULL_PUSH" | grep -q '"checkpoint_mode": "full"' || {
  printf '%s\n' "$FULL_PUSH" >&2
  echo "first peer Git push was not a complete checkpoint" >&2
  exit 1
}
FULL_FETCH=$(run_git_client "$LAPTOP_STATE" git fetch desktop --associate --json)
printf '%s\n' "$FULL_FETCH" | grep -q '"checkpoint_mode": "full"' || {
  printf '%s\n' "$FULL_FETCH" >&2
  echo "first peer Git fetch did not apply a complete checkpoint" >&2
  exit 1
}
run_client "$DESKTOP_STATE" sync laptop >/dev/null

docker run --rm --user 1000 --entrypoint /bin/sh \
  -v "$DESKTOP_STATE:/state" "$CLIENT_IMAGE" -c \
  'printf "incremental\n" > /state/repo/README.md && git -C /state/repo add README.md && git -C /state/repo commit -m incremental >/dev/null'
INCREMENTAL_PUSH=$(run_git_client "$DESKTOP_STATE" git push laptop --json)
printf '%s\n' "$INCREMENTAL_PUSH" | grep -q '"checkpoint_mode": "incremental"' || {
  printf '%s\n' "$INCREMENTAL_PUSH" >&2
  echo "automatic peer Git push did not select an incremental checkpoint" >&2
  exit 1
}
printf '%s\n' "$INCREMENTAL_PUSH" | grep -q '"base_sequence": ' || {
  printf '%s\n' "$INCREMENTAL_PUSH" >&2
  echo "incremental peer Git push omitted its base sequence" >&2
  exit 1
}
INCREMENTAL_FETCH=$(run_git_client "$LAPTOP_STATE" git fetch desktop --json)
printf '%s\n' "$INCREMENTAL_FETCH" | grep -q '"checkpoint_mode": "incremental"' || {
  printf '%s\n' "$INCREMENTAL_FETCH" >&2
  echo "peer Git fetch did not apply the incremental checkpoint" >&2
  exit 1
}
docker run --rm --user 1000 --entrypoint /bin/sh \
  -v "$LAPTOP_STATE:/state" "$CLIENT_IMAGE" -c \
  'test "$(git -C /state/repo show refs/remotes/desktop/main:README.md)" = incremental' || {
  echo "incremental peer Git fetch did not update the isolated remote ref" >&2
  exit 1
}

# A Git bundle does not carry the repository's shallow-boundary file. Rejecting
# the repository before creating DUD state prevents a bundle that looks complete
# but still references parent commits the sender does not have.
docker run --rm --user 1000 --entrypoint /bin/sh \
  -v "$DESKTOP_STATE:/state" "$CLIENT_IMAGE" -c \
  'git clone --depth 1 file:///state/repo /state/shallow-repo >/dev/null &&
   cp -R /state/repo/.git/dud /state/shallow-repo/.git/dud &&
   test "$(git -C /state/shallow-repo rev-parse --is-shallow-repository)" = true'
if SHALLOW_PUSH=$(run_git_client_at "$DESKTOP_STATE" /state/shallow-repo git push laptop --full 2>&1); then
  echo "peer Git push accepted a shallow repository" >&2
  exit 1
fi
printf '%s\n' "$SHALLOW_PUSH" | grep -q 'git push does not support shallow repositories; fetch the missing history first' || {
  printf '%s\n' "$SHALLOW_PUSH" >&2
  echo "peer Git push did not explain its shallow-repository rejection" >&2
  exit 1
}
if SHALLOW_FETCH=$(run_git_client_at "$DESKTOP_STATE" /state/shallow-repo git fetch laptop 2>&1); then
  echo "peer Git fetch accepted a shallow repository" >&2
  exit 1
fi
printf '%s\n' "$SHALLOW_FETCH" | grep -q 'git fetch does not support shallow repositories; fetch the missing history first' || {
  printf '%s\n' "$SHALLOW_FETCH" >&2
  echo "peer Git fetch did not explain its shallow-repository rejection" >&2
  exit 1
}
# Reporting neither packs nor applies objects, so it answers the same way at any
# history depth and stays available where an operator reads the rejection.
run_git_client_at "$DESKTOP_STATE" /state/shallow-repo git status --json >/dev/null || {
  echo "peer Git status rejected a shallow repository" >&2
  exit 1
}

# Dead drops run on the same in-process transport. Exercising them against the
# same stack is the only end-to-end proof that DoH resolution, address
# classification, exactly TLS 1.3, and the streamed request and response bodies
# work outside the Go tests.
mkdir -p "$DROP_STATE"
chmod 700 "$DROP_STATE"
docker run --rm --user 0 --entrypoint /bin/chown \
  -v "$DROP_STATE:/drop" "$CLIENT_IMAGE" -R 1000:1000 /drop

run_drop() {
  docker run --rm -i --network "$NETWORK" \
    --add-host "dud.local.test:$CADDY_IP" \
    --add-host "doh.local.test:$CADDY_IP" \
    -e DUD_BASE_URL="$ORIGIN" \
    -e DUD_DOH_URL="$DOH_URL" \
    -e DUD_ECH_MODE=off \
    -e DUD_DROP_SECRET="$DROP_SECRET" \
    -e DUD_CA_BUNDLE=/cert/root.crt \
    -v "$ROOT_CERT:/cert/root.crt:ro" \
    -v "$DROP_STATE:/drop" \
    "$CLIENT_IMAGE" "$@"
}

run_drop test >"$TEMP_ROOT/drop-test.txt"
# The summary is read from the TLS connection state, so these two lines are the
# handshake this request actually completed.
for expected in '^  tls  *TLSv1.3' '^  alpn  *h2$'; do
  grep -q "$expected" "$TEMP_ROOT/drop-test.txt" || {
    cat "$TEMP_ROOT/drop-test.txt" >&2
    echo "dud test did not report $expected" >&2
    exit 1
  }
done

# Recipient mode, because age refuses to read a passphrase without a terminal.
run_drop keygen --out /drop/identity.txt -R /drop/recipients.txt >/dev/null
docker run --rm --user 1000 --entrypoint /bin/sh \
  -v "$DROP_STATE:/drop" "$CLIENT_IMAGE" -c \
  'printf "drop-payload" > /drop/payload.bin'
DROP_ID=$(run_drop upload --file /drop/payload.bin \
  -R /drop/recipients.txt --ttl 10m --json |
  sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
[ -n "$DROP_ID" ] || {
  echo "dead drop upload returned no object ID" >&2
  exit 1
}

run_drop download --id "$DROP_ID" -i /drop/identity.txt \
  --out /drop/received.bin
state_file_matches "$DROP_STATE" /state/received.bin '^drop-payload$' || {
  echo "dead drop download did not round-trip the payload" >&2
  exit 1
}

run_drop flush >/dev/null

# Nothing in the image speaks HTTP but the client itself.
if docker run --rm --entrypoint /bin/sh "$CLIENT_IMAGE" -c \
  'command -v curl >/dev/null 2>&1'; then
  echo "the client image still contains curl" >&2
  exit 1
fi

echo "V2 Docker pairing, bidirectional delivery, incremental Git, shallow-repository rejection, and dead drop transport passed."
