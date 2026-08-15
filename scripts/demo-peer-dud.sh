#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
set -eu

: "${DUD_DEMO_NETWORK:?record-peer-transfer-demo.sh did not define DUD_DEMO_NETWORK}"
: "${DUD_DEMO_CADDY_IP:?record-peer-transfer-demo.sh did not define DUD_DEMO_CADDY_IP}"
: "${DUD_DEMO_STATE:?record-peer-transfer-demo.sh did not define DUD_DEMO_STATE}"
: "${DUD_DEMO_ROOT_CERT:?record-peer-transfer-demo.sh did not define DUD_DEMO_ROOT_CERT}"
: "${DUD_DEMO_CLIENT_IMAGE:?record-peer-transfer-demo.sh did not define DUD_DEMO_CLIENT_IMAGE}"
: "${DUD_DEMO_DESKTOP_WORK:?record-peer-transfer-demo.sh did not define DUD_DEMO_DESKTOP_WORK}"
: "${DUD_DEMO_LAPTOP_WORK:?record-peer-transfer-demo.sh did not define DUD_DEMO_LAPTOP_WORK}"
: "${DUD_DEMO_ENROLLMENT_SECRET:?record-peer-transfer-demo.sh did not define DUD_DEMO_ENROLLMENT_SECRET}"
: "${DUD_PROFILE:?set DUD_PROFILE to desktop or laptop}"

case "$DUD_PROFILE" in
  desktop|laptop)
    if [ "$DUD_PROFILE" = desktop ]; then
      work_dir=$DUD_DEMO_DESKTOP_WORK
    else
      work_dir=$DUD_DEMO_LAPTOP_WORK
    fi
    ;;
  *)
    echo "The peer demo recognizes only the desktop and laptop profiles." >&2
    exit 2
    ;;
esac

run_dud() {
  docker run --rm \
    --network "$DUD_DEMO_NETWORK" \
    --add-host "dud.local.test:$DUD_DEMO_CADDY_IP" \
    --add-host "doh.local.test:$DUD_DEMO_CADDY_IP" \
    -e DUD_HOME=/state/dud \
    -e "DUD_PROFILE=$DUD_PROFILE" \
    -e DUD_BASE_URL=https://dud.local.test \
    -e DUD_DOH_URL=https://doh.local.test/dns-query \
    -e DUD_ECH_MODE=off \
    -e "DUD_PEER_SECRET=$DUD_DEMO_ENROLLMENT_SECRET" \
    -e DUD_CA_BUNDLE=/cert/root.crt \
    -v "$DUD_DEMO_STATE:/state" \
    -v "$DUD_DEMO_ROOT_CERT:/cert/root.crt:ro" \
    -v "$work_dir:/work" \
    "$DUD_DEMO_CLIENT_IMAGE" "$@"
}

if [ "${1:-}" = init ]; then
  run_dud "$@"
  status=$?
  if [ "$status" -eq 0 ]; then
    docker run --rm --user 1000 --entrypoint /bin/sh \
      -e CADDY_IP="$DUD_DEMO_CADDY_IP" \
      -v "$DUD_DEMO_STATE:/state" "$DUD_DEMO_CLIENT_IMAGE" -c \
      "sed -i \"/^doh_url =/a doh_bootstrap = [\\\"$DUD_DEMO_CADDY_IP\\\"]\" /state/dud/$DUD_PROFILE/config/config.toml"
  fi
  exit "$status"
fi

if [ "${DUD_DEMO_AUTO_ACCEPT:-}" = 1 ] && [ "${1:-}" = peer ] && [ "${2:-}" = accept ]; then
  pairing_state="$DUD_DEMO_STATE/dud/desktop/state/pairings/laptop.json"
  pairing_code=""
  attempt=0
  while [ -z "$pairing_code" ]; do
    if [ -f "$pairing_state" ]; then
      pairing_code=$(sed -n 's/^  "pairing_code": "\([0-9a-f-]*\)",$/\1/p' "$pairing_state")
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
      echo "The desktop pairing code did not become available." >&2
      exit 1
    fi
    [ -n "$pairing_code" ] || sleep 1
  done
  export DUD_DEMO_CADDY_IP DUD_DEMO_CLIENT_IMAGE DUD_DEMO_ENROLLMENT_SECRET DUD_DEMO_ROOT_CERT DUD_DEMO_STATE DUD_PROFILE pairing_code work_dir
expect <<'EXPECT_EOF'
set timeout 90
log_user 0
spawn docker run --rm -it --network $env(DUD_DEMO_NETWORK) \
  --add-host dud.local.test:$env(DUD_DEMO_CADDY_IP) \
  --add-host doh.local.test:$env(DUD_DEMO_CADDY_IP) \
  -e DUD_HOME=/state/dud \
  -e DUD_PROFILE=$env(DUD_PROFILE) \
  -e DUD_BASE_URL=https://dud.local.test \
  -e DUD_DOH_URL=https://doh.local.test/dns-query \
  -e DUD_ECH_MODE=off \
  -e DUD_PEER_SECRET=$env(DUD_DEMO_ENROLLMENT_SECRET) \
  -e DUD_CA_BUNDLE=/cert/root.crt \
  -v $env(DUD_DEMO_STATE):/state \
  -v $env(DUD_DEMO_ROOT_CERT):/cert/root.crt:ro \
  -v $env(work_dir):/work \
  $env(DUD_DEMO_CLIENT_IMAGE) peer accept desktop
log_user 1
expect "Pairing code: "
send -- "$env(pairing_code)\r"
expect eof
catch wait result
exit [lindex $result 3]
EXPECT_EOF
  exit $?
fi

exec docker run --rm \
  --network "$DUD_DEMO_NETWORK" \
  --add-host "dud.local.test:$DUD_DEMO_CADDY_IP" \
  --add-host "doh.local.test:$DUD_DEMO_CADDY_IP" \
  -e DUD_HOME=/state/dud \
  -e "DUD_PROFILE=$DUD_PROFILE" \
  -e DUD_BASE_URL=https://dud.local.test \
  -e DUD_DOH_URL=https://doh.local.test/dns-query \
  -e DUD_ECH_MODE=off \
  -e "DUD_PEER_SECRET=$DUD_DEMO_ENROLLMENT_SECRET" \
  -e DUD_CA_BUNDLE=/cert/root.crt \
  -v "$DUD_DEMO_STATE:/state" \
  -v "$DUD_DEMO_ROOT_CERT:/cert/root.crt:ro" \
  -v "$work_dir:/work" \
  "$DUD_DEMO_CLIENT_IMAGE" "$@"
