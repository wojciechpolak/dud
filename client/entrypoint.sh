#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Wojciech Polak
set -eu
umask 0077

DUD_BASE_URL="${DUD_BASE_URL:-https://dud.example.com}"
DUD_DOH_URL="${DUD_DOH_URL:-https://cloudflare-dns.com/dns-query}"
DUD_ECH_MODE="${DUD_ECH_MODE:-hard}"
DUD_SECRET_TOKEN="${DUD_SECRET_TOKEN:-}"
DUD_CURL_BIN="${DUD_CURL_BIN:-curl}"
DUD_AGE_BIN="${DUD_AGE_BIN:-age}"

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

need_value() {
  if [ $# -lt 2 ]; then
    die "Missing value for $1"
  fi
}

validate_ech_mode() {
  case "$DUD_ECH_MODE" in
    hard|grease)
      ;;
    *)
      die "DUD_ECH_MODE must be either 'hard' or 'grease'"
      ;;
  esac
}

run_secure_curl() {
  validate_ech_mode

  "$DUD_CURL_BIN" \
    --silent \
    --show-error \
    --fail \
    --proto '=https' \
    --tlsv1.3 \
    --tls-max 1.3 \
    --ech "$DUD_ECH_MODE" \
    --doh-url "$DUD_DOH_URL" \
    "$@"
}

upload_json_string_field() {
  field="$1"
  response_file="$2"

  tr -d '\n' <"$response_file" \
    | sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" \
    | head -n 1
}

upload_json_boolean_field() {
  field="$1"
  response_file="$2"

  tr -d '\n' <"$response_file" \
    | sed -n "s/.*\"$field\"[[:space:]]*:[[:space:]]*\\([a-z][a-z]*\\).*/\\1/p" \
    | head -n 1
}

print_upload_response() {
  response_file="$1"

  id="$(upload_json_string_field id "$response_file")"
  expires_at="$(upload_json_string_field expiresAt "$response_file")"
  delete_after_read="$(upload_json_boolean_field deleteAfterRead "$response_file")"

  [ -n "$id" ] || die "Upload succeeded but returned an unexpected JSON response."
  [ -n "$expires_at" ] || die "Upload succeeded but returned an unexpected JSON response."

  case "$delete_after_read" in
    true)
      delete_after_read_label="yes"
      ;;
    false)
      delete_after_read_label="no"
      ;;
    *)
      die "Upload succeeded but returned an unexpected JSON response."
      ;;
  esac

  printf 'Upload complete\n'
  printf 'ID: %s\n' "$id"
  printf 'Expires: %s\n' "$expires_at"
  printf 'Delete after read: %s\n' "$delete_after_read_label"
}

print_test_details() {
  trace_file="$1"
  tls_summary="$(sed -n 's/^\* SSL connection using //p' "$trace_file" | head -n 1)"
  alpn_summary="$(sed -n 's/^\* ALPN: server accepted //p' "$trace_file" | head -n 1)"
  ech_status="$(sed -n "s/^\\* ECH: result: status is \\([^,]*\\).*/\\1/p" "$trace_file" | head -n 1)"
  ech_inner="$(sed -n "s/^\\* ECH: result: status is [^,]*, inner is \\([^,]*\\), outer is .*/\\1/p" "$trace_file" | head -n 1)"
  ech_outer="$(sed -n "s/^\\* ECH: result: status is [^,]*, inner is [^,]*, outer is \\(.*\\)/\\1/p" "$trace_file" | head -n 1)"

  printf 'Transport:\n'
  printf '  doh resolver: %s\n' "$DUD_DOH_URL"
  printf '  ech mode: %s\n' "$DUD_ECH_MODE"

  if [ -n "$tls_summary" ]; then
    printf '  tls: %s\n' "$tls_summary"
  fi

  if [ -n "$alpn_summary" ]; then
    printf '  alpn: %s\n' "$alpn_summary"
  fi

  if [ -n "$ech_status" ]; then
    printf '  ech: %s\n' "$ech_status"
  else
    printf '  ech: unavailable\n'
  fi

  if [ -n "$ech_inner" ]; then
    printf '  inner sni: %s\n' "$ech_inner"
  fi

  if [ -n "$ech_outer" ]; then
    printf '  outer sni: %s\n' "$ech_outer"
  fi
}

cmd_test() {
  url="$DUD_BASE_URL/v1/test"

  while [ $# -gt 0 ]; do
    case "$1" in
      --url)
        need_value "$@"
        url="$2"
        shift 2
        ;;
      --doh-url)
        need_value "$@"
        DUD_DOH_URL="$2"
        shift 2
        ;;
      *)
        die "Unknown test option: $1"
        ;;
    esac
  done

  response_file="$(mktemp /tmp/dud-test-response-XXXXXX)"
  trace_file="$(mktemp /tmp/dud-test-trace-XXXXXX)"
  trap 'rm -f "$response_file" "$trace_file"' EXIT HUP INT TERM

  validate_ech_mode

  if ! "$DUD_CURL_BIN" \
    --silent \
    --show-error \
    --fail \
    --verbose \
    --proto '=https' \
    --tlsv1.3 \
    --tls-max 1.3 \
    --ech "$DUD_ECH_MODE" \
    --doh-url "$DUD_DOH_URL" \
    --output "$response_file" \
    "$url" \
    2>"$trace_file"; then
    cat "$trace_file" >&2
    exit 1
  fi

  print_test_details "$trace_file"
  printf 'Response:\n'
  cat "$response_file"

  printf '\n'
}

cmd_upload() {
  file=""
  ttl="24h"
  delete_after_read="false"
  base_url="$DUD_BASE_URL"
  output_json="false"

  while [ $# -gt 0 ]; do
    case "$1" in
      --file)
        need_value "$@"
        file="$2"
        shift 2
        ;;
      --ttl)
        need_value "$@"
        ttl="$2"
        shift 2
        ;;
      --delete-after-read)
        delete_after_read="true"
        shift 1
        ;;
      --json)
        output_json="true"
        shift 1
        ;;
      --url)
        need_value "$@"
        base_url="$2"
        shift 2
        ;;
      --doh-url)
        need_value "$@"
        DUD_DOH_URL="$2"
        shift 2
        ;;
      *)
        die "Unknown upload option: $1"
        ;;
    esac
  done

  [ -n "$file" ] || die "upload requires --file"
  [ -f "$file" ] || die "File not found: $file"
  [ -n "$DUD_SECRET_TOKEN" ] || die "upload requires DUD_SECRET_TOKEN"

  encrypted_file="$(mktemp /tmp/dud-upload-XXXXXX.age)"
  response_file="$(mktemp /tmp/dud-upload-response-XXXXXX.json)"
  trap 'rm -f "$encrypted_file" "$response_file"' EXIT HUP INT TERM

  "$DUD_AGE_BIN" --encrypt --passphrase -o "$encrypted_file" "$file"

  run_secure_curl \
    -X POST \
    -H "content-type: application/octet-stream" \
    -H "x-dud-ttl: $ttl" \
    -H "x-dud-delete-after-read: $delete_after_read" \
    -H "x-dud-secret-token: $DUD_SECRET_TOKEN" \
    --data-binary "@$encrypted_file" \
    --output "$response_file" \
    "$base_url/v1/files"

  if [ "$output_json" = "true" ]; then
    cat "$response_file"
    printf '\n'
    return
  fi

  print_upload_response "$response_file"
}

cmd_download() {
  id=""
  out=""
  base_url="$DUD_BASE_URL"

  while [ $# -gt 0 ]; do
    case "$1" in
      --id)
        need_value "$@"
        id="$2"
        shift 2
        ;;
      --out)
        need_value "$@"
        out="$2"
        shift 2
        ;;
      --url)
        need_value "$@"
        base_url="$2"
        shift 2
        ;;
      --doh-url)
        need_value "$@"
        DUD_DOH_URL="$2"
        shift 2
        ;;
      *)
        die "Unknown download option: $1"
        ;;
    esac
  done

  [ -n "$id" ] || die "download requires --id"
  [ -n "$out" ] || die "download requires --out"

  encrypted_file="$(mktemp /tmp/dud-download-XXXXXX.age)"
  trap 'rm -f "$encrypted_file"' EXIT HUP INT TERM

  run_secure_curl -o "$encrypted_file" "$base_url/v1/files/$id"
  "$DUD_AGE_BIN" --decrypt -o "$out" "$encrypted_file"
}

cmd_flush() {
  base_url="$DUD_BASE_URL"

  while [ $# -gt 0 ]; do
    case "$1" in
      --url)
        need_value "$@"
        base_url="$2"
        shift 2
        ;;
      --doh-url)
        need_value "$@"
        DUD_DOH_URL="$2"
        shift 2
        ;;
      *)
        die "Unknown flush option: $1"
        ;;
    esac
  done

  [ -n "$DUD_SECRET_TOKEN" ] || die "flush requires DUD_SECRET_TOKEN"

  run_secure_curl \
    -X POST \
    -H "x-dud-secret-token: $DUD_SECRET_TOKEN" \
    "$base_url/v1/admin/flush"

  printf '\n'
}

DUD_IMAGE="${DUD_IMAGE:-ghcr.io/wojciechpolak/dud/dud-client:latest}"

usage() {
  cat <<'EOF'
Usage:
  dud test [--url URL] [--doh-url URL]
  dud upload --file PATH [--ttl 24h] [--delete-after-read] [--json] [--url URL] [--doh-url URL]
  dud download --id ID --out PATH [--url URL] [--doh-url URL]
  dud flush [--url URL] [--doh-url URL]
  dud install        Print a host wrapper script to stdout
  dud shell-alias    Print a shell alias definition to stdout

Environment:
  DUD_BASE_URL   Base Worker URL. Default: https://dud.example.com
  DUD_DOH_URL    DNS-over-HTTPS resolver. Default: https://cloudflare-dns.com/dns-query
  DUD_ECH_MODE   curl ECH mode. Allowed: hard, grease. Default: hard
  DUD_SECRET_TOKEN  Shared secret required for upload and flush
  DUD_IMAGE      Docker image used by install/shell-alias output
EOF
}

cmd_install() {
  cat <<EOF
#!/bin/sh
exec docker run --rm -it \\
  --tmpfs /tmp:rw,noexec,nosuid,size=128m \\
  -v "\$PWD:/work" \\
  $DUD_IMAGE "\$@"
EOF
}

cmd_shell_alias() {
  printf "alias dud='docker run --rm -it --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"\$PWD:/work\" %s'\n" "$DUD_IMAGE"
}

interactive_menu() {
  printf '\ndud — Discreet Upload/Download\n\n'
  printf '  1) test\n'
  printf '  2) upload\n'
  printf '  3) download\n'
  printf '  4) flush\n'
  printf '  q) quit\n\n'
  printf 'Choice: '
  read -r choice
  case $choice in
    1|test)      interactive_test ;;
    2|upload)    interactive_upload ;;
    3|download)  interactive_download ;;
    4|flush)     interactive_flush ;;
    q|quit)      exit 0 ;;
    *)           die "Unknown choice: $choice" ;;
  esac
}

interactive_test() {
  printf 'Server URL [%s]: ' "$DUD_BASE_URL"
  read -r url
  url="${url:-$DUD_BASE_URL}"
  exec "$0" test --url "$url/v1/test"
}

interactive_upload() {
  printf 'File path: '
  read -r file
  [ -n "$file" ] || die "file path required"
  case "$file" in
    /*) ;;
    *) file="$(pwd)/$file" ;;
  esac

  printf 'TTL [24h]: '
  read -r ttl
  ttl="${ttl:-24h}"

  printf 'Delete after read? [y/N]: '
  read -r ans
  dar_flag=""
  case $ans in [Yy]*) dar_flag="--delete-after-read" ;; esac

  printf 'Server URL [%s]: ' "$DUD_BASE_URL"
  read -r url
  url="${url:-$DUD_BASE_URL}"

  # shellcheck disable=SC2086
  exec "$0" upload --file "$file" --ttl "$ttl" --url "$url" $dar_flag
}

interactive_download() {
  printf 'File ID: '
  read -r id
  [ -n "$id" ] || die "file ID required"

  printf 'Output path: '
  read -r out
  [ -n "$out" ] || die "output path required"
  case "$out" in
    /*) ;;
    *) out="$(pwd)/$out" ;;
  esac

  printf 'Server URL [%s]: ' "$DUD_BASE_URL"
  read -r url
  url="${url:-$DUD_BASE_URL}"

  exec "$0" download --id "$id" --out "$out" --url "$url"
}

interactive_flush() {
  printf 'Flush all expired files? [y/N]: '
  read -r ans
  case $ans in
    [Yy]*) exec "$0" flush ;;
    *)     printf 'Cancelled.\n'; exit 0 ;;
  esac
}

main() {
  if [ $# -eq 0 ]; then
    if [ -t 0 ]; then
      interactive_menu
      return
    fi
    usage
    exit 1
  fi

  command="$1"
  shift

  case "$command" in
    test)
      cmd_test "$@"
      ;;
    upload)
      cmd_upload "$@"
      ;;
    download)
      cmd_download "$@"
      ;;
    flush)
      cmd_flush "$@"
      ;;
    install)
      cmd_install
      ;;
    shell-alias)
      cmd_shell_alias
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      die "Unknown command: $command"
      ;;
  esac
}

main "$@"
