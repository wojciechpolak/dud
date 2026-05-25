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
DUD_AGE_KEYGEN_BIN="${DUD_AGE_KEYGEN_BIN:-age-keygen}"
DUD_QRENCODE_BIN="${DUD_QRENCODE_BIN:-qrencode}"
DUD_VERSION="${DUD_VERSION:-1.2.0}"

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

stdin_is_tty() {
  [ "${DUD_TEST_STDIN_TTY:-0}" = "1" ] || [ -t 0 ]
}

has_controlling_tty() {
  tty >/dev/null 2>&1
}

run_age_command() {
  if has_controlling_tty; then
    "$@" </dev/tty
    return
  fi

  "$@"
}

age_keygen_supports_pq() {
  "$DUD_AGE_KEYGEN_BIN" --help 2>&1 | grep -q -- '-pq'
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

UPLOAD_ID=""
UPLOAD_EXPIRES_AT=""
UPLOAD_DELETE_AFTER_READ_LABEL=""

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

load_upload_response() {
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

  UPLOAD_ID="$id"
  UPLOAD_EXPIRES_AT="$expires_at"
  UPLOAD_DELETE_AFTER_READ_LABEL="$delete_after_read_label"
}

print_upload_response() {
  printf 'Upload complete\n'
  printf 'ID: %s\n' "$UPLOAD_ID"
  printf 'Expires: %s\n' "$UPLOAD_EXPIRES_AT"
  printf 'Delete after read: %s\n' "$UPLOAD_DELETE_AFTER_READ_LABEL"
}

print_upload_qr() {
  printf '\nQR Code:\n'
  "$DUD_QRENCODE_BIN" -t ansiutf8 "$UPLOAD_ID"
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
  message=""
  ttl="24h"
  delete_after_read="false"
  base_url="$DUD_BASE_URL"
  output_json="false"
  output_qr="true"
  passphrase_requested="false"
  inline_recipients=""
  recipients_file=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --file)
        need_value "$@"
        file="$2"
        shift 2
        ;;
      -m)
        need_value "$@"
        message="$2"
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
      --passphrase)
        passphrase_requested="true"
        shift 1
        ;;
      --recipient|-r)
        need_value "$@"
        if [ -n "$inline_recipients" ]; then
          inline_recipients="${inline_recipients}
$2"
        else
          inline_recipients="$2"
        fi
        shift 2
        ;;
      --recipient-file|-R)
        need_value "$@"
        recipients_file="$2"
        shift 2
        ;;
      --json)
        output_json="true"
        shift 1
        ;;
      --no-qr)
        output_qr="false"
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

  source_count=0
  if [ -n "$file" ]; then
    source_count=$((source_count + 1))
  fi
  if [ -n "$message" ]; then
    source_count=$((source_count + 1))
  fi
  [ "$source_count" -le 1 ] || die "upload accepts only one source: --file, -m, or stdin"
  if [ -n "$file" ]; then
    [ -f "$file" ] || die "File not found: $file"
  fi
  if [ -n "$recipients_file" ]; then
    [ -f "$recipients_file" ] || die "Recipients file not found: $recipients_file"
  fi
  [ -n "$DUD_SECRET_TOKEN" ] || die "upload requires DUD_SECRET_TOKEN"

  recipient_mode="false"
  if [ -n "$inline_recipients" ] || [ -n "$recipients_file" ]; then
    recipient_mode="true"
  fi
  if [ "$passphrase_requested" = "true" ] && [ "$recipient_mode" = "true" ]; then
    die "upload accepts either --passphrase or recipient options, not both"
  fi

  plaintext_file="$(mktemp /tmp/dud-upload-plain-XXXXXX)"
  encrypted_file="$(mktemp /tmp/dud-upload-XXXXXX.age)"
  response_file="$(mktemp /tmp/dud-upload-response-XXXXXX.json)"
  inline_recipients_file=""
  trap 'rm -f "$plaintext_file" "$encrypted_file" "$response_file" "$inline_recipients_file"' EXIT HUP INT TERM

  if [ -n "$file" ]; then
    cat "$file" >"$plaintext_file"
  elif [ -n "$message" ]; then
    printf '%s' "$message" >"$plaintext_file"
  else
    if stdin_is_tty; then
      printf 'Enter plaintext, then press Ctrl-D when finished.\n' >&2
    fi
    cat >"$plaintext_file"
  fi

  if [ "$recipient_mode" = "true" ]; then
    if [ -n "$inline_recipients" ]; then
      inline_recipients_file="$(mktemp /tmp/dud-upload-recipients-XXXXXX.txt)"
      printf '%s\n' "$inline_recipients" >"$inline_recipients_file"
    fi

    if [ -n "$inline_recipients_file" ] && [ -n "$recipients_file" ]; then
      run_age_command \
        "$DUD_AGE_BIN" \
        --encrypt \
        -R "$inline_recipients_file" \
        -R "$recipients_file" \
        -o "$encrypted_file" \
        "$plaintext_file"
    elif [ -n "$inline_recipients_file" ]; then
      run_age_command \
        "$DUD_AGE_BIN" \
        --encrypt \
        -R "$inline_recipients_file" \
        -o "$encrypted_file" \
        "$plaintext_file"
    else
      run_age_command \
        "$DUD_AGE_BIN" \
        --encrypt \
        -R "$recipients_file" \
        -o "$encrypted_file" \
        "$plaintext_file"
    fi
  else
    run_age_command "$DUD_AGE_BIN" --encrypt --passphrase -o "$encrypted_file" "$plaintext_file"
  fi

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

  load_upload_response "$response_file"
  print_upload_response
  if [ "$output_qr" = "true" ]; then
    print_upload_qr
  fi
}

cmd_download() {
  id=""
  out=""
  output_stdout="false"
  base_url="$DUD_BASE_URL"
  identity=""

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
      --stdout)
        output_stdout="true"
        shift 1
        ;;
      --identity|-i)
        need_value "$@"
        identity="$2"
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
  if [ -n "$out" ] && [ "$output_stdout" = "true" ]; then
    die "download accepts only one output target: --out or --stdout"
  fi
  if [ -z "$out" ] && [ "$output_stdout" != "true" ]; then
    die "download requires either --out or --stdout"
  fi
  if [ -n "$identity" ]; then
    [ -f "$identity" ] || die "Identity file not found: $identity"
  fi

  encrypted_file="$(mktemp /tmp/dud-download-XXXXXX.age)"
  plaintext_file="$(mktemp /tmp/dud-download-plain-XXXXXX)"
  trap 'rm -f "$encrypted_file" "$plaintext_file"' EXIT HUP INT TERM

  run_secure_curl -o "$encrypted_file" "$base_url/v1/files/$id"
  if [ -n "$identity" ]; then
    run_age_command \
      "$DUD_AGE_BIN" \
      --decrypt \
      -i "$identity" \
      -o "$plaintext_file" \
      "$encrypted_file"
  else
    run_age_command "$DUD_AGE_BIN" --decrypt -o "$plaintext_file" "$encrypted_file"
  fi

  if [ "$output_stdout" = "true" ]; then
    cat "$plaintext_file"
    return
  fi

  cat "$plaintext_file" >"$out"
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

cmd_keygen() {
  out=""
  recipient_out=""
  pq="false"
  input=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --out)
        need_value "$@"
        out="$2"
        shift 2
        ;;
      --recipient-out|-R)
        need_value "$@"
        recipient_out="$2"
        shift 2
        ;;
      --pq)
        pq="true"
        shift 1
        ;;
      -*)
        die "Unknown keygen option: $1"
        ;;
      *)
        if [ -n "$input" ]; then
          die "keygen accepts at most one input path"
        fi
        input="$1"
        shift 1
        ;;
    esac
  done

  if [ -n "$input" ]; then
    if [ "$pq" = "true" ]; then
      die "keygen does not accept --pq when converting an identity to recipients"
    fi
    if [ -n "$out" ] && [ -n "$recipient_out" ]; then
      die "keygen accepts only one recipient output target: --out or -R"
    fi

    if [ -n "$recipient_out" ]; then
      "$DUD_AGE_KEYGEN_BIN" -y -o "$recipient_out" "$input"
    elif [ -n "$out" ]; then
      "$DUD_AGE_KEYGEN_BIN" -y -o "$out" "$input"
    else
      "$DUD_AGE_KEYGEN_BIN" -y "$input"
    fi
    return
  fi

  if [ -n "$recipient_out" ] && [ -z "$out" ]; then
    die "keygen requires --out when generating a new identity with -R"
  fi

  if [ "$pq" = "true" ] && ! age_keygen_supports_pq; then
    die "The bundled age-keygen does not support -pq. Rebuild the client image with age v1.3.0 or later."
  fi

  if [ "$pq" = "true" ]; then
    if [ -n "$out" ]; then
      "$DUD_AGE_KEYGEN_BIN" -pq -o "$out"
    else
      "$DUD_AGE_KEYGEN_BIN" -pq
    fi
  else
    if [ -n "$out" ]; then
      "$DUD_AGE_KEYGEN_BIN" -o "$out"
    else
      "$DUD_AGE_KEYGEN_BIN"
    fi
  fi

  if [ -n "$recipient_out" ]; then
    "$DUD_AGE_KEYGEN_BIN" -y "$out" >"$recipient_out"
  fi
}

DUD_IMAGE="${DUD_IMAGE:-ghcr.io/wojciechpolak/dud/dud-client:latest}"

usage() {
  cat <<'EOF'
Usage:
  dud --version
  dud test [--url URL] [--doh-url URL]
  dud upload [--file PATH | -m TEXT] [--ttl 24h] [--delete-after-read] [--passphrase | --recipient AGE_RECIPIENT | --recipient-file PATH] [--json] [--no-qr] [--url URL] [--doh-url URL]
  dud download --id ID (--out PATH | --stdout) [--identity PATH] [--url URL] [--doh-url URL]
  dud flush [--url URL] [--doh-url URL]
  dud keygen [--pq] [--out PATH] [-R PATH]
  dud keygen [INPUT] [--out PATH | -R PATH]
  dud install        Print a host wrapper script to stdout
  dud shell-init     Print a shell function definition to stdout

Environment:
  DUD_BASE_URL   Base Worker URL. Default: https://dud.example.com
  DUD_DOH_URL    DNS-over-HTTPS resolver. Default: https://cloudflare-dns.com/dns-query
  DUD_ECH_MODE   curl ECH mode. Allowed: hard, grease. Default: hard
  DUD_SECRET_TOKEN  Shared secret required for upload and flush
  DUD_IMAGE      Docker image used by install/shell-init output
EOF
}

print_version() {
  printf '%s\n' "$DUD_VERSION"
}

cmd_install() {
  cat <<EOF
#!/bin/sh

dud_shell_quote() {
  printf "'%s'" "\$(printf '%s' "\$1" | sed "s/'/'\\\\''/g")"
}

dud_host_has_tty() {
  [ "\${DUD_TEST_HOST_TTY:-0}" = "1" ] || { : </dev/tty; } 2>/dev/null
}

dud_stdout_is_tty() {
  [ "\${DUD_TEST_STDOUT_TTY:-0}" = "1" ] || [ -t 1 ]
}

dud_tty_input_path() {
  printf '%s' "\${DUD_TEST_TTY_INPUT_PATH:-/dev/tty}"
}

dud_upload_uses_stdin() {
  shift

  while [ \$# -gt 0 ]; do
    case "\$1" in
      --file|-m)
        return 1
        ;;
    esac
    shift
  done

  return 0
}

dud_docker_cli_args() {
  args=""

  for arg in "\$@"; do
    if [ -n "\$args" ]; then
      args="\$args "
    fi
    args="\$args\$(dud_shell_quote "\$arg")"
  done

  printf '%s' "\$args"
}

dud_docker_env_args() {
  args=""

  if [ -r .env ]; then
    args="\$(dud_shell_quote --env-file) \$(dud_shell_quote .env)"
  fi

  for name in DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN; do
    eval "value=\\\${\$name-}"
    if [ -n "\$value" ]; then
      if [ -n "\$args" ]; then
        args="\$args "
      fi
      args="\$args\$(dud_shell_quote -e) \$(dud_shell_quote "\$name=\$value")"
    fi
  done

  printf '%s' "\$args"
}

dud_env_args="\$(dud_docker_env_args)"

if [ "\$#" -gt 0 ] && [ "\$1" = "upload" ] && ! [ -t 0 ] && dud_stdout_is_tty && dud_host_has_tty && dud_upload_uses_stdin "\$@"; then
  dud_stdin_file="\$(mktemp /tmp/dud-wrapper-stdin-XXXXXX)"
  trap 'rm -f "\$dud_stdin_file"' EXIT HUP INT TERM
  cat >"\$dud_stdin_file"
  shift
  set -- upload --file /tmp/dud-stdin "\$@"
  dud_cli_args="\$(dud_docker_cli_args "\$@")"
  dud_stdin_mount="\$(dud_shell_quote -v) \$(dud_shell_quote "\$dud_stdin_file:/tmp/dud-stdin:ro")"
  dud_tty_input="\$(dud_tty_input_path)"
  eval "exec docker run --rm -it \$dud_env_args \$dud_stdin_mount --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \\"\$PWD:/work\\" \\"$DUD_IMAGE\\" \$dud_cli_args" <"\$dud_tty_input"
fi

dud_cli_args="\$(dud_docker_cli_args "\$@")"

if [ -t 0 ] && [ -t 1 ]; then
  eval "exec docker run --rm -it \$dud_env_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \\"\$PWD:/work\\" \\"$DUD_IMAGE\\" \$dud_cli_args"
fi

eval "exec docker run --rm -i \$dud_env_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \\"\$PWD:/work\\" \\"$DUD_IMAGE\\" \$dud_cli_args"
EOF
}

cmd_shell_alias() {
  cat <<EOF
_dud_shell_quote() {
  printf "'%s'" "\$(printf '%s' "\$1" | sed "s/'/'\\\\''/g")"
}

dud_host_has_tty() {
  [ "\${DUD_TEST_HOST_TTY:-0}" = "1" ] || { : </dev/tty; } 2>/dev/null
}

dud_stdout_is_tty() {
  [ "\${DUD_TEST_STDOUT_TTY:-0}" = "1" ] || [ -t 1 ]
}

dud_tty_input_path() {
  printf '%s' "\${DUD_TEST_TTY_INPUT_PATH:-/dev/tty}"
}

dud_upload_uses_stdin() {
  shift

  while [ \$# -gt 0 ]; do
    case "\$1" in
      --file|-m)
        return 1
        ;;
    esac
    shift
  done

  return 0
}

dud_docker_cli_args() {
  args=""

  for arg in "\$@"; do
    if [ -n "\$args" ]; then
      args="\$args "
    fi
    args="\$args\$(_dud_shell_quote "\$arg")"
  done

  printf '%s' "\$args"
}

dud() {
  dud_env_args=""

  if [ -r .env ]; then
    dud_env_args="\$(_dud_shell_quote --env-file) \$(_dud_shell_quote .env)"
  fi

  for name in DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN; do
    eval "value=\\\${\$name-}"
    if [ -n "\$value" ]; then
      if [ -n "\$dud_env_args" ]; then
        dud_env_args="\$dud_env_args "
      fi
      dud_env_args="\$dud_env_args\$(_dud_shell_quote -e) \$(_dud_shell_quote "\$name=\$value")"
    fi
  done

  if [ "\$#" -gt 0 ] && [ "\$1" = "upload" ] && ! [ -t 0 ] && dud_stdout_is_tty && dud_host_has_tty && dud_upload_uses_stdin "\$@"; then
    dud_stdin_file="\$(mktemp /tmp/dud-wrapper-stdin-XXXXXX)"
    cat >"\$dud_stdin_file"
    shift
    set -- upload --file /tmp/dud-stdin "\$@"
    dud_cli_args="\$(dud_docker_cli_args "\$@")"
    dud_stdin_mount="\$(_dud_shell_quote -v) \$(_dud_shell_quote "\$dud_stdin_file:/tmp/dud-stdin:ro")"
    dud_tty_input="\$(dud_tty_input_path)"
    trap 'rm -f "\$dud_stdin_file"' EXIT HUP INT TERM
    eval "docker run --rm -it \$dud_env_args \$dud_stdin_mount --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \\"\$PWD:/work\\" \\"$DUD_IMAGE\\" \$dud_cli_args" <"\$dud_tty_input"
    status=\$?
    rm -f "\$dud_stdin_file"
    trap - EXIT HUP INT TERM
    return \$status
  fi

  dud_cli_args="\$(dud_docker_cli_args "\$@")"

  if [ -t 0 ] && [ -t 1 ]; then
    eval "docker run --rm -it \$dud_env_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \\"\$PWD:/work\\" \\"$DUD_IMAGE\\" \$dud_cli_args"
    return
  fi

  eval "docker run --rm -i \$dud_env_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \\"\$PWD:/work\\" \\"$DUD_IMAGE\\" \$dud_cli_args"
}
EOF
}

interactive_menu() {
  printf '\ndud — Discreet Upload/Download\n\n'
  printf '  1) test\n'
  printf '  2) upload\n'
  printf '  3) download\n'
  printf '  4) keygen\n'
  printf '  5) flush\n'
  printf '  q) quit\n\n'
  printf 'Choice: '
  read -r choice
  case $choice in
    1|test)      interactive_test ;;
    2|upload)    interactive_upload ;;
    3|download)  interactive_download ;;
    4|keygen)    interactive_keygen ;;
    5|flush)     interactive_flush ;;
    q|quit)      exit 0 ;;
    *)           die "Unknown choice: $choice" ;;
  esac
}

abs_path_if_relative() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$(pwd)" "$1" ;;
  esac
}

interactive_test() {
  printf 'Server URL [%s]: ' "$DUD_BASE_URL"
  read -r url
  url="${url:-$DUD_BASE_URL}"
  exec "$0" test --url "$url/v1/test"
}

interactive_upload() {
  printf 'Server URL [%s]: ' "$DUD_BASE_URL"
  read -r url
  url="${url:-$DUD_BASE_URL}"

  printf 'Upload source:\n'
  printf '  1) file path\n'
  printf '  2) typed or pasted text (Ctrl-D to finish)\n'
  printf '  3) one-line message\n'
  printf 'Choice [1]: '
  read -r source_choice
  source_choice="${source_choice:-1}"

  case $source_choice in
    1|file)
      printf 'File path: '
      read -r file
      [ -n "$file" ] || die "file path required"
      file="$(abs_path_if_relative "$file")"
      ;;
    2|text|stdin)
      ;;
    3|message)
      printf 'Message: '
      read -r message
      [ -n "$message" ] || die "message required"
      ;;
    *)
      die "Unknown upload source: $source_choice"
      ;;
  esac

  printf 'Encryption mode:\n'
  printf '  1) passphrase\n'
  printf '  2) recipient string\n'
  printf '  3) recipient file\n'
  printf 'Choice [1]: '
  read -r encryption_choice
  encryption_choice="${encryption_choice:-1}"

  case $encryption_choice in
    1|passphrase)
      encryption_mode="passphrase"
      ;;
    2|recipient)
      printf 'Recipient: '
      read -r recipient
      [ -n "$recipient" ] || die "recipient required"
      encryption_mode="recipient"
      ;;
    3|recipient-file)
      printf 'Recipient file: '
      read -r recipient_file
      [ -n "$recipient_file" ] || die "recipient file required"
      recipient_file="$(abs_path_if_relative "$recipient_file")"
      encryption_mode="recipient-file"
      ;;
    *)
      die "Unknown encryption mode: $encryption_choice"
      ;;
  esac

  printf 'TTL [24h]: '
  read -r ttl
  ttl="${ttl:-24h}"

  printf 'Delete after read? [y/N]: '
  read -r ans
  dar_flag=""
  case $ans in [Yy]*) dar_flag="--delete-after-read" ;; esac

  case $source_choice in
    1|file)
      case $encryption_mode in
        passphrase)
          # shellcheck disable=SC2086
          exec "$0" upload --file "$file" --ttl "$ttl" --url "$url" $dar_flag
          ;;
        recipient)
          # shellcheck disable=SC2086
          exec "$0" upload --file "$file" --ttl "$ttl" --url "$url" $dar_flag -r "$recipient"
          ;;
        recipient-file)
          # shellcheck disable=SC2086
          exec "$0" upload --file "$file" --ttl "$ttl" --url "$url" $dar_flag -R "$recipient_file"
          ;;
      esac
      ;;
    2|text|stdin)
      case $encryption_mode in
        passphrase)
          # shellcheck disable=SC2086
          exec "$0" upload --ttl "$ttl" --url "$url" $dar_flag
          ;;
        recipient)
          # shellcheck disable=SC2086
          exec "$0" upload --ttl "$ttl" --url "$url" $dar_flag -r "$recipient"
          ;;
        recipient-file)
          # shellcheck disable=SC2086
          exec "$0" upload --ttl "$ttl" --url "$url" $dar_flag -R "$recipient_file"
          ;;
      esac
      ;;
    3|message)
      case $encryption_mode in
        passphrase)
          # shellcheck disable=SC2086
          exec "$0" upload -m "$message" --ttl "$ttl" --url "$url" $dar_flag
          ;;
        recipient)
          # shellcheck disable=SC2086
          exec "$0" upload -m "$message" --ttl "$ttl" --url "$url" $dar_flag -r "$recipient"
          ;;
        recipient-file)
          # shellcheck disable=SC2086
          exec "$0" upload -m "$message" --ttl "$ttl" --url "$url" $dar_flag -R "$recipient_file"
          ;;
      esac
      ;;
    *)
      die "Unknown upload source: $source_choice"
      ;;
  esac
}

interactive_download() {
  printf 'Server URL [%s]: ' "$DUD_BASE_URL"
  read -r url
  url="${url:-$DUD_BASE_URL}"

  printf 'File ID: '
  read -r id
  [ -n "$id" ] || die "file ID required"

  printf 'Download output:\n'
  printf '  1) file path\n'
  printf '  2) stdout\n'
  printf 'Choice [1]: '
  read -r output_choice
  output_choice="${output_choice:-1}"

  if [ "$output_choice" = "1" ] || [ "$output_choice" = "file" ]; then
    printf 'Output path: '
    read -r out
    [ -n "$out" ] || die "output path required"
    out="$(abs_path_if_relative "$out")"
  fi

  printf 'Identity file (leave empty if not needed): '
  read -r identity
  if [ -n "$identity" ]; then
    identity="$(abs_path_if_relative "$identity")"
  fi

  case $output_choice in
    1|file)
      if [ -n "$identity" ]; then
        exec "$0" download --id "$id" --out "$out" --url "$url" -i "$identity"
      fi

      exec "$0" download --id "$id" --out "$out" --url "$url"
      ;;
    2|stdout)
      if [ -n "$identity" ]; then
        exec "$0" download --id "$id" --stdout --url "$url" -i "$identity"
      fi

      exec "$0" download --id "$id" --stdout --url "$url"
      ;;
    *)
      die "Unknown download output: $output_choice"
      ;;
  esac
}

interactive_keygen() {
  printf 'Keygen mode:\n'
  printf '  1) generate a new identity\n'
  printf '  2) convert an identity to recipients\n'
  printf 'Choice [1]: '
  read -r mode_choice
  mode_choice="${mode_choice:-1}"

  case $mode_choice in
    1|generate)
      printf 'Post-quantum key? [y/N]: '
      read -r pq_answer
      case $pq_answer in [Yy]*) pq_flag="--pq" ;; esac

      printf 'Identity output path (leave empty for stdout): '
      read -r out

      if [ -n "$out" ]; then
        out="$(abs_path_if_relative "$out")"

        printf 'Recipient output path (leave empty to skip): '
        read -r recipient_out
        if [ -n "$recipient_out" ]; then
          recipient_out="$(abs_path_if_relative "$recipient_out")"
          if [ -n "${pq_flag:-}" ]; then
            exec "$0" keygen --pq --out "$out" -R "$recipient_out"
          fi

          exec "$0" keygen --out "$out" -R "$recipient_out"
        fi

        if [ -n "${pq_flag:-}" ]; then
          exec "$0" keygen --pq --out "$out"
        fi

        exec "$0" keygen --out "$out"
      fi

      if [ -n "${pq_flag:-}" ]; then
        exec "$0" keygen --pq
      fi

      exec "$0" keygen
      ;;
    2|convert)
      printf 'Identity file: '
      read -r input
      [ -n "$input" ] || die "identity file required"
      input="$(abs_path_if_relative "$input")"

      printf 'Recipient output path (leave empty for stdout): '
      read -r recipient_out
      if [ -n "$recipient_out" ]; then
        recipient_out="$(abs_path_if_relative "$recipient_out")"
        exec "$0" keygen -R "$recipient_out" "$input"
      fi

      exec "$0" keygen "$input"
      ;;
    *)
      die "Unknown keygen mode: $mode_choice"
      ;;
  esac
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
    if stdin_is_tty; then
      interactive_menu
      return
    fi
    usage
    exit 1
  fi

  command="$1"
  shift

  case "$command" in
    --version|version)
      print_version
      ;;
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
    keygen)
      cmd_keygen "$@"
      ;;
    install)
      cmd_install
      ;;
    shell-init)
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
