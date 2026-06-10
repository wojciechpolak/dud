// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "fmt"

func installScript(image string) string {
	return fmt.Sprintf(`#!/bin/sh

dud_shell_quote() {
  printf "'%%s'" "$(printf '%%s' "$1" | sed "s/'/'\\''/g")"
}

dud_host_has_tty() {
  [ "${DUD_TEST_HOST_TTY:-0}" = "1" ] || { : </dev/tty; } 2>/dev/null
}

dud_stdout_is_tty() {
  [ "${DUD_TEST_STDOUT_TTY:-0}" = "1" ] || [ -t 1 ]
}

dud_tty_input_path() {
  printf '%%s' "${DUD_TEST_TTY_INPUT_PATH:-/dev/tty}"
}

dud_upload_uses_stdin() {
  shift

  while [ $# -gt 0 ]; do
    case "$1" in
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

  for arg in "$@"; do
    if [ -n "$args" ]; then
      args="$args "
    fi
    args="$args$(dud_shell_quote "$arg")"
  done

  printf '%%s' "$args"
}

dud_docker_env_args() {
  args=""

  if [ -r .env ]; then
    args="$(dud_shell_quote --env-file) $(dud_shell_quote .env)"
  fi

  for name in DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN DUD_CA_BUNDLE DUD_CONNECT_TO; do
    eval "value=\${$name-}"
    if [ -n "$value" ]; then
      if [ -n "$args" ]; then
        args="$args "
      fi
      args="$args$(dud_shell_quote -e) $(dud_shell_quote "$name=$value")"
    fi
  done

  printf '%%s' "$args"
}

dud_docker_run_args() {
  args=""
  if [ -n "${DUD_DOCKER_NETWORK:-}" ]; then
    args="$(dud_shell_quote --network) $(dud_shell_quote "$DUD_DOCKER_NETWORK")"
  fi
  printf '%%s' "$args"
}

dud_env_args="$(dud_docker_env_args)"
dud_run_args="$(dud_docker_run_args)"
dud_image="${DUD_IMAGE:-%s}"
dud_image_arg="$(dud_shell_quote "$dud_image")"

if [ "$#" -gt 0 ] && { [ "$1" = "upload" ] || [ "$1" = "send" ]; } && ! [ -t 0 ] && dud_stdout_is_tty && dud_host_has_tty && dud_upload_uses_stdin "$@"; then
  dud_stdin_file="$(mktemp /tmp/dud-wrapper-stdin-XXXXXX)"
  trap 'rm -f "$dud_stdin_file"' EXIT HUP INT TERM
  cat >"$dud_stdin_file"
  dud_command="$1"
  shift
  set -- "$dud_command" --file /tmp/dud-stdin "$@"
  dud_cli_args="$(dud_docker_cli_args "$@")"
  dud_stdin_mount="$(dud_shell_quote -v) $(dud_shell_quote "$dud_stdin_file:/tmp/dud-stdin:ro")"
  dud_tty_input="$(dud_tty_input_path)"
  eval "exec docker run --rm -it $dud_env_args $dud_run_args $dud_stdin_mount --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args" <"$dud_tty_input"
fi

dud_cli_args="$(dud_docker_cli_args "$@")"

if [ -t 0 ] && [ -t 1 ]; then
  eval "exec docker run --rm -it $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
fi

eval "exec docker run --rm -i $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
`, image)
}

func shellInitScript(image string) string {
	return fmt.Sprintf(`_dud_shell_quote() {
  printf "'%%s'" "$(printf '%%s' "$1" | sed "s/'/'\\''/g")"
}

_dud_host_has_tty() {
  [ "${DUD_TEST_HOST_TTY:-0}" = "1" ] || { : </dev/tty; } 2>/dev/null
}

_dud_stdout_is_tty() {
  [ "${DUD_TEST_STDOUT_TTY:-0}" = "1" ] || [ -t 1 ]
}

_dud_tty_input_path() {
  printf '%%s' "${DUD_TEST_TTY_INPUT_PATH:-/dev/tty}"
}

_dud_upload_uses_stdin() {
  shift

  while [ $# -gt 0 ]; do
    case "$1" in
      --file|-m)
        return 1
        ;;
    esac
    shift
  done

  return 0
}

_dud_docker_cli_args() {
  args=""

  for arg in "$@"; do
    if [ -n "$args" ]; then
      args="$args "
    fi
    args="$args$(_dud_shell_quote "$arg")"
  done

  printf '%%s' "$args"
}

_dud_complete_wordlist() {
  case "$1" in
    top)
      printf '%%s\n' --version version test upload download send receive git flush keygen install shell-init help -h --help
      ;;
    git)
      printf '%%s\n' push fetch send receive
      ;;
    test)
      printf '%%s\n' --url --doh-url
      ;;
    upload)
      printf '%%s\n' --file -m --ttl --delete-after-read --passphrase --recipient -r --recipient-file -R --json --no-qr --url --doh-url
      ;;
    download)
      printf '%%s\n' --id --out --stdout --extract --out-dir --identity -i --url --doh-url
      ;;
    git-push)
      printf '%%s\n' --ttl --delete-after-read --passphrase --recipient -r --recipient-file -R --json --no-qr --url --doh-url
      ;;
    git-fetch)
      printf '%%s\n' --id --identity -i --remote --url --doh-url
      ;;
    flush)
      printf '%%s\n' --url --doh-url
      ;;
    keygen)
      printf '%%s\n' --pq --out --recipient-out -R
      ;;
  esac
}

_dud_complete_filter_prefix() {
  prefix="$1"

  while IFS= read -r candidate; do
    case "$candidate" in
      "$prefix"*)
        printf '%%s\n' "$candidate"
        ;;
    esac
  done
}

_dud_complete_parse() {
  _dud_complete_command=""
  _dud_complete_subcommand=""
  _dud_complete_expect=""
  _dud_complete_value_kind=""
  _dud_complete_keygen_input_seen=0

  while [ $# -gt 0 ]; do
    if [ -n "$_dud_complete_expect" ]; then
      _dud_complete_expect=""
      _dud_complete_value_kind=""
      shift
      continue
    fi

    if [ -z "$_dud_complete_command" ]; then
      case "$1" in
        --version|version|test|upload|download|send|receive|git|flush|keygen|install|shell-init|help|-h|--help)
          _dud_complete_command="$1"
          shift
          continue
          ;;
      esac
      shift
      continue
    fi

    case "$_dud_complete_command" in
      upload|send)
        case "$1" in
          --file|--recipient-file|-R)
            _dud_complete_expect="$1"
            _dud_complete_value_kind="file"
            ;;
          -m|--ttl|--recipient|-r|--url|--doh-url)
            _dud_complete_expect="$1"
            _dud_complete_value_kind="plain"
            ;;
        esac
        ;;
      download|receive)
        case "$1" in
          --out|--identity|-i)
            _dud_complete_expect="$1"
            _dud_complete_value_kind="file"
            ;;
          --out-dir)
            _dud_complete_expect="$1"
            _dud_complete_value_kind="dir"
            ;;
          --id|--url|--doh-url)
            _dud_complete_expect="$1"
            _dud_complete_value_kind="plain"
            ;;
        esac
        ;;
      git)
        if [ -z "$_dud_complete_subcommand" ]; then
          case "$1" in
            push|send|fetch|receive|help|-h|--help)
              _dud_complete_subcommand="$1"
              shift
              continue
              ;;
          esac
        fi

        case "$_dud_complete_subcommand" in
          push|send)
            case "$1" in
              --recipient-file|-R)
                _dud_complete_expect="$1"
                _dud_complete_value_kind="file"
                ;;
              --ttl|--recipient|-r|--url|--doh-url)
                _dud_complete_expect="$1"
                _dud_complete_value_kind="plain"
                ;;
            esac
            ;;
          fetch|receive)
            case "$1" in
              --identity|-i)
                _dud_complete_expect="$1"
                _dud_complete_value_kind="file"
                ;;
              --id|--remote|--url|--doh-url)
                _dud_complete_expect="$1"
                _dud_complete_value_kind="plain"
                ;;
            esac
            ;;
        esac
        ;;
      test|flush)
        case "$1" in
          --url|--doh-url)
            _dud_complete_expect="$1"
            _dud_complete_value_kind="plain"
            ;;
        esac
        ;;
      keygen)
        case "$1" in
          --out|--recipient-out|-R)
            _dud_complete_expect="$1"
            _dud_complete_value_kind="file"
            ;;
          --pq)
            ;;
          -*)
            ;;
          *)
            _dud_complete_keygen_input_seen=1
            ;;
        esac
        ;;
    esac

    shift
  done
}

_dud_complete_candidates() {
  if [ -n "$_dud_complete_expect" ]; then
    return 0
  fi

  if [ -z "$_dud_complete_command" ]; then
    _dud_complete_wordlist top
    return 0
  fi

  case "$_dud_complete_command" in
    upload|send)
      _dud_complete_wordlist upload
      ;;
    download|receive)
      _dud_complete_wordlist download
      ;;
    git)
      if [ -z "$_dud_complete_subcommand" ]; then
        _dud_complete_wordlist git
        return 0
      fi
      case "$_dud_complete_subcommand" in
        push|send)
          _dud_complete_wordlist git-push
          ;;
        fetch|receive)
          _dud_complete_wordlist git-fetch
          ;;
      esac
      ;;
    test)
      _dud_complete_wordlist test
      ;;
    flush)
      _dud_complete_wordlist flush
      ;;
    keygen)
      _dud_complete_wordlist keygen
      ;;
  esac
}

if [ -n "${BASH_VERSION:-}" ] && command -v complete >/dev/null 2>&1; then
  eval '
_dud_complete_bash() {
  local cur
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  _dud_complete_parse "${COMP_WORDS[@]:1:$((COMP_CWORD - 1))}"

  if [ -n "$_dud_complete_expect" ]; then
    case "$_dud_complete_value_kind" in
      file)
        COMPREPLY=( $(compgen -f -- "$cur") )
        return
        ;;
      dir)
        COMPREPLY=( $(compgen -d -- "$cur") )
        return
        ;;
      *)
        return
        ;;
    esac
  fi

  if [ "$_dud_complete_command" = "keygen" ] && [ "$_dud_complete_keygen_input_seen" != "1" ] && [ "${cur#-}" = "$cur" ]; then
    COMPREPLY=( $(compgen -f -- "$cur") $(compgen -W "$(_dud_complete_wordlist keygen)" -- "$cur") )
    return
  fi

  COMPREPLY=( $(compgen -W "$(_dud_complete_candidates)" -- "$cur") )
}

complete -o default -F _dud_complete_bash dud
'
fi

if [ -n "${ZSH_VERSION:-}" ]; then
  eval '
_dud_complete_zsh() {
  emulate -L zsh
  local cur
  local -a dud_args candidates

  cur="${words[CURRENT]}"
  if (( CURRENT > 2 )); then
    dud_args=("${(@)words[2,CURRENT-1]}")
  else
    dud_args=()
  fi

  _dud_complete_parse "${dud_args[@]}"

  if [ -n "$_dud_complete_expect" ]; then
    case "$_dud_complete_value_kind" in
      file)
        _files
        return
        ;;
      dir)
        _files -/
        return
        ;;
      *)
        return
        ;;
    esac
  fi

  if [ "$_dud_complete_command" = "keygen" ] && [ "$_dud_complete_keygen_input_seen" != "1" ] && [ "${cur#-}" = "$cur" ]; then
    _files
    candidates=(${(f)"$(_dud_complete_wordlist keygen | _dud_complete_filter_prefix "$cur")"})
    if (( ${#candidates[@]} > 0 )); then
      compadd -- ${candidates[@]}
    fi
    return
  fi

  candidates=(${(f)"$(_dud_complete_candidates | _dud_complete_filter_prefix "$cur")"})
  if (( ${#candidates[@]} > 0 )); then
    compadd -- ${candidates[@]}
  fi
}

if command -v compdef >/dev/null 2>&1; then
  compdef _dud_complete_zsh dud
fi
'
fi

dud() {
  dud_env_args=""
  dud_run_args=""
  dud_image="${DUD_IMAGE:-%s}"
  dud_image_arg="$(_dud_shell_quote "$dud_image")"

  if [ -r .env ]; then
    dud_env_args="$(_dud_shell_quote --env-file) $(_dud_shell_quote .env)"
  fi

  for name in DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN DUD_CA_BUNDLE DUD_CONNECT_TO; do
    eval "value=\${$name-}"
    if [ -n "$value" ]; then
      if [ -n "$dud_env_args" ]; then
        dud_env_args="$dud_env_args "
      fi
      dud_env_args="$dud_env_args$(_dud_shell_quote -e) $(_dud_shell_quote "$name=$value")"
    fi
  done

  if [ -n "${DUD_DOCKER_NETWORK:-}" ]; then
    dud_run_args="$(_dud_shell_quote --network) $(_dud_shell_quote "$DUD_DOCKER_NETWORK")"
  fi

  if [ "$#" -gt 0 ] && { [ "$1" = "upload" ] || [ "$1" = "send" ]; } && ! [ -t 0 ] && _dud_stdout_is_tty && _dud_host_has_tty && _dud_upload_uses_stdin "$@"; then
    dud_stdin_file="$(mktemp /tmp/dud-wrapper-stdin-XXXXXX)"
    cat >"$dud_stdin_file"
    dud_command="$1"
    shift
    set -- "$dud_command" --file /tmp/dud-stdin "$@"
    dud_cli_args="$(_dud_docker_cli_args "$@")"
    dud_stdin_mount="$(_dud_shell_quote -v) $(_dud_shell_quote "$dud_stdin_file:/tmp/dud-stdin:ro")"
    dud_tty_input="$(_dud_tty_input_path)"
    trap 'rm -f "$dud_stdin_file"' EXIT HUP INT TERM
    eval "docker run --rm -it $dud_env_args $dud_run_args $dud_stdin_mount --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args" <"$dud_tty_input"
    status=$?
    rm -f "$dud_stdin_file"
    trap - EXIT HUP INT TERM
    return $status
  fi

  dud_cli_args="$(_dud_docker_cli_args "$@")"

  if [ -t 0 ] && [ -t 1 ]; then
    eval "docker run --rm -it $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
    return
  fi

  eval "docker run --rm -i $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
}
`, image)
}
