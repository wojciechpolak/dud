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
    args="$args$(_dud_shell_quote "$arg")"
  done

  printf '%%s' "$args"
}

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

  if [ "$#" -gt 0 ] && { [ "$1" = "upload" ] || [ "$1" = "send" ]; } && ! [ -t 0 ] && dud_stdout_is_tty && dud_host_has_tty && dud_upload_uses_stdin "$@"; then
    dud_stdin_file="$(mktemp /tmp/dud-wrapper-stdin-XXXXXX)"
    cat >"$dud_stdin_file"
    dud_command="$1"
    shift
    set -- "$dud_command" --file /tmp/dud-stdin "$@"
    dud_cli_args="$(dud_docker_cli_args "$@")"
    dud_stdin_mount="$(_dud_shell_quote -v) $(_dud_shell_quote "$dud_stdin_file:/tmp/dud-stdin:ro")"
    dud_tty_input="$(dud_tty_input_path)"
    trap 'rm -f "$dud_stdin_file"' EXIT HUP INT TERM
    eval "docker run --rm -it $dud_env_args $dud_run_args $dud_stdin_mount --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args" <"$dud_tty_input"
    status=$?
    rm -f "$dud_stdin_file"
    trap - EXIT HUP INT TERM
    return $status
  fi

  dud_cli_args="$(dud_docker_cli_args "$@")"

  if [ -t 0 ] && [ -t 1 ]; then
    eval "docker run --rm -it $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
    return
  fi

  eval "docker run --rm -i $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
}
`, image)
}
