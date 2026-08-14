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

dud_world_dir_name() {
  if [ -z "${DUD_PROFILE-}" ]; then
    printf 'default'
    return 0
  fi
  # The value names a directory under the DUD root and the mount point that
  # answers to it inside the container, so accept only what can escape neither.
  case "$DUD_PROFILE" in
    [!A-Za-z0-9]* | *[!A-Za-z0-9._-]*)
      printf '%%s\n' "Refusing invalid DUD_PROFILE" >&2
      return 1
      ;;
  esac
  if [ "${#DUD_PROFILE}" -gt 64 ]; then
    printf '%%s\n' "Refusing invalid DUD_PROFILE" >&2
    return 1
  fi
  printf '%%s' "$DUD_PROFILE"
}

dud_docker_env_args() {
  args=""

  if [ -r .env ]; then
    args="$(dud_shell_quote --env-file) $(dud_shell_quote .env)"
  fi

  # Always passed, empty included: the host decides which world is mounted, so a
  # DUD_HOME or DUD_PROFILE arriving from .env must not make the container look
  # for a directory that was never mounted.
  args="$args $(dud_shell_quote -e) $(dud_shell_quote DUD_HOME=/dud)"
  args="$args $(dud_shell_quote -e) $(dud_shell_quote "DUD_PROFILE=${DUD_PROFILE-}")"
  # Repository .env may configure network settings, but nothing in the
  # bind-mounted worktree may choose the code this container runs. Every
  # selector is pinned after --env-file, so a .env assignment loses: the helper
  # variables name the image's own binaries, PATH resolves those bare names
  # against image-owned directories only (/work is never on it), and the dynamic
  # loader overrides are cleared so a repository object cannot be injected into
  # git, age, or qrencode instead.
  for dud_pinned in \
    DUD_GIT_BIN=git \
    DUD_AGE_BIN=age \
    DUD_AGE_KEYGEN_BIN=age-keygen \
    DUD_QRENCODE_BIN=qrencode \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LD_PRELOAD= \
    LD_LIBRARY_PATH= \
    LD_AUDIT=; do
    args="$args $(dud_shell_quote -e) $(dud_shell_quote "$dud_pinned")"
  done

  for name in DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_DROP_SECRET DUD_PEER_SECRET DUD_CA_BUNDLE DUD_CONNECT_TO; do
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
  dud_world="$(dud_world_dir_name)" || return 1
  dud_root="${DUD_HOME:-$HOME/.dud}"
  dud_world_dir="$dud_root/$dud_world"
  dud_world_dir_existed=0
  [ -d "$dud_world_dir" ] && dud_world_dir_existed=1
  if [ -L "$dud_root" ] || [ -L "$dud_world_dir" ]; then
    printf '%%s\n' "Refusing symlinked DUD root or world directory" >&2
    return 1
  fi
  mkdir -p "$dud_world_dir" || return 1
  chmod 700 "$dud_root" "$dud_world_dir" || return 1
  dud_uid="$(id -u)"
  dud_gid="$(id -g)"
  # The client needs no capabilities and never escalates, so drop both. Exactly
  # one world is mounted, so a container opened for one profile cannot reach
  # another's seed or peer graph. It stays writable because init, pairing, and
  # delivery bookkeeping write it; every other mount below is read-only.
  args="$(dud_shell_quote --security-opt) $(dud_shell_quote no-new-privileges)"
  args="$args $(dud_shell_quote --cap-drop) $(dud_shell_quote ALL)"
  args="$args $(dud_shell_quote --user) $(dud_shell_quote "$dud_uid:$dud_gid")"
  args="$args $(dud_shell_quote -v) $(dud_shell_quote "$dud_world_dir:/dud/$dud_world")"
  # A CA bundle is static configuration the client only reads. Mounting it at
  # its own absolute path keeps DUD_CA_BUNDLE valid inside the container, which
  # a relative path under the working directory already was.
  case "${DUD_CA_BUNDLE:-}" in
    /*)
      if [ -f "$DUD_CA_BUNDLE" ] && [ -r "$DUD_CA_BUNDLE" ]; then
        args="$args $(dud_shell_quote -v) $(dud_shell_quote "$DUD_CA_BUNDLE:$DUD_CA_BUNDLE:ro")"
      fi
      ;;
  esac
  if [ -f .git ] && command -v git >/dev/null 2>&1; then
    dud_git_common_dir="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || dud_git_common_dir=""
    if [ -n "$dud_git_common_dir" ]; then
      args="$args $(dud_shell_quote -v) $(dud_shell_quote "$PWD:$PWD")"
      args="$args $(dud_shell_quote -v) $(dud_shell_quote "$dud_git_common_dir:$dud_git_common_dir")"
    fi
  fi
  if [ -n "${DUD_DOCKER_NETWORK:-}" ]; then
    args="$args $(dud_shell_quote --network) $(dud_shell_quote "$DUD_DOCKER_NETWORK")"
  fi
  printf '%%s' "$args"
}

dud_world="$(dud_world_dir_name)" || exit 1
dud_root="${DUD_HOME:-$HOME/.dud}"
dud_world_dir="$dud_root/$dud_world"
dud_world_dir_existed=0
[ -d "$dud_world_dir" ] && dud_world_dir_existed=1
dud_env_args="$(dud_docker_env_args)"
dud_run_args="$(dud_docker_run_args)" || exit 1
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
  # Deliberately not exec: the staged stdin file holds the caller's plaintext
  # and must be removed once the container exits. exec would replace this shell
  # and the EXIT trap would never run, leaving the payload on the host.
  eval "docker run --rm -it $dud_env_args $dud_run_args $dud_stdin_mount --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args" <"$dud_tty_input"
  dud_status=$?
  rm -f "$dud_stdin_file"
  trap - EXIT HUP INT TERM
  exit $dud_status
fi

dud_cli_args="$(dud_docker_cli_args "$@")"

# Bind-mounted directory roots cannot be renamed or removed from inside the
# container. The client erases their contents and this wrapper removes the now
# empty host roots after the bind mounts are gone.
if [ "${1:-}" = "erase" ] && [ "${2:-}" = "all" ]; then
  dud_erase_dry_run=0
  for dud_erase_arg in "$@"; do
    if [ "$dud_erase_arg" = "--dry-run" ]; then
      dud_erase_dry_run=1
    fi
  done
  if [ -t 0 ] && [ -t 1 ]; then
    eval "docker run --rm -it $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
  else
    eval "docker run --rm -i $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
  fi
  dud_status=$?
  if [ "$dud_status" -eq 0 ]; then
    if [ "$dud_erase_dry_run" -eq 0 ] || [ "$dud_world_dir_existed" -eq 0 ]; then
      rmdir "$dud_world_dir" || dud_status=1
      # Best effort: the root also holds every other world, and rmdir removes it
      # only when this was the last one.
      rmdir "$dud_root" 2>/dev/null || :
    fi
  fi
  exit "$dud_status"
fi

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

_dud_world_dir_name() {
  if [ -z "${DUD_PROFILE-}" ]; then
    printf 'default'
    return 0
  fi
  # The value names a directory under the DUD root and the mount point that
  # answers to it inside the container, so accept only what can escape neither.
  case "$DUD_PROFILE" in
    [!A-Za-z0-9]* | *[!A-Za-z0-9._-]*)
      printf '%%s\n' "Refusing invalid DUD_PROFILE" >&2
      return 1
      ;;
  esac
  if [ "${#DUD_PROFILE}" -gt 64 ]; then
    printf '%%s\n' "Refusing invalid DUD_PROFILE" >&2
    return 1
  fi
  printf '%%s' "$DUD_PROFILE"
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
      printf '%%s\n' --version version init doctor capabilities config migrate erase peer sync test upload download send receive git flush keygen install shell-init help -h --help
      ;;
    config)
      printf '%%s\n' show validate
      ;;
    erase)
      printf '%%s\n' pairings peer repo all
      ;;
    erase-options)
      printf '%%s\n' --yes --dry-run --json --repo
      ;;
    peer)
      printf '%%s\n' invite accept list show rename revoke remove
      ;;
    peer-invite)
      printf '%%s\n' --expires --json
      ;;
    peer-accept)
      printf '%%s\n' --json
      ;;
    git)
      printf '%%s\n' push fetch send receive status
      ;;
    test)
      printf '%%s\n' --json --url --doh-url
      ;;
    upload)
      printf '%%s\n' --file -m --ttl --delete-after-read --passphrase --recipient -r --recipient-file -R --json --no-qr --url --doh-url
      ;;
    download)
      printf '%%s\n' --id --out --stdout --extract --out-dir --identity -i --json --url --doh-url
      ;;
    git-push)
      printf '%%s\n' --branch --current --ttl --json --delete-after-read --passphrase --recipient -r --recipient-file -R --no-qr --url --doh-url
      ;;
    git-fetch)
      printf '%%s\n' --associate --allow-rewrite --json --id --identity -i --remote --url --doh-url
      ;;
    flush)
      printf '%%s\n' --json --url --doh-url
      ;;
    keygen)
      printf '%%s\n' --pq --out --recipient-out -R --json
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

_dud_peer_aliases() {
  world="$(_dud_world_dir_name)" || return 0
  config_file="${DUD_HOME:-$HOME/.dud}/$world/config/config.toml"
  if [ -r "$config_file" ]; then
    sed -n 's/^\[peer\."\([A-Za-z0-9][A-Za-z0-9._-]*\)"\]$/\1/p' "$config_file"
  fi
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
        --version|version|init|doctor|capabilities|config|migrate|erase|peer|sync|test|upload|download|send|receive|git|flush|keygen|install|shell-init|help|-h|--help)
          _dud_complete_command="$1"
          shift
          continue
          ;;
      esac
      shift
      continue
    fi

    case "$_dud_complete_command" in
      config)
        if [ -z "$_dud_complete_subcommand" ]; then
          _dud_complete_subcommand="$1"
        fi
        ;;
      erase)
        if [ -z "$_dud_complete_subcommand" ]; then
          _dud_complete_subcommand="$1"
        fi
        ;;
      peer)
        if [ -z "$_dud_complete_subcommand" ]; then
          _dud_complete_subcommand="$1"
        else
          case "$_dud_complete_subcommand:$1" in
            invite:--expires)
              _dud_complete_expect="$1"
              _dud_complete_value_kind="plain"
              ;;
          esac
        fi
        ;;
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
            push|send|fetch|receive|status|help|-h|--help)
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
              --branch|--ttl|--recipient|-r|--url|--doh-url)
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
    config)
      if [ -z "$_dud_complete_subcommand" ]; then
        _dud_complete_wordlist config
      fi
      ;;
    erase)
      if [ -z "$_dud_complete_subcommand" ]; then
        _dud_complete_wordlist erase
        return 0
      fi
      if [ "$_dud_complete_subcommand" = "peer" ]; then
        _dud_peer_aliases
      fi
      _dud_complete_wordlist erase-options
      ;;
    peer)
      if [ -z "$_dud_complete_subcommand" ]; then
        _dud_complete_wordlist peer
        return 0
      fi
      case "$_dud_complete_subcommand" in
        invite)
          _dud_peer_aliases
          _dud_complete_wordlist peer-invite
          ;;
        accept)
          _dud_complete_wordlist peer-accept
          ;;
        show|rename|remove|confirm|revoke)
          _dud_peer_aliases
          ;;
      esac
      ;;
    upload|send)
      _dud_peer_aliases
      _dud_complete_wordlist upload
      ;;
    download|receive)
      _dud_peer_aliases
      _dud_complete_wordlist download
      ;;
    sync)
      _dud_peer_aliases
      ;;
    git)
      if [ -z "$_dud_complete_subcommand" ]; then
        _dud_complete_wordlist git
        return 0
      fi
      case "$_dud_complete_subcommand" in
        push|send)
          _dud_peer_aliases
          _dud_complete_wordlist git-push
          ;;
        fetch|receive)
          _dud_peer_aliases
          _dud_complete_wordlist git-fetch
          ;;
        status)
          _dud_peer_aliases
          printf '%%s\n' --json
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
  dud_world="$(_dud_world_dir_name)" || return 1
  dud_root="${DUD_HOME:-$HOME/.dud}"
  dud_world_dir="$dud_root/$dud_world"
  dud_world_dir_existed=0
  [ -d "$dud_world_dir" ] && dud_world_dir_existed=1
  if [ -L "$dud_root" ] || [ -L "$dud_world_dir" ]; then
    printf '%%s\n' "Refusing symlinked DUD root or world directory" >&2
    return 1
  fi
  mkdir -p "$dud_world_dir" || return 1
  chmod 700 "$dud_root" "$dud_world_dir" || return 1
  dud_uid="$(id -u)"
  dud_gid="$(id -g)"
  # The client needs no capabilities and never escalates, so drop both. Exactly
  # one world is mounted, so a container opened for one profile cannot reach
  # another's seed or peer graph. It stays writable because init, pairing, and
  # delivery bookkeeping write it; every other mount below is read-only.
  dud_run_args="$(_dud_shell_quote --security-opt) $(_dud_shell_quote no-new-privileges)"
  dud_run_args="$dud_run_args $(_dud_shell_quote --cap-drop) $(_dud_shell_quote ALL)"
  dud_run_args="$dud_run_args $(_dud_shell_quote --user) $(_dud_shell_quote "$dud_uid:$dud_gid")"
  dud_run_args="$dud_run_args $(_dud_shell_quote -v) $(_dud_shell_quote "$dud_world_dir:/dud/$dud_world")"
  # A CA bundle is static configuration the client only reads. Mounting it at
  # its own absolute path keeps DUD_CA_BUNDLE valid inside the container, which
  # a relative path under the working directory already was.
  case "${DUD_CA_BUNDLE:-}" in
    /*)
      if [ -f "$DUD_CA_BUNDLE" ] && [ -r "$DUD_CA_BUNDLE" ]; then
        dud_run_args="$dud_run_args $(_dud_shell_quote -v) $(_dud_shell_quote "$DUD_CA_BUNDLE:$DUD_CA_BUNDLE:ro")"
      fi
      ;;
  esac
  if [ -f .git ] && command -v git >/dev/null 2>&1; then
    dud_git_common_dir="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || dud_git_common_dir=""
    if [ -n "$dud_git_common_dir" ]; then
      dud_run_args="$dud_run_args $(_dud_shell_quote -v) $(_dud_shell_quote "$PWD:$PWD")"
      dud_run_args="$dud_run_args $(_dud_shell_quote -v) $(_dud_shell_quote "$dud_git_common_dir:$dud_git_common_dir")"
    fi
  fi
  dud_image="${DUD_IMAGE:-%s}"
  dud_image_arg="$(_dud_shell_quote "$dud_image")"

  if [ -r .env ]; then
    dud_env_args="$dud_env_args $(_dud_shell_quote --env-file) $(_dud_shell_quote .env)"
  fi

  # Always passed, empty included: the host decides which world is mounted, so a
  # DUD_HOME or DUD_PROFILE arriving from .env must not make the container look
  # for a directory that was never mounted.
  dud_env_args="$dud_env_args $(_dud_shell_quote -e) $(_dud_shell_quote DUD_HOME=/dud)"
  dud_env_args="$dud_env_args $(_dud_shell_quote -e) $(_dud_shell_quote "DUD_PROFILE=${DUD_PROFILE-}")"
  # Repository .env may configure network settings, but nothing in the
  # bind-mounted worktree may choose the code this container runs. Every
  # selector is pinned after --env-file, so a .env assignment loses: the helper
  # variables name the image's own binaries, PATH resolves those bare names
  # against image-owned directories only (/work is never on it), and the dynamic
  # loader overrides are cleared so a repository object cannot be injected into
  # git, age, or qrencode instead.
  for dud_pinned in \
    DUD_GIT_BIN=git \
    DUD_AGE_BIN=age \
    DUD_AGE_KEYGEN_BIN=age-keygen \
    DUD_QRENCODE_BIN=qrencode \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LD_PRELOAD= \
    LD_LIBRARY_PATH= \
    LD_AUDIT=; do
    dud_env_args="$dud_env_args $(_dud_shell_quote -e) $(_dud_shell_quote "$dud_pinned")"
  done

  for name in DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_DROP_SECRET DUD_PEER_SECRET DUD_CA_BUNDLE DUD_CONNECT_TO; do
    eval "value=\${$name-}"
    if [ -n "$value" ]; then
      if [ -n "$dud_env_args" ]; then
        dud_env_args="$dud_env_args "
      fi
      dud_env_args="$dud_env_args$(_dud_shell_quote -e) $(_dud_shell_quote "$name=$value")"
    fi
  done

  if [ -n "${DUD_DOCKER_NETWORK:-}" ]; then
    dud_run_args="$dud_run_args $(_dud_shell_quote --network) $(_dud_shell_quote "$DUD_DOCKER_NETWORK")"
  fi

  if [ "$#" -gt 0 ] && { [ "$1" = "upload" ] || [ "$1" = "send" ]; } && ! [ -t 0 ] && _dud_stdout_is_tty && _dud_host_has_tty && _dud_upload_uses_stdin "$@"; then
    dud_stdin_file="$(mktemp /tmp/dud-wrapper-stdin-XXXXXX)"
    # Armed before the payload is written, so an interrupt while reading a slow
    # or large stdin cannot leave the caller's plaintext on the host.
    trap 'rm -f "$dud_stdin_file"' EXIT HUP INT TERM
    cat >"$dud_stdin_file"
    dud_command="$1"
    shift
    set -- "$dud_command" --file /tmp/dud-stdin "$@"
    dud_cli_args="$(_dud_docker_cli_args "$@")"
    dud_stdin_mount="$(_dud_shell_quote -v) $(_dud_shell_quote "$dud_stdin_file:/tmp/dud-stdin:ro")"
    dud_tty_input="$(_dud_tty_input_path)"
    eval "docker run --rm -it $dud_env_args $dud_run_args $dud_stdin_mount --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args" <"$dud_tty_input"
    dud_status=$?
    rm -f "$dud_stdin_file"
    trap - EXIT HUP INT TERM
    return $dud_status
  fi

  dud_cli_args="$(_dud_docker_cli_args "$@")"

  # The container erases the bind-mounted world's contents; after it exits,
  # remove the empty host directory so erase-all leaves nothing behind.
  if [ "${1:-}" = "erase" ] && [ "${2:-}" = "all" ]; then
    dud_erase_dry_run=0
    for dud_erase_arg in "$@"; do
      if [ "$dud_erase_arg" = "--dry-run" ]; then
        dud_erase_dry_run=1
      fi
    done
    if [ -t 0 ] && [ -t 1 ]; then
      eval "docker run --rm -it $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
    else
      eval "docker run --rm -i $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
    fi
    dud_status=$?
    if [ "$dud_status" -eq 0 ]; then
      if [ "$dud_erase_dry_run" -eq 0 ] || [ "$dud_world_dir_existed" -eq 0 ]; then
        rmdir "$dud_world_dir" || dud_status=1
        # Best effort: the root also holds every other world, and rmdir removes
        # it only when this was the last one.
        rmdir "$dud_root" 2>/dev/null || :
      fi
    fi
    return "$dud_status"
  fi

  if [ -t 0 ] && [ -t 1 ]; then
    eval "docker run --rm -it $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
    return
  fi

  eval "docker run --rm -i $dud_env_args $dud_run_args --tmpfs /tmp:rw,noexec,nosuid,size=128m -v \"$PWD:/work\" $dud_image_arg $dud_cli_args"
}
`, image)
}
