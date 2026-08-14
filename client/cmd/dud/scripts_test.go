// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"strings"
	"testing"
)

func TestShellInitScriptContainsWrapperContracts(t *testing.T) {
	script := shellInitScript("dud-client-test")
	for _, needle := range []string{
		"dud() {",
		"_dud_host_has_tty() {",
		"_dud_stdout_is_tty() {",
		"_dud_tty_input_path() {",
		"_dud_upload_uses_stdin() {",
		"_dud_docker_cli_args() {",
		"_dud_complete_wordlist() {",
		"_dud_complete_filter_prefix() {",
		"_dud_peer_aliases() {",
		"_dud_complete_parse() {",
		"_dud_complete_candidates() {",
		"_dud_complete_bash() {",
		"_dud_complete_zsh() {",
		"complete -o default -F _dud_complete_bash dud",
		"compdef _dud_complete_zsh dud",
		"_dud_world_dir_name() {",
		`"DUD_PROFILE=${DUD_PROFILE-}"`,
		"DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_DROP_SECRET DUD_PEER_SECRET DUD_CA_BUNDLE DUD_CONNECT_TO",
		"DUD_DOCKER_NETWORK",
		"DUD_HOME=/dud",
		`"$dud_world_dir:/dud/$dud_world"`,
		`git rev-parse --path-format=absolute --git-common-dir`,
		`"$dud_git_common_dir:$dud_git_common_dir"`,
		"invite accept list show rename revoke remove",
		"pairings peer repo all",
		"push fetch send receive status",
		"--associate --allow-rewrite",
		`--user`,
		"/tmp/dud-stdin:ro",
		"dud-client-test",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("shell init missing %q", needle)
		}
	}

	for _, needle := range []string{
		"\ndud_host_has_tty() {",
		"\ndud_stdout_is_tty() {",
		"\ndud_tty_input_path() {",
		"\ndud_upload_uses_stdin() {",
		"\ndud_docker_cli_args() {",
	} {
		if strings.Contains(script, needle) {
			t.Fatalf("shell init leaked public helper %q", needle)
		}
	}
}

func TestInstallScriptContainsWrapperContracts(t *testing.T) {
	script := installScript("dud-client-test")
	for _, needle := range []string{
		"dud_docker_env_args()",
		"dud_docker_run_args()",
		"dud_world_dir_name()",
		`"DUD_PROFILE=${DUD_PROFILE-}"`,
		"DUD_HOME=/dud",
		`"$dud_world_dir:/dud/$dud_world"`,
		`git rev-parse --path-format=absolute --git-common-dir`,
		`"$dud_git_common_dir:$dud_git_common_dir"`,
		`--user`,
		"/tmp/dud-stdin:ro",
		"dud-client-test",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("install script missing %q", needle)
		}
	}
}

func TestPairingCommandsNeverEnterStagedStdinPath(t *testing.T) {
	for name, script := range map[string]string{
		"install":    installScript("dud-client-test"),
		"shell-init": shellInitScript("dud-client-test"),
	} {
		conditionStart := strings.Index(script, `if [ "$#" -gt 0 ] && { [ "$1" = "upload" ] || [ "$1" = "send" ]; }`)
		if conditionStart < 0 {
			t.Fatalf("%s wrapper lost the explicit staged-stdin command allowlist", name)
		}
		conditionEnd := strings.Index(script[conditionStart:], "; then")
		if conditionEnd < 0 {
			t.Fatalf("%s wrapper staged-stdin condition is malformed", name)
		}
		condition := script[conditionStart : conditionStart+conditionEnd]
		for _, forbidden := range []string{"peer", "init", "config", "doctor", "capabilities", "migrate", "erase"} {
			if strings.Contains(condition, forbidden) {
				t.Fatalf("%s wrapper stages stdin for v2 command %q", name, forbidden)
			}
		}
	}
}

// The staged stdin file holds the caller's plaintext on the host. exec would
// replace the wrapper shell and skip both the EXIT trap and the explicit
// cleanup, so the branch that stages stdin must not use it.
func TestInstallScriptDoesNotExecWhileStagedStdinNeedsCleanup(t *testing.T) {
	script := installScript("dud-client-test")
	stdinBranch, _, found := strings.Cut(script, "dud_cli_args=\"$(dud_docker_cli_args \"$@\")\"\n\n# Bind-mounted")
	if !found {
		t.Fatal("install script has no separable staged-stdin branch")
	}
	if !strings.Contains(stdinBranch, "mktemp /tmp/dud-wrapper-stdin-") {
		t.Fatal("staged-stdin branch does not stage stdin to a host file")
	}
	if strings.Contains(stdinBranch, "exec docker run") {
		t.Fatal("staged-stdin branch uses exec, so the staged plaintext is never removed")
	}
	for _, needle := range []string{
		`trap 'rm -f "$dud_stdin_file"' EXIT HUP INT TERM`,
		`rm -f "$dud_stdin_file"`,
		"exit $dud_status",
	} {
		if !strings.Contains(stdinBranch, needle) {
			t.Fatalf("staged-stdin branch missing cleanup step %q", needle)
		}
	}
}

// Same exposure in the shell-init wrapper: the trap has to be armed before the
// payload is written, or an interrupt during a slow read leaks it.
func TestShellInitArmsStdinCleanupBeforeReading(t *testing.T) {
	script := shellInitScript("dud-client-test")
	trapIndex := strings.Index(script, `trap 'rm -f "$dud_stdin_file"' EXIT HUP INT TERM`)
	if trapIndex < 0 {
		t.Fatal("shell init does not trap staged stdin cleanup")
	}
	catIndex := strings.Index(script, `cat >"$dud_stdin_file"`)
	if catIndex < 0 {
		t.Fatal("shell init does not stage stdin to a host file")
	}
	if trapIndex > catIndex {
		t.Fatal("shell init arms stdin cleanup only after writing the payload")
	}
}

// The wrapper's mount policy is a security contract: nothing the client only
// reads may be writable, and nothing it writes may be read-only.
func TestGeneratedWrappersMountReadOnlyWhereverPossible(t *testing.T) {
	for name, script := range map[string]string{
		"install":    installScript("dud-client-test"),
		"shell-init": shellInitScript("dud-client-test"),
	} {
		for _, needle := range []string{
			// Static configuration and staged input are read-only.
			`"$DUD_CA_BUNDLE:$DUD_CA_BUNDLE:ro"`,
			"/tmp/dud-stdin:ro",
			// The container needs no capability and never escalates.
			"--security-opt",
			"no-new-privileges",
			"--cap-drop",
			"ALL",
		} {
			if !strings.Contains(script, needle) {
				t.Fatalf("%s wrapper missing %q", name, needle)
			}
		}
		// The device seed, peer graph, delivery state, repository, and working
		// directory are written by ordinary commands and stay writable.
		for _, writable := range []string{
			`"$dud_world_dir:/dud/$dud_world"`,
			`"$dud_git_common_dir:$dud_git_common_dir"`,
			`-v \"$PWD:/work\"`,
		} {
			if !strings.Contains(script, writable) {
				t.Fatalf("%s wrapper lost writable mount %q", name, writable)
			}
			if strings.Contains(script, writable+":ro") {
				t.Fatalf("%s wrapper made %q read-only, which breaks writes", name, writable)
			}
		}
	}
}

// A CA bundle is only mounted when it is a readable absolute host path, so a
// relative path keeps resolving under the working-directory mount exactly as it
// did before.
func TestGeneratedWrappersOnlyMountAnAbsoluteReadableCABundle(t *testing.T) {
	for name, script := range map[string]string{
		"install":    installScript("dud-client-test"),
		"shell-init": shellInitScript("dud-client-test"),
	} {
		start := strings.Index(script, `case "${DUD_CA_BUNDLE:-}" in`)
		if start < 0 {
			t.Fatalf("%s wrapper has no CA bundle mount guard", name)
		}
		end := strings.Index(script[start:], "\n  esac")
		if end < 0 {
			t.Fatalf("%s wrapper CA bundle guard is malformed", name)
		}
		guard := script[start : start+end]
		for _, needle := range []string{
			"    /*)",
			`[ -f "$DUD_CA_BUNDLE" ] && [ -r "$DUD_CA_BUNDLE" ]`,
		} {
			if !strings.Contains(guard, needle) {
				t.Fatalf("%s wrapper CA bundle guard missing %q:\n%s", name, needle, guard)
			}
		}
	}
}
