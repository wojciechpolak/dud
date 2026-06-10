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
		"_dud_complete_parse() {",
		"_dud_complete_candidates() {",
		"_dud_complete_bash() {",
		"_dud_complete_zsh() {",
		"complete -o default -F _dud_complete_bash dud",
		"compdef _dud_complete_zsh dud",
		"DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN DUD_CA_BUNDLE DUD_CONNECT_TO",
		"DUD_DOCKER_NETWORK",
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
		"/tmp/dud-stdin:ro",
		"dud-client-test",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("install script missing %q", needle)
		}
	}
}
