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
		"DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN DUD_CA_BUNDLE DUD_CONNECT_TO",
		"DUD_DOCKER_NETWORK",
		"/tmp/dud-stdin:ro",
		"dud-client-test",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("shell init missing %q", needle)
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
