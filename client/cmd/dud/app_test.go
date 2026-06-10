// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppMainHandlesVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)

	code := a.main([]string{"--version"})
	if code != 0 {
		t.Fatalf("main returned %d", code)
	}
	if stdout.String() != version+"\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestAppMainHonorsVersionEnvOverride(t *testing.T) {
	t.Setenv("DUD_VERSION", "9.9.9")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)

	code := a.main([]string{"--version"})
	if code != 0 {
		t.Fatalf("main returned %d", code)
	}
	if stdout.String() != "9.9.9\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAppMainPropagatesSubprocessExitCode(t *testing.T) {
	dir := t.TempDir()
	curlMock := filepath.Join(dir, "curl-mock.sh")
	if err := os.WriteFile(curlMock, []byte("#!/bin/sh\nexit 22\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.cfg.SecretToken = "top-secret"
	a.cfg.CurlBin = curlMock

	code := a.main([]string{"flush"})
	if code != 22 {
		t.Fatalf("main returned %d, want curl's exit code 22", code)
	}
	if strings.Contains(stderr.String(), "exit status") {
		t.Fatalf("stderr leaks Go error text: %q", stderr.String())
	}
}

func TestAppMainUsageWithoutArgsKeepsStderrClean(t *testing.T) {
	t.Setenv("DUD_TEST_STDIN_TTY", "0")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)

	code := a.main(nil)
	if code != 1 {
		t.Fatalf("main returned %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
}

func TestAppMainHandlesUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)

	code := a.main([]string{"bogus"})
	if code != 1 {
		t.Fatalf("main returned %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "Unknown command: bogus\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
