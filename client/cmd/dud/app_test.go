// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestMain removes ambient DUD_* configuration before tests run. Peer and dead
// drop commands read these variables. A developer shell that exports
// DUD_BASE_URL could send a test to the wrong origin. A command that bypasses
// its stubbed state can then fall through to an interactive prompt and block
// on /dev/tty instead of failing.
func TestMain(m *testing.M) {
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		// DUD_UPDATE_VECTORS and DUD_TEST_* control the test harness, not the
		// client. Removing them could skip a supplied fixture or prevent wire
		// vector regeneration while still reporting success.
		if ok && strings.HasPrefix(name, "DUD_") &&
			name != "DUD_UPDATE_VECTORS" && !strings.HasPrefix(name, "DUD_TEST_") {
			os.Unsetenv(name)
		}
	}
	os.Exit(m.Run())
}

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
	ageMock := filepath.Join(dir, "age-mock.sh")
	if err := os.WriteFile(ageMock, []byte("#!/bin/sh\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	a, _, _, stderr := newDropTestApp(t, "")
	a.cfg.AgeBin = ageMock

	code := a.main([]string{"upload", "--passphrase", "-m", "hello", "--json"})
	if code != 7 {
		t.Fatalf("main returned %d, want age's exit code 7", code)
	}
	if strings.Contains(stderr.String(), "exit status") {
		t.Fatalf("stderr leaks Go error text: %q", stderr.String())
	}
}

// Dead drop route failures with an HTTP status of 400 or more exit with 22.
func TestAppMainMapsHTTPFailureStatusesToExitCode22(t *testing.T) {
	for _, status := range []int{400, 401, 404, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			a, transport, _, stderr := newDropTestApp(t, "")
			transport.respond = func(recordedDropRequest) (*v2Response, error) {
				return &v2Response{StatusCode: status}, nil
			}
			if code := a.main([]string{"flush"}); code != 22 {
				t.Fatalf("main returned %d for HTTP %d, want 22", code, status)
			}
			if !strings.Contains(stderr.String(), "The requested URL returned error: "+strconv.Itoa(status)) {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
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

func TestAliasPairsHaveIdenticalDispatchOutputAndExitCodes(t *testing.T) {
	setTestV2Homes(t)
	tests := []struct {
		name  string
		left  []string
		right []string
	}{
		{
			name:  "legacy upload and send",
			left:  []string{"upload", "--passphrase"},
			right: []string{"send", "--passphrase"},
		},
		{
			name:  "peer upload and send",
			left:  []string{"upload", "laptop", "--message", "hello"},
			right: []string{"send", "laptop", "--message", "hello"},
		},
		{
			name:  "legacy download and receive",
			left:  []string{"download", "--id", "abcd", "--stdout"},
			right: []string{"receive", "--id", "abcd", "--stdout"},
		},
		{
			name:  "peer download and receive",
			left:  []string{"download", "laptop"},
			right: []string{"receive", "laptop"},
		},
		{
			name:  "legacy git push and send",
			left:  []string{"git", "push", "--unknown"},
			right: []string{"git", "send", "--unknown"},
		},
		{
			name:  "peer git push and send",
			left:  []string{"git", "push", "laptop"},
			right: []string{"git", "send", "laptop"},
		},
		{
			name:  "legacy git fetch and receive",
			left:  []string{"git", "fetch", "--unknown"},
			right: []string{"git", "receive", "--unknown"},
		},
		{
			name:  "peer git fetch and receive",
			left:  []string{"git", "fetch", "laptop"},
			right: []string{"git", "receive", "laptop"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leftCode, leftOut, leftErr := runAliasInvocation(tt.left)
			rightCode, rightOut, rightErr := runAliasInvocation(tt.right)
			if leftCode != rightCode || leftOut != rightOut || leftErr != rightErr {
				t.Fatalf(
					"alias mismatch:\nleft  code=%d stdout=%q stderr=%q\nright code=%d stdout=%q stderr=%q",
					leftCode,
					leftOut,
					leftErr,
					rightCode,
					rightOut,
					rightErr,
				)
			}
		})
	}
}

func runAliasInvocation(args []string) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.cfg.SecretToken = ""
	a.cfg.GitBin = "/bin/false"
	// An alias pair must produce identical failures. Unit tests must not reach a
	// real resolver.
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return nil, errors.New("transport unavailable")
	}
	return a.main(args), stdout.String(), stderr.String()
}
