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

// TestMain drops the ambient DUD_* configuration before any test runs, the same
// way tests/clean-env.mjs does for the Node suites. These variables reach peer
// commands as well as dead drops, so a developer shell that exports
// DUD_BASE_URL could otherwise send a test at the wrong origin — and a command
// that then loses its stubbed state can fall through to an interactive prompt,
// which blocks on /dev/tty instead of failing.
func TestMain(m *testing.M) {
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		// DUD_UPDATE_VECTORS and the DUD_TEST_* variables switch the harness
		// rather than configure a client. Scrubbing them would silently ignore
		// the documented way to regenerate the frozen wire corpus, and would
		// turn a fixture the Node suite passes in here into a skip that still
		// reports success.
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

// On the dead drop routes any HTTP status of 400 or more reaches the shell as
// exit 22.
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
	// An alias pair must fail identically, so the transport has to fail
	// identically too — and never reach a real resolver from a unit test.
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return nil, errors.New("transport unavailable")
	}
	return a.main(args), stdout.String(), stderr.String()
}
