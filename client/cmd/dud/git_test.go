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

func TestValidateGitRemoteName(t *testing.T) {
	for _, remote := range []string{"dud", "A", "origin_1", "team.remote-2"} {
		if err := validateGitRemoteName(remote); err != nil {
			t.Fatalf("expected %q to be valid: %v", remote, err)
		}
	}
	for _, remote := range []string{"", ".dud", "dud.", "a..b", "bad/name", "bad name"} {
		if err := validateGitRemoteName(remote); err == nil {
			t.Fatalf("expected %q to be invalid", remote)
		}
	}
}

func TestParseGitFetchOptionsDefaultsRemote(t *testing.T) {
	opts, err := parseGitFetchOptions(
		[]string{"--id", "abc"},
		"https://dud.example.com",
		"https://cloudflare-dns.com/dns-query",
	)
	if err != nil {
		t.Fatal(err)
	}
	if opts.remote != "dud" || opts.id != "abc" {
		t.Fatalf("unexpected options: %#v", opts)
	}
}

func TestValidateGitFetchOptionsRequiresID(t *testing.T) {
	err := validateGitFetchOptions(gitFetchOptions{remote: "dud"})
	if err == nil || err.Error() != "git fetch requires --id" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdGitFetchForceUpdatesRemoteTrackingRefs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	gitLog := filepath.Join(dir, "git.log")
	gitMock := filepath.Join(dir, "git-mock.sh")
	curlMock := filepath.Join(dir, "curl-mock.sh")
	ageMock := filepath.Join(dir, "age-mock.sh")

	if err := os.WriteFile(gitMock, []byte(`#!/bin/sh
printf '%s\n' "$@" >> "`+gitLog+`"
if [ "$1" = "rev-parse" ]; then
  printf '.git\n'
  exit 0
fi
if [ "$1" = "bundle" ] && [ "$2" = "verify" ]; then
  exit 0
fi
if [ "$1" = "ls-remote" ]; then
  printf 'abc123\trefs/heads/master\n'
  exit 0
fi
if [ "$1" = "fetch" ]; then
  exit 0
fi
exit 1
`), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(curlMock, []byte(`#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf bundle > "$output"
`), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ageMock, []byte(`#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`), 0o700); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.cfg.GitBin = gitMock
	a.cfg.CurlBin = curlMock
	a.cfg.AgeBin = ageMock

	if err := a.cmdGitFetch([]string{"--id", "abc", "--remote", "peer"}); err != nil {
		t.Fatalf("cmdGitFetch returned error: %v\nstderr: %s", err, stderr.String())
	}
	logData, err := os.ReadFile(gitLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "\n+refs/heads/*:refs/remotes/peer/*\n") {
		t.Fatalf("git fetch did not force-update remote-tracking refs:\n%s", string(logData))
	}
	if !strings.Contains(stdout.String(), "git merge --ff-only peer/master") {
		t.Fatalf("stdout missing merge hint: %q", stdout.String())
	}
}
