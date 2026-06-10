// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "testing"

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
