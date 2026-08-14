// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDownloadOptions(t *testing.T) {
	opts, err := parseDownloadOptions(
		[]string{"--id", "abc", "--stdout", "--url", "https://alt.example.com", "--doh-url", "https://resolver.example.com/dns-query"},
		"https://dud.example.com",
		"https://cloudflare-dns.com/dns-query",
	)
	if err != nil {
		t.Fatal(err)
	}
	if opts.id != "abc" || !opts.outputStdout || opts.baseURL != "https://alt.example.com" || opts.dohURL != "https://resolver.example.com/dns-query" {
		t.Fatalf("unexpected options: %#v", opts)
	}
}

func TestValidateDownloadOptionsRejectsInvalidOutputCombinations(t *testing.T) {
	err := validateDownloadOptions(downloadOptions{
		id:           "abc",
		extract:      true,
		outputStdout: true,
	})
	if err == nil || err.Error() != "download does not support --stdout with --extract" {
		t.Fatalf("unexpected error: %v", err)
	}

	err = validateDownloadOptions(downloadOptions{
		id:           "abc",
		out:          "file.txt",
		outputStdout: true,
	})
	if err == nil || err.Error() != "download accepts only one output target: --out or --stdout" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownloadOptionsCoverEveryOutputAndIdentityConstraint(t *testing.T) {
	opts, err := parseDownloadOptions([]string{"--id", "abc", "--out", "file", "--extract", "--out-dir", "dir", "--identity", "key", "--json"}, "base", "doh")
	if err != nil || opts.out != "file" || opts.outDir != "dir" || !opts.extract || !opts.outputJSON {
		t.Fatalf("options = %#v, %v", opts, err)
	}
	for _, args := range [][]string{{"--id"}, {"--out"}, {"--out-dir"}, {"--identity"}, {"--url"}, {"--doh-url"}, {"--wat"}, {"--json", "--json"}} {
		if _, err := parseDownloadOptions(args, "base", "doh"); err == nil {
			t.Fatalf("options accepted: %v", args)
		}
	}
	for _, value := range []downloadOptions{
		{}, {id: "abc", extract: true, out: "file"}, {id: "abc", extract: true, outputJSON: true, outputStdout: true}, {id: "abc", outDir: "dir"}, {id: "abc"}, {id: "abc", identity: "/missing"},
	} {
		if err := validateDownloadOptions(value); err == nil {
			t.Fatalf("invalid download options accepted: %#v", value)
		}
	}
	identity := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(identity, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateDownloadOptions(downloadOptions{id: "abc", out: "file", identity: identity}); err != nil {
		t.Fatal(err)
	}
}
