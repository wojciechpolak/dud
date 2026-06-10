// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "testing"

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
