// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseUploadResponse(t *testing.T) {
	response, err := parseUploadResponse(
		[]byte(`{"id":"abc","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":true}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if response.ID != "abc" || response.ExpiresAt == "" || !response.DeleteAfterRead {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestParseUploadResponseRejectsInvalidShape(t *testing.T) {
	_, err := parseUploadResponse([]byte(`{"id":"abc"}`))
	if err == nil || !strings.Contains(err.Error(), "unexpected JSON response") {
		t.Fatalf("expected unexpected JSON response error, got %v", err)
	}
}

func TestBuildReceiveCommand(t *testing.T) {
	got := buildReceiveCommand("dud receive", "abc", "https://dud.example.com", true)
	want := "dud receive --id abc --url https://dud.example.com --extract"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseUploadOptions(t *testing.T) {
	opts, err := parseUploadOptions(
		[]string{"--file", "a.txt", "--recipient", "age1abc", "--ttl", "48h", "--json", "--no-qr", "--url", "https://alt.example.com", "--doh-url", "https://resolver.example.com/dns-query"},
		"https://dud.example.com",
		"https://cloudflare-dns.com/dns-query",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.files) != 1 || opts.files[0] != "a.txt" {
		t.Fatalf("files = %#v", opts.files)
	}
	if len(opts.inlineRecipients) != 1 || opts.inlineRecipients[0] != "age1abc" {
		t.Fatalf("inlineRecipients = %#v", opts.inlineRecipients)
	}
	if opts.ttl != "48h" || !opts.outputJSON || opts.outputQR || opts.baseURL != "https://alt.example.com" || opts.dohURL != "https://resolver.example.com/dns-query" {
		t.Fatalf("unexpected options: %#v", opts)
	}
}

func TestValidateUploadOptionsRejectsConflictingSources(t *testing.T) {
	err := validateUploadOptions(uploadOptions{
		files:   []string{"a.txt"},
		message: "hello",
	}, config{SecretToken: "top-secret"})
	if err == nil || err.Error() != "upload accepts only one source: --file, -m, or stdin" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUploadOptionsRejectsPassphraseAndRecipients(t *testing.T) {
	err := validateUploadOptions(uploadOptions{
		passphraseRequested: true,
		inlineRecipients:    []string{"age1abc"},
	}, config{SecretToken: "top-secret"})
	if err == nil || err.Error() != "upload accepts either --passphrase or recipient options, not both" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUploadOptionParserAndValidationCoverRemainingModes(t *testing.T) {
	opts, err := parseUploadOptions([]string{"-m", "hello", "--passphrase", "--delete-after-read"}, "base", "doh")
	if err != nil || opts.message != "hello" || !opts.passphraseRequested || !opts.deleteAfterRead {
		t.Fatalf("options = %#v, %v", opts, err)
	}
	for _, args := range [][]string{{"--file"}, {"-m"}, {"--ttl"}, {"--recipient"}, {"--recipient-file"}, {"--url"}, {"--doh-url"}, {"--json", "--json"}, {"--wat"}} {
		if _, err := parseUploadOptions(args, "base", "doh"); err == nil {
			t.Fatalf("options accepted: %v", args)
		}
	}
	if err := validateUploadOptions(uploadOptions{recipientsFile: "/missing"}, config{SecretToken: "token"}); err == nil {
		t.Fatal("missing recipient file accepted")
	}
	if err := validateUploadOptions(uploadOptions{}, config{}); err == nil {
		t.Fatal("missing secret token accepted")
	}
	file := filepath.Join(t.TempDir(), "recipients")
	if err := os.WriteFile(file, []byte("age1test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateUploadOptions(uploadOptions{recipientsFile: file}, config{SecretToken: "token"}); err != nil {
		t.Fatal(err)
	}
}
