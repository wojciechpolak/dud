// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadUploadResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "response.json")
	if err := os.WriteFile(path, []byte(`{"id":"abc","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	response, err := loadUploadResponse(path)
	if err != nil {
		t.Fatal(err)
	}
	if response.ID != "abc" || response.ExpiresAt == "" || !response.DeleteAfterRead {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestLoadUploadResponseRejectsInvalidShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "response.json")
	if err := os.WriteFile(path, []byte(`{"id":"abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadUploadResponse(path)
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
