// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsTerminalRejectsDevNull(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f.Fd()) {
		t.Fatal("expected /dev/null to not be a terminal")
	}
}

func TestTempFileHonorsTMPDIR(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	path, err := tempFile("dud-test-tmpdir-")
	if err != nil {
		t.Fatal(err)
	}
	defer removeTempFile(path)
	if filepath.Dir(path) != dir {
		t.Fatalf("temp file %q not created in TMPDIR %q", path, dir)
	}
}

func TestRemoveAllTempFilesDeletesRegisteredFiles(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	first, err := tempFile("dud-test-cleanup-")
	if err != nil {
		t.Fatal(err)
	}
	second, err := tempFile("dud-test-cleanup-")
	if err != nil {
		t.Fatal(err)
	}

	removeAllTempFiles()

	for _, path := range []string{first, second} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %q to be removed, stat err = %v", path, err)
		}
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("DUD_BASE_URL", "")
	t.Setenv("DUD_DOH_URL", "")
	t.Setenv("DUD_ECH_MODE", "")
	t.Setenv("DUD_IMAGE", "")

	cfg := loadConfig()
	if cfg.BaseURL != "https://dud.example.com" {
		t.Fatalf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.DOHURL != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("DOHURL = %q", cfg.DOHURL)
	}
	if cfg.ECHMode != "hard" {
		t.Fatalf("ECHMode = %q", cfg.ECHMode)
	}
	if cfg.Image != "ghcr.io/wojciechpolak/dud/dud-client:latest" {
		t.Fatalf("Image = %q", cfg.Image)
	}
}

func TestValidateBundleListing(t *testing.T) {
	if err := validateBundleListing([]byte("alpha.txt\ndocs/beta.txt\n")); err != nil {
		t.Fatal(err)
	}
	for _, listing := range []string{"/etc/passwd\n", "docs/../secret\n"} {
		if err := validateBundleListing([]byte(listing)); err == nil {
			t.Fatalf("expected listing %q to be rejected", listing)
		}
	}
}

func TestRunCommandReturnsSubprocessError(t *testing.T) {
	a := newApp(strings.NewReader(""), os.Stdout, os.Stderr)
	if err := a.runCommand("__dud_missing_command__", nil, nil, nil, nil); err == nil {
		t.Fatal("expected subprocess error")
	}
}
