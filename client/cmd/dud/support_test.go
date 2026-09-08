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
	t.Setenv("DUD_DROP_BASE_URL", "")
	t.Setenv("DUD_PEER_BASE_URL", "")
	t.Setenv("DUD_DOH_URL", "")
	t.Setenv("DUD_ECH_MODE", "")
	t.Setenv("DUD_IMAGE", "")

	cfg := loadConfig()
	if cfg.DropBaseURL != "https://dud.example.com" || cfg.PeerBaseURL != "https://dud.example.com" {
		t.Fatalf("base URLs = %q, %q", cfg.DropBaseURL, cfg.PeerBaseURL)
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

func TestLoadConfigSeparatesModeBaseURLs(t *testing.T) {
	tests := []struct {
		name     string
		shared   string
		drop     string
		peer     string
		wantDrop string
		wantPeer string
	}{
		{
			name:     "shared fallback",
			shared:   "https://shared.example.com",
			wantDrop: "https://shared.example.com",
			wantPeer: "https://shared.example.com",
		},
		{
			name:     "drop only",
			drop:     "https://drop.example.com",
			wantDrop: "https://drop.example.com",
			wantPeer: v2DefaultBaseURL,
		},
		{
			name:     "peer only",
			peer:     "https://peer.example.com",
			wantDrop: v2DefaultBaseURL,
			wantPeer: "https://peer.example.com",
		},
		{
			name:     "mode variables outrank shared fallback",
			shared:   "https://shared.example.com",
			drop:     "https://drop.example.com",
			peer:     "https://peer.example.com",
			wantDrop: "https://drop.example.com",
			wantPeer: "https://peer.example.com",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(dudBaseURLEnvironment, test.shared)
			t.Setenv(dudDropBaseURLEnvironment, test.drop)
			t.Setenv(dudPeerBaseURLEnvironment, test.peer)
			cfg := loadConfig()
			if cfg.DropBaseURL != test.wantDrop || cfg.PeerBaseURL != test.wantPeer {
				t.Fatalf("base URLs = %q, %q, want %q, %q", cfg.DropBaseURL, cfg.PeerBaseURL, test.wantDrop, test.wantPeer)
			}
		})
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
