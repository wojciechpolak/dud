// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func writePassthroughAge(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "age-passthrough.sh")
	script := `#!/bin/sh
out=""
input=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2; continue ;;
    -R) shift 2; continue ;;
    -*) shift; continue ;;
  esac
  input="$1"
  shift
done
cp "$input" "$out"
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpticalInputBuildsContainerBeforeAgeEncryption(t *testing.T) {
	file := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(file, []byte("file payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		opts     options
		wantType drop.PayloadType
		wantName string
		wantBody string
	}{
		{
			name:     "passphrase message",
			opts:     options{message: "hello", passphrase: true},
			wantType: drop.PayloadMessage, wantName: "message.txt", wantBody: "hello",
		},
		{
			name:     "X25519 file",
			opts:     options{files: stringListFlag{file}, recipients: stringListFlag{"age1examplex25519recipient"}},
			wantType: drop.PayloadFile, wantName: "report.txt", wantBody: "file payload",
		},
		{
			name:     "hybrid post-quantum file",
			opts:     options{files: stringListFlag{file}, recipients: stringListFlag{"age1pq1examplehybridrecipient"}},
			wantType: drop.PayloadFile, wantName: "report.txt", wantBody: "file payload",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.opts.ageBin = writePassthroughAge(t)
			ciphertext, err := loadOpticalCiphertext(test.opts, &bytes.Buffer{}, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			metadata, payload, err := capsule.Decode(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Type != test.wantType || metadata.DisplayName != test.wantName || string(payload) != test.wantBody {
				t.Fatalf("container = %#v, %q", metadata, payload)
			}
		})
	}
}

func TestOpticalInputBuildsCollectionArchiveInsideContainer(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.txt")
	second := filepath.Join(root, "second.txt")
	if err := os.WriteFile(first, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := options{
		files: stringListFlag{first, second}, recipients: stringListFlag{"age1example"}, ageBin: writePassthroughAge(t),
	}
	ciphertext, err := loadOpticalCiphertext(opts, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	metadata, payload, err := capsule.Decode(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Type != drop.PayloadCollection || metadata.ArchiveFormat != drop.ArchiveTar || metadata.DisplayName != "dud-collection.tar" {
		t.Fatalf("metadata = %#v", metadata)
	}
	archive := filepath.Join(t.TempDir(), "collection.tar")
	if err := os.WriteFile(archive, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	listing, err := exec.Command("tar", "-tf", archive).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first.txt", "second.txt"} {
		if !strings.Contains(string(listing), name) {
			t.Fatalf("archive omitted %q: %s", name, listing)
		}
	}
}

func TestOpticalCiphertextMustPassCompleteSizeBoundBeforeEncoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.age")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(optical.MaxCapsuleSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = loadOpticalCiphertext(options{ciphertextFile: path}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "1..64 MiB") {
		t.Fatalf("error = %v", err)
	}
}

func TestOpticalCiphertextModeRejectsPlaintextAndEncryptionOptions(t *testing.T) {
	_, err := loadOpticalCiphertext(options{ciphertextFile: "capsule.age", message: "secret"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("error = %v", err)
	}
}

func TestDefaultRepairOverheadMatchesFastestPhysicalRun(t *testing.T) {
	if display.DefaultRepairOverhead != 25 {
		t.Fatalf("default repair overhead=%d, want 25", display.DefaultRepairOverhead)
	}
}

func TestDefaultCarrierMatchesSelectedHighRateProfile(t *testing.T) {
	if defaultQRVersion != 40 || defaultBlockSize != 2860 || defaultFramesPerSecond != 60 || display.DefaultRepairOverhead != 25 {
		t.Fatalf(
			"defaults = version %d, block %d, fps %d, repair %d",
			defaultQRVersion,
			defaultBlockSize,
			defaultFramesPerSecond,
			display.DefaultRepairOverhead,
		)
	}
}
