// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package drop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestPrepareInputCoversEveryDeadDropSource(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "report.txt")
	if err := os.WriteFile(file, []byte("file body"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "docs")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "readme.txt"), []byte("archive body"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		opts        InputOptions
		stdin       string
		wantPayload string
		wantType    PayloadType
		wantName    string
		wantArchive ArchiveFormat
		wantBundle  bool
	}{
		{name: "message", opts: InputOptions{Message: "hello"}, wantPayload: "hello", wantType: PayloadMessage, wantName: "message.txt"},
		{name: "stdin", stdin: "stream body", wantPayload: "stream body", wantType: PayloadStream, wantName: "stdin.bin"},
		{name: "file", opts: InputOptions{Files: []string{file}}, wantPayload: "file body", wantType: PayloadFile, wantName: "report.txt"},
		{name: "collection", opts: InputOptions{Files: []string{file, directory}}, wantType: PayloadCollection, wantName: "dud-collection.tar", wantArchive: ArchiveTar, wantBundle: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "prepared")
			prepared, err := PrepareInput(target, test.opts, InputEnvironment{
				Stdin: strings.NewReader(test.stdin), Stderr: &bytes.Buffer{}, CommandOutput: &bytes.Buffer{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Type != test.wantType || prepared.DisplayName != test.wantName ||
				prepared.ArchiveFormat != test.wantArchive || prepared.Bundle != test.wantBundle {
				t.Fatalf("prepared input = %#v", prepared)
			}
			if test.wantBundle {
				listing, err := exec.Command("tar", "-tf", target).Output()
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"report.txt", "docs/readme.txt"} {
					if !strings.Contains(string(listing), name) {
						t.Fatalf("archive omitted %q: %s", name, listing)
					}
				}
				return
			}
			payload, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) != test.wantPayload {
				t.Fatalf("payload = %q, want %q", payload, test.wantPayload)
			}
		})
	}
}

func TestPrepareCollectionPreservesLeadingDashNames(t *testing.T) {
	for _, limit := range []int64{0, 64 * 1024} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			root := t.TempDir()
			contents := map[string]string{
				"--exclude=foo": "literal exclude filename", "foo": "included payload",
				"-C": "literal directory option", "--": "literal separator", "-": "literal dash",
				"@archive":      "literal archive import filename",
				"-folder/-leaf": "nested payload",
			}
			for name, body := range contents {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var sources []string
			for _, name := range []string{"--exclude=foo", "foo", "-C", "--", "-", "-folder", "@archive"} {
				sources = append(sources, filepath.Join(root, name))
			}
			target := filepath.Join(t.TempDir(), "archive")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			var diagnostics bytes.Buffer
			if _, err := PrepareInput(target, InputOptions{Files: sources}, InputEnvironment{
				Stderr: &diagnostics, CommandOutput: io.Discard, MaxBytes: limit,
			}); err != nil {
				t.Fatalf("prepare literal filenames: %v: %s", err, diagnostics.String())
			}
			destination := t.TempDir()
			if output, err := exec.Command("tar", "-xf", target, "-C", destination).CombinedOutput(); err != nil {
				t.Fatalf("extract prepared collection: %v: %s", err, output)
			}
			for name, want := range contents {
				body, err := os.ReadFile(filepath.Join(destination, name))
				if err != nil || string(body) != want {
					t.Fatalf("collection changed %q: %q, %v", name, body, err)
				}
			}
		})
	}
}

func TestEncryptFileCoversPassphraseAndRecipientKinds(t *testing.T) {
	x25519Identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybridIdentity, err := age.ParseHybridIdentity("AGE-SECRET-KEY-PQ-1TNKN5N7GU6X7H46D69HMCT89GWQ5P3MVC2YA8RA0EXFWCYQ6L3QQELH8KS")
	if err != nil {
		t.Fatal(err)
	}
	x25519 := x25519Identity.Recipient().String()
	hybrid := hybridIdentity.Recipient().String()
	tests := []struct {
		name       string
		opts       EncryptionOptions
		passphrase bool
		want       []string
	}{
		{name: "passphrase", passphrase: true},
		{name: "X25519", opts: EncryptionOptions{InlineRecipients: []string{x25519}}, want: []string{x25519}},
		{name: "hybrid post-quantum", opts: EncryptionOptions{InlineRecipients: []string{hybrid}}, want: []string{hybrid}},
		{name: "mixed recipients", opts: EncryptionOptions{InlineRecipients: []string{x25519, hybrid}}, want: []string{x25519, hybrid}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			input := filepath.Join(directory, "input")
			output := filepath.Join(directory, "output")
			if err := os.WriteFile(input, []byte("capsule"), 0o600); err != nil {
				t.Fatal(err)
			}
			var args []string
			var recipientBody string
			run := func(values ...string) error {
				args = append([]string(nil), values...)
				for index := 0; index+1 < len(values); index++ {
					if values[index] == "-R" {
						body, err := os.ReadFile(values[index+1])
						if err != nil {
							return err
						}
						recipientBody += string(body)
					}
				}
				return os.WriteFile(output, []byte("same opaque ciphertext"), 0o600)
			}
			createTemp := func(pattern string) (string, error) {
				file, err := os.CreateTemp(directory, pattern)
				if err != nil {
					return "", err
				}
				name := file.Name()
				return name, file.Close()
			}
			if err := EncryptFile(input, output, test.opts, run, createTemp, func(path string) { _ = os.Remove(path) }); err != nil {
				t.Fatal(err)
			}
			if test.passphrase {
				if !containsArgument(args, "--passphrase") || recipientBody != "" {
					t.Fatalf("age args = %q, recipients = %q", args, recipientBody)
				}
			} else {
				if containsArgument(args, "--passphrase") {
					t.Fatalf("recipient encryption used a passphrase: %q", args)
				}
				if recipientBody != strings.Join(test.want, "\n")+"\n" {
					t.Fatalf("recipient file = %q", recipientBody)
				}
			}
			ciphertext, err := os.ReadFile(output)
			if err != nil || string(ciphertext) != "same opaque ciphertext" {
				t.Fatalf("ciphertext = %q, %v", ciphertext, err)
			}
		})
	}
}

func containsArgument(args []string, want string) bool {
	for _, argument := range args {
		if argument == want {
			return true
		}
	}
	return false
}

func TestBoundedInputPreparationStopsStreamsFilesAndCollections(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "file")
	if err := os.WriteFile(source, bytes.Repeat([]byte{1}, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []InputOptions{{Message: strings.Repeat("x", 129)}, {}, {Files: []string{source}}, {Files: []string{root}}} {
		target := filepath.Join(t.TempDir(), "prepared")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := PrepareInput(target, opts, InputEnvironment{Stdin: strings.NewReader(strings.Repeat("x", 129)), Stderr: io.Discard, CommandOutput: io.Discard, MaxBytes: 128})
		if !errors.Is(err, ErrInputLimit) {
			t.Fatalf("limit not enforced: %v", err)
		}
		info, err := os.Stat(target)
		if err != nil || info.Size() > 128 {
			t.Fatal("staged more than the bound")
		}
	}
}

func TestPrepareCollectionHonorsCancellation(t *testing.T) {
	for _, limit := range []int64{0, 1024} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			target := filepath.Join(t.TempDir(), "prepared")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := PrepareInput(target, InputOptions{Files: []string{t.TempDir()}}, InputEnvironment{
				Context: ctx, Stderr: io.Discard, CommandOutput: io.Discard, MaxBytes: limit,
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("archive preparation ignored cancellation: %v", err)
			}
		})
	}
}
