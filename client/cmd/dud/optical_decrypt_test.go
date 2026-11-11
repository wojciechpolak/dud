// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
)

func encryptedOpticalTestFile(t *testing.T, encoded []byte, recipient age.Recipient) string {
	t.Helper()
	var cipher bytes.Buffer
	writer, err := age.Encrypt(&cipher, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "saved.age")
	if err := os.WriteFile(path, cipher.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func encodeOpticalTestPayload(t *testing.T, payload []byte, kind drop.PayloadType) []byte {
	t.Helper()
	metadata := capsule.Metadata{Type: kind, DisplayName: "private-name"}
	if kind == drop.PayloadCollection {
		metadata.ArchiveFormat = drop.ArchiveTar
	}
	encoded, err := capsule.Encode(payload, metadata)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestOpticalDecryptRejectsUsageBeforeLocalOrNetworkWork(t *testing.T) {
	cases := [][]string{
		{}, {"--file", "missing"}, {"--file", "missing", "--out", "a", "--stdout"},
		{"--file", "missing", "--extract", "--stdout"}, {"--file", "missing", "--extract", "--out", "a"},
		{"--file", "missing", "--out-dir", "a"}, {"--file", "missing", "--stdout"},
		{"--file", "missing", "--out", "a", "--id", ""}, {"--file", "missing", "--out", "a", "--url", "ambient"},
		{"--file", "missing", "--out", "a", "--doh-url", "ambient"}, {"--file", "missing", "--out", ""},
		{"--file", "missing", "--extract", "--out-dir", ""}, {"--file", "missing", "--out", "a", "--identity", ""},
		{"--file", "missing", "--out", "a", "--file", "missing"}, {"--file", "", "--file", "missing", "--out", "a"},
		{"--file"}, {"--optical"}, {"--optical-profile", "balanced"}, {"--ttl", "24h"}, {"--no-qr"}, {"--json"},
	}
	for _, flags := range cases {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			a, renderer, out, _ := newOpticalTestApp(t, "")
			a.in = opticalUnreadableInput{t}
			a.cfg.AgeBin = "/missing-age"
			err := a.run(append([]string{"optical", "decrypt", "--json"}, flags...))
			if err == nil || opticalJSON(t, out)["error"].(map[string]any)["code"] != "usage" {
				t.Fatal("usage accepted", err, out.String())
			}
			if renderer.called {
				t.Fatal("download opened a renderer")
			}
			assertOpticalCleanup(t)
		})
	}
	if opticalDecryptFlagPresent([]string{"--out", "--optical"}, "--optical") || opticalDecryptFlagPresent([]string{"-i", "--json"}, "--json") {
		t.Fatal("flag value treated as selection")
	}
	if _, err := parseDownloadOptions([]string{"--id", "id", "--file", "path", "--stdout"}, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := validateDownloadOptions(downloadOptions{id: "id", outputStdout: true, explicitFlags: map[string]bool{"--file": true}}); err == nil {
		t.Fatal("HTTP download accepted local file")
	}
	a, _, _, _ := newOpticalTestApp(t, "")
	a.in = opticalUnreadableInput{t}
	if err := a.run([]string{"receive", "laptop", "--optical"}); err == nil {
		t.Fatal("peer accepted optical")
	}
}

func TestOpticalDecryptRecoversNativeEncryptionAndAllOutputKinds(t *testing.T) {
	ageBin := opticalTestAge(t)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	h, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s, err := age.NewScryptRecipient(opticalTestPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	s.SetWorkFactor(10)
	for _, test := range []struct {
		name      string
		recipient age.Recipient
		identity  string
	}{
		{"passphrase", s, ""}, {"x25519", x.Recipient(), x.String()}, {"hybrid", h.Recipient(), h.String()},
	} {
		for _, kind := range []drop.PayloadType{drop.PayloadMessage, drop.PayloadStream, drop.PayloadFile, drop.PayloadCollection} {
			t.Run(test.name+string(rune('0'+kind)), func(t *testing.T) {
				payload := []byte("exact private bytes\x00\xff")
				if kind == drop.PayloadCollection {
					payload = opticalTestArchive(t, []tar.Header{{Name: "folder", Typeflag: tar.TypeDir, Mode: 0o700}, {Name: "folder/file", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4}, {Name: "exec", Typeflag: tar.TypeReg, Mode: 0o4755, Size: 4}})
				}
				source := encryptedOpticalTestFile(t, encodeOpticalTestPayload(t, payload, kind), test.recipient)
				identityArgs := []string{}
				if test.identity != "" {
					path := filepath.Join(t.TempDir(), "key")
					if err := os.WriteFile(path, []byte(test.identity), 0o600); err != nil {
						t.Fatal(err)
					}
					identityArgs = []string{"--identity", path}
				}
				modes := []string{"out", "stdout"}
				if kind == drop.PayloadCollection {
					modes = append(modes, "extract")
				}
				for _, mode := range modes {
					a, _, out, diagnostics := newOpticalTestApp(t, "")
					a.cfg.AgeBin = ageBin
					a.cfg.DropBaseURL = "invalid ambient"
					a.cfg.DOHURL = "invalid ambient"
					args := append([]string{"optical", "decrypt", "--file", source}, identityArgs...)
					destination := filepath.Join(t.TempDir(), "result")
					switch mode {
					case "out":
						args = append(args, "--out", destination, "--json")
					case "stdout":
						args = append(args, "--stdout")
					case "extract":
						args = append(args, "--extract", "--out-dir", destination, "--json")
					}
					if err := a.run(args); err != nil {
						t.Fatal(err)
					}
					if mode == "stdout" {
						if !bytes.Equal(out.Bytes(), payload) {
							t.Fatal("stdout differs")
						}
					} else {
						report := opticalJSON(t, out)
						if report["status"] != "recovered" || report["operation"] != "decrypt" || report["output"] != destination || len(report) != 5 {
							t.Fatal(report)
						}
						path := destination
						expected := payload
						permissions := os.FileMode(0o600)
						if mode == "extract" {
							path = filepath.Join(destination, "folder/file")
							expected = []byte("data")
							permissions = 0o644
							executable, _ := os.Stat(filepath.Join(destination, "exec"))
							if executable.Mode().Perm() != 0o755 {
								t.Fatal("executable permissions", executable.Mode())
							}
						}
						actual, err := os.ReadFile(path)
						if err != nil || !bytes.Equal(actual, expected) {
							t.Fatal("file differs", err)
						}
						info, err := os.Stat(path)
						if err != nil || info.Mode().Perm() != permissions {
							t.Fatal("permissions differ", err)
						}
					}
					if diagnostics.Len() != 0 || a.cfg.DOHURL != "invalid ambient" {
						t.Fatal("diagnostic or DNS side effect")
					}
					assertOpticalCleanup(t)
				}
			})
		}
	}
}

func opticalTestArchive(t *testing.T, headers []tar.Header) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := tar.NewWriter(&out)
	for _, header := range headers {
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write(bytes.Repeat([]byte("data"), int(header.Size)/4)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestOpticalDecryptValidationFailuresEmitNoPayload(t *testing.T) {
	ageBin := opticalTestAge(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(key, []byte(identity.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := encodeOpticalTestPayload(t, []byte("private bytes"), drop.PayloadFile)
	cases := []struct {
		name, code string
		mutate     func([]byte) []byte
	}{
		{"truncated", "capsule", func(b []byte) []byte { return b[:len(b)-1] }},
		{"trailing", "capsule", func(b []byte) []byte { return append(b, 1) }},
		{"digest", "capsule", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
		{"length", "capsule", func(b []byte) []byte { binary.BigEndian.PutUint64(b[16:24], 99); return b }},
		{"type", "capsule", func(b []byte) []byte { b[9] = 99; return b }},
		{"name", "capsule", func(b []byte) []byte { b[64] = '/'; return b }},
		{"UTF8", "capsule", func(b []byte) []byte { b[64] = 255; return b }},
		{"reserved", "capsule", func(b []byte) []byte { b[11] = 1; return b }},
		{"version", "unsupported-format", func(b []byte) []byte { b[8] = 0; return b }},
		{"magic", "unsupported-format", func(b []byte) []byte { b[0] = 0; return b }},
		{"archive", "archive", func(b []byte) []byte { return encodeOpticalTestPayload(t, []byte("not tar"), drop.PayloadCollection) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			source := encryptedOpticalTestFile(t, test.mutate(bytes.Clone(valid)), identity.Recipient())
			for _, stdout := range []bool{false, true} {
				a, _, out, diagnostics := newOpticalTestApp(t, "")
				a.cfg.AgeBin = ageBin
				destination := filepath.Join(t.TempDir(), "result")
				args := []string{"optical", "decrypt", "--file", source, "-i", key}
				if stdout {
					args = append(args, "--stdout")
				} else {
					args = append(args, "--out", destination, "--json")
				}
				err := a.run(args)
				var failure *opticalCommandError
				if !errors.As(err, &failure) || failure.Code != test.code {
					t.Fatal("incorrect error", err)
				}
				if stdout && out.Len() != 0 {
					t.Fatal("failed capsule emitted plaintext")
				}
				if !stdout {
					report := opticalJSON(t, out)
					if len(report) != 5 || report["status"] != "failed" {
						t.Fatal(report)
					}
				}
				if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed capsule created output")
				}
				if diagnostics.Len() != 0 || strings.Contains(out.String(), "private-name") {
					t.Fatal("private diagnostics")
				}
				assertOpticalCleanup(t)
			}
		})
	}
}

func TestOpticalOutputAndExtractionRejectCollisionsBeforeWriting(t *testing.T) {
	valid := opticalTestArchive(t, []tar.Header{{Name: "new", Typeflag: tar.TypeReg, Size: 4}, {Name: "Dir/file", Typeflag: tar.TypeReg, Size: 4}})
	for _, variant := range []string{"file", "symlink", "case", "directory"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			existing := filepath.Join(root, "Dir")
			switch variant {
			case "file":
				if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), existing); err != nil {
					t.Fatal(err)
				}
			case "case":
				if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(existing, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := extractOpticalCollection(valid, root); err == nil {
				t.Fatal("collision accepted")
			}
			if _, err := os.Lstat(filepath.Join(root, "new")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("wrote before collision validation")
			}
		})
	}
	destination := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeOpticalFile(destination, []byte("replacement")); err == nil {
		t.Fatal("overwrote file")
	}
	body, _ := os.ReadFile(destination)
	if string(body) != "original" {
		t.Fatal("changed existing output")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(destination, link); err != nil {
		t.Fatal(err)
	}
	if err := writeOpticalFile(link, []byte("replacement")); err == nil {
		t.Fatal("followed output symlink")
	}
	writer := opticalPlaintextWriter{writer: io.Discard, remaining: 3}
	if _, err := writer.Write([]byte("four")); err == nil {
		t.Fatal("unbounded plaintext staging")
	}
}

func TestOpticalDecryptBoundsAuthenticationAndIdentityFailures(t *testing.T) {
	ageBin := opticalTestAge(t)
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	source := encryptedOpticalTestFile(t, encodeOpticalTestPayload(t, nil, drop.PayloadFile), x.Recipient())
	for _, test := range []struct {
		name, code string
		prepare    func(string) string
	}{
		{"missing", "input", func(_ string) string { return "/missing-optical-capsule" }},
		{"directory", "input", func(_ string) string { return t.TempDir() }},
		{"empty", "ciphertext-limit", func(path string) string {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"oversize", "ciphertext-limit", func(path string) string {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, optical.MaxCapsuleSize+1); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"authentication", "decryption", func(path string) string {
			body, _ := os.ReadFile(source)
			body[len(body)-1] ^= 1
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, _, out, _ := newOpticalTestApp(t, "")
			a.cfg.AgeBin = ageBin
			path := test.prepare(filepath.Join(t.TempDir(), "source"))
			err := a.run([]string{"optical", "decrypt", "--file", path, "--out", filepath.Join(t.TempDir(), "output"), "--json"})
			if err == nil || opticalJSON(t, out)["error"].(map[string]any)["code"] != test.code {
				t.Fatal(err, out.String())
			}
			assertOpticalCleanup(t)
		})
	}
	for _, body := range []string{"AGE-PLUGIN-TEST-secret", "not an identity"} {
		key := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(key, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		a, _, out, _ := newOpticalTestApp(t, "")
		a.cfg.AgeBin = "/missing-age"
		if err := a.run([]string{"optical", "decrypt", "--file", source, "--identity", key, "--out", "unused", "--json"}); err == nil || opticalJSON(t, out)["error"].(map[string]any)["code"] != "decryption" {
			t.Fatal(err, out.String())
		}
		assertOpticalCleanup(t)
	}
}

func opticalTestIdentityArgs(t *testing.T, identity string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(path, []byte(identity), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"--identity", path}
}

func TestOpticalExtractionDefaultsToWorkingDirectoryAndReportsOutputFailures(t *testing.T) {
	t.Chdir(t.TempDir())
	a, _, out, _ := newOpticalTestApp(t, "")
	body := opticalTestArchive(t, []tar.Header{{Name: "file", Typeflag: tar.TypeReg, Size: 4}})
	destination, err := a.writeOpticalPayload(downloadOptions{extract: true}, capsule.Metadata{Type: drop.PayloadCollection}, body)
	cwd, _ := os.Getwd()
	if err != nil || destination != cwd {
		t.Fatal("default extraction root", destination, err)
	}
	actual, err := os.ReadFile("file")
	if err != nil || string(actual) != "data" {
		t.Fatal("default extraction content", err)
	}
	if _, err := a.writeOpticalPayload(downloadOptions{extract: true}, capsule.Metadata{Type: drop.PayloadFile}, nil); err == nil {
		t.Fatal("extracted noncollection")
	}
	if _, err := a.writeOpticalPayload(downloadOptions{out: filepath.Join(t.TempDir(), "missing", "file")}, capsule.Metadata{}, nil); err == nil {
		t.Fatal("ignored output failure")
	}
	if out.Len() != 0 {
		t.Fatal("payload helper emitted report")
	}
}

func TestOpticalDecryptAuthenticatesCompleteCiphertextBeforeOutput(t *testing.T) {
	ageBin := opticalTestAge(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	source := encryptedOpticalTestFile(t, encodeOpticalTestPayload(t, []byte("authenticated private payload"), drop.PayloadFile), identity.Recipient())
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(body []byte) []byte { body[len(body)-1] ^= 1; return body },
		func(body []byte) []byte { return body[:len(body)-1] },
		func(body []byte) []byte { return append(body, 0) },
	} {
		damaged := filepath.Join(t.TempDir(), "damaged.age")
		if err := os.WriteFile(damaged, mutate(bytes.Clone(original)), 0o600); err != nil {
			t.Fatal(err)
		}
		a, _, out, _ := newOpticalTestApp(t, "")
		a.cfg.AgeBin = ageBin
		args := append([]string{"optical", "decrypt", "--file", damaged, "--stdout"}, opticalTestIdentityArgs(t, identity.String())...)
		err := a.run(args)
		var failure *opticalCommandError
		if !errors.As(err, &failure) || failure.Code != "decryption" || out.Len() != 0 {
			t.Fatal("corrupt ciphertext emitted output", err)
		}
		assertOpticalCleanup(t)
	}
}
