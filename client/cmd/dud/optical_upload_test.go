// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

type opticalTestRenderer struct {
	options        display.Options
	called, closed bool
	ciphertext     []byte
	fail           error
}

func (r *opticalTestRenderer) Display(_ context.Context, path string) error {
	r.called = true
	data, err := os.ReadFile(path)
	r.ciphertext = data
	if err != nil {
		return err
	}
	return r.fail
}
func (r *opticalTestRenderer) Close() error { r.closed = true; return nil }
func newOpticalTestApp(t *testing.T, input string) (*app, *opticalTestRenderer, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	a, transport, out, stderr := newDropTestApp(t, input)
	a.cfg.SecretToken = ""
	a.cfg.DropBaseURL = "bad origin"
	a.cfg.DOHURL = "bad resolver"
	a.cfg.ECHMode = "bad mode"
	a.cfg.ConnectTo = "invalid"
	a.cfg.CABundle = "/missing"
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		t.Fatal("optical constructed an HTTP/DNS transport")
		return nil, nil
	}
	t.Cleanup(func() {
		if len(transport.requests) != 0 || len(transport.options) != 0 {
			t.Fatal("optical contacted a transport")
		}
	})
	renderer := &opticalTestRenderer{}
	a.newOpticalRenderer = func(_ context.Context, options display.Options) (display.Renderer, error) {
		renderer.options = options
		return renderer, nil
	}
	return a, renderer, out, stderr
}
func assertOpticalCleanup(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(os.Getenv("TMPDIR"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "dud-optical-") || strings.HasPrefix(entry.Name(), "dud-upload-recipients-") {
			t.Fatalf("staging file retained: %s", entry.Name())
		}
	}
}
func opticalJSON(t *testing.T, out *bytes.Buffer) map[string]any {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("report %q: %v", out.String(), err)
	}
	if report["mode"] != "optical" || report["format"] != "dud/optical/1" {
		t.Fatalf("invalid optical report identity: %#v", report)
	}
	if _, exists := report["carrier"]; exists {
		t.Fatalf("optical report contains a carrier field: %#v", report)
	}
	return report
}
func TestOpticalUploadSourceContainersAndLocalReports(t *testing.T) {
	root := t.TempDir()
	one := filepath.Join(root, "one.txt")
	two := filepath.Join(root, "two.txt")
	if err := os.WriteFile(one, []byte("private file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, []byte("another file"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		args      []string
		input     string
		kind      drop.PayloadType
		nameValue string
		payload   []byte
	}{
		{"message", []string{"-m", "private message"}, "", drop.PayloadMessage, "message.txt", []byte("private message")},
		{"stream", nil, "private stream", drop.PayloadStream, "stdin.bin", []byte("private stream")},
		{"empty stream", nil, "", drop.PayloadStream, "stdin.bin", []byte{}},
		{"file", []string{"--file", one}, "", drop.PayloadFile, "one.txt", []byte("private file")},
		{"collection", []string{"--file", one, "--file", two}, "", drop.PayloadCollection, "dud-collection.tar", nil},
		{"directory", []string{"--file", root}, "", drop.PayloadCollection, "dud-collection.tar", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, r, out, _ := newOpticalTestApp(t, test.input)
			args := append([]string{"send", "--optical", "--json"}, test.args...)
			if err := a.run(args); err != nil {
				t.Fatal(err)
			}
			metadata, payload, err := capsule.Decode(r.ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Type != test.kind || metadata.DisplayName != test.nameValue {
				t.Fatalf("metadata %+v", metadata)
			}
			if test.payload != nil && !bytes.Equal(payload, test.payload) {
				t.Fatal("source bytes differ")
			}
			if !r.called || !r.closed || r.options.BlockSize != optical.HighDensityBlockSize || r.options.FPS != 60 || r.options.Settings.Version != 40 {
				t.Fatal("renderer selection or cleanup failed")
			}
			report := opticalJSON(t, out)
			if len(report) != 7 || report["status"] != "display-ended" || report["ciphertextBytes"] != float64(len(r.ciphertext)) || report["profile"] != "high-rate" || report["renderer"] != "window" {
				t.Fatalf("report %+v", report)
			}
			if a.cfg.DOHURL != "bad resolver" {
				t.Fatal("optical applied DNS configuration")
			}
			for _, secret := range []string{test.nameValue, "private", "plaintext", "recipient", "\"id\"", "expiresAt"} {
				if strings.Contains(out.String(), secret) {
					t.Fatalf("report exposes %q", secret)
				}
			}
			assertOpticalCleanup(t)
		})
	}
}

func TestOpticalCollectionPreservesLeadingDashNamesAndContents(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%t", directory), func(t *testing.T) {
			root := t.TempDir()
			contents := map[string]string{"--exclude=foo": "literal filename", "foo": "selected payload"}
			sources := []string{filepath.Join(root, "--exclude=foo"), filepath.Join(root, "foo")}
			if directory {
				contents["-folder/-leaf"] = "nested payload"
				contents["-folder/-"+strings.Repeat("long", 40)] = "long nested path"
				contents["@archive"] = "literal archive import filename"
				sources = append(sources, filepath.Join(root, "-folder"), filepath.Join(root, "@archive"))
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
			a, renderer, _, _ := newOpticalTestApp(t, "")
			args := []string{"optical", "send", "--passphrase"}
			for _, source := range sources {
				args = append(args, "--file", source)
			}
			if err := a.run(args); err != nil {
				t.Fatal(err)
			}
			metadata, payload, err := capsule.Decode(renderer.ciphertext)
			if err != nil || metadata.Type != drop.PayloadCollection {
				t.Fatalf("invalid collection capsule: %+v, %v", metadata, err)
			}
			destination := t.TempDir()
			if err := extractOpticalCollection(payload, destination); err != nil {
				t.Fatal(err)
			}
			for name, want := range contents {
				body, err := os.ReadFile(filepath.Join(destination, name))
				if err != nil || string(body) != want {
					t.Fatalf("capsule changed %q: %q, %v", name, body, err)
				}
			}
			assertOpticalCleanup(t)
		})
	}
}
func TestOpticalParserProfilesPresenceAndEarlyRejection(t *testing.T) {
	invalid := [][]string{
		{"--ttl", "24h"}, {"--delete-after-read"}, {"--url", "https://dud.example.com"}, {"--doh-url", "https://cloudflare-dns.com/dns-query"}, {"--no-qr"}, {"--id", "id"},
		{"--optical-profile", "invalid"}, {"--optical-renderer", "frames"}, {"--optical-scale", "0"}, {"--optical-scale", "17"}, {"--optical-scale", "bad"}, {"--optical-quiet-zone", "3"}, {"--optical-quiet-zone", "17"},
		{"--optical-profile"}, {"--optical-renderer"}, {"--optical-scale"}, {"--optical-quiet-zone"}, {"--json", "--json"}, {"-m", ""}, {"--file", "a", "-m", "b"}, {"--passphrase", "-r", "secret-recipient"},
	}
	for _, flags := range invalid {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			a, r, out, _ := newOpticalTestApp(t, "")
			a.in = opticalUnreadableInput{t}
			a.newOpticalRenderer = func(context.Context, display.Options) (display.Renderer, error) {
				t.Fatal("invalid options opened a renderer")
				return nil, nil
			}
			err := a.run(append([]string{"upload", "--optical", "--json"}, flags...))
			if err == nil || r.called {
				t.Fatal("invalid options accepted")
			}
			report := opticalJSON(t, out)
			if report["status"] != "failed" || report["error"].(map[string]any)["code"] != "usage" || len(report) != 5 {
				t.Fatalf("report %+v", report)
			}
			assertOpticalCleanup(t)
		})
	}
	opts, err := parseUploadOptions([]string{"--optical", "--optical-profile", "balanced", "--optical-renderer", "terminal", "--optical-scale", "1", "--optical-quiet-zone", "16"}, "ambient", "ambient")
	if err != nil || validateUploadOptions(opts, config{}) != nil {
		t.Fatal("balanced options rejected")
	}
	settings := opticalDisplayOptions(opts)
	if settings.FPS != 30 || settings.BlockSize != 1600 || settings.Side() != 338 {
		t.Fatalf("settings %+v side %d", settings, settings.Side())
	}
	for _, flag := range []string{"--optical-profile", "--optical-renderer", "--optical-scale", "--optical-quiet-zone"} {
		args := []string{flag, "1"}
		if flag == "--optical-renderer" {
			args[1] = "terminal"
		}
		if flag == "--optical-profile" {
			args[1] = "balanced"
		}
		options, err := parseUploadOptions(args, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if validateUploadOptions(options, config{SecretToken: "token"}) == nil {
			t.Fatal("optical option accepted without --optical")
		}
	}
	if hasOpticalUploadFlag([]string{"-m", "--optical"}) || hasJSONFlag([]string{"-m", "--json"}) {
		t.Fatal("message value selected a command flag")
	}
}

type opticalUnreadableInput struct{ t *testing.T }

func (r opticalUnreadableInput) Read([]byte) (int, error) {
	r.t.Fatal("read input before renderer preflight")
	return 0, io.EOF
}
func TestOpticalUnavailableRendererAndPeerRoutingAvoidSourceAndEncryption(t *testing.T) {
	a, _, out, _ := newOpticalTestApp(t, "")
	a.in = opticalUnreadableInput{t}
	a.cfg.AgeBin = "/missing"
	a.newOpticalRenderer = func(context.Context, display.Options) (display.Renderer, error) {
		return nil, errors.New("private display details")
	}
	if a.main([]string{"upload", "--optical", "--json"}) != 1 {
		t.Fatal("unavailable renderer did not fail")
	}
	if opticalJSON(t, out)["error"].(map[string]any)["code"] != "renderer-unavailable" {
		t.Fatal("wrong preflight failure")
	}
	if !strings.Contains(out.String(), "Optical window renderer unavailable") {
		t.Fatal("preflight failure does not identify the selected renderer")
	}
	if strings.Contains(out.String(), "private") {
		t.Fatal("preflight diagnostics escaped")
	}
	assertOpticalCleanup(t)
	a, _, _, _ = newOpticalTestApp(t, "")
	a.in = opticalUnreadableInput{t}
	a.newOpticalRenderer = func(context.Context, display.Options) (display.Renderer, error) {
		t.Fatal("peer alias routed to optical")
		return nil, nil
	}
	if err := a.run([]string{"send", "laptop", "--optical"}); err == nil {
		t.Fatal("peer accepted optical flag")
	}
}
func TestOpticalFailuresAreSanitizedAndRemoveStaging(t *testing.T) {
	for _, test := range []struct {
		name, code  string
		flags       []string
		ageBody     string
		rendererErr error
	}{
		{name: "input", code: "input", flags: []string{"--file", "/missing-private-name"}},
		{name: "recipient input", code: "input", flags: []string{"-R", "/missing-private-recipient"}},
		{name: "encryption", code: "encryption", ageBody: "printf 'secret failure' >&2; printf 'secret stdout'; exit 42"},
		{name: "empty", code: "ciphertext-limit", ageBody: "while [ \"$1\" != -o ]; do shift; done; : > \"$2\""},
		{name: "oversized", code: "ciphertext-limit", ageBody: "while [ \"$1\" != -o ]; do shift; done; truncate -s 67108865 \"$2\""},
		{name: "renderer", code: "renderer", rendererErr: errors.New("private metadata")},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, r, out, stderr := newOpticalTestApp(t, "")
			r.fail = test.rendererErr
			if test.ageBody != "" {
				path := filepath.Join(t.TempDir(), "age-fail")
				if err := os.WriteFile(path, []byte("#!/bin/sh\n"+test.ageBody+"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				a.cfg.AgeBin = path
			}
			args := append([]string{"upload", "--optical", "--json", "-m", "secret payload"}, test.flags...)
			if len(test.flags) > 0 {
				args = append([]string{"upload", "--optical", "--json"}, test.flags...)
			}
			if a.main(args) != 1 {
				t.Fatal("failure did not exit 1")
			}
			report := opticalJSON(t, out)
			if report["error"].(map[string]any)["code"] != test.code || len(report) != 5 {
				t.Fatalf("report %+v", report)
			}
			if strings.Contains(out.String()+stderr.String(), "secret") || strings.Contains(out.String(), "private") {
				t.Fatal("private diagnostics escaped")
			}
			if test.code != "renderer" && r.called {
				t.Fatal("invalid ciphertext reached renderer")
			}
			assertOpticalCleanup(t)
		})
	}
}
func TestOpticalUploadEncryptsPassphraseX25519AndHybridRecipientFiles(t *testing.T) {
	ageBin := opticalTestAge(t)
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		identity  age.Identity
		recipient string
		file      bool
	}{
		{"passphrase", mustOpticalScryptIdentity(t), "", false},
		{"x25519", x25519, x25519.Recipient().String(), false},
		{"hybrid", hybrid, hybrid.Recipient().String(), false},
		{"recipient file", x25519, x25519.Recipient().String(), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, r, out, _ := newOpticalTestApp(t, "")
			a.cfg.AgeBin = ageBin
			args := []string{"upload", "--optical", "--json", "-m", "encrypted private message", "--optical-profile", "balanced"}
			if test.recipient == "" {
				args = append(args, "--passphrase")
			} else if test.file {
				path := filepath.Join(t.TempDir(), "recipients")
				if err := os.WriteFile(path, []byte(test.recipient+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-R", path)
			} else {
				args = append(args, "-r", test.recipient)
			}
			if err := a.run(args); err != nil {
				t.Fatal(err)
			}
			// The display's frame API must carry the complete ciphertext, not its private
			// container or an ID. Recover from repair symbols and compare every byte.
			encoder, err := optical.NewEncoderWithBlockSize(r.ciphertext, [optical.SessionIDSize]byte{}, r.options.BlockSize)
			if err != nil {
				t.Fatal(err)
			}
			decoder := optical.NewDecoder()
			for stripe := 0; stripe < encoder.StripeCount(); stripe++ {
				count, _ := encoder.SourceCount(stripe)
				for sequence := 0; sequence < count-1; sequence++ {
					frame, err := encoder.Frame(stripe, uint32(sequence))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := decoder.Add(frame); err != nil {
						t.Fatal(err)
					}
				}
				sequence, err := encoder.NextMaximumDegreeRepairSequence(stripe, uint64(count))
				if err != nil {
					t.Fatal(err)
				}
				frame, err := encoder.Frame(stripe, sequence)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := decoder.Add(frame); err != nil {
					t.Fatal(err)
				}
			}
			recovered, err := decoder.Result()
			if err != nil || !bytes.Equal(recovered, r.ciphertext) {
				t.Fatal("optical ciphertext differs", err)
			}
			plaintext, err := age.Decrypt(bytes.NewReader(recovered), test.identity)
			if err != nil {
				t.Fatal(err)
			}
			container, err := io.ReadAll(plaintext)
			if err != nil {
				t.Fatal(err)
			}
			metadata, payload, err := capsule.Decode(container)
			if err != nil || metadata.Type != drop.PayloadMessage || string(payload) != "encrypted private message" {
				t.Fatal("native recovery differs", err)
			}

			saved := filepath.Join(t.TempDir(), "dud-encrypted-capsule.age")
			if err := os.WriteFile(saved, recovered, 0o600); err != nil {
				t.Fatal(err)
			}
			recovery, _, recoveredOut, _ := newOpticalTestApp(t, "")
			recovery.cfg.AgeBin = ageBin
			recoveryArgs := []string{"optical", "decrypt", "--file", saved, "--stdout"}
			switch identity := test.identity.(type) {
			case *age.X25519Identity:
				recoveryArgs = append(recoveryArgs, opticalTestIdentityArgs(t, identity.String())...)
			case *age.HybridIdentity:
				recoveryArgs = append(recoveryArgs, opticalTestIdentityArgs(t, identity.String())...)
			}
			if err := recovery.run(recoveryArgs); err != nil || recoveredOut.String() != "encrypted private message" {
				t.Fatal("CLI handoff differs", err)
			}
			if test.recipient != "" && strings.Contains(out.String(), test.recipient) {
				t.Fatal("report exposed recipient")
			}
			assertOpticalCleanup(t)
		})
	}
}
func TestOpticalRecipientArgumentsUsePrivateFilesAndPassphraseDefaults(t *testing.T) {
	first, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	second, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{nil, {"--passphrase"}, {"-r", first.Recipient().String(), "--recipient", second.Recipient().String()}} {
		a, _, _, _ := newOpticalTestApp(t, "")
		log := filepath.Join(t.TempDir(), "args")
		a.cfg.AgeBin = writeRecordingAge(t, log, "")
		if err := a.run(append([]string{"upload", "--optical", "-m", "message"}, flags...)); err != nil {
			t.Fatal(err)
		}
		args, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(args), first.Recipient().String()) || strings.Contains(string(args), second.Recipient().String()) {
			t.Fatal("inline recipients entered process arguments")
		}
		if len(flags) == 0 || flags[0] == "--passphrase" {
			if !strings.Contains(string(args), "--passphrase") {
				t.Fatal("default passphrase mode lost")
			}
		} else if !strings.Contains(string(args), "-R\n") {
			t.Fatal("recipient file missing")
		}
		assertOpticalCleanup(t)
	}
}

const opticalTestPassphrase = "fixed optical test passphrase"

func mustOpticalScryptIdentity(t *testing.T) *age.ScryptIdentity {
	t.Helper()
	id, err := age.NewScryptIdentity(opticalTestPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func opticalTestAge(t *testing.T) string {
	t.Helper()
	t.Setenv("DUD_TEST_OPTICAL_AGE_PROCESS", "1")
	path := filepath.Join(t.TempDir(), "age-test")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec '%s' -test.run=^TestOpticalAgeProcess$ -- \"$@\"\n", strings.ReplaceAll(exe, "'", "'\"'\"'"))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestOpticalAgeProcess(t *testing.T) {
	if os.Getenv("DUD_TEST_OPTICAL_AGE_PROCESS") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	args = args[1:]
	var recipients []age.Recipient
	var identities []age.Identity
	decrypt := false
	var output, input string
	for len(args) > 0 {
		switch args[0] {
		case "--encrypt":
			args = args[1:]
		case "--decrypt":
			decrypt = true
			args = args[1:]
		case "-i":
			file, err := os.Open(args[1])
			if err != nil {
				t.Fatal(err)
			}
			identities, err = age.ParseIdentities(file)
			_ = file.Close()
			if err != nil {
				t.Fatal(err)
			}
			args = args[2:]
		case "--passphrase":
			r, err := age.NewScryptRecipient(opticalTestPassphrase)
			if err != nil {
				t.Fatal(err)
			}
			r.SetWorkFactor(10)
			recipients = append(recipients, r)
			args = args[1:]
		case "-R":
			file, err := os.Open(args[1])
			if err != nil {
				t.Fatal(err)
			}
			values, err := age.ParseRecipients(file)
			_ = file.Close()
			if err != nil {
				t.Fatal(err)
			}
			recipients = append(recipients, values...)
			args = args[2:]
		case "-o":
			output = args[1]
			args = args[2:]
		default:
			input = args[0]
			args = args[1:]
		}
	}
	plain, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	if decrypt {
		if len(identities) == 0 {
			identities = append(identities, mustOpticalScryptIdentity(t))
		}
		reader, err := age.Decrypt(plain, identities...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(os.Stdout, reader); err != nil {
			t.Fatal(err)
		}
		_ = plain.Close()
		os.Exit(0)
	}
	cipher, err := os.OpenFile(output, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := age.Encrypt(cipher, recipients...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(writer, plain); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	_ = plain.Close()
	if err = cipher.Close(); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func TestOpticalRecipientsRejectPluginsAndSnapshotNativeFiles(t *testing.T) {
	a, r, out, _ := newOpticalTestApp(t, "")
	a.cfg.AgeBin = "/missing-age"
	if err := a.run([]string{"upload", "--optical", "--json", "-m", "private", "-r", "age1plugin-test"}); err == nil {
		t.Fatal("plugin recipient accepted")
	}
	if opticalJSON(t, out)["error"].(map[string]any)["code"] != "encryption" || r.called {
		t.Fatal("plugin reached encryption or display")
	}
	assertOpticalCleanup(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recipients")
	if err := os.WriteFile(path, []byte("# native recipients\n\n"+identity.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := uploadOptions{recipientsFile: path}
	snapshot, err := opticalRecipients(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("age1plugin-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if snapshot.RecipientsFile != "" || len(snapshot.InlineRecipients) != 1 || snapshot.InlineRecipients[0] != identity.Recipient().String() {
		t.Fatal("encryption can reread a mutable recipient file")
	}
}
