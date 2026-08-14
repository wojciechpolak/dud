// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseKeygenOptions(t *testing.T) {
	opts, err := parseKeygenOptions([]string{"--pq", "--out", "identity.txt", "-R", "recipient.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.pq || opts.out != "identity.txt" || opts.recipientOut != "recipient.txt" || opts.input != "" {
		t.Fatalf("unexpected options: %#v", opts)
	}
}

func TestValidateKeygenOptions(t *testing.T) {
	err := validateKeygenOptions(keygenOptions{
		input: "identity.txt",
		pq:    true,
	})
	if err == nil || err.Error() != "keygen does not accept --pq when converting an identity to recipients" {
		t.Fatalf("unexpected error: %v", err)
	}

	err = validateKeygenOptions(keygenOptions{
		recipientOut: "recipient.txt",
	})
	if err == nil || err.Error() != "keygen requires --out when generating a new identity with -R" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAgeKeygenSupportsPQToleratesNonZeroHelpExit(t *testing.T) {
	dir := t.TempDir()
	mock := filepath.Join(dir, "age-keygen-mock.sh")
	script := "#!/bin/sh\nprintf '%s\\n' 'usage: age-keygen [-pq] [-o OUTPUT]' >&2\nexit 2\n"
	if err := os.WriteFile(mock, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.cfg.AgeKeygenBin = mock

	supports, err := a.ageKeygenSupportsPQ()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !supports {
		t.Fatal("expected -pq support to be detected from help text despite exit status 2")
	}
}

func TestCmdKeygenWritesJSONWithoutLeakingIdentity(t *testing.T) {
	dir := t.TempDir()
	mock := filepath.Join(dir, "age-keygen-mock.sh")
	script := `#!/bin/sh
if [ "$1" = "-y" ]; then
  printf 'age1public-test\n'
  exit 0
fi
if [ "$1" = "--help" ]; then
  printf '%s\n' '-pq'
  exit 0
fi
if [ "$1" = "-o" ]; then
  printf 'AGE-SECRET-KEY-TEST\n' > "$2"
  exit 0
fi
printf 'AGE-SECRET-KEY-TEST\n'
`
	if err := os.WriteFile(mock, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "identity.txt")
	recipient := filepath.Join(dir, "recipient.txt")
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.cfg.AgeKeygenBin = mock
	if err := a.run([]string{"keygen", "--out", identity, "--recipient-out", recipient, "--json"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "AGE-SECRET") || !strings.Contains(stdout.String(), "age1public-test") {
		t.Fatalf("keygen output = %s", stdout.String())
	}
	if body, err := os.ReadFile(identity); err != nil || !strings.Contains(string(body), "AGE-SECRET") {
		t.Fatalf("identity file = %q, %v", body, err)
	}
	if body, err := os.ReadFile(recipient); err != nil || string(body) != "age1public-test\n" {
		t.Fatalf("recipient file = %q, %v", body, err)
	}
}

func TestKeygenRejectsInvalidCommandCombinations(t *testing.T) {
	for _, args := range [][]string{
		{"--unknown"}, {"one", "two"}, {"--json"}, {"-R", "recipient"},
		{"--pq", "identity"}, {"--out", "identity", "-R", "recipient", "identity"},
	} {
		a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		if err := a.cmdKeygen(args); err == nil {
			t.Fatalf("invalid keygen args accepted: %v", args)
		}
	}
}

func TestKeygenOptionParserCoversFlagsAndValidation(t *testing.T) {
	opts, err := parseKeygenOptions([]string{"--out", "identity", "-R", "recipient", "--pq", "--json"})
	if err != nil || opts.out != "identity" || opts.recipientOut != "recipient" || !opts.pq || !opts.outputJSON {
		t.Fatalf("options = %#v, %v", opts, err)
	}
	for _, args := range [][]string{{"--out"}, {"-R"}, {"--wat"}, {"first", "second"}, {"--json", "--json"}} {
		if _, err := parseKeygenOptions(args); err == nil {
			t.Fatalf("options accepted: %v", args)
		}
	}
	for _, value := range []keygenOptions{{input: "identity", pq: true}, {input: "identity", out: "a", recipientOut: "b"}, {recipientOut: "recipient"}, {outputJSON: true}} {
		if err := validateKeygenOptions(value); err == nil {
			t.Fatalf("options accepted: %#v", value)
		}
	}
}

func TestCmdKeygenGeneratesPlainAndConvertsExistingIdentity(t *testing.T) {
	dir := t.TempDir()
	mock := filepath.Join(dir, "age-keygen-mock.sh")
	script := `#!/bin/sh
if [ "$1" = "-y" ]; then printf 'age1converted\n'; exit 0; fi
if [ "$1" = "-o" ]; then printf 'AGE-SECRET-KEY-TEST\n' > "$2"; exit 0; fi
printf 'AGE-SECRET-KEY-STDOUT\n'
`
	if err := os.WriteFile(mock, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.cfg.AgeKeygenBin = mock
	if err := a.cmdKeygen(nil); err != nil || stdout.String() != "AGE-SECRET-KEY-STDOUT\n" {
		t.Fatalf("plain keygen = %q, %v", stdout.String(), err)
	}
	stdout.Reset()
	if err := a.cmdKeygen([]string{"identity.txt", "--json"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "age1converted") || strings.Contains(stdout.String(), "SECRET") {
		t.Fatalf("converted JSON = %s", stdout.String())
	}
}
