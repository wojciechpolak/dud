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
