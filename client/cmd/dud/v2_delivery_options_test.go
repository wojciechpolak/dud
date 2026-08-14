// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"strings"
	"testing"
)

// A drain must not stall on the first delivery whose name is already taken, so
// the default skips that one output and keeps going. Nothing is lost: the
// payload stays in the durable store, and nothing on disk is overwritten.
func TestV2PeerReceiveDefaultsToSkippingConflictingOutputs(t *testing.T) {
	opts, err := parseV2PeerReceiveOptions([]string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.onConflict != "skip" {
		t.Fatalf("default policy = %q", opts.onConflict)
	}
	for _, policy := range []string{"refuse", "skip", "overwrite"} {
		opts, err := parseV2PeerReceiveOptions([]string{"alice", "--on-conflict", policy})
		if err != nil || opts.onConflict != policy {
			t.Fatalf("policy %q = %#v, %v", policy, opts, err)
		}
	}
	if _, err := parseV2PeerReceiveOptions([]string{"alice", "--on-conflict", "replace"}); err == nil {
		t.Fatal("unknown conflict policy was accepted")
	}
	// The alias spelling accepts its one legal value.
	opts, err = parseV2PeerReceiveOptions([]string{"alice", "--collection-overwrite", "refuse"})
	if err != nil || opts.onConflict != "refuse" {
		t.Fatalf("collection overwrite alias = %#v, %v", opts, err)
	}
	if _, err := parseV2PeerReceiveOptions([]string{"alice", "--collection-overwrite", "replace"}); err == nil {
		t.Fatal("unsafe replacement policy was accepted")
	}
}

func TestV2ReceivedFileNameIsOneSafePathComponent(t *testing.T) {
	for _, name := range []string{"report.txt", "archive.tar"} {
		if err := v2SafeReceivedFileName(name); err != nil {
			t.Fatalf("safe name %q: %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "../escape", "/escape", `dir\\file`} {
		if err := v2SafeReceivedFileName(name); err == nil {
			t.Fatalf("unsafe name %q was accepted", name)
		}
	}
}

func TestV2PeerReceiveMaxBoundsTheDrain(t *testing.T) {
	opts, err := parseV2PeerReceiveOptions([]string{"alice"})
	if err != nil || opts.max != 0 {
		t.Fatalf("unbounded drain = %#v, %v", opts, err)
	}
	opts, err = parseV2PeerReceiveOptions([]string{"alice", "--max", "1"})
	if err != nil || opts.max != 1 {
		t.Fatalf("--max 1 = %#v, %v", opts, err)
	}
	for _, value := range []string{"0", "-1", "all"} {
		if _, err := parseV2PeerReceiveOptions([]string{"alice", "--max", value}); err == nil {
			t.Fatalf("--max %s was accepted", value)
		}
	}
	// The --id path exports one already-committed delivery from local state, so
	// a drain bound has nothing to bound there.
	if _, err := parseV2PeerReceiveOptions([]string{"alice", "--id", strings.Repeat("ab", 32), "--max", "2"}); err == nil {
		t.Fatal("--id accepted a drain bound")
	}
}

// --stdin carries the long text the interactive payload step offers, so it is
// one source among three rather than a modifier of the other two.
func TestV2PeerSendTakesExactlyOneSource(t *testing.T) {
	opts, err := parseV2PeerSendOptions([]string{"alice", "--stdin"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.stdin || opts.message != "" || len(opts.files) != 0 {
		t.Fatalf("options = %#v", opts)
	}
	for _, args := range [][]string{
		{"alice"},
		{"alice", "--stdin", "-m", "text"},
		{"alice", "--stdin", "--file", "/tmp/one"},
		{"alice", "-m", "text", "--file", "/tmp/one"},
	} {
		if _, err := parseV2PeerSendOptions(args); err == nil {
			t.Fatalf("%q was accepted", args)
		}
	}
}

func TestV2PeerSendReadsLongTextFromStandardInput(t *testing.T) {
	var output bytes.Buffer
	a := newApp(strings.NewReader("first line\nsecond line\n"), &output, &output)
	opts, err := parseV2PeerSendOptions([]string{"alice", "--stdin", "--name", "notes"})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, payloadType, displayName, metadata, format, err := a.readV2PeerSendPayload(opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "first line\nsecond line\n" {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if payloadType != 1 || displayName != "notes" || metadata != nil || format != nil {
		t.Fatalf("payload = %d, %q, %v, %v", payloadType, displayName, metadata, format)
	}
	empty := newApp(strings.NewReader(""), &output, &output)
	if _, _, _, _, _, err := empty.readV2PeerSendPayload(opts); err == nil {
		t.Fatal("an empty standard input was accepted as a payload")
	}
}

func TestInteractiveCollectionExtractionShowsVerifiedContentsBeforeConfirmation(t *testing.T) {
	var output bytes.Buffer
	a := newApp(strings.NewReader("yes\n"), &output, &output)
	if !a.confirmV2CollectionExtraction([]v2CollectionEntry{
		{name: "docs", dir: true},
		{name: "docs/readme.txt", size: 12},
	}) {
		t.Fatal("affirmative confirmation was not accepted")
	}
	text := output.String()
	if !strings.Contains(text, "docs/") || !strings.Contains(text, "docs/readme.txt (12 bytes)") {
		t.Fatalf("collection preview = %q", text)
	}
}
