// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"strings"
	"testing"
)

// hostileV2PeerText is what a paired peer puts in a descriptor display name or
// an archive entry name when it wants the receiver's terminal, rather than the
// receiver, to read the report: an OSC title write, a carriage return that
// rewrites the line just printed, and a newline that forges a line of its own.
const hostileV2PeerText = "\x1b]0;pwned\aok\rDUD: nothing to report\ninjected"

// assertNoTerminalControl fails when peer-controlled text reached a terminal
// with its power intact. Escaped text may still read as the attacker's words —
// that is unavoidable, and a quoted line is legible as quoted — but it must not
// carry control bytes, and it must not have escaped its own line: forging a line
// of DUD output is what the newline in the payload is for.
func assertNoTerminalControl(t *testing.T, label, rendered string) {
	t.Helper()
	if index := strings.IndexAny(rendered, "\x00\x07\x1b\r"); index >= 0 {
		t.Fatalf("%s emitted a terminal control byte at %d: %q", label, index, rendered)
	}
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "DUD: nothing to report") {
			t.Fatalf("%s let peer text forge a line of its own: %q", label, rendered)
		}
	}
}

// TestV2ReceiveReportContainsHostilePeerText covers the receive report, whose
// display names, committed outputs, and conflicting paths all carry text the
// sending peer chose.
func TestV2ReceiveReportContainsHostilePeerText(t *testing.T) {
	drained := []v2ReceivedItem{
		{Sequence: 1, Outcome: "received", DisplayName: hostileV2PeerText, Output: "/tmp/" + hostileV2PeerText},
		{Sequence: 2, Outcome: "skipped", DescriptorDigest: "digest", Conflict: "/tmp/" + hostileV2PeerText},
	}
	for _, drain := range [][]v2ReceivedItem{drained, drained[:1]} {
		var out, errOut bytes.Buffer
		a := newApp(strings.NewReader(""), &out, &errOut)
		opts := v2PeerReceiveOptions{alias: "laptop"}
		if err := a.renderV2ReceiveReport(opts, drain, nil, v2DeliveryStatus{}); err != nil {
			t.Fatal(err)
		}
		assertNoTerminalControl(t, "receive report", out.String()+errOut.String())
	}
}

// TestV2ReceiveStopContainsHostileConflictPath covers the conflict stop, which
// names a path whose last component is the peer's display name. The stop is
// rendered twice — as the report's reason row when earlier deliveries committed,
// and as the run's error when none did — so both are checked.
func TestV2ReceiveStopContainsHostileConflictPath(t *testing.T) {
	stop := &v2ReceiveStop{Reason: "conflict", Sequence: 3, Detail: "/tmp/" + hostileV2PeerText}
	assertNoTerminalControl(t, "receive stop error", stop.Error())

	var out, errOut bytes.Buffer
	a := newApp(strings.NewReader(""), &out, &errOut)
	opts := v2PeerReceiveOptions{alias: "laptop"}
	drained := []v2ReceivedItem{{Sequence: 2, Outcome: "received", Output: "/tmp/report.txt"}}
	if err := a.renderV2ReceiveReport(opts, drained, stop, v2DeliveryStatus{}); err != nil {
		t.Fatal(err)
	}
	assertNoTerminalControl(t, "receive stop report", out.String()+errOut.String())
}

// TestV2InboxReportContainsHostilePeerText covers the inbox preview, which
// reports the head of the queue without committing it and so is the first place
// a hostile display name is rendered.
func TestV2InboxReportContainsHostilePeerText(t *testing.T) {
	var out, errOut bytes.Buffer
	a := newApp(strings.NewReader(""), &out, &errOut)
	results := []map[string]any{{
		"peer": "laptop",
		"ok":   true,
		"next": &v2InboxPreview{
			Sequence:    1,
			Expected:    1,
			Kind:        v2PayloadKind(2),
			DisplayName: hostileV2PeerText,
		},
		"inbound_waiting": false,
	}}
	if err := a.renderV2InboxReport(results); err != nil {
		t.Fatal(err)
	}
	assertNoTerminalControl(t, "inbox report", out.String()+errOut.String())
}

// TestV2CollectionPreviewContainsHostileArchiveNames covers the interactive
// extraction prompt. Archive path validation keeps the entry inside the
// destination but says nothing about control bytes, so the preview escapes them.
func TestV2CollectionPreviewContainsHostileArchiveNames(t *testing.T) {
	var out, errOut bytes.Buffer
	a := newApp(strings.NewReader("n\n"), &out, &errOut)
	if a.confirmV2CollectionExtraction([]v2CollectionEntry{
		{name: hostileV2PeerText, dir: true},
		{name: hostileV2PeerText + "/notes.txt", size: 12},
	}) {
		t.Fatal("a declined confirmation was read as consent")
	}
	assertNoTerminalControl(t, "collection preview", out.String()+errOut.String())
}
