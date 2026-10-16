// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestV2CompactStatusReportsWorkAndRecoveryInThreeLines(t *testing.T) {
	t.Setenv("DUD_PROFILE", "work")
	for _, test := range []struct {
		name                        string
		status                      v2DeliveryStatus
		gitQuarantined, gitRejected int
		want                        []string
		absent                      []string
	}{
		{name: "healthy", want: []string{"Status: queued deliveries 0; unacknowledged deliveries 0."}, absent: []string{"Warning:", "Next", "active generation"}},
		{name: "awaiting signed acknowledgement", status: v2DeliveryStatus{UnacknowledgedDeliveries: 2}, want: []string{"unacknowledged deliveries 2", "After receipt", "DUD_PROFILE=work dud sync laptop"}, absent: []string{"Warning:"}},
		{name: "saved publications", status: v2DeliveryStatus{PendingDeliveries: 2, PendingCompletions: 1, PendingControlPublications: 3}, want: []string{"queued deliveries 2", "queued completions 1", "queued control events 3", "dud sync laptop"}},
		{name: "resumable transfers", status: v2DeliveryStatus{PendingChunkTransfers: 1, PendingDeliveries: 1, InboundChunkTransfers: 2, ResumableTransfers: []v2ResumableTransfer{{DescriptorDigest: "private-digest"}}}, want: []string{"resumable uploads 1", "resumable downloads 2", "dud sync laptop"}, absent: []string{"private-digest"}},
		{name: "partial inbox drain", status: v2DeliveryStatus{InboundWaiting: true}, want: []string{"inbound waiting at last check", "dud inbox laptop"}},
		{name: "undrained control", status: v2DeliveryStatus{UndrainedControl: true}, want: []string{"undrained control", "dud sync laptop"}},
		{name: "quarantined chain", status: v2DeliveryStatus{PendingDeliveries: 1, QuarantinedChains: []v2QuarantinedChain{{Chain: "in:control", Reason: "long reason\nwith more lines"}}}, want: []string{"Warning: quarantined chains 1.", "dud peer resume laptop"}, absent: []string{"long reason", "dud sync laptop"}},
		{name: "halted relationship", status: v2DeliveryStatus{Halted: true, HaltReason: "long reason\nwith more lines", PendingDeliveries: 1}, want: []string{"Warning: relationship halted.", "dud peer show laptop"}, absent: []string{"long reason", "dud sync laptop"}},
		{name: "relationship reset", status: v2DeliveryStatus{RelationshipReset: &v2RelationshipReset{Phase: "proposed", ResetID: "private-digest", LocalConsent: true, RecoveryCommand: "dud peer reset laptop --yes"}}, want: []string{"relationship reset proposed", "dud peer reset laptop"}, absent: []string{"private-digest", "dud sync laptop", "--yes"}},
		{name: "completed reset", status: v2DeliveryStatus{RelationshipReset: &v2RelationshipReset{Phase: "active"}}, absent: []string{"Warning:", "Next"}},
		{name: "Git quarantine and rejection", gitQuarantined: 2, gitRejected: 3, want: []string{"quarantined Git deliveries 2", "refused Git deliveries 3", "dud git status laptop"}},
		{name: "Git warning with halted guard", gitQuarantined: 1, status: v2DeliveryStatus{Halted: true}, want: []string{"relationship halted", "quarantined Git deliveries 1", "dud peer show laptop"}, absent: []string{"dud git status laptop"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.status.Alias = "laptop"
			text := test.status.compactReport(test.gitQuarantined, test.gitRejected).String()
			if lines := strings.Count(text, "\n"); lines < 1 || lines > 3 {
				t.Fatalf("status has %d lines: %q", lines, text)
			}
			for _, want := range test.want {
				if !strings.Contains(text, want) {
					t.Fatalf("status omitted %q: %s", want, text)
				}
			}
			for _, absent := range test.absent {
				if strings.Contains(text, absent) {
					t.Fatalf("status includes %q: %s", absent, text)
				}
			}
		})
	}
}

func TestInteractiveTransferReportsCompactStatusAndReturnsToMenu(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader("1\n1\n1\nhello\n\n\n\nq\n"), &stdout, &stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &echoingV2DeliveryTransport{}, nil }
	if err := a.interactiveMenu(); err != nil {
		t.Fatalf("menu: %v, stderr %s", err, stderr.String())
	}
	text := stdout.String()
	if strings.Count(text, "dud — Discreet Upload/Download") != 2 ||
		strings.Count(text, "Status:") != 1 || strings.Contains(text, "Status\n") ||
		!strings.Contains(text, "unacknowledged deliveries 1") {
		t.Fatalf("interactive send = %s", text)
	}
}

func TestSendTreatsHelpAliasAndHelpMessageAsTransferData(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "help")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	transport := &echoingV2DeliveryTransport{}
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
	for _, message := range []string{"help", "--help", "-h"} {
		if err := a.run([]string{"send", "help", "-m", message}); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(stdout.String(), "Sent to help as data sequence") != 3 || transport.requests == 0 || strings.Contains(stdout.String(), "Usage\n") {
		t.Fatalf("send consumed help data: %s", stdout.String())
	}
}
