// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestV2PeerRecoveryHintPreservesCauseAndProfile(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	for _, item := range []struct {
		code   uint64
		status int
		hint   bool
	}{
		{1, 400, true}, {2, 401, true}, {3, 403, true},
		{5, 409, false}, {7, 410, false}, {10, 429, false}, {11, 429, false}, {14, 500, false},
		{1, 500, false},
	} {
		cause := &v2ProtocolError{Code: item.code, Status: item.status, Message: "Request refused."}
		err := v2PeerCapabilityRecoveryHint(fmt.Errorf("peer operation: %w", cause), "ak2")
		var recovered *v2ProtocolError
		if !errors.As(err, &recovered) || recovered != cause {
			t.Fatal("recovery hint discarded the protocol error")
		}
		hasHint := strings.Contains(err.Error(), "DUD_PROFILE=ak dud sync ak2 --refresh-capabilities")
		if hasHint != item.hint || strings.Contains(err.Error(), "expired") {
			t.Fatalf("unexpected recovery for code %d, status %d: %v", item.code, item.status, err)
		}
	}
	local := errors.New("local payload could not be read")
	if v2PeerCapabilityRecoveryHint(local, "ak2") != local || v2PeerCapabilityRecoveryHint(nil, "ak2") != nil {
		t.Fatal("recovery hint changed a local error or successful result")
	}
}

func TestV2PeerRequestRefusalShowsCapabilityRecovery(t *testing.T) {
	for _, command := range []string{"send", "receive", "inbox", "sync"} {
		t.Run(command, func(t *testing.T) {
			paths, state := newPairedV2TestPeer(t, "laptop")
			if err := writeV2PeerDeliveryState(paths, state); err != nil {
				t.Fatal(err)
			}
			body, err := v2EncMode.Marshal(map[int]any{1: uint64(1), 2: "Peer request is invalid."})
			if err != nil {
				t.Fatal(err)
			}
			transport := &v2CoverageResponseTransport{response: &v2Response{StatusCode: 400, ContentType: v2CBORContentType, Body: body}}
			var stdout bytes.Buffer
			a := newDrainingV2TestApp(t, transport, &stdout, &bytes.Buffer{})
			args := []string{command, "laptop", "--json"}
			if command == "send" {
				args = append(args, "-m", "hello")
			}
			err = a.run(args)
			if err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "dud sync laptop --refresh-capabilities") {
				t.Fatalf("%s refusal omitted recovery: %v", command, err)
			}
			if (command == "sync" || command == "inbox") && !strings.Contains(stdout.String(), "dud sync laptop --refresh-capabilities") {
				t.Fatalf("%s JSON omitted recovery: %s", command, stdout.String())
			}
			stored, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.CapabilityReissues != state.CapabilityReissues {
				t.Fatal("displaying a recovery hint rotated capabilities")
			}
			if command == "send" && len(stored.PendingGranularDeliveries) != 1 {
				t.Fatal("a refused send lost its queued delivery")
			}
		})
	}
}
