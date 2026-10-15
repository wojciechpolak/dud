// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestV2ResetReportsCommandsForBothDevices(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	for _, phase := range []string{"proposed", "accepted", "activating", "active", "cancelled"} {
		t.Run(phase, func(t *testing.T) {
			reset := &v2RelationshipReset{
				ResetID: strings.Repeat("01", 16), Phase: phase, Generation: 2,
				LocalConsent: true, PeerConsent: phase != "proposed",
				ServerActivated: phase == "active" || phase == "activating",
				RecoveryCommand: "dud peer reset ak2 --yes",
			}
			var output bytes.Buffer
			a := newApp(strings.NewReader(""), &output, &bytes.Buffer{})
			opts := v2PeerResetOptions{alias: "ak2", confirmed: true}
			if err := a.reportV2PeerReset(opts, reset); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if !strings.Contains(text, "Next steps:") || !strings.Contains(text, "DUD_PROFILE=ak dud ") {
				t.Fatalf("reset omitted actionable steps: %s", text)
			}
			if phase == "proposed" && (!strings.Contains(text, "[peer device]") || !strings.Contains(text, "NAME_FOR_THIS_DEVICE --yes") || !strings.Contains(text, "DUD_PROFILE=ak dud peer reset ak2 --cancel --yes")) {
				t.Fatalf("waiting reset omitted consent, resume, or cancellation: %s", text)
			}
			if phase == "cancelled" && strings.Contains(text, "waiting for peer consent") {
				t.Fatal("cancelled reset was reported as waiting for consent")
			}
			output.Reset()
			opts.json = true
			if err := a.reportV2PeerReset(opts, reset); err != nil {
				t.Fatal(err)
			}
			var result struct {
				CanCancel     bool              `json:"can_cancel"`
				CancelCommand string            `json:"cancel_command"`
				NextSteps     []v2ResetNextStep `json:"next_steps"`
			}
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.CanCancel != v2ResetCanCancel(reset) || len(result.NextSteps) == 0 {
				t.Fatalf("reset JSON omitted its actions: %s", output.String())
			}
			if !result.CanCancel && result.CancelCommand != "" {
				t.Fatal("completed reset offered cancellation")
			}
			status := v2DeliveryStatusOf(&v2PeerDeliveryState{Reset: reset})
			if status.fields()["relationship_reset_next_step"] == nil || !strings.Contains(status.report("Status").String(), "reset next step") {
				t.Fatal("peer status omitted reset guidance")
			}
		})
	}
}

func TestV2ResetRequiresNewToStartAnotherGeneration(t *testing.T) {
	for _, phase := range []string{"active", "cancelled"} {
		for _, startNew := range []bool{false, true} {
			runtime, _ := resetTestRuntimes(t)
			runtime.state.Generation = 1
			runtime.state.Reset = &v2RelationshipReset{Phase: phase}
			transport := &resetDiscoveryTestTransport{}
			runtime.transport = transport
			reset, _, err := runtime.proposeV2PeerReset(context.Background(), startNew)
			if err != nil {
				t.Fatal(err)
			}
			if !startNew {
				if reset != nil || len(transport.paths) != 1 {
					t.Fatalf("repeated reset created another generation: %#v, %v", reset, transport.paths)
				}
			} else if reset == nil || reset.Generation != 2 || len(transport.paths) != 2 {
				t.Fatalf("explicit new reset did not propose generation two: %#v, %v", reset, transport.paths)
			}
		}
	}
}

func TestV2ResetPreviewPreservesProfileAndNewIntent(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	var output bytes.Buffer
	a := newApp(strings.NewReader(""), &output, &bytes.Buffer{})
	err := a.reportV2ResetDisposition(v2PeerResetOptions{alias: "ak2", newReset: true}, v2ResetDisposition{})
	if err == nil || !strings.Contains(err.Error(), "DUD_PROFILE=ak dud peer reset ak2 --new --yes") {
		t.Fatalf("preview omitted its confirmation command: %v", err)
	}
	if _, err := parseV2PeerResetOptions([]string{"ak2", "--new", "--cancel", "--yes"}); err == nil {
		t.Fatal("reset accepted incompatible creation and cancellation")
	}
	runtime := &v2PeerRuntime{state: &v2PeerDeliveryState{Reset: &v2RelationshipReset{Phase: "proposed"}}}
	err = a.cancelV2PeerReset(runtime, v2PeerResetOptions{alias: "ak2", cancel: true})
	if err == nil || !strings.Contains(err.Error(), "DUD_PROFILE=ak dud peer reset ak2 --cancel --yes") {
		t.Fatalf("cancellation omitted its confirmation command: %v", err)
	}
}
