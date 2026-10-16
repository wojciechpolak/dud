// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func requireCLIStep(t *testing.T, steps []cliNextStep, device, command string) cliNextStep {
	t.Helper()
	for _, step := range steps {
		if step.Device == device && step.Command == command {
			return step
		}
	}
	t.Fatalf("missing %s command %q in %#v", device, command, steps)
	return cliNextStep{}
}

func TestCLIStatusGuidancePrioritizesRecoveryGuards(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	for _, test := range []struct {
		name   string
		status v2DeliveryStatus
		want   string
	}{
		{"queued", v2DeliveryStatus{PendingDeliveries: 1, PendingCompletions: 1}, "sync ak2"},
		{"inbound", v2DeliveryStatus{InboundWaiting: true}, "inbox ak2"},
		{"halt", v2DeliveryStatus{Halted: true, PendingDeliveries: 1}, "peer reset ak2"},
		{"gap", v2DeliveryStatus{QuarantinedChains: []v2QuarantinedChain{{Chain: "in:data"}}, PendingDeliveries: 1}, "peer resume ak2"},
		{"reset", v2DeliveryStatus{RelationshipReset: &v2RelationshipReset{Phase: "activating", ServerActivated: true}, PendingDeliveries: 1}, "peer reset ak2 --yes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := test.status
			status.Alias = "ak2"
			steps := status.nextSteps()
			requireCLIStep(t, steps, "local", "DUD_PROFILE=ak dud "+test.want)
			if test.name == "halt" || test.name == "gap" || test.name == "reset" {
				for _, step := range steps {
					if strings.Contains(step.Command, " dud sync ") {
						t.Fatal("blocked relationship offered queue synchronization")
					}
				}
			}
			raw, err := json.Marshal(status.fields())
			if err != nil {
				t.Fatal(err)
			}
			text := status.report("Status").String()
			for _, step := range steps {
				if !strings.Contains(string(raw), step.Command) || !strings.Contains(text, step.Command) {
					t.Fatalf("text and JSON omitted a step: %s\n%s", text, raw)
				}
			}
		})
	}
	status := v2DeliveryStatus{Alias: "ak2", UnacknowledgedDeliveries: 1}
	peer := requireCLIStep(t, status.nextSteps(), "peer", "dud receive PEER")
	if !peer.PeerAliasRequired || !peer.ProfileRequired || strings.Contains(peer.Command, "ak2") {
		t.Fatal("remote recipe assumed local alias or profile")
	}
	requireCLIStep(t, status.nextSteps(), "local", "DUD_PROFILE=ak dud sync ak2")
}

func TestCLIPairingWaitAndCancellationRetainTheSelectedProfile(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	for _, role := range []uint64{0, 1} {
		pending := &v2PendingPairing{Alias: "ak2", Role: role, ExpiresAt: uint64(time.Now().Add(time.Minute).Unix())}
		action := "accept"
		if role == 0 {
			action = "invite"
		}
		steps := v2PairingNextSteps(pending)
		requireCLIStep(t, steps, "local", "DUD_PROFILE=ak dud peer "+action+" ak2")
		requireCLIStep(t, steps, "local", "DUD_PROFILE=ak dud peer remove ak2 --yes")
		cause := context.DeadlineExceeded
		failure := v2PairingFailureHint(cause, pending)
		if !errors.Is(failure, cause) || !strings.Contains(failure.Error(), "Resume:") || !strings.Contains(failure.Error(), "Cancel:") {
			t.Fatal("pairing interruption lost its cause or actor")
		}
	}
}

func TestCLITerminalPairingAllowsAFreshInvitation(t *testing.T) {
	for _, phase := range []uint64{4, 5} {
		t.Run(fmt.Sprint(phase), func(t *testing.T) {
			setTestV2Homes(t)
			t.Setenv("DUD_PROFILE", "ak")
			cfg, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
			if err != nil {
				t.Fatal(err)
			}
			pending := &v2PendingPairing{Version: v2PairingStateVersion, Alias: "ak2", Role: 0, ExpiresAt: uint64(time.Now().Add(time.Minute).Unix()), CanonicalOrigin: cfg.BaseURL, RendezvousLocator: strings.Repeat("01", 32), StatusCapability: v2Base64URL(bytesRepeatV2(1, 32))}
			if err := writeV2PendingPairing(paths, pending); err != nil {
				t.Fatal(err)
			}
			body, err := v2EncMode.Marshal(map[int]any{1: phase})
			if err != nil {
				t.Fatal(err)
			}
			transport := &v2CoverageResponseTransport{response: &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}}
			a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
			failure := a.waitV2Pairing(cfg, paths, pending, transport, true)
			if failure == nil || !strings.Contains(failure.Error(), "DUD_PROFILE=ak dud peer invite ak2") {
				t.Fatalf("terminal pairing omitted restart: %v", failure)
			}
			if _, err := os.Stat(pairingStatePath(paths, "ak2")); !os.IsNotExist(err) {
				t.Fatal("terminal invitation would be reused instead of restarted")
			}
		})
	}
}

func TestCLISendBackoffResumesTheQueueWithoutDuplicatingIt(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "ak2", "ak")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	body, err := v2EncMode.Marshal(map[int]any{1: uint64(14), 2: "server unavailable"})
	if err != nil {
		t.Fatal(err)
	}
	transport := &v2CoverageResponseTransport{response: &v2Response{StatusCode: 500, ContentType: v2CBORContentType, Body: body}}
	a := newDrainingV2TestApp(t, transport, &bytes.Buffer{}, &bytes.Buffer{})
	if err := a.run([]string{"send", "ak2", "-m", "hello"}); err == nil || !strings.Contains(err.Error(), "DUD_PROFILE=ak dud sync ak2") || !strings.Contains(err.Error(), "do not repeat send") {
		t.Fatalf("queued send omitted safe resume: %v", err)
	}
	queued, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued.PendingGranularDeliveries) != 1 {
		t.Fatal("failed send was not retained exactly once")
	}
	retryAt := uint64(time.Now().Add(time.Minute).Unix())
	queued.PendingGranularDeliveries[0].NextAttemptAt = retryAt
	if err := writeV2PeerDeliveryState(paths, queued); err != nil {
		t.Fatal(err)
	}
	failure := a.run([]string{"sync", "ak2"})
	if failure == nil || !strings.Contains(failure.Error(), time.Unix(int64(retryAt), 0).UTC().Format(time.RFC3339)) || !strings.Contains(failure.Error(), "DUD_PROFILE=ak dud sync ak2") {
		t.Fatalf("backoff omitted date and resume command: %v", failure)
	}
	after, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.PendingGranularDeliveries) != 1 || after.Chains["out:data"].SendSequence != queued.Chains["out:data"].SendSequence {
		t.Fatal("backoff advanced the queue or created a duplicate")
	}
}

func TestCLIDeadDropRefusalPreservesExitCodeAndOriginalServer(t *testing.T) {
	a, transport, _, stderr := newDropTestApp(t, "")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusNotFound}, nil
	}
	t.Setenv("DUD_PROFILE", "unrelated")
	if code := a.main([]string{"test", "--url", "https://other.example.com/v1/test"}); code != 22 {
		t.Fatalf("HTTP refusal exit code=%d", code)
	}
	if !strings.Contains(stderr.String(), "dud test --url https://other.example.com/v1/test --json") || strings.Contains(stderr.String(), "DUD_PROFILE=unrelated") {
		t.Fatalf("drop hint changed server or implied a peer profile: %s", stderr.String())
	}
	if len(transport.requests) != 1 {
		t.Fatal("printing a hint sent another request")
	}
}

func TestCLIOutputRecoveryRecipesParseAndPreservePayloadType(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	for _, test := range []struct {
		payload   uint64
		noExtract bool
		want      string
	}{
		{2, false, "--out PATH"}, {3, true, "--no-extract --out PATH"}, {3, false, "--out-dir PATH"},
	} {
		opts := v2PeerReceiveOptions{alias: "ak2", noExtract: test.noExtract}
		command := v2ReceiveOutputRecoveryCommand(opts, test.payload)
		if !strings.HasSuffix(command, test.want) {
			t.Fatalf("recovery changed extraction mode: %s", command)
		}
		if _, err := parseV2PeerReceiveOptions(strings.Fields(strings.TrimPrefix(command, "receive "))); err != nil {
			t.Fatalf("invalid recovery recipe: %s: %v", command, err)
		}
	}
	command := buildReceiveCommand("dud receive", "id", "https://drops.example.com", false)
	if _, err := parseDownloadOptions(strings.Fields(strings.TrimPrefix(command, "dud receive ")), "https://elsewhere.example.com", "https://dns.google/dns-query"); err != nil {
		t.Fatalf("drop recipe lacks a required argument: %s: %v", command, err)
	}
}

func TestCLIRewriteApprovalIsSpecificAndRetainsAssociation(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	cause := &v2GitRewriteConsentError{cause: errors.New("branch deletes accepted history")}
	failure := v2GitPromotionHint(cause, v2GitFetchOptions{Alias: "ak2", Associate: true})
	var guided *cliGuidanceError
	if !errors.As(failure, &guided) || !errors.Is(failure, cause) {
		t.Fatal("rewrite guidance lost its typed cause")
	}
	step := requireCLIStep(t, guided.steps, "local", "DUD_PROFILE=ak dud git fetch ak2 --allow-rewrite --associate")
	args := strings.Fields(strings.TrimPrefix(step.Command, "DUD_PROFILE=ak dud git fetch "))
	if _, err := parseV2GitFetchOptions(args); err != nil {
		t.Fatal(err)
	}
	tagFailure := v2GitPromotionHint(errors.New("tag conflicts"), v2GitFetchOptions{Alias: "ak2"})
	if strings.Contains(tagFailure.Error(), "--allow-rewrite") {
		t.Fatal("a tag conflict offered an ineffective rewrite bypass")
	}
}

func TestCLIShellRecipesQuoteUntrustedValues(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	target := "https://drops.example.com/$(touch sentinel)"
	command := buildReceiveCommand("dud receive", "id", target, false)
	if !strings.Contains(command, "'"+target+"'") {
		t.Fatalf("URL was not shell quoted: %s", command)
	}
	quoted := cliShellArg("a'b")
	if quoted != "'a'\"'\"'b'" {
		t.Fatalf("single quote escaped incorrectly: %s", quoted)
	}
}

func TestCLIArgumentFailuresNameTheProfiledCommandReference(t *testing.T) {
	t.Setenv("DUD_PROFILE", "ak")
	for _, args := range [][]string{
		{"send", "ak2"}, {"receive", "ak2", "--out", "a", "--out-dir", "b"}, {"sync", "one", "two"},
		{"git", "push", "ak2", "--full", "--incremental"}, {"git", "fetch", "ak2", "--unknown"}, {"download", "--id", "id"},
	} {
		a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		failure := a.run(args)
		if failure == nil || !strings.Contains(failure.Error(), "DUD_PROFILE=ak dud help") {
			t.Fatalf("argument failure omitted command reference for %q: %v", args, failure)
		}
	}
}
