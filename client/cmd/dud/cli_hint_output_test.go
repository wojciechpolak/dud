// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCLIRecoveryOutputFixtures(t *testing.T) {
	cause := errors.New("connection closed")
	pending := &v2PendingPairing{Alias: "desktop", Role: 1, ExpiresAt: uint64(time.Now().Add(time.Minute).Unix())}
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"pairing interruption", v2PairingFailureHint(cause, pending), "pairing interrupted: connection closed\nResume: dud peer accept desktop\nCancel: dud peer remove desktop --yes"},
		{"invitation expired", v2PairingFailureHint(&v2PairingTerminalError{phase: 5}, &v2PendingPairing{Alias: "laptop"}), "pairing invitation expired\nShare a new pairing code.\nHere: dud peer invite laptop"},
		{"invitation cancelled", v2PairingFailureHint(&v2PairingTerminalError{phase: 4}, &v2PendingPairing{Alias: "laptop"}), "pairing was cancelled\nShare a new pairing code.\nHere: dud peer invite laptop"},
		{"queued publication", v2QueuedPublicationHint(cause, "desktop"), "delivery saved locally: connection closed\nResume after any retry delay; do not repeat send or Git push.\nHere: dud sync desktop"},
		{"sequence gap", v2GapRecoveryHint(&v2SequenceGapError{sequence: 4}, "desktop"), "gap before sequence 4\nSkipping loses deliveries; ask the sender to resend them.\nHere: dud peer resume desktop\nAfter approving the gap, continue.\nHere: dud receive desktop"},
		{"halted peer", v2HaltedPeerHint("rollback", "desktop"), "peer relationship is halted: rollback\nCheck peer state and verify both devices.\nHere: dud peer show desktop\nIf both devices are trusted, preview reset losses.\nHere: dud peer reset desktop"},
		{"receive conflict", withCLISteps(errors.New("output already exists"), localCLIStep("Choose an unused output path.", v2ReceiveOutputRecoveryCommand(v2PeerReceiveOptions{alias: "desktop"}, 2))), "output already exists\nChoose an unused output path.\nHere: dud receive desktop --out PATH"},
		{"Git rewrite", v2GitPromotionHint(&v2GitRewriteConsentError{cause: errors.New("history rewrite")}, v2GitFetchOptions{Alias: "desktop", Associate: true}), "history rewrite\nInspect the checkpoint and verify the peer.\nHere: dud git status desktop\nConfirm only if you accept the rewrite or branch deletion.\nHere: dud git fetch desktop --allow-rewrite --associate"},
		{"capability refusal", v2PeerCapabilityRecoveryHint(&v2ProtocolError{Code: 3, Status: 403, Message: "Request refused."}, "desktop"), "Request refused. (HTTP 403, v2 error 3)\nTry refreshing authorization; ask the operator if refused again.\nHere: dud sync desktop --refresh-capabilities"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.err.Error(); got != test.want {
				t.Fatalf("output:\n%s\nwant:\n%s", got, test.want)
			}
			assertShortHintOutput(t, test.err.Error())
		})
	}
	if !errors.Is(v2PairingFailureHint(cause, pending), cause) || !errors.Is(v2QueuedPublicationHint(cause, "desktop"), cause) {
		t.Fatal("short guidance lost the original error")
	}
}

func assertShortHintOutput(t *testing.T, text string) {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "dud ") && len([]rune(line)) > 78 {
			t.Fatalf("long hint (%d columns): %s", len([]rune(line)), line)
		}
	}
	for _, forbidden := range []string{"PROFILE_ON_OTHER_DEVICE", "NAME_FOR_THIS_DEVICE", "PATH_TO_NEW_", " Run '", "Replace "} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("verbose guidance %q in %s", forbidden, text)
		}
	}
}

func TestCLIHintCommandsPreserveProfilesAndJSONMetadata(t *testing.T) {
	t.Setenv("DUD_PROFILE", "home")
	pending := &v2PendingPairing{Alias: "desktop", Role: 1, ExpiresAt: uint64(time.Now().Add(time.Minute).Unix())}
	text := v2PairingFailureHint(errors.New("offline"), pending).Error()
	if !strings.Contains(text, "Resume: DUD_PROFILE=home dud peer accept desktop\nCancel: DUD_PROFILE=home dud peer remove desktop --yes") {
		t.Fatal(text)
	}
	step := peerCLIStep("Enter the pairing code.", "peer accept PEER")
	if step.Command != "dud peer accept PEER" || strings.Contains(step.text(), "home") {
		t.Fatal(step)
	}
	raw, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 5 || decoded["device"] != "peer" || decoded["action"] != step.Action || decoded["command"] != step.Command ||
		decoded["peer_alias_required"] != true || decoded["profile_required"] != true {
		t.Fatalf("JSON metadata = %s", raw)
	}
	for _, recovery := range v2PairingRecoverySteps(pending) {
		raw, err := json.Marshal(recovery)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "label") {
			t.Fatalf("text label leaked into JSON: %s", raw)
		}
	}
	command := "dud receive desktop --out " + strings.Repeat("long-path-", 20)
	report := &textReport{}
	section := report.section("Status")
	section.add("queued", "0")
	section.addRows(cliStepRows([]cliNextStep{{Device: "local", Action: "Choose an unused output path.", Command: command}}))
	if !strings.Contains(report.String(), "  queued  0\n") || !strings.Contains(report.String(), command+"\n") {
		t.Fatalf("wrapped command: %s", report.String())
	}
}

func TestCLIResetOutputFixtures(t *testing.T) {
	for _, test := range []struct {
		phase                                string
		localConsent, peerConsent, activated bool
		want                                 string
	}{
		{"proposed", true, false, false, "Reset for desktop: proposed (generation 2).\nIf not active there, confirm the reset.\nOther device: dud peer reset PEER --yes\nAfter activation there, finish here.\nHere: dud peer reset desktop --yes\nCancel before activation: dud peer reset desktop --cancel --yes\n"},
		{"proposed", false, false, false, "Reset for desktop: proposed (generation 2).\nConfirm only if you accept the listed losses.\nHere: dud peer reset desktop --yes\nCancel before activation: dud peer reset desktop --cancel --yes\n"},
		{"activating", true, true, true, "Reset for desktop: activating (generation 2).\nFinish activation here.\nHere: dud peer reset desktop --yes\nCancellation is unavailable after server activation.\n"},
		{"active", true, true, true, "Reset for desktop: active (generation 2).\nIf still waiting there, finish activation.\nOther device: dud peer reset PEER --yes\nOnce both devices are active, sync.\nHere: dud sync desktop\nCancellation is unavailable after server activation.\n"},
		{"cancelled", true, false, false, "Reset for desktop: cancelled (generation 2).\nInspect the retained pairing.\nHere: dud peer show desktop\nIf still pending there, retrieve cancellation.\nOther device: dud peer reset PEER --yes\n"},
	} {
		t.Run(test.phase, func(t *testing.T) {
			var output bytes.Buffer
			a := newApp(strings.NewReader(""), &output, &bytes.Buffer{})
			reset := &v2RelationshipReset{Phase: test.phase, Generation: 2, LocalConsent: test.localConsent, PeerConsent: test.peerConsent, ServerActivated: test.activated}
			if err := a.reportV2PeerReset(v2PeerResetOptions{alias: "desktop"}, reset); err != nil {
				t.Fatal(err)
			}
			if output.String() != test.want {
				t.Fatalf("reset output = %s", output.String())
			}
			assertShortHintOutput(t, output.String())
		})
	}
}

func TestCLIDeadDropErrorsStayShortAndPreserveExitCodes(t *testing.T) {
	for _, status := range []int{401, 403, 404, 410, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			a, transport, _, stderr := newDropTestApp(t, "")
			transport.respond = func(recordedDropRequest) (*v2Response, error) { return &v2Response{StatusCode: status}, nil }
			if code := a.main([]string{"test", "--url", "https://drops.example.com/v1/test"}); code != 22 {
				t.Fatalf("exit code = %d", code)
			}
			if lines := strings.Count(stderr.String(), "\n"); lines != 3 {
				t.Fatalf("error has %d lines: %s", lines, stderr.String())
			}
			if !strings.Contains(stderr.String(), "\nHere: dud test --url https://drops.example.com/v1/test --json\n") {
				t.Fatal(stderr.String())
			}
			assertShortHintOutput(t, stderr.String())
		})
	}
}

func TestCLIEraseHintRequiresPreview(t *testing.T) {
	_, err := parseV2EraseOptions([]string{"peer", "desktop"})
	want := "dud erase is destructive\nPreview the files and state that erasure removes.\nHere: dud erase peer desktop --dry-run"
	if err == nil || err.Error() != want {
		t.Fatalf("erase hint = %v", err)
	}
	assertShortHintOutput(t, err.Error())
}

func TestCLIDeadDropHintPreservesExplicitResolver(t *testing.T) {
	a, transport, _, stderr := newDropTestApp(t, "")
	transport.respond = func(recordedDropRequest) (*v2Response, error) { return &v2Response{StatusCode: 403}, nil }
	if code := a.main([]string{"test", "--url", "https://drops.example.com/v1/test", "--doh-url", "https://resolver.example.com/dns-query"}); code != 22 {
		t.Fatalf("exit code = %d", code)
	}
	command := "Here: dud test --url https://drops.example.com/v1/test --doh-url https://resolver.example.com/dns-query --json\n"
	if !strings.Contains(stderr.String(), command) {
		t.Fatal(stderr.String())
	}
}
