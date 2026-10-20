// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestV2GitTransferWarningsIdentifyDirectionAndRecovery(t *testing.T) {
	t.Setenv("DUD_PROFILE", "work")
	for _, test := range []struct {
		name   string
		result v2GitTransferReport
		want   []string
		absent []string
	}{
		{name: "incoming refusal", result: v2GitTransferReport{rejected: []map[string]any{{"descriptor_digest": "aa", "reason": "private reason"}}}, want: []string{"Warning: This device rejected 1 incoming Git checkpoint from laptop.", "Details: DUD_PROFILE=work dud git status laptop"}, absent: []string{"private reason", "outgoing", "Resume:"}},
		{name: "outgoing refusal", result: v2GitTransferReport{refused: []map[string]any{{}, {}}}, want: []string{"Warning: laptop rejected 2 outgoing Git checkpoints from this device."}, absent: []string{"incoming", "Resume:"}},
		{name: "both directions", result: v2GitTransferReport{rejected: []map[string]any{{}, {}, {}}, refused: []map[string]any{{}, {}}}, want: []string{"rejected 3 incoming Git checkpoints from laptop", "laptop rejected 2 outgoing Git checkpoints from this device"}},
		{name: "current refusal", result: v2GitTransferReport{rejectedDigest: "aa", rejected: []map[string]any{{"descriptor_digest": "aa"}}}, want: []string{"Details:"}, absent: []string{"Warning:"}},
		{name: "current and stored refusal", result: v2GitTransferReport{rejectedDigest: "aa", rejected: []map[string]any{{"descriptor_digest": "aa"}, {"descriptor_digest": "bb"}}}, want: []string{"rejected 1 incoming Git checkpoint"}, absent: []string{"rejected 2"}},
		{name: "review", result: v2GitTransferReport{quarantined: []map[string]any{{}}}, want: []string{"1 incoming Git checkpoint from laptop needs review", "Details:"}, absent: []string{"rejected"}},
		{name: "queued receipt", result: v2GitTransferReport{confirmationQueued: true, status: v2DeliveryStatus{PendingCompletions: 2}}, want: []string{"Resume: DUD_PROFILE=work dud sync laptop"}, absent: []string{"Warning:"}},
		{name: "other queued confirmations", result: v2GitTransferReport{status: v2DeliveryStatus{PendingCompletions: 1}}, want: []string{"Confirmations for incoming transfers from laptop are waiting to be sent", "Resume:"}},
		{name: "queued uploads", result: v2GitTransferReport{status: v2DeliveryStatus{PendingDeliveries: 1, PendingChunkTransfers: 1, UndrainedControl: true}}, want: []string{"Local transfers to laptop are waiting to be sent", "Peer updates with laptop need synchronization", "Resume:"}},
		{name: "inbox check", result: v2GitTransferReport{inboundWaiting: true}, want: []string{"Incoming data from laptop was waiting at the last inbox check.", "Check: DUD_PROFILE=work dud inbox laptop"}},
		{name: "halted guard", result: v2GitTransferReport{confirmationQueued: true, inboundWaiting: true, status: v2DeliveryStatus{Halted: true, PendingCompletions: 1}}, want: []string{"relationship with laptop is halted", "dud peer show laptop", "dud peer reset laptop"}, absent: []string{"dud sync", "dud inbox"}},
		{name: "chain guard", result: v2GitTransferReport{status: v2DeliveryStatus{QuarantinedChains: []v2QuarantinedChain{{Chain: "in:data"}}, PendingDeliveries: 1}}, want: []string{"Transfers with laptop require chain recovery", "dud peer resume laptop"}, absent: []string{"dud sync"}},
		{name: "reset guard", result: v2GitTransferReport{status: v2DeliveryStatus{RelationshipReset: &v2RelationshipReset{Phase: "proposed", LocalConsent: true}, Halted: true, PendingDeliveries: 1}}, want: []string{"requires reset recovery", "dud peer reset laptop"}, absent: []string{"dud sync", "dud peer show"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := test.result
			result.status.Alias = "laptop"
			text := result.report(false).String()
			for _, want := range test.want {
				if !strings.Contains(text, want) {
					t.Fatalf("output omitted %q: %s", want, text)
				}
			}
			for _, absent := range test.absent {
				if strings.Contains(text, absent) {
					t.Fatalf("output contains %q: %s", absent, text)
				}
			}
			for _, label := range []string{"Details:", "Resume:", "Check:"} {
				if strings.Count(text, label) > 1 {
					t.Fatalf("duplicate %s: %s", label, text)
				}
			}
		})
	}
}

func TestV2GitConfirmationTracksItsOwnDescriptor(t *testing.T) {
	state := &v2PeerDeliveryState{PendingCompletions: []v2PendingCompletion{{DescriptorDigest: "other"}}}
	if v2GitConfirmationQueued(state, "committed") {
		t.Fatal("another delivery's queued confirmation changed this checkpoint's result")
	}
	state.PendingCompletions = append(state.PendingCompletions, v2PendingCompletion{DescriptorDigest: "committed"})
	if !v2GitConfirmationQueued(state, "committed") {
		t.Fatal("checkpoint's queued confirmation was reported as sent")
	}
}

type v2GitOutputTransport struct {
	v2Transport
	failConfirmation bool
	failPublication  bool
}

func (transport *v2GitOutputTransport) Do(ctx context.Context, request v2Request) (*v2Response, error) {
	if transport.failConfirmation && strings.HasSuffix(request.Path, "/complete") {
		return nil, errors.New("confirmation publication unavailable")
	}
	if transport.failPublication && request.Path == "/v2/deliveries" {
		return nil, errors.New("publication unavailable")
	}
	return transport.v2Transport.Do(ctx, request)
}

type v2GitFetchOutputFixture struct {
	app            *app
	directory      string
	paths          v2Paths
	state          *v2PeerDeliveryState
	metadata       *v2GitMetadata
	delivery       stubbedV2Delivery
	transport      *v2GitOutputTransport
	stdout, stderr bytes.Buffer
}

func newV2GitFetchOutputFixture(t *testing.T, reject bool) *v2GitFetchOutputFixture {
	t.Helper()
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	for _, directory := range []string{source, destination} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		initializeGitTestRepository(t, directory)
	}
	commitGitTestFile(t, source, "README.md", "peer content\n", "peer commit")
	commitGitTestFile(t, destination, "README.md", "local content\n", "local commit")
	bundle, metadata := newV2GitTestCheckpoint(t, source)
	paths, state := newPairedV2TestPeer(t, "laptop", "work")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	var mutate func(map[int]any)
	if reject {
		mutate = unapplicableV2GitMetadata
	}
	delivery := buildInboundV2GitDeliveryAt(t, crypto, *metadata, bundle, 1, strings.Repeat("00", 32), mutate)
	fixture := &v2GitFetchOutputFixture{
		directory: destination, paths: paths, state: state, metadata: metadata, delivery: delivery,
		transport: &v2GitOutputTransport{v2Transport: &drainingInboxTransport{queue: []stubbedV2Delivery{delivery}}},
	}
	fixture.app = newDrainingV2TestApp(t, fixture.transport, &fixture.stdout, &fixture.stderr)
	return fixture
}

func TestV2GitFetchTextReportsCommitAndConfirmationIndependently(t *testing.T) {
	for _, test := range []struct {
		name                               string
		queued, verbose, olderConfirmation bool
		remote, verb                       string
	}{
		{name: "ordinary fetch", remote: "laptop", verb: "fetch"},
		{name: "remote alias", remote: "workstation", verb: "receive"},
		{name: "queued confirmation", queued: true, remote: "laptop", verb: "fetch"},
		{name: "older queued confirmation", olderConfirmation: true, remote: "laptop", verb: "fetch"},
		{name: "verbose fetch", verbose: true, remote: "laptop", verb: "fetch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newV2GitFetchOutputFixture(t, false)
			fixture.transport.failConfirmation = test.queued
			if test.olderConfirmation {
				completion := queuedV2TestCompletion()
				completion.NextAttemptAt = uint64(time.Now().Add(time.Hour).Unix())
				fixture.state.PendingCompletions = []v2PendingCompletion{completion}
				if err := writeV2PeerDeliveryState(fixture.paths, fixture.state); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
				peer := cfg.Peers["laptop"]
				peer.GitRemote = test.remote
				cfg.Peers["laptop"] = peer
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			localHead := runGitTestCommand(t, fixture.directory, "rev-parse", "HEAD")
			if err := os.WriteFile(filepath.Join(fixture.directory, "README.md"), []byte("uncommitted work\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			localStatus := runGitTestCommand(t, fixture.directory, "status", "--porcelain")
			args := []string{"git", test.verb, "laptop", "--associate"}
			if test.verbose {
				args = append(args, "--verbose")
			}
			withGitTestDirectory(t, fixture.directory, func() {
				if err := fixture.app.run(args); err != nil {
					t.Fatal(err)
				}
			})
			confirmation := "Receipt confirmation sent to laptop.\n"
			if test.queued || test.olderConfirmation {
				confirmation = "Receipt confirmation to laptop is queued.\n"
			}
			want := "Fetched Git checkpoint from laptop (remote: " + test.remote + ").\n" + confirmation + "Local branches and working tree unchanged.\n"
			if test.queued || test.olderConfirmation {
				want += "\nResume: DUD_PROFILE=work dud sync laptop\n"
			}
			text := fixture.stdout.String()
			if (!test.verbose && text != want) || !strings.HasPrefix(text, want) {
				t.Fatalf("fetch result = %q, want %q", text, want)
			}
			if test.verbose {
				for _, detail := range []string{"checkpoint mode", "full", "data sequence", "repository ID", fixture.delivery.digest, "queued deliveries", "Inspect with: git log", "git merge --ff-only laptop/main"} {
					if !strings.Contains(text, detail) {
						t.Fatalf("verbose fetch omitted %q: %s", detail, text)
					}
				}
			}
			if fixture.stderr.Len() != 0 {
				t.Fatalf("duplicate diagnostics on stderr: %s", fixture.stderr.String())
			}
			if runGitTestCommand(t, fixture.directory, "rev-parse", "HEAD") != localHead || runGitTestCommand(t, fixture.directory, "status", "--porcelain") != localStatus {
				t.Fatal("fetch changed local branch, index, or working tree")
			}
			if got := runGitTestCommand(t, fixture.directory, "rev-parse", "refs/remotes/"+test.remote+"/main"); got != hex.EncodeToString(fixture.metadata.Refs["refs/heads/main"]) {
				t.Fatalf("fetched ref = %s", got)
			}
		})
	}
}

func TestV2GitRejectedFetchReportsNotificationAndStoredReason(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(map[bool]string{false: "sent", true: "queued"}[queued], func(t *testing.T) {
			fixture := newV2GitFetchOutputFixture(t, true)
			fixture.transport.failConfirmation = queued
			withGitTestDirectory(t, fixture.directory, func() {
				if err := fixture.app.run([]string{"git", "fetch", "laptop"}); err != nil {
					t.Fatal(err)
				}
			})
			confirmation := "Refusal notification sent to laptop.\n"
			if queued {
				confirmation = "Refusal notification to laptop is queued.\n"
			}
			want := "This device rejected an incoming Git checkpoint from laptop.\nRemote-tracking refs unchanged.\n" + confirmation + "\nDetails: DUD_PROFILE=work dud git status laptop\n"
			if queued {
				want += "Resume: DUD_PROFILE=work dud sync laptop\n"
			}
			want += "On the sending device, review the refusal before sending a compatible checkpoint. Use that device's peer alias and profile.\nOther device: dud git push PEER --full\n"
			if fixture.stdout.String() != want || fixture.stderr.Len() != 0 {
				t.Fatalf("refusal output = %q, stderr %q", fixture.stdout.String(), fixture.stderr.String())
			}
			state, err := loadV2PeerDeliveryState(fixture.paths, fixture.state.RelationshipID)
			if err != nil || state.InboundTransfers[fixture.delivery.digest].RejectionReason == "" {
				t.Fatalf("refusal reason was not retained: %v", err)
			}
		})
	}
}

func TestV2GitFetchJSONKeepsConfirmationAndRejectionContracts(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "refused"}[reject], func(t *testing.T) {
			fixture := newV2GitFetchOutputFixture(t, reject)
			fixture.transport.failConfirmation = true
			withGitTestDirectory(t, fixture.directory, func() {
				if err := fixture.app.run([]string{"git", "fetch", "laptop", "--associate", "--json"}); err != nil {
					t.Fatal(err)
				}
			})
			var result map[string]any
			if err := json.Unmarshal(fixture.stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result["received"] != !reject || result["acknowledgement"] != false || result["descriptor_digest"] != fixture.delivery.digest || result["sequence"] != float64(1) {
				t.Fatalf("JSON result = %#v", result)
			}
			if _, exists := result["refused_git_checkpoints"]; exists {
				t.Fatal("text diagnostics changed the fetch JSON schema")
			}
			if !strings.Contains(fixture.stderr.String(), "acknowledgement queued:") {
				t.Fatalf("JSON diagnostics lost confirmation error: %s", fixture.stderr.String())
			}
		})
	}
}

func TestV2GitPushTextDistinguishesPublicationFromReceipt(t *testing.T) {
	for _, test := range []struct {
		name, mode, verb, progress   string
		verbose, queued, interactive bool
	}{
		{name: "full", mode: "--full", verb: "push", progress: "--no-progress"},
		{name: "incremental alias", mode: "--incremental", verb: "send", progress: "--progress"},
		{name: "verbose incremental", mode: "--incremental", verb: "push", verbose: true},
		{name: "queued publication", mode: "--full", verb: "push", queued: true, progress: "--progress"},
		{name: "interactive", interactive: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			initializeGitTestRepository(t, directory)
			baseOID := commitGitTestFile(t, directory, "README.md", "base\n", "base")
			paths, state := newPairedV2TestPeer(t, "laptop", "work")
			state.PeerFeatures = []uint64{5, 6}
			state.Chains["out:data"].SendSequence = 7
			state.Chains["out:data"].SendDigest = strings.Repeat("ab", 32)
			if err := writeV2PeerDeliveryState(paths, state); err != nil {
				t.Fatal(err)
			}
			policy := v2TransportPolicyMap(v2TransportPolicy{ExpiresAt: uint64(time.Now().Add(time.Hour).Unix()), Consume: 0, ClaimLeaseSeconds: 300, AckMode: 1})
			response, err := v2EncMode.Marshal(map[int]any{1: bytesRepeatV2(0x81, 16), 2: policy, 3: false, 4: []any{}, 5: []any{}})
			if err != nil {
				t.Fatal(err)
			}
			transport := &v2GitOutputTransport{v2Transport: &gitPushTransport{deliveryResponse: response}, failPublication: test.queued}
			var stdout, stderr bytes.Buffer
			a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
			withGitTestDirectory(t, directory, func() {
				repository, err := a.resolveV2GitRepository("push")
				if err != nil {
					t.Fatal(err)
				}
				repositoryID, err := repository.ensureRepositoryID()
				if err != nil {
					t.Fatal(err)
				}
				gitState := newV2GitPeerState(repositoryID, strings.Repeat("32", 16))
				gitState.LastAcknowledgedSentSequence = 7
				gitState.LastAcknowledgedRefs = map[string]string{"refs/heads/main": baseOID}
				if err := repository.writePeerState(gitState); err != nil {
					t.Fatal(err)
				}
				commitGitTestFile(t, directory, "README.md", "next\n", "next")
				args := []string{"git", test.verb, "laptop", test.mode}
				if test.progress != "" {
					args = append(args, test.progress)
				}
				if test.verbose {
					args = append(args, "--verbose")
				}
				if test.interactive {
					a.in = strings.NewReader("3\n1\n1\n1\n\nq\n")
					err = a.interactiveMenu()
				} else {
					err = a.run(args)
				}
				if test.queued {
					if err == nil || !strings.Contains(err.Error(), "delivery saved locally") || !strings.Contains(err.Error(), "DUD_PROFILE=work dud sync laptop") || stdout.Len() != 0 {
						t.Fatalf("queued publication = %v, stdout %q", err, stdout.String())
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			want := "Uploaded Git checkpoint for laptop.\nAwaiting receipt confirmation from laptop.\n"
			if !test.queued {
				text := stdout.String()
				if (!test.verbose && !test.interactive && text != want) || strings.Count(text, want) != 1 {
					t.Fatalf("push output = %q", text)
				}
				if test.verbose && (!strings.Contains(text, "checkpoint mode") || !strings.Contains(text, "incremental") || !strings.Contains(text, "acknowledged base sequence  7")) {
					t.Fatalf("verbose push omitted checkpoint details: %s", text)
				}
			}
			if strings.Contains(stderr.String(), ": complete") || strings.Contains(stderr.String(), ": failed") {
				t.Fatalf("Git progress emitted a competing result: %s", stderr.String())
			}
			if test.progress == "--no-progress" && stderr.Len() != 0 {
				t.Fatalf("--no-progress output = %s", stderr.String())
			}
		})
	}
}

func TestV2GitEmptyFetchReportsRefusalsForItsRepository(t *testing.T) {
	fixture := newV2GitFetchOutputFixture(t, false)
	fixture.transport.v2Transport = &emptySlotTransport{}
	withGitTestDirectory(t, fixture.directory, func() {
		repository, err := fixture.app.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.app.run([]string{"git", "fetch", "laptop"}); err != nil {
			t.Fatal(err)
		}
		if fixture.stdout.String() != "No pending Git checkpoint from laptop.\n" {
			t.Fatalf("empty result = %q", fixture.stdout.String())
		}
		fixture.stdout.Reset()
		if err := repository.associateRepositoryID(fixture.metadata.RepositoryID); err != nil {
			t.Fatal(err)
		}
		for index := 1; index <= 2; index++ {
			metadata := *fixture.metadata
			if index == 2 {
				metadata.RepositoryID = bytesRepeatV2(0x99, 16)
			}
			encoded, err := v2EncMode.Marshal(encodeV2GitMetadata(metadata))
			if err != nil {
				t.Fatal(err)
			}
			digest := strings.Repeat(string(rune('a'+index)), 64)
			fixture.state.Sent[digest] = v2SentDelivery{Sequence: uint64(index), DescriptorDigest: digest, PayloadType: 4, TypeMetadata: v2Base64URL(encoded), Rejected: true, RejectedAt: uint64(time.Now().Unix())}
		}
		fixture.state.Chains["out:data"].SendSequence = 2
		fixture.state.Chains["out:data"].SendDigest = strings.Repeat("c", 64)
		if err := writeV2PeerDeliveryState(fixture.paths, fixture.state); err != nil {
			t.Fatal(err)
		}
		if err := fixture.app.run([]string{"git", "fetch", "laptop"}); err != nil {
			t.Fatal(err)
		}
	})
	want := "No pending Git checkpoint from laptop.\n\nWarning: laptop rejected 1 outgoing Git checkpoint from this device.\nDetails: DUD_PROFILE=work dud git status laptop\n"
	if fixture.stdout.String() != want {
		t.Fatalf("empty fetch with outbound refusals = %q, want %q", fixture.stdout.String(), want)
	}
}

func TestV2GitIncrementalFetchReportsResultAndFullCheckpointRecovery(t *testing.T) {
	for _, missingBase := range []bool{false, true} {
		t.Run(map[bool]string{false: "incremental result", true: "missing authenticated base"}[missingBase], func(t *testing.T) {
			fixture := newV2GitFetchOutputFixture(t, false)
			withGitTestDirectory(t, fixture.directory, func() {
				if err := fixture.app.run([]string{"git", "fetch", "laptop", "--associate"}); err != nil {
					t.Fatal(err)
				}
				if missingBase {
					repository, err := fixture.app.resolveV2GitRepository("fetch")
					if err != nil {
						t.Fatal(err)
					}
					state, err := repository.loadPeerState(fixture.metadata.RepositoryID, strings.Repeat("32", 16))
					if err != nil {
						t.Fatal(err)
					}
					delete(state.Inbound, fixture.delivery.digest)
					if err := repository.writePeerState(state); err != nil {
						t.Fatal(err)
					}
				}
			})
			source := filepath.Join(filepath.Dir(fixture.directory), "source")
			var metadata *v2GitMetadata
			var bundle []byte
			withGitTestDirectory(t, source, func() {
				repository, err := fixture.app.resolveV2GitRepository("push")
				if err != nil {
					t.Fatal(err)
				}
				state := newV2GitPeerState(fixture.metadata.RepositoryID, strings.Repeat("32", 16))
				state.LastAcknowledgedSentSequence = 1
				state.LastAcknowledgedRefs = stringGitRefs(fixture.metadata.Refs)
				commitGitTestFile(t, source, "README.md", "next peer commit\n", "next")
				path, nextMetadata, _, err := fixture.app.createV2GitCheckpoint(repository, v2GitPushOptions{Mode: v2GitCheckpointIncremental}, fixture.metadata.RepositoryID, state, []uint64{5, 6})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(path) })
				metadata = nextMetadata
				bundle, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			})
			crypto := newV2TestPeerCrypto(t, fixture.paths, fixture.state, "laptop")
			fixture.transport.v2Transport = &drainingInboxTransport{queue: []stubbedV2Delivery{buildInboundV2GitDeliveryAt(t, crypto, *metadata, bundle, 2, fixture.delivery.digest, nil)}}
			fixture.stdout.Reset()
			withGitTestDirectory(t, fixture.directory, func() {
				if err := fixture.app.run([]string{"git", "fetch", "laptop"}); err != nil {
					t.Fatal(err)
				}
			})
			if missingBase {
				for _, want := range []string{"This device rejected an incoming Git checkpoint from laptop.", "On the sending device, sync, then send a full checkpoint", "Other device: dud git push PEER --full"} {
					if !strings.Contains(fixture.stdout.String(), want) {
						t.Fatalf("recovery output omitted %q: %s", want, fixture.stdout.String())
					}
				}
			} else if fixture.stdout.String() != "Fetched Git checkpoint from laptop (remote: laptop).\nReceipt confirmation sent to laptop.\nLocal branches and working tree unchanged.\n" {
				t.Fatalf("incremental result = %q", fixture.stdout.String())
			}
		})
	}
}
