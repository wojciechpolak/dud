// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newV2GitTestCheckpoint builds a real complete checkpoint from a repository and
// returns the bundle bytes with the metadata a peer would sign for it.
func newV2GitTestCheckpoint(t *testing.T, source string) ([]byte, *v2GitMetadata) {
	t.Helper()
	var bundlePath string
	var metadata *v2GitMetadata
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, source, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err := repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		bundlePath, metadata, err = a.createV2GitBundle(repository, v2GitPushOptions{}, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() { _ = os.Remove(bundlePath) })
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, metadata
}

// unapplicableV2GitMetadata makes a signed checkpoint that no 2.0 receiver can
// apply, by advertising incremental prerequisites that this client refuses.
// The fixture exercises the version-skew refusal path.
func unapplicableV2GitMetadata(metadata map[int]any) {
	metadata[5] = [][]byte{bytes.Repeat([]byte{0x11}, 20)}
}

// TestV2GitFetchRefusesAnUnapplicableCheckpointAndContinues is the regression
// that justifies the refusal path: before it, a checkpoint the receiver could
// not apply sat at the head of the data chain forever, and because dud receive
// also refuses to step over a Git payload, the whole relationship went quiet.
func TestV2GitFetchRefusesAnUnapplicableCheckpointAndContinues(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	for _, directory := range []string{source, destination} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	initializeGitTestRepository(t, source)
	wantOID := commitGitTestFile(t, source, "README.md", "checkpoint\n", "checkpoint")
	initializeGitTestRepository(t, destination)
	bundle, metadata := newV2GitTestCheckpoint(t, source)

	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	unapplicable := buildInboundV2GitDeliveryAt(t, crypto, *metadata, bundle, 1, strings.Repeat("00", 32), unapplicableV2GitMetadata)
	applicable := buildInboundV2GitDeliveryAt(t, crypto, *metadata, bundle, 2, unapplicable.digest, nil)
	transport := &drainingInboxTransport{queue: []stubbedV2Delivery{unapplicable, applicable}}

	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	withGitTestDirectory(t, destination, func() {
		if err := a.run([]string{"git", "fetch", "laptop", "--associate"}); err != nil {
			t.Fatalf("fetch of an unapplicable checkpoint failed instead of refusing it: %v", err)
		}
	})
	if !strings.Contains(stdout.String(), "Refused Git checkpoint 1") {
		t.Fatalf("first fetch output = %s", stdout.String())
	}
	if transport.completions != 1 {
		t.Fatalf("completions after refusal = %d, want 1", transport.completions)
	}
	if got := runGitTestCommand(t, destination, "for-each-ref", "--format=%(refname)", "refs/remotes/"); got != "" {
		t.Fatalf("refused checkpoint promoted refs: %s", got)
	}

	stdout.Reset()
	withGitTestDirectory(t, destination, func() {
		if err := a.run([]string{"git", "fetch", "laptop", "--associate"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(stdout.String(), "Fetched complete Git checkpoint") {
		t.Fatalf("second fetch output = %s", stdout.String())
	}
	if got := runGitTestCommand(t, destination, "rev-parse", "refs/remotes/laptop/main"); got != wantOID {
		t.Fatalf("remote-tracking ref = %s, want %s", got, wantOID)
	}
	if transport.completions != 2 {
		t.Fatalf("completions after recovery = %d, want 2", transport.completions)
	}
}

// TestV2GitRefusalIsDurableBeforeItIsSent checks the ordering that makes a
// refusal crash-safe: the reason and the advanced watermark are on disk, so a
// process that dies before the peer hears about it still refuses the same way.
func TestV2GitRefusalIsDurableBeforeItIsSent(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	for _, directory := range []string{source, destination} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	initializeGitTestRepository(t, source)
	commitGitTestFile(t, source, "README.md", "durable\n", "durable")
	initializeGitTestRepository(t, destination)
	bundle, metadata := newV2GitTestCheckpoint(t, source)

	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	refused := buildInboundV2GitDeliveryAt(t, crypto, *metadata, bundle, 1, strings.Repeat("00", 32), unapplicableV2GitMetadata)
	transport := &drainingInboxTransport{queue: []stubbedV2Delivery{refused}}

	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	withGitTestDirectory(t, destination, func() {
		if err := a.run([]string{"git", "fetch", "laptop", "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["received"] != false || result["rejected"] != true || result["sequence"] != float64(1) {
		t.Fatalf("refusal result = %#v", result)
	}
	if reason, _ := result["reason"].(string); !strings.Contains(reason, "base sequence") {
		t.Fatalf("refusal reason = %#v", result["reason"])
	}

	reloaded, err := loadV2PeerDeliveryState(paths, hex.EncodeToString(crypto.relationshipID))
	if err != nil {
		t.Fatal(err)
	}
	transfer, exists := reloaded.InboundTransfers[refused.digest]
	if !exists || transfer.Phase != "rejected" || transfer.RejectionReason == "" {
		t.Fatalf("durable inbound transfer = %#v", transfer)
	}
	if watermark := reloaded.Chains["in:data"].ReceiveWatermark; watermark != 1 {
		t.Fatalf("data watermark after refusal = %d, want 1", watermark)
	}
	if entry := reloaded.Chains["in:data"].Replay[1]; entry.OutputDigest != strings.Repeat("00", 32) {
		t.Fatalf("refused replay entry output digest = %q", entry.OutputDigest)
	}
}

// TestV2GitTamperedPayloadIsNotRefused separates the two failure classes. A
// payload that contradicts its signed descriptor is evidence of tampering in
// transit, not a checkpoint the sender built wrong, so it must stay a loud
// error: refusing it would let a server that corrupts one delivery convince the
// receiver to skip past it permanently.
func TestV2GitTamperedPayloadIsNotRefused(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	for _, directory := range []string{source, destination} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	initializeGitTestRepository(t, source)
	commitGitTestFile(t, source, "README.md", "tamper\n", "tamper")
	initializeGitTestRepository(t, destination)
	bundle, metadata := newV2GitTestCheckpoint(t, source)

	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	delivery := buildInboundV2GitDelivery(t, crypto, *metadata, bundle)
	delivery.payload[len(delivery.payload)-1] ^= 0xff
	transport := &drainingInboxTransport{queue: []stubbedV2Delivery{delivery}}

	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	withGitTestDirectory(t, destination, func() {
		if err := a.run([]string{"git", "fetch", "laptop", "--associate"}); err == nil {
			t.Fatal("tampered payload was accepted")
		}
	})
	if transport.completions != 0 {
		t.Fatalf("completions after tampering = %d, want 0", transport.completions)
	}
	reloaded, err := loadV2PeerDeliveryState(paths, hex.EncodeToString(crypto.relationshipID))
	if err != nil {
		t.Fatal(err)
	}
	if watermark := reloaded.Chains["in:data"].ReceiveWatermark; watermark != 0 {
		t.Fatalf("data watermark after tampering = %d, want 0", watermark)
	}
}

// TestV2GitQuarantineSeparatesPermanentFromTransientFailures pins the allowlist
// itself. A durable local limit is a verdict that will not change on a retry; a
// malformed pack is caught by fsck and stays retryable, because the same bytes
// arriving intact later must still be applicable.
func TestV2GitQuarantineSeparatesPermanentFromTransientFailures(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	limited := filepath.Join(root, "limited")
	tolerant := filepath.Join(root, "tolerant")
	for _, directory := range []string{source, limited, tolerant} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		initializeGitTestRepository(t, directory)
	}
	commitGitTestFile(t, source, "README.md", "limits\n", "limits")
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})

	bundlePath := filepath.Join(root, "complete.bundle")
	runGitTestCommand(t, source, "bundle", "create", bundlePath, "--branches")
	head := runGitTestCommand(t, source, "rev-parse", "refs/heads/main")
	oid, err := hex.DecodeString(head)
	if err != nil {
		t.Fatal(err)
	}
	metadata := func() *v2GitMetadata {
		return &v2GitMetadata{
			RepositoryID: bytes.Repeat([]byte{0x7a}, 16), ObjectFormat: 1, BundleVersion: 2,
			Refs: map[string][]byte{"refs/heads/main": oid}, Prerequisites: [][]byte{},
		}
	}

	runGitTestCommand(t, limited, "config", "dud.gitObjectCount", "1")
	withGitTestDirectory(t, limited, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.verifyV2GitQuarantine(repository, bundlePath, strings.Repeat("a", 64), metadata()); err == nil {
			t.Fatal("object-count limit did not fail")
		} else if !isV2GitPermanentRejection(err) {
			t.Fatalf("object-count limit is not a permanent rejection: %v", err)
		}
	})

	corruptPath := filepath.Join(root, "corrupt.bundle")
	complete, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt inside the packfile, past the bundle header, so the damage is
	// found by object verification rather than by header parsing.
	for index := len(complete) - 32; index < len(complete)-8; index++ {
		complete[index] ^= 0xff
	}
	if err := os.WriteFile(corruptPath, complete, 0o600); err != nil {
		t.Fatal(err)
	}
	withGitTestDirectory(t, tolerant, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.verifyV2GitQuarantine(repository, corruptPath, strings.Repeat("b", 64), metadata()); err == nil {
			t.Fatal("corrupt pack was accepted")
		} else if isV2GitPermanentRejection(err) {
			t.Fatalf("corrupt pack was treated as permanently refusable: %v", err)
		}
	})
}

// TestV2TypeMetadataFollowsTheDescriptorExtensionRule pins the property that
// makes an additive field possible: an unknown extension key is ignored while
// an unknown core key is refused. Without it, any added type_meta field would
// be a breaking change for deployed peers.
func TestV2TypeMetadataFollowsTheDescriptorExtensionRule(t *testing.T) {
	base := map[int]any{
		1: bytes.Repeat([]byte{0x7a}, 16),
		2: uint64(1),
		3: uint64(2),
		4: map[string]any{"refs/heads/main": bytes.Repeat([]byte{0x30}, 20)},
		5: []any{},
	}
	clone := func(mutate func(map[int]any)) map[int]any {
		copied := map[int]any{}
		for key, value := range base {
			copied[key] = value
		}
		mutate(copied)
		return copied
	}

	if _, err := decodeV2GitMetadata(clone(func(metadata map[int]any) {
		metadata[129] = []any{uint64(5)}
	})); err != nil {
		t.Fatalf("extension key was refused: %v", err)
	}
	if _, err := decodeV2GitMetadata(clone(func(metadata map[int]any) {
		metadata[7] = uint64(1)
	})); err == nil {
		t.Fatal("unknown core key was accepted")
	}
	if _, err := decodeV2GitMetadata(clone(func(metadata map[int]any) {
		delete(metadata, 4)
	})); err == nil {
		t.Fatal("missing required key was accepted")
	}

	if err := validateV2MetadataKeys([]int{1, 2, 8, 128, 9000}, []int{1, 2}, []int{8}); err != nil {
		t.Fatalf("valid acknowledgement key set was refused: %v", err)
	}
	if err := validateV2MetadataKeys([]int{1, 2, 10}, []int{1, 2}, []int{8}); err == nil {
		t.Fatal("undefined core key was accepted")
	}
}

// TestV2PeerFeaturesAreAdvertisedAndParsed covers the only channel by which a
// peer learns what the other side implements, since the protocol negotiates
// capabilities with the server and never between peers.
func TestV2PeerFeaturesAreAdvertisedAndParsed(t *testing.T) {
	runtime := &v2PeerRuntime{state: &v2PeerDeliveryState{
		Chains: map[string]*v2ChainState{
			"out:data": {}, "out:control": {}, "in:data": {}, "in:control": {},
		},
	}}
	metadata := runtime.acknowledgementMetadata(1, bytes.Repeat([]byte{0x01}, 32), make([]byte, 32), 1, nil, nil)
	if metadata[3] != uint64(1) {
		t.Fatalf("acknowledgement result = %#v, want 1", metadata[3])
	}
	if _, exists := metadata[9]; exists {
		t.Fatal("refusal carried result metadata")
	}
	features := v2MetadataFeatures(metadata)
	if len(features) != len(v2LocalPeerFeatures) {
		t.Fatalf("advertised features = %#v, want %#v", features, v2LocalPeerFeatures)
	}
	for index, id := range v2LocalPeerFeatures {
		if features[index] != id {
			t.Fatalf("advertised features = %#v, want %#v", features, v2LocalPeerFeatures)
		}
	}
	if len(features) != 2 || features[0] != 5 || features[1] != 6 {
		t.Fatalf("incremental peer features = %#v", features)
	}
	if v2MetadataFeatures(map[int]any{1: uint64(1)}) != nil {
		t.Fatal("absent feature list produced features")
	}
	if v2MetadataFeatures(map[int]any{kPeerFeatures: []any{"five"}}) != nil {
		t.Fatal("malformed feature list produced features")
	}
	if v2MetadataFeatures(map[int]any{kPeerFeatures: []any{uint64(6), uint64(5)}}) != nil {
		t.Fatal("unsorted feature list produced features")
	}
	if v2MetadataFeatures(map[int]any{kPeerFeatures: []any{uint64(5), uint64(5)}}) != nil {
		t.Fatal("duplicate feature list produced features")
	}
}

// TestV2GitAcknowledgedRefusalIsRecordedBySender checks that a refusal reaching
// the sender is distinguishable from an acknowledgement that has not arrived
// yet. Counting it as pending would leave the operator waiting forever.
func TestV2GitAcknowledgedRefusalIsRecordedBySender(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	commitGitTestFile(t, repositoryPath, "README.md", "refused\n", "refused")
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err := repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		peerID := strings.Repeat("32", 16)
		state := newV2GitPeerState(repositoryID, peerID)
		state.Outbound["deadbeef"] = v2GitOutboundState{
			Sequence: 7, DescriptorDigest: "deadbeef",
			Refs: map[string]string{"refs/heads/main": strings.Repeat("ab", 20)}, Prerequisites: []string{},
		}
		runtime := &v2PeerRuntime{state: &v2PeerDeliveryState{
			Sent: map[string]v2SentDelivery{
				"deadbeef": {Sequence: 7, DescriptorDigest: "deadbeef", PayloadType: 4, Rejected: true, RejectedAt: 99},
			},
		}}
		if err := reconcileV2GitAcknowledgements(runtime, repository, state); err != nil {
			t.Fatal(err)
		}
		outbound := state.Outbound["deadbeef"]
		if !outbound.Rejected || outbound.Acknowledged || outbound.RejectedAt != 99 {
			t.Fatalf("outbound after refusal = %#v", outbound)
		}
		if state.LastAcknowledgedSentSequence != 0 || len(state.LastAcknowledgedRefs) != 0 {
			t.Fatalf("refusal advanced acknowledged state: %#v", state)
		}
		if pending := countPendingV2GitOutbound(state); pending != 0 {
			t.Fatalf("pending outbound after refusal = %d, want 0", pending)
		}
		refused := refusedV2GitCheckpoints(state)
		if len(refused) != 1 || refused[0]["sequence"] != uint64(7) {
			t.Fatalf("refused checkpoints = %#v", refused)
		}
	})
}
