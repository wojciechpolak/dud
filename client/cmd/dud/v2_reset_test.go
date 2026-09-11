// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type resetStatusTestTransport struct {
	response *v2Response
	actions  []uint64
}

func (transport *resetStatusTestTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	var wrapper map[int]any
	if err := v2DecMode.Unmarshal(request.Body, &wrapper); err != nil {
		return nil, err
	}
	action, ok := asV2Uint(wrapper[1])
	if !ok {
		return nil, errors.New("reset test request omitted its action")
	}
	transport.actions = append(transport.actions, action)
	return transport.response, nil
}

func resetTestBytes(start byte, length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = start + byte(index)
	}
	return result
}

func resetTestRuntimes(t *testing.T) (*v2PeerRuntime, *v2PeerRuntime) {
	t.Helper()
	relationshipID := resetTestBytes(0x10, 16)
	seeds := [][]byte{resetTestBytes(0x30, 32), resetTestBytes(0x60, 32)}
	ids := make([][]byte, 2)
	signing := make([][]byte, 2)
	recipients := make([][]byte, 2)
	for role := range uint64(2) {
		var err error
		ids[role], signing[role], recipients[role], err = v2ResetIdentity(seeds[role], relationshipID)
		if err != nil {
			t.Fatal(err)
		}
	}
	forward := resetTestBytes(0x90, 32)
	reverse := resetTestBytes(0xb0, 32)
	runtimes := make([]*v2PeerRuntime, 2)
	for role := range uint64(2) {
		outbound, inbound := forward, reverse
		if role == 1 {
			outbound, inbound = reverse, forward
		}
		pending := &v2PendingPairing{
			RelationshipID:             hex.EncodeToString(relationshipID),
			Role:                       role,
			OutboundRelationshipSecret: v2Base64URL(outbound),
			InboundRelationshipSecret:  v2Base64URL(inbound),
		}
		state := newV2PeerDeliveryState(pending, map[string]string{})
		key, err := deriveV2SigningKey(seeds[role], relationshipID, 0)
		if err != nil {
			t.Fatal(err)
		}
		runtimes[role] = &v2PeerRuntime{
			peer: v2PeerProfile{
				RelationshipID:       hex.EncodeToString(relationshipID),
				PeerPseudonymousID:   hex.EncodeToString(ids[1-role]),
				PeerSigningPublicKey: v2Base64URL(signing[1-role]),
				PeerAgeRecipient:     v2Base64URL(recipients[1-role]),
			},
			state: state, seed: seeds[role], relationshipID: relationshipID,
			localID: ids[role], peerID: ids[1-role], signingKey: key,
			origin: "https://dud.example.com",
		}
	}
	return runtimes[0], runtimes[1]
}

func activeV2ResetResponse(t *testing.T, proposer, accepter *v2PeerRuntime) (map[int]any, map[int]any, map[int]any) {
	t.Helper()
	reset, err := proposer.newV2ResetProposal()
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := decodeV2ResetMap(reset.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	proposalSignature, err := decodeV2Base64URL(reset.ProposalSignature, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accepter.validateV2ResetProposal(proposal, proposalSignature); err != nil {
		t.Fatal(err)
	}
	accepted := &v2RelationshipReset{}
	if err := accepter.acceptV2Reset(accepted, proposal); err != nil {
		t.Fatal(err)
	}
	acceptance, err := decodeV2ResetMap(accepted.Acceptance)
	if err != nil {
		t.Fatal(err)
	}
	acceptanceSignature, err := decodeV2Base64URL(accepted.AcceptanceSignature, 64)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := v2EncMode.Marshal(map[int]any{
		1: proposal, 2: proposalSignature, 3: acceptance, 4: acceptanceSignature,
	})
	if err != nil {
		t.Fatal(err)
	}
	transcriptDigest := sha256.Sum256(transcript)
	receipt, err := v2EncMode.Marshal(map[int]any{
		1: uint64(1), 2: proposal[3], 3: proposal[2], 4: proposal[4],
		5: proposal[6], 6: transcriptDigest[:], 7: uint64(1_800_000_000),
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[int]any{
		1: uint64(2), 2: proposal, 3: proposalSignature,
		4: acceptance, 5: acceptanceSignature, 6: receipt,
	}, proposal, acceptance
}

func TestV2RelationshipResetFindsPeerProposalBeforeCreatingOne(t *testing.T) {
	proposer, accepter := resetTestRuntimes(t)
	reset, err := proposer.newV2ResetProposal()
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := decodeV2ResetMap(reset.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := decodeV2Base64URL(reset.ProposalSignature, 64)
	if err != nil {
		t.Fatal(err)
	}
	body, err := v2EncMode.Marshal(map[int]any{1: uint64(1), 2: proposal, 3: signature})
	if err != nil {
		t.Fatal(err)
	}
	transport := &resetStatusTestTransport{response: &v2Response{
		StatusCode: http.StatusOK, ContentType: v2CBORContentType, Body: body,
	}}
	accepter.transport = transport
	result, found, err := accepter.findV2Reset(context.Background())
	if err != nil || !found {
		t.Fatalf("find reset = %#v, %v", result, err)
	}
	selected, _, err := accepter.applyV2ResetResponse(result)
	if err != nil {
		t.Fatal(err)
	}
	if selected.InitiatorRole == accepter.state.Role || len(transport.actions) != 1 || transport.actions[0] != 2 {
		t.Fatalf("status lookup selected %#v after actions %#v", selected, transport.actions)
	}
}

func TestV2RelationshipResetTreatsMissingStatusAsNoProposal(t *testing.T) {
	_, runtime := resetTestRuntimes(t)
	body, err := v2EncMode.Marshal(map[int]any{1: uint64(4), 2: "Relationship reset is not available."})
	if err != nil {
		t.Fatal(err)
	}
	transport := &resetStatusTestTransport{response: &v2Response{
		StatusCode: http.StatusNotFound, ContentType: v2CBORContentType, Body: body,
	}}
	runtime.transport = transport
	result, found, err := runtime.findV2Reset(context.Background())
	if err != nil || found || result != nil {
		t.Fatalf("missing reset = %#v, %v, %v", result, found, err)
	}
}

func TestV2RelationshipResetVerifiesBothConsentsAndReceipt(t *testing.T) {
	proposer, accepter := resetTestRuntimes(t)
	response, proposal, _ := activeV2ResetResponse(t, proposer, accepter)
	for _, runtime := range []*v2PeerRuntime{proposer, accepter} {
		reset, selected, err := runtime.applyV2ResetResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		if reset.Generation != 1 || !reset.LocalConsent || !reset.PeerConsent || !reset.ServerActivated || reset.Phase != "active" {
			t.Fatalf("active reset = %#v", reset)
		}
		if !bytes.Equal(selected[4].([]byte), proposal[4].([]byte)) {
			t.Fatal("client selected a different relationship generation")
		}
	}

	tamperedAcceptance := map[int]any{}
	for key, value := range response {
		tamperedAcceptance[key] = value
	}
	tamperedAcceptance[5] = resetTestBytes(0x01, 64)
	if _, _, err := proposer.applyV2ResetResponse(tamperedAcceptance); err == nil || !strings.Contains(err.Error(), "acceptance signature") {
		t.Fatalf("tampered acceptance error = %v", err)
	}

	tamperedReceipt := map[int]any{}
	for key, value := range response {
		tamperedReceipt[key] = value
	}
	receipt := map[int]any{
		1: uint64(1), 2: proposal[3], 3: proposal[2], 4: resetTestBytes(0xee, 16),
		5: proposal[6], 6: resetTestBytes(0xdd, 32), 7: uint64(1_800_000_000),
	}
	tamperedReceipt[6], _ = v2EncMode.Marshal(receipt)
	if _, _, err := proposer.applyV2ResetResponse(tamperedReceipt); err == nil || !strings.Contains(err.Error(), "receipt binding") {
		t.Fatalf("tampered receipt error = %v", err)
	}
}

func TestV2RelationshipResetCreatesDisjointSecretsAndZeroedChains(t *testing.T) {
	proposer, accepter := resetTestRuntimes(t)
	response, proposal, _ := activeV2ResetResponse(t, proposer, accepter)
	proposerReset, _, err := proposer.applyV2ResetResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	accepterReset, _, err := accepter.applyV2ResetResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	newRelationshipID := proposal[4].([]byte)
	resetID := proposal[3].([]byte)
	proposerOut, _ := decodeV2Base64URL(proposer.state.OutboundRelationshipSecret, 32)
	accepterIn, _ := decodeV2Base64URL(accepter.state.InboundRelationshipSecret, 32)
	newProposerOut, err := deriveV2ResetRelationshipSecret(proposerOut, resetID, newRelationshipID, v2OutboundDirection(proposer.state.Role))
	if err != nil {
		t.Fatal(err)
	}
	newAccepterIn, err := deriveV2ResetRelationshipSecret(accepterIn, resetID, newRelationshipID, v2InboundDirection(accepter.state.Role))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newProposerOut, newAccepterIn) || bytes.Equal(newProposerOut, proposerOut) {
		t.Fatal("reset relationship secrets are not fresh and directionally shared")
	}
	for role, reset := range []*v2RelationshipReset{proposerReset, accepterReset} {
		pending := &v2PendingPairing{RelationshipID: reset.NewRelationshipID, Role: uint64(role), OutboundRelationshipSecret: v2Base64URL(newProposerOut), InboundRelationshipSecret: v2Base64URL(newAccepterIn)}
		state := newV2PeerDeliveryState(pending, map[string]string{})
		state.Generation = reset.Generation
		initializeV2ResetChains(state, newRelationshipID)
		for name, chain := range state.Chains {
			if chain.SendSequence != 0 || chain.ReceiveWatermark != 0 || chain.SendDigest == strings.Repeat("0", 64) || chain.SendDigest != chain.ReceiveDigest {
				t.Fatalf("fresh chain %s = %#v", name, chain)
			}
		}
	}
	if v2ResetChainGenesis(newRelationshipID, 0, 0) != func() string {
		state := newV2PeerDeliveryState(&v2PendingPairing{Role: 1}, map[string]string{})
		initializeV2ResetChains(state, newRelationshipID)
		return state.Chains["in:data"].ReceiveDigest
	}() {
		t.Fatal("opposite peers derived different data-chain genesis digests")
	}
}

func TestV2RelationshipResetCleansOnlyTargetPeerGitState(t *testing.T) {
	repositoryPath := t.TempDir()
	runGitTestCommand(t, repositoryPath, "init")
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repositoryPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	common := strings.TrimSpace(runGitTestCommand(t, repositoryPath, "rev-parse", "--git-common-dir"))
	if !filepath.IsAbs(common) {
		common = filepath.Join(repositoryPath, common)
	}
	repository := &v2GitRepository{CommonDir: common, DUDDir: filepath.Join(common, "dud")}
	for _, directory := range []string{repository.DUDDir, filepath.Join(repository.DUDDir, "peers"), filepath.Join(repository.DUDDir, "transfers"), filepath.Join(repository.DUDDir, "quarantine")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	repositoryID := resetTestBytes(0x22, 16)
	if err := repository.associateRepositoryID(repositoryID); err != nil {
		t.Fatal(err)
	}
	oldPeerID := hex.EncodeToString(resetTestBytes(0x44, 16))
	digest := hex.EncodeToString(resetTestBytes(0x66, 32))
	bundle := filepath.Join(repository.DUDDir, "transfers", digest+".bundle")
	if err := os.WriteFile(bundle, []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	quarantine := filepath.Join(repository.DUDDir, "quarantine", digest)
	if err := os.Mkdir(quarantine, 0o700); err != nil {
		t.Fatal(err)
	}
	state := newV2GitPeerState(repositoryID, oldPeerID)
	state.Inbound[digest] = v2GitInboundState{DescriptorDigest: digest, BundlePath: bundle, Phase: "quarantined"}
	if err := repository.writePeerState(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.loadPeerState(repositoryID, oldPeerID)
	if err != nil || loaded.Inbound[digest].BundlePath != bundle {
		t.Fatalf("stored reset Git state = %#v, %v", loaded, err)
	}
	otherPeerID := hex.EncodeToString(resetTestBytes(0x88, 16))
	other := newV2GitPeerState(repositoryID, otherPeerID)
	if err := repository.writePeerState(other); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteV2File(repository.managedRefsPath(), []byte("{\"version\":1,\"refs\":{}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newApp(bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{})
	probe := a.localV2GitCommand("rev-parse", "--git-common-dir")
	probe.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0")
	if output, err := probe.Output(); err != nil || strings.TrimSpace(string(output)) != ".git" {
		t.Fatalf("Git reset probe = %q, %v", output, err)
	}
	if err := cleanupV2ResetGitState(a, oldPeerID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{repository.peerStatePath(oldPeerID), bundle, quarantine} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("reset retained %s", path)
		}
	}
	for _, path := range []string{repository.repoIDPath(), repository.managedRefsPath(), repository.peerStatePath(otherPeerID)} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("reset removed retained state %s: %v", path, err)
		}
	}
}

func v2ResetServerContract(t *testing.T, state *v2PeerDeliveryState) {
	t.Helper()
	capabilities, err := state.ServerContract.capabilities()
	if err != nil {
		t.Fatal(err)
	}
	if !hasV2Feature(capabilities.Features, 12) {
		capabilities.Features = append(capabilities.Features, 12)
	}
	contract, err := newV2ServerContract(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	state.ServerContract = contract
}

func TestV2RelationshipResetRejectsMixedVersionsWithoutWritingState(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	state.PeerFeatures = []uint64{12}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	path := peerDeliveryStatePath(paths, state.RelationshipID)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{})
	if err := a.cmdPeerReset([]string{"laptop", "--yes"}); err == nil || !strings.Contains(err.Error(), "server does not support") {
		t.Fatalf("missing server feature error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("server feature rejection changed peer state")
	}

	v2ResetServerContract(t, state)
	state.PeerFeatures = nil
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	before, _ = os.ReadFile(path)
	if err := a.cmdPeerReset([]string{"laptop", "--yes"}); err == nil || !strings.Contains(err.Error(), "peer does not advertise") {
		t.Fatalf("missing peer feature error = %v", err)
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("peer feature rejection changed peer state")
	}
}

func TestV2RelationshipResetPreviewRemainsAvailableWhileHalted(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	v2ResetServerContract(t, state)
	state.PeerFeatures = []uint64{12}
	state.Halted = true
	state.HaltReason = "signed peer rollback"
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	a := newApp(bytes.NewReader(nil), &output, &bytes.Buffer{})
	err := a.cmdPeerReset([]string{"laptop"})
	if err == nil || !strings.Contains(err.Error(), "rerun with --yes") || !strings.Contains(output.String(), "Peer relationship reset") {
		t.Fatalf("halted reset preview = %q, %v", output.String(), err)
	}
}

func TestV2RelationshipResetDispositionMatchesPreviewClasses(t *testing.T) {
	_, state := newPairedV2TestPeer(t, "laptop")
	state.PendingGranularDeliveries = []v2PendingGranularDelivery{{DescriptorDigest: strings.Repeat("01", 32)}}
	state.PendingChunkDeliveries = []v2PendingChunkDelivery{
		{DescriptorDigest: strings.Repeat("02", 32)},
		{DescriptorDigest: strings.Repeat("03", 32)},
	}
	state.PendingCompletions = []v2PendingCompletion{{DescriptorDigest: strings.Repeat("04", 32)}}
	state.PendingControlPublications = []v2PendingControlPublication{{OperationID: strings.Repeat("05", 16)}}
	state.Sent = map[string]v2SentDelivery{
		"unacknowledged": {PayloadType: 1},
		"refused-git":    {PayloadType: 4, Acknowledged: true, Rejected: true},
	}
	state.InboundTransfers = map[string]v2InboundTransfer{
		"small": {DescriptorDigest: strings.Repeat("06", 32)},
		"chunked": {
			DescriptorDigest: strings.Repeat("07", 32),
			Chunks:           []v2InboundChunkPart{{CiphertextLength: 1024}},
		},
	}
	state.Chains["in:data"].Quarantined = true
	state.Chains["out:control"].Quarantined = true

	got := v2ResetDispositionOf(state)
	want := v2ResetDisposition{
		QueuedDeliveries: 3, QueuedCompletions: 1, QueuedControlEvents: 1,
		Unacknowledged: 1, InboundTransfers: 2, QuarantinedChains: 2,
		ResumableTransfers: 3, RefusedGitCheckpoints: 1,
	}
	if got != want {
		t.Fatalf("reset disposition = %#v, want %#v", got, want)
	}
	roundTrip, err := decodeV2ResetDisposition(encodeV2ResetDisposition(got))
	if err != nil || roundTrip != want {
		t.Fatalf("reset disposition round trip = %#v, %v", roundTrip, err)
	}
}
