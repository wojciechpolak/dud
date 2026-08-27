// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func mustV2TestServerContract(t *testing.T) v2ServerContract {
	t.Helper()
	body, err := hex.DecodeString(v2CapabilitiesVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := decodeV2Capabilities(body)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := newV2ServerContract(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

type failingPeerTransport struct {
	requests int
}

type emptySlotTransport struct {
	requests   int
	dataProofs int
}

type controlPublicationTransport struct {
	operationID []byte
	requests    int
}

type retryingControlPublicationTransport struct {
	operationID []byte
	requests    int
	nonces      [][]byte
}

type granularDeliveryPublicationTransport struct {
	response []byte
	requests int
}

type retryingGranularDeliveryPublicationTransport struct {
	response     []byte
	requests     int
	operationIDs [][]byte
	nonces       [][]byte
}

type completionPublicationTransport struct {
	response []byte
	requests int
}

type retryingCompletionPublicationTransport struct {
	response      []byte
	requests      int
	operationIDs  [][]byte
	ackNonces     [][]byte
	controlNonces [][]byte
}

func (transport *emptySlotTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests++
	if request.Method != "POST" || request.Path != "/v2/inbox" {
		return nil, errors.New("unexpected bounded-drain request")
	}
	var query map[int]any
	if err := v2DecMode.Unmarshal(request.Body, &query); err != nil {
		return nil, err
	}
	rawProofs, ok := query[1].([]any)
	if !ok {
		return nil, errors.New("inbox request data proofs are invalid")
	}
	transport.dataProofs = len(rawProofs)
	results := make([]any, 0, len(rawProofs))
	for _, raw := range rawProofs {
		proof, err := normalizeV2Map(raw)
		if err != nil {
			return nil, err
		}
		results = append(results, map[int]any{1: proof[1], 2: proof[2], 3: false})
	}
	digest := sha256.Sum256(nil)
	body, err := encodeV2GranularFrame(map[int]any{
		1: results,
		2: []any{},
		7: uint64(0),
		8: digest[:],
		9: []any{},
	}, nil, 7, 8)
	if err != nil {
		return nil, err
	}
	return &v2Response{
		StatusCode:  200,
		ContentType: v2CBORContentType,
		Body:        body,
	}, nil
}

func (transport *failingPeerTransport) Do(context.Context, v2Request) (*v2Response, error) {
	transport.requests++
	return nil, errors.New("injected transport failure")
}

func (transport *controlPublicationTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests++
	if request.Method != "POST" || request.Path != "/v2/control-events" {
		return nil, errors.New("unexpected control publication request")
	}
	body, err := v2EncMode.Marshal(map[int]any{1: transport.operationID, 2: false})
	if err != nil {
		return nil, err
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
}

func (transport *retryingControlPublicationTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests++
	if request.Method != "POST" || request.Path != "/v2/control-events" {
		return nil, errors.New("unexpected control publication request")
	}
	var body map[int]any
	if err := v2DecMode.Unmarshal(request.Body, &body); err != nil {
		return nil, err
	}
	nonce, err := granularProofNonce(body[2])
	if err != nil {
		return nil, err
	}
	transport.nonces = append(transport.nonces, nonce)
	if transport.requests == 1 {
		return nil, retryableV2TestError{}
	}
	response, err := v2EncMode.Marshal(map[int]any{1: transport.operationID, 2: true})
	if err != nil {
		return nil, err
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: response}, nil
}

func (transport *granularDeliveryPublicationTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests++
	if request.Method != "POST" || request.Path != "/v2/deliveries" {
		return nil, errors.New("unexpected granular delivery request")
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.response}, nil
}

func (transport *retryingGranularDeliveryPublicationTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests++
	if request.Method != "POST" || request.Path != "/v2/deliveries" {
		return nil, errors.New("unexpected granular delivery request")
	}
	header, _, err := decodeV2GranularFrame(request.Body, 4, 5)
	if err != nil {
		return nil, err
	}
	operationID, operationOK := header[1].([]byte)
	proofSlot, proofErr := normalizeV2Map(header[6])
	if !operationOK || proofErr != nil {
		return nil, errors.New("granular delivery request is missing authorization")
	}
	proofBytes, proofOK := proofSlot[4].([]byte)
	if !proofOK {
		return nil, errors.New("granular delivery proof is invalid")
	}
	var proof map[int]any
	if err := v2DecMode.Unmarshal(proofBytes, &proof); err != nil {
		return nil, err
	}
	nonce, nonceOK := proof[2].([]byte)
	if !nonceOK || len(nonce) != 16 {
		return nil, errors.New("granular delivery proof nonce is invalid")
	}
	transport.operationIDs = append(transport.operationIDs, append([]byte(nil), operationID...))
	transport.nonces = append(transport.nonces, append([]byte(nil), nonce...))
	if transport.requests == 1 {
		return nil, retryableV2TestError{}
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.response}, nil
}

type retryableV2TestError struct{}

func (retryableV2TestError) Error() string   { return "injected temporary network failure" }
func (retryableV2TestError) Timeout() bool   { return false }
func (retryableV2TestError) Temporary() bool { return true }

func (transport *completionPublicationTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests++
	if request.Method != "POST" || !strings.HasSuffix(request.Path, "/complete") {
		return nil, errors.New("unexpected completion request")
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.response}, nil
}

func (transport *retryingCompletionPublicationTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests++
	if request.Method != "POST" || !strings.HasSuffix(request.Path, "/complete") {
		return nil, errors.New("unexpected completion request")
	}
	var body map[int]any
	if err := v2DecMode.Unmarshal(request.Body, &body); err != nil {
		return nil, err
	}
	operationID, operationOK := body[9].([]byte)
	ackNonce, err := granularProofNonce(body[2])
	if err != nil {
		return nil, err
	}
	controlNonce, err := granularProofNonce(body[3])
	if err != nil {
		return nil, err
	}
	if !operationOK || len(operationID) != 16 {
		return nil, errors.New("completion operation ID is invalid")
	}
	transport.operationIDs = append(transport.operationIDs, append([]byte(nil), operationID...))
	transport.ackNonces = append(transport.ackNonces, ackNonce)
	transport.controlNonces = append(transport.controlNonces, controlNonce)
	if transport.requests == 1 {
		return nil, retryableV2TestError{}
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.response}, nil
}

func granularProofNonce(raw any) ([]byte, error) {
	slot, err := normalizeV2Map(raw)
	if err != nil {
		return nil, errors.New("completion authorization slot is invalid")
	}
	proofBytes, ok := slot[4].([]byte)
	if !ok {
		return nil, errors.New("completion authorization proof is invalid")
	}
	var proof map[int]any
	if err := v2DecMode.Unmarshal(proofBytes, &proof); err != nil {
		return nil, err
	}
	nonce, ok := proof[2].([]byte)
	if !ok || len(nonce) != 16 {
		return nil, errors.New("completion authorization nonce is invalid")
	}
	return append([]byte(nil), nonce...), nil
}

func TestV2EffectivePolicyAcceptsOnlySafeExpiryDominance(t *testing.T) {
	signed := map[int]any{
		1: uint64(100),
		2: uint64(1),
		3: uint64(300),
		4: uint64(1),
	}
	earlier := map[int]any{
		1: uint64(90),
		2: uint64(1),
		3: uint64(300),
		4: uint64(1),
	}
	if err := validateV2EffectivePolicy(signed, earlier); err != nil {
		t.Fatalf("earlier effective expiry was rejected: %v", err)
	}
	later := map[int]any{
		1: uint64(101),
		2: uint64(1),
		3: uint64(300),
		4: uint64(1),
	}
	if err := validateV2EffectivePolicy(signed, later); err == nil {
		t.Fatal("later effective expiry was accepted")
	}
	changed := map[int]any{
		1: uint64(90),
		2: uint64(0),
		3: uint64(300),
		4: uint64(1),
	}
	if err := validateV2EffectivePolicy(signed, changed); err == nil {
		t.Fatal("changed consume semantics were accepted")
	}
}

func TestV2DeliveryChainQuarantinesGapAndForkIndependently(t *testing.T) {
	state := &v2PeerDeliveryState{
		Chains: map[string]*v2ChainState{
			"in:data":    emptyV2ChainState(),
			"in:control": emptyV2ChainState(),
		},
	}
	runtime := &v2PeerRuntime{state: state}
	gap := &validatedV2Envelope{
		Descriptor: map[int]any{
			kSequence:       uint64(2),
			kPreviousDigest: make([]byte, 32),
		},
		DescriptorDigest: sha256.Sum256([]byte("gap")),
	}
	if _, err := runtime.validateNextDescriptor(state.Chains["in:data"], gap); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("gap error = %v", err)
	}
	if !state.Chains["in:data"].Quarantined {
		t.Fatal("data chain was not quarantined")
	}
	if state.Chains["in:control"].Quarantined {
		t.Fatal("data divergence quarantined the independent control chain")
	}

	forkChain := emptyV2ChainState()
	forkChain.ReceiveWatermark = 1
	forkChain.ReceiveDigest = strings.Repeat("11", 32)
	forkChain.Replay[1] = v2ReplayEntry{
		Sequence:         1,
		DescriptorDigest: strings.Repeat("22", 32),
	}
	fork := &validatedV2Envelope{
		Descriptor: map[int]any{
			kSequence:       uint64(1),
			kPreviousDigest: make([]byte, 32),
		},
		DescriptorDigest: sha256.Sum256([]byte("different")),
	}
	if _, err := runtime.validateNextDescriptor(forkChain, fork); err == nil || !strings.Contains(err.Error(), "fork") {
		t.Fatalf("fork error = %v", err)
	}
}

func TestV2FailedCompletionRemainsDurableWithoutCompletingSend(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
		Lock:      filepath.Join(root, "config", ".config.lock"),
	}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("12", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"invitee->inviter|ack":   v2Base64URL(bytesRepeatV2(0x51, 32)),
			"inviter->invitee|write": v2Base64URL(bytesRepeatV2(0x52, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data":    emptyV2ChainState(),
			"out:control": emptyV2ChainState(),
			"in:data":     emptyV2ChainState(),
			"in:control":  emptyV2ChainState(),
		},
		PendingCompletions: []v2PendingCompletion{{
			DeliveryID:       strings.Repeat("01", 16),
			SourceSlot:       strings.Repeat("02", 16),
			SourceSlotEpoch:  20_000,
			TargetSlot:       strings.Repeat("03", 16),
			TargetSlotEpoch:  20_000,
			PolicyDigest:     strings.Repeat("04", 32),
			DescriptorDigest: strings.Repeat("05", 32),
			OperationID:      strings.Repeat("06", 16),
			Acknowledgement:  v2Base64URL([]byte("encrypted-acknowledgement")),
			CreatedAt:        uint64(time.Now().Unix()),
		}},
		InboundTransfers: map[string]v2InboundTransfer{},
		Sent: map[string]v2SentDelivery{
			"delivery": {Sequence: 1, DescriptorDigest: "delivery"},
		},
		SignedAcknowledgements: map[string]string{},
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &failingPeerTransport{}
	runtime := &v2PeerRuntime{
		paths:     paths,
		state:     state,
		transport: transport,
		origin:    "https://dud.example.com",
	}
	if err := runtime.flushPendingCompletions(context.Background()); err == nil {
		t.Fatal("injected completion failure was ignored")
	}
	reloaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.PendingCompletions) != 1 ||
		reloaded.PendingCompletions[0].Attempts != 1 {
		t.Fatalf("durable queue = %#v", reloaded.PendingCompletions)
	}
	if reloaded.Sent["delivery"].Acknowledged {
		t.Fatal("failed completion advanced sender completion")
	}
}

func TestV2BoundedControlFailureIsRecordedForCallerToTreatAsNoInformation(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
		Lock:      filepath.Join(root, "config", ".config.lock"),
	}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("23", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"invitee->inviter|read": v2Base64URL(bytesRepeatV2(0x51, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data":    emptyV2ChainState(),
			"out:control": emptyV2ChainState(),
			"in:data":     emptyV2ChainState(),
			"in:control":  emptyV2ChainState(),
		},
		InboundTransfers:       map[string]v2InboundTransfer{},
		Sent:                   map[string]v2SentDelivery{},
		SignedAcknowledgements: map[string]string{},
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	runtime := &v2PeerRuntime{
		paths:     paths,
		state:     state,
		transport: &failingPeerTransport{},
		origin:    "https://dud.example.com",
	}
	if err := runtime.boundedControlDrain(context.Background()); err == nil {
		t.Fatal("injected control-drain failure was not reported internally")
	}
	reloaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.UndrainedControl || reloaded.ConsecutiveDrainFailures != 1 {
		t.Fatalf("drain state = %#v", reloaded)
	}
}

func TestV2PendingControlPublicationRetriesThroughInlineEndpoint(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
		Lock:      filepath.Join(root, "config", ".config.lock"),
	}
	operationID := bytesRepeatV2(0x64, 16)
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("24", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"inviter->invitee|write": v2Base64URL(bytesRepeatV2(0x51, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data":    emptyV2ChainState(),
			"out:control": emptyV2ChainState(),
			"in:data":     emptyV2ChainState(),
			"in:control":  emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{{
			OperationID:    hex.EncodeToString(operationID),
			EncryptedEvent: v2Base64URL([]byte("encrypted-control")),
			ControlSlot:    hex.EncodeToString(bytesRepeatV2(0x52, 16)),
			SlotEpoch:      20_000,
			CreatedAt:      uint64(time.Now().Unix()),
		}},
		InboundTransfers:       map[string]v2InboundTransfer{},
		Sent:                   map[string]v2SentDelivery{},
		SignedAcknowledgements: map[string]string{},
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &controlPublicationTransport{operationID: operationID}
	runtime := &v2PeerRuntime{paths: paths, state: state, transport: transport, origin: "https://dud.example.com"}
	if err := runtime.flushPendingControlPublications(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.requests != 1 || len(state.PendingControlPublications) != 0 {
		t.Fatalf("control publication state = %#v", state.PendingControlPublications)
	}
}

func TestV2ControlPublicationRetriesOnceWithFreshAuthorizationNonce(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), Lock: filepath.Join(root, "config", ".config.lock")}
	operationID := bytesRepeatV2(0x71, 16)
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("72", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"inviter->invitee|write": v2Base64URL(bytesRepeatV2(0x73, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data": emptyV2ChainState(), "out:control": emptyV2ChainState(),
			"in:data": emptyV2ChainState(), "in:control": emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{{
			OperationID:    hex.EncodeToString(operationID),
			EncryptedEvent: v2Base64URL([]byte("encrypted-control")),
			ControlSlot:    hex.EncodeToString(bytesRepeatV2(0x74, 16)),
			SlotEpoch:      20_000,
			CreatedAt:      uint64(time.Now().Unix()),
		}},
		InboundTransfers:       map[string]v2InboundTransfer{},
		Sent:                   map[string]v2SentDelivery{},
		SignedAcknowledgements: map[string]string{},
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &retryingControlPublicationTransport{operationID: operationID}
	runtime := &v2PeerRuntime{paths: paths, state: state, transport: transport, origin: "https://dud.example.com"}
	if err := runtime.flushPendingControlPublications(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.requests != 2 || len(state.PendingControlPublications) != 0 {
		t.Fatalf("control publication retry state = %#v after %d requests", state.PendingControlPublications, transport.requests)
	}
	if bytes.Equal(transport.nonces[0], transport.nonces[1]) {
		t.Fatalf("control publication retry reused proof nonce %x", transport.nonces[0])
	}
}

func TestV2PendingGranularDeliveryPublishesThroughAtomicEndpoint(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
		Lock:      filepath.Join(root, "config", ".config.lock"),
	}
	policy := v2TransportPolicyMap(v2TransportPolicy{ExpiresAt: 1_800_000_000, Consume: 0, ClaimLeaseSeconds: 300, AckMode: 1})
	policyBytes, err := v2EncMode.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	operationID := bytesRepeatV2(0x64, 16)
	response, err := v2EncMode.Marshal(map[int]any{
		1: bytesRepeatV2(0x65, 16),
		2: policy,
		3: false,
		4: []any{},
		5: []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("25", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"inviter->invitee|write": v2Base64URL(bytesRepeatV2(0x51, 32)),
			"invitee->inviter|read":  v2Base64URL(bytesRepeatV2(0x52, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data":    emptyV2ChainState(),
			"out:control": emptyV2ChainState(),
			"in:data":     emptyV2ChainState(),
			"in:control":  emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{},
		PendingGranularDeliveries: []v2PendingGranularDelivery{{
			OperationID:         hex.EncodeToString(operationID),
			EncryptedDescriptor: v2Base64URL([]byte("encrypted-descriptor")),
			PayloadCiphertext:   v2Base64URL([]byte("ciphertext")),
			DataSlot:            hex.EncodeToString(bytesRepeatV2(0x53, 16)),
			SlotEpoch:           20_000,
			RequestedPolicy:     v2Base64URL(policyBytes),
			DescriptorDigest:    strings.Repeat("26", 32),
			Sequence:            1,
			CreatedAt:           uint64(time.Now().Unix()),
		}},
		InboundTransfers:       map[string]v2InboundTransfer{},
		Sent:                   map[string]v2SentDelivery{},
		SignedAcknowledgements: map[string]string{},
		DataScanEpoch:          20_000,
		ControlScanEpoch:       20_000,
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &granularDeliveryPublicationTransport{response: response}
	runtime := &v2PeerRuntime{paths: paths, state: state, transport: transport, origin: "https://dud.example.com"}
	if err := runtime.flushPendingGranularDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.requests != 1 || len(state.PendingGranularDeliveries) != 0 {
		t.Fatalf("granular delivery state = %#v", state.PendingGranularDeliveries)
	}
}

func TestV2GranularDeliveryRetriesOnceWithFreshAuthorizationNonce(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
		Lock:      filepath.Join(root, "config", ".config.lock"),
	}
	policy := v2TransportPolicyMap(v2TransportPolicy{ExpiresAt: 1_800_000_000, Consume: 0, ClaimLeaseSeconds: 300, AckMode: 1})
	policyBytes, err := v2EncMode.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	operationID := bytesRepeatV2(0x74, 16)
	response, err := v2EncMode.Marshal(map[int]any{
		1: bytesRepeatV2(0x75, 16), 2: policy, 3: true, 4: []any{}, 5: []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("76", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"inviter->invitee|write": v2Base64URL(bytesRepeatV2(0x77, 32)),
			"invitee->inviter|read":  v2Base64URL(bytesRepeatV2(0x78, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data": emptyV2ChainState(), "out:control": emptyV2ChainState(),
			"in:data": emptyV2ChainState(), "in:control": emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{},
		PendingGranularDeliveries: []v2PendingGranularDelivery{{
			OperationID:         hex.EncodeToString(operationID),
			EncryptedDescriptor: v2Base64URL([]byte("encrypted-descriptor")),
			PayloadCiphertext:   v2Base64URL([]byte("ciphertext")),
			DataSlot:            hex.EncodeToString(bytesRepeatV2(0x79, 16)),
			SlotEpoch:           20_000,
			RequestedPolicy:     v2Base64URL(policyBytes),
			DescriptorDigest:    strings.Repeat("7a", 32),
			Sequence:            1,
			CreatedAt:           uint64(time.Now().Unix()),
		}},
		InboundTransfers:       map[string]v2InboundTransfer{},
		Sent:                   map[string]v2SentDelivery{},
		SignedAcknowledgements: map[string]string{},
		DataScanEpoch:          20_000,
		ControlScanEpoch:       20_000,
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &retryingGranularDeliveryPublicationTransport{response: response}
	runtime := &v2PeerRuntime{paths: paths, state: state, transport: transport, origin: "https://dud.example.com"}
	if err := runtime.flushPendingGranularDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.requests != 2 || len(state.PendingGranularDeliveries) != 0 {
		t.Fatalf("granular delivery retry state = %#v after %d requests", state.PendingGranularDeliveries, transport.requests)
	}
	if !bytes.Equal(transport.operationIDs[0], operationID) || !bytes.Equal(transport.operationIDs[1], operationID) {
		t.Fatalf("operation IDs changed across retry: %x, %x", transport.operationIDs[0], transport.operationIDs[1])
	}
	if bytes.Equal(transport.nonces[0], transport.nonces[1]) {
		t.Fatalf("delivery retry reused proof nonce %x", transport.nonces[0])
	}
}

func TestV2PendingCompletionRetriesThroughAtomicEndpoint(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), Lock: filepath.Join(root, "config", ".config.lock")}
	deliveryID := bytesRepeatV2(0x61, 16)
	response, err := v2EncMode.Marshal(map[int]any{1: deliveryID, 2: bytesRepeatV2(0x62, 16), 3: false})
	if err != nil {
		t.Fatal(err)
	}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("27", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"invitee->inviter|ack":   v2Base64URL(bytesRepeatV2(0x51, 32)),
			"inviter->invitee|write": v2Base64URL(bytesRepeatV2(0x52, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data": emptyV2ChainState(), "out:control": emptyV2ChainState(), "in:data": emptyV2ChainState(), "in:control": emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{},
		PendingGranularDeliveries:  []v2PendingGranularDelivery{},
		PendingCompletions: []v2PendingCompletion{{
			DeliveryID:       hex.EncodeToString(deliveryID),
			SourceSlot:       hex.EncodeToString(bytesRepeatV2(0x63, 16)),
			SourceSlotEpoch:  20_000,
			TargetSlot:       hex.EncodeToString(bytesRepeatV2(0x64, 16)),
			TargetSlotEpoch:  20_000,
			PolicyDigest:     strings.Repeat("65", 32),
			DescriptorDigest: strings.Repeat("66", 32),
			OperationID:      strings.Repeat("67", 16),
			Acknowledgement:  v2Base64URL([]byte("encrypted-acknowledgement")),
			CreatedAt:        uint64(time.Now().Unix()),
		}},
		InboundTransfers:       map[string]v2InboundTransfer{},
		Sent:                   map[string]v2SentDelivery{},
		SignedAcknowledgements: map[string]string{},
		DataScanEpoch:          20_000,
		ControlScanEpoch:       20_000,
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &completionPublicationTransport{response: response}
	runtime := &v2PeerRuntime{paths: paths, state: state, transport: transport, origin: "https://dud.example.com"}
	if err := runtime.flushPendingCompletions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.requests != 1 || len(state.PendingCompletions) != 0 {
		t.Fatalf("completion state = %#v", state.PendingCompletions)
	}
}

func TestV2CompletionRetriesOnceWithFreshAuthorizationNonces(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), Lock: filepath.Join(root, "config", ".config.lock")}
	deliveryID := bytesRepeatV2(0x81, 16)
	operationID := bytesRepeatV2(0x82, 16)
	response, err := v2EncMode.Marshal(map[int]any{1: deliveryID, 2: bytesRepeatV2(0x83, 16), 3: true})
	if err != nil {
		t.Fatal(err)
	}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("84", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"invitee->inviter|ack":   v2Base64URL(bytesRepeatV2(0x85, 32)),
			"inviter->invitee|write": v2Base64URL(bytesRepeatV2(0x86, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data": emptyV2ChainState(), "out:control": emptyV2ChainState(),
			"in:data": emptyV2ChainState(), "in:control": emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{},
		PendingGranularDeliveries:  []v2PendingGranularDelivery{},
		PendingCompletions: []v2PendingCompletion{{
			DeliveryID:       hex.EncodeToString(deliveryID),
			SourceSlot:       hex.EncodeToString(bytesRepeatV2(0x87, 16)),
			SourceSlotEpoch:  20_000,
			TargetSlot:       hex.EncodeToString(bytesRepeatV2(0x88, 16)),
			TargetSlotEpoch:  20_000,
			PolicyDigest:     strings.Repeat("89", 32),
			DescriptorDigest: strings.Repeat("8a", 32),
			OperationID:      hex.EncodeToString(operationID),
			Acknowledgement:  v2Base64URL([]byte("encrypted-acknowledgement")),
			CreatedAt:        uint64(time.Now().Unix()),
		}},
		InboundTransfers:       map[string]v2InboundTransfer{},
		Sent:                   map[string]v2SentDelivery{},
		SignedAcknowledgements: map[string]string{},
		DataScanEpoch:          20_000,
		ControlScanEpoch:       20_000,
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &retryingCompletionPublicationTransport{response: response}
	runtime := &v2PeerRuntime{paths: paths, state: state, transport: transport, origin: "https://dud.example.com"}
	if err := runtime.flushPendingCompletions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.requests != 2 || len(state.PendingCompletions) != 0 {
		t.Fatalf("completion retry state = %#v after %d requests", state.PendingCompletions, transport.requests)
	}
	if !bytes.Equal(transport.operationIDs[0], operationID) || !bytes.Equal(transport.operationIDs[1], operationID) {
		t.Fatalf("completion operation IDs changed across retry: %x, %x", transport.operationIDs[0], transport.operationIDs[1])
	}
	if bytes.Equal(transport.ackNonces[0], transport.ackNonces[1]) || bytes.Equal(transport.controlNonces[0], transport.controlNonces[1]) {
		t.Fatalf("completion retry reused authorization nonces: ack=%x/%x control=%x/%x", transport.ackNonces[0], transport.ackNonces[1], transport.controlNonces[0], transport.controlNonces[1])
	}
}

func TestV2SignedWatermarksDetectLocalAndPeerRollback(t *testing.T) {
	state := &v2PeerDeliveryState{
		Chains: map[string]*v2ChainState{
			"out:data":    emptyV2ChainState(),
			"out:control": emptyV2ChainState(),
			"in:data":     emptyV2ChainState(),
			"in:control":  emptyV2ChainState(),
		},
		Sent: map[string]v2SentDelivery{},
	}
	state.Chains["out:data"].SendSequence = 2
	runtime := &v2PeerRuntime{state: state}
	if err := runtime.validatePeerWatermarks([4]uint64{0, 1, 3, 0}); err == nil ||
		!strings.Contains(err.Error(), "local rollback") {
		t.Fatalf("local rollback error = %v", err)
	}
	if !state.Halted {
		t.Fatal("local rollback did not halt the relationship")
	}

	state.Halted = false
	state.HaltReason = ""
	state.Sent["proof"] = v2SentDelivery{
		Sequence:     2,
		Acknowledged: true,
	}
	if err := runtime.validatePeerWatermarks([4]uint64{0, 1, 1, 0}); err == nil ||
		!strings.Contains(err.Error(), "peer rollback") {
		t.Fatalf("peer rollback error = %v", err)
	}
	if !state.Halted {
		t.Fatal("peer rollback did not halt the relationship")
	}
}

func TestV2ControlDrainUsesExactlyOneInboxRequest(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
		Lock:      filepath.Join(root, "config", ".config.lock"),
	}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("45", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"invitee->inviter|read": v2Base64URL(bytesRepeatV2(0x51, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data":    emptyV2ChainState(),
			"out:control": emptyV2ChainState(),
			"in:data":     emptyV2ChainState(),
			"in:control":  emptyV2ChainState(),
		},
		InboundTransfers:       map[string]v2InboundTransfer{},
		Sent:                   map[string]v2SentDelivery{},
		SignedAcknowledgements: map[string]string{},
		PendingDataEpochs:      []uint64{},
		PendingControlEventIDs: []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &emptySlotTransport{}
	runtime := &v2PeerRuntime{
		paths:     paths,
		state:     state,
		transport: transport,
		origin:    "https://dud.example.com",
	}
	if err := runtime.boundedControlDrain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if transport.requests != 1 {
		t.Fatalf("control drain requests = %d", transport.requests)
	}
	if state.LastSuccessfulDrain == 0 || state.UndrainedControl {
		t.Fatalf("successful drain state = %#v", state)
	}
}

func TestV2EmptyReceiveUsesExactlyOneInboxRequest(t *testing.T) {
	root := t.TempDir()
	paths := v2Paths{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), Lock: filepath.Join(root, "config", ".config.lock")}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             strings.Repeat("46", 16),
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(make([]byte, 32)),
		InboundRelationshipSecret:  v2Base64URL(make([]byte, 32)),
		Capabilities: map[string]string{
			"invitee->inviter|read": v2Base64URL(bytesRepeatV2(0x51, 32)),
		},
		ServerContract: mustV2TestServerContract(t),
		Chains: map[string]*v2ChainState{
			"out:data": emptyV2ChainState(), "out:control": emptyV2ChainState(), "in:data": emptyV2ChainState(), "in:control": emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{},
		PendingGranularDeliveries:  []v2PendingGranularDelivery{},
		PendingCompletions:         []v2PendingCompletion{},
		InboundTransfers:           map[string]v2InboundTransfer{},
		Sent:                       map[string]v2SentDelivery{},
		SignedAcknowledgements:     map[string]string{},
		DataScanEpoch:              20_000,
		ControlScanEpoch:           20_000,
		PendingDataEpochs:          []uint64{},
		PendingControlEventIDs:     []string{},
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &emptySlotTransport{}
	runtime := &v2PeerRuntime{paths: paths, state: state, transport: transport, origin: "https://dud.example.com"}
	received, sawDelivery, err := runtime.receiveAvailable(context.Background(), nil, v2PeerReceiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if received != nil || sawDelivery || transport.requests != 1 || transport.dataProofs != 30 {
		t.Fatalf("empty receive = %v after %d requests", received, transport.requests)
	}
}

func TestV2GranularDataQueryProofsAreChronological(t *testing.T) {
	current := v2SlotEpoch(time.Now())
	runtime := &v2PeerRuntime{state: &v2PeerDeliveryState{
		Role:                      0,
		InboundRelationshipSecret: v2Base64URL(bytesRepeatV2(0x71, 32)),
		Capabilities: map[string]string{
			"invitee->inviter|read": v2Base64URL(bytesRepeatV2(0x72, 32)),
		},
		DataScanEpoch:     current,
		PendingDataEpochs: []uint64{current - 5, current - 2},
	}}
	proofs, err := runtime.granularDataQueryProofs(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) != 3 || proofs[0].Epoch != current-5 || proofs[1].Epoch != current-2 || proofs[2].Epoch != current {
		t.Fatalf("data proof epochs = %#v", proofs)
	}
}

func bytesRepeatV2(value byte, length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

func sequentialV2TestBytes(start byte, length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = start + byte(index)
	}
	return result
}

// A gap quarantine is permanent by design: deliveries are strictly ordered, so
// the chain cannot pass a missing sequence without abandoning it. Abandoning it
// is the operator's decision, taken through `dud peer resume`, and it
// authorizes exactly one forward jump.
func TestV2ResumeApprovalCrossesOneGapAndNoMore(t *testing.T) {
	chain := emptyV2ChainState()
	chain.ReceiveWatermark = 6
	chain.ReceiveDigest = strings.Repeat("aa", 32)
	runtime := &v2PeerRuntime{state: &v2PeerDeliveryState{
		Chains: map[string]*v2ChainState{"in:data": chain},
	}}

	previous := bytes.Repeat([]byte{0xbb}, 32)
	ninth := &validatedV2Envelope{
		Descriptor: map[int]any{
			kSequence:       uint64(9),
			kPreviousDigest: previous,
		},
		DescriptorDigest: sha256.Sum256([]byte("nine")),
	}

	// Without an approval the chain stops and stays stopped.
	if _, err := runtime.validateNextDescriptor(chain, ninth); err == nil ||
		!strings.Contains(err.Error(), "gap before sequence 9") {
		t.Fatalf("gap error = %v", err)
	}
	if !chain.Quarantined {
		t.Fatal("the chain was not quarantined")
	}

	// What `dud peer resume` records.
	chain.Quarantined = false
	chain.QuarantineReason = ""
	chain.ResumeApproved = true

	next, err := runtime.validateNextDescriptor(chain, ninth)
	if err != nil || !next {
		t.Fatalf("approved resume was refused: next=%v err=%v", next, err)
	}
	if chain.ResumeApproved {
		t.Fatal("the approval survived the jump it authorized")
	}
	if chain.Quarantined {
		t.Fatal("the chain stayed quarantined after an approved resume")
	}
	// The chain continues from the delivery that was accepted, so ordering
	// holds from here even though it does not cover what was skipped.
	if chain.ReceiveWatermark != 8 {
		t.Fatalf("watermark = %d, want 8", chain.ReceiveWatermark)
	}
	if chain.ReceiveDigest != hex.EncodeToString(previous) {
		t.Fatalf("receive digest = %q, want the accepted predecessor", chain.ReceiveDigest)
	}

	// A second gap after the approval was spent stops the chain again.
	twelfth := &validatedV2Envelope{
		Descriptor: map[int]any{
			kSequence:       uint64(12),
			kPreviousDigest: bytes.Repeat([]byte{0xcc}, 32),
		},
		DescriptorDigest: sha256.Sum256([]byte("twelve")),
	}
	chain.ReceiveWatermark = 9
	chain.ReceiveDigest = hex.EncodeToString(ninth.DescriptorDigest[:])
	if _, err := runtime.validateNextDescriptor(chain, twelfth); err == nil ||
		!strings.Contains(err.Error(), "gap before sequence 12") {
		t.Fatalf("second gap error = %v", err)
	}
}

// An output that already holds the payload is a no-op, so it is accepted on
// the first attempt and anything else is refused. The durable transfer record
// is written before the output check, so refusing the first run would let an
// identical second one succeed by the resume path: one file, two invocations.
func TestV2ExistingOutputMatchesOnlyIdenticalContent(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("the same bytes both times\n")
	digest := sha256.Sum256(payload)

	identical := filepath.Join(dir, "identical")
	if err := os.WriteFile(identical, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if !v2ExistingOutputMatches(identical, digest[:]) {
		t.Fatal("identical content was not recognized as a no-op write")
	}

	// Same length, different bytes: a digest comparison catches it where a
	// size check would not.
	altered := filepath.Join(dir, "altered")
	changed := append([]byte(nil), payload...)
	changed[0] ^= 0xff
	if err := os.WriteFile(altered, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if v2ExistingOutputMatches(altered, digest[:]) {
		t.Fatal("different content of the same length compared equal")
	}

	if v2ExistingOutputMatches(filepath.Join(dir, "absent"), digest[:]) {
		t.Fatal("a missing output reported a match")
	}
	if v2ExistingOutputMatches(dir, digest[:]) {
		t.Fatal("a directory reported a match")
	}
	if v2ExistingOutputMatches(filepath.Join(dir, "dangling"), digest[:]) {
		t.Fatal("a broken symlink reported a match")
	}
}

func TestV2InboundControlRevocationHaltsTheRelationship(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	ciphertext := buildInboundV2ControlEnvelope(t, crypto, 6, map[int]any{
		1: uint64(1), 2: uint64(0), 3: uint64(1), 4: uint64(0), 5: uint64(0), 6: uint64(0),
	})
	a := newDrainingV2TestApp(t, &emptySlotTransport{}, &bytes.Buffer{}, &bytes.Buffer{})
	var applied *v2PeerDeliveryState
	if err := a.withV2Peer("laptop", time.Second, func(runtime *v2PeerRuntime) error {
		err := runtime.applyV2GranularControlEnvelope(ciphertext)
		applied = runtime.state
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !applied.Halted || applied.HaltReason != "peer revoked the relationship" {
		t.Fatalf("control revocation state = %#v", applied)
	}
	if applied.Chains["in:control"].ReceiveWatermark != 1 || len(applied.SignedAcknowledgements) != 1 {
		t.Fatalf("control chain = %#v", applied.Chains["in:control"])
	}
}

func TestV2InboundAcknowledgementMarksMatchingDelivery(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	ackedDigest := bytesRepeatV2(0x82, 32)
	state.Sent[hex.EncodeToString(ackedDigest)] = v2SentDelivery{Sequence: 4, DescriptorDigest: hex.EncodeToString(ackedDigest)}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	ciphertext := buildInboundV2ControlEnvelope(t, crypto, 5, map[int]any{
		1: uint64(4), 2: ackedDigest, 3: uint64(0), 4: bytesRepeatV2(0x83, 32),
		5: uint64(0), 6: uint64(1), 7: uint64(0), 8: uint64(0),
	})
	a := newDrainingV2TestApp(t, &emptySlotTransport{}, &bytes.Buffer{}, &bytes.Buffer{})
	var applied *v2PeerDeliveryState
	if err := a.withV2Peer("laptop", time.Second, func(runtime *v2PeerRuntime) error {
		err := runtime.applyV2GranularControlEnvelope(ciphertext)
		applied = runtime.state
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !applied.Sent[hex.EncodeToString(ackedDigest)].Acknowledged {
		t.Fatalf("acknowledgement state = %#v", applied.Sent)
	}
}

func TestWithV2PeerPrunesExpiredInboundTransferPayloadAfterRestart(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	digest := strings.Repeat("a1", 32)
	transferDir := filepath.Join(paths.StateDir, "transfers", state.RelationshipID)
	if err := os.MkdirAll(transferDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(transferDir, digest)
	committedOutput := filepath.Join(t.TempDir(), "operator-copy")
	if err := os.WriteFile(payload, []byte("expired plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(committedOutput, []byte("keep this"), 0o600); err != nil {
		t.Fatal(err)
	}
	state.InboundTransfers[digest] = v2InboundTransfer{
		DescriptorDigest: digest,
		PlaintextPayload: payload,
		TemporaryOutput:  payload,
		CommittedOutput:  committedOutput,
		ExpiresAt:        uint64(time.Now().Add(-time.Second).Unix()),
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}

	a := newDrainingV2TestApp(t, &emptySlotTransport{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err := a.withV2Peer("laptop", time.Second, func(runtime *v2PeerRuntime) error {
		if _, exists := runtime.state.InboundTransfers[digest]; exists {
			t.Fatal("expired inbound transfer remained in the loaded state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(payload); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired plaintext payload still exists: %v", err)
	}
	if body, err := os.ReadFile(committedOutput); err != nil || string(body) != "keep this" {
		t.Fatalf("operator output was altered: %q, %v", body, err)
	}
	reloaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := reloaded.InboundTransfers[digest]; exists {
		t.Fatal("expired inbound transfer remained on disk")
	}
}

func TestPruneV2ExpiredInboundTransfersRetainsStateWhenPayloadRemovalFails(t *testing.T) {
	payload := filepath.Join(t.TempDir(), "payload")
	if err := os.MkdirAll(payload, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "child"), []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A second removable transfer proves the undeletable one is reported without
	// stopping the sweep. Every peer operation prunes, so one stuck file must not
	// make the peer unusable.
	removable := filepath.Join(t.TempDir(), "removable")
	if err := os.WriteFile(removable, []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := &v2PeerDeliveryState{InboundTransfers: map[string]v2InboundTransfer{
		"expired":   {PlaintextPayload: payload, ExpiresAt: 1},
		"removable": {PlaintextPayload: removable, ExpiresAt: 1},
	}}
	changed, problems := pruneV2ExpiredInboundTransfers(state, 2)
	if len(problems) != 1 || !changed {
		t.Fatalf("expired cleanup = changed %v, problems %v", changed, problems)
	}
	if _, exists := state.InboundTransfers["expired"]; !exists {
		t.Fatal("cleanup forgot a transfer whose payload was not removed")
	}
	if _, exists := state.InboundTransfers["removable"]; exists {
		t.Fatal("one undeletable payload stopped the rest of the sweep")
	}
	if _, err := os.Stat(removable); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removable expired payload survived: %v", err)
	}
}

func TestV2CapabilityReissueRefreshesDurableGrant(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	relationshipID, err := hex.DecodeString(state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deriveV2RelationshipIdentity(seed, relationshipID, state.Role)
	if err != nil {
		t.Fatal(err)
	}
	grant := encryptV2TestCapabilityGrant(t, identity.Recipient(), relationshipID, state.Role, "https://dud.example.com")
	transport := &capabilityReissueTransport{grant: grant}
	a := newDrainingV2TestApp(t, transport, &bytes.Buffer{}, &bytes.Buffer{})
	if err := a.withV2Peer("laptop", time.Second, func(runtime *v2PeerRuntime) error {
		return runtime.reissueCapabilities(context.Background())
	}); err != nil {
		t.Fatal(err)
	}
	if transport.reissues != 1 {
		t.Fatalf("capability reissues = %d", transport.reissues)
	}
	stored, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CapabilityReissues != 1 || stored.CapabilitiesIssuedAt == 0 || len(stored.Capabilities) != 3 {
		t.Fatalf("reissued state = %#v", stored)
	}
}

type capabilityReissueTransport struct {
	grant    []byte
	reissues int
}

func (transport *capabilityReissueTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	switch request.Path {
	case "/v2/capabilities":
		body, err := hex.DecodeString(v2CapabilitiesVectorHex)
		if err != nil {
			return nil, err
		}
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
	case "/v2/capabilities/reissue":
		transport.reissues++
		body, err := v2EncMode.Marshal(map[int]any{1: transport.grant})
		if err != nil {
			return nil, err
		}
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
	default:
		return nil, errors.New("unexpected capability request: " + request.Path)
	}
}

func encryptV2TestCapabilityGrant(t *testing.T, recipient age.Recipient, relationshipID []byte, role uint64, origin string) []byte {
	t.Helper()
	plaintext, err := v2EncMode.Marshal(map[int]any{
		1: uint64(2), 2: relationshipID, 3: role, 4: uint64(0), 5: origin,
		6: []any{
			map[int]any{1: uint64(0), 2: "write", 3: bytesRepeatV2(0x91, 32)},
			map[int]any{1: uint64(0), 2: "read", 3: bytesRepeatV2(0x92, 32)},
			map[int]any{1: uint64(0), 2: "ack", 3: bytesRepeatV2(0x93, 32)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return encrypted.Bytes()
}

func TestExportCommittedTransferWritesAndOverwritesOnRequest(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	if err := os.WriteFile(payload, []byte("recovered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	runtime := &v2PeerRuntime{state: &v2PeerDeliveryState{InboundTransfers: map[string]v2InboundTransfer{
		digest: {Phase: "output-committed", PlaintextPayload: payload},
	}}}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	if err := runtime.exportCommittedTransfer(a, v2PeerReceiveOptions{alias: "laptop", id: digest}); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "recovered\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.exportCommittedTransfer(a, v2PeerReceiveOptions{alias: "laptop", id: digest, out: target, onConflict: "refuse"}); err == nil {
		t.Fatal("existing output was overwritten without permission")
	}
	if err := runtime.exportCommittedTransfer(a, v2PeerReceiveOptions{alias: "laptop", id: digest, out: target, onConflict: "overwrite", json: true}); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(target); err != nil || string(body) != "recovered\n" {
		t.Fatalf("recovered target = %q, %v", body, err)
	}
}

func TestReadV2PeerSendPayloadCoversMessageStdinFileAndCollection(t *testing.T) {
	a := newApp(strings.NewReader("stdin payload"), &bytes.Buffer{}, &bytes.Buffer{})
	body, kind, _, metadata, archive, err := a.readV2PeerSendPayload(v2PeerSendOptions{message: "message"})
	if err != nil || string(body) != "message" || kind != 1 || metadata != nil || archive != nil {
		t.Fatalf("message payload = %q, %d, %#v, %#v, %v", body, kind, metadata, archive, err)
	}
	body, kind, _, _, _, err = a.readV2PeerSendPayload(v2PeerSendOptions{stdin: true})
	if err != nil || string(body) != "stdin payload" || kind != 1 {
		t.Fatalf("stdin payload = %q, %d, %v", body, kind, err)
	}
	root := t.TempDir()
	file := filepath.Join(root, "note.txt")
	if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, kind, name, metadata, archive, err := a.readV2PeerSendPayload(v2PeerSendOptions{files: []string{file}})
	if err != nil || string(body) != "file" || kind != 2 || name != "note.txt" || metadata != nil || archive != nil {
		t.Fatalf("file payload = %q, %d, %q, %#v, %#v, %v", body, kind, name, metadata, archive, err)
	}
	directory := filepath.Join(root, "folder")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "inside"), []byte("collection"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, kind, name, metadata, archive, err = a.readV2PeerSendPayload(v2PeerSendOptions{files: []string{directory}})
	if err != nil || len(body) == 0 || kind != 3 || name != "collection" || metadata == nil || archive == nil || *archive != 1 {
		t.Fatalf("collection payload = %d, %d, %q, %#v, %#v, %v", len(body), kind, name, metadata, archive, err)
	}
}

func buildInboundV2ControlEnvelope(t *testing.T, crypto v2TestPeerCrypto, payloadType uint64, metadata map[int]any) []byte {
	t.Helper()
	now := uint64(time.Now().Unix())
	payloadCiphertext, err := encryptV2Payload(nil, crypto.recipient)
	if err != nil {
		t.Fatal(err)
	}
	descriptorID, err := newV2DescriptorID()
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(nil)
	cipherDigest := sha256.Sum256(payloadCiphertext)
	descriptor := v2Descriptor{
		DescriptorID: descriptorID, PayloadType: payloadType, RelationshipID: crypto.relationshipID,
		Direction: v2InboundDirection(crypto.role), Chain: 1, KeyEpoch: 0, Sequence: 1,
		PreviousDigest: make([]byte, 32), SenderDeviceID: crypto.peerID, RecipientDeviceID: crypto.localID,
		CanonicalOrigin: crypto.origin, CreatedAt: now,
		TransportPolicy: v2TransportPolicy{ExpiresAt: now + 86_400, Consume: 1, ClaimLeaseSeconds: 300, AckMode: 0},
		PayloadHash:     payloadDigest[:], ChunkHashes: [][]byte{cipherDigest[:]}, TypeMetadata: metadata,
	}
	ciphertext, err := encryptV2Envelope(descriptor, crypto.signingKey, crypto.recipient)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}
