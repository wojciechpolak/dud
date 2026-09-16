// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

const v2ResetLifetime = 24 * time.Hour

func v2ResetSign(label string, value map[int]any, key ed25519.PrivateKey) ([]byte, error) {
	encoded, err := v2EncMode.Marshal(value)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return ed25519.Sign(key, append([]byte("dud/v2/relationship-reset/"+label+"\x00"), digest[:]...)), nil
}

func v2ResetVerify(label string, value map[int]any, signature []byte, key ed25519.PublicKey) bool {
	if len(signature) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize {
		return false
	}
	encoded, err := v2EncMode.Marshal(value)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(encoded)
	return ed25519.Verify(key, append([]byte("dud/v2/relationship-reset/"+label+"\x00"), digest[:]...), signature)
}

func v2ResetDispositionOf(state *v2PeerDeliveryState) v2ResetDisposition {
	disposition := v2ResetDisposition{
		QueuedDeliveries:    len(state.PendingGranularDeliveries) + len(state.PendingChunkDeliveries),
		QueuedCompletions:   len(state.PendingCompletions),
		QueuedControlEvents: len(state.PendingControlPublications),
		Unacknowledged:      unacknowledgedV2Deliveries(state),
		InboundTransfers:    len(state.InboundTransfers),
	}
	for _, chain := range state.Chains {
		if chain != nil && chain.Quarantined {
			disposition.QuarantinedChains++
		}
	}
	disposition.ResumableTransfers = len(v2DeliveryStatusOf(state).ResumableTransfers)
	for _, sent := range state.Sent {
		if sent.PayloadType == 4 && sent.Rejected {
			disposition.RefusedGitCheckpoints++
		}
	}
	return disposition
}

func encodeV2ResetDisposition(value v2ResetDisposition) map[int]any {
	return map[int]any{
		1: uint64(value.QueuedDeliveries), 2: uint64(value.QueuedCompletions),
		3: uint64(value.QueuedControlEvents), 4: uint64(value.Unacknowledged),
		5: uint64(value.InboundTransfers), 6: uint64(value.QuarantinedChains),
		7: uint64(value.ResumableTransfers), 8: uint64(value.RefusedGitCheckpoints),
	}
}

func decodeV2ResetDisposition(raw any) (v2ResetDisposition, error) {
	value, err := normalizeV2Map(raw)
	if err != nil || len(value) != 8 {
		return v2ResetDisposition{}, errors.New("peer relationship reset disposition is invalid")
	}
	items := make([]uint64, 8)
	for index := range items {
		items[index], err = metadataUint(value, index+1)
		if err != nil || items[index] > uint64(^uint(0)>>1) {
			return v2ResetDisposition{}, errors.New("peer relationship reset disposition is invalid")
		}
	}
	return v2ResetDisposition{
		QueuedDeliveries: int(items[0]), QueuedCompletions: int(items[1]),
		QueuedControlEvents: int(items[2]), Unacknowledged: int(items[3]),
		InboundTransfers: int(items[4]), QuarantinedChains: int(items[5]),
		ResumableTransfers: int(items[6]), RefusedGitCheckpoints: int(items[7]),
	}, nil
}

func v2ResetChainSnapshot(state *v2PeerDeliveryState) []any {
	result := make([]any, 0, 4)
	for _, name := range []string{"out:data", "out:control", "in:data", "in:control"} {
		chain := state.Chains[name]
		sequence, digest := chain.SendSequence, chain.SendDigest
		if name[0] == 'i' {
			sequence, digest = chain.ReceiveWatermark, chain.ReceiveDigest
		}
		result = append(result, map[int]any{1: name, 2: sequence, 3: mustDecodeHexV2(digest, 32)})
	}
	return result
}

func validateV2ResetChainSnapshot(raw any) error {
	items, ok := raw.([]any)
	if !ok || len(items) != 4 {
		return errors.New("peer relationship reset chain snapshot is invalid")
	}
	for index, name := range []string{"out:data", "out:control", "in:data", "in:control"} {
		item, err := normalizeV2Map(items[index])
		_, sequenceOK := asV2Uint(item[2])
		digest, digestOK := item[3].([]byte)
		if err != nil || len(item) != 3 || item[1] != name || !sequenceOK || !digestOK || len(digest) != 32 {
			return errors.New("peer relationship reset chain snapshot is invalid")
		}
	}
	return nil
}

func v2ResetIdentity(seed, relationshipID []byte) ([]byte, []byte, []byte, error) {
	deviceID, err := deriveV2DeviceID(seed, relationshipID, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	signing, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	hpkeKey, err := v2HPKEPrivateKey(seed, relationshipID)
	if err != nil {
		return nil, nil, nil, err
	}
	return deviceID, append([]byte(nil), signing.Public().(ed25519.PublicKey)...), hpkeKey.PublicKey().Bytes(), nil
}

func v2ResetChainGenesis(relationshipID []byte, direction, chain uint64) string {
	input := append([]byte("dud/v2/chain-genesis\x00"), relationshipID...)
	input = append(input, byte(direction), byte(chain))
	digest := sha256.Sum256(input)
	return hex.EncodeToString(digest[:])
}

func initializeV2ResetChains(state *v2PeerDeliveryState, relationshipID []byte) {
	for _, item := range []struct {
		name      string
		direction uint64
		chain     uint64
	}{
		{"out:data", v2OutboundDirection(state.Role), 0},
		{"out:control", v2OutboundDirection(state.Role), 1},
		{"in:data", v2InboundDirection(state.Role), 0},
		{"in:control", v2InboundDirection(state.Role), 1},
	} {
		digest := v2ResetChainGenesis(relationshipID, item.direction, item.chain)
		state.Chains[item.name].SendDigest = digest
		state.Chains[item.name].ReceiveDigest = digest
	}
}

func (runtime *v2PeerRuntime) newV2ResetProposal() (*v2RelationshipReset, error) {
	resetID, err := randomV2Bytes(16)
	if err != nil {
		return nil, err
	}
	newRelationshipID, err := randomV2Bytes(16)
	if err != nil {
		return nil, err
	}
	deviceID, signingPublic, agePublic, err := v2ResetIdentity(runtime.seed, newRelationshipID)
	if err != nil {
		return nil, err
	}
	disposition := v2ResetDispositionOf(runtime.state)
	now := uint64(time.Now().Unix())
	proposal := map[int]any{
		1: uint64(1), 2: runtime.relationshipID, 3: resetID, 4: newRelationshipID,
		5: runtime.state.Role, 6: runtime.state.Generation + 1, 7: runtime.origin,
		8: v2ResetChainSnapshot(runtime.state), 9: runtime.localID, 10: runtime.peerID,
		11: deviceID, 12: signingPublic, 13: agePublic,
		14: encodeV2ResetDisposition(disposition), 15: now + uint64(v2ResetLifetime/time.Second),
		16: uint64(0),
	}
	signature, err := v2ResetSign("proposal", proposal, runtime.signingKey)
	if err != nil {
		return nil, err
	}
	encoded, err := v2EncMode.Marshal(proposal)
	if err != nil {
		return nil, err
	}
	return &v2RelationshipReset{
		ResetID: hex.EncodeToString(resetID), OldRelationshipID: runtime.state.RelationshipID,
		NewRelationshipID: hex.EncodeToString(newRelationshipID), Generation: runtime.state.Generation + 1,
		InitiatorRole: runtime.state.Role, Phase: "proposed", Proposal: v2Base64URL(encoded),
		ProposalSignature: v2Base64URL(signature), LocalConsent: true,
		LocalDisposition: disposition, CreatedAt: now,
	}, nil
}

func decodeV2ResetMap(encoded string) (map[int]any, error) {
	body, err := decodeV2Base64URL(encoded, -1)
	if err != nil || len(body) == 0 || len(body) > v2MaxDescriptorBytes {
		if err == nil {
			err = errors.New("peer relationship reset transcript exceeds the size limit")
		}
		return nil, err
	}
	var value map[int]any
	if err := v2DecMode.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	canonical, err := v2EncMode.Marshal(value)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("peer relationship reset transcript is not deterministic CBOR")
	}
	return value, nil
}

// v2ResetProposalFields is a reset proposal's decoded content: the identifiers
// of the relationship being abandoned and of the one that replaces it, the role
// of the device that proposed the reset, and the identity that device will hold
// in the new generation.
type v2ResetProposalFields struct {
	resetID    []byte
	oldID      []byte
	newID      []byte
	role       uint64
	generation uint64
	expires    uint64
	oldLocal   []byte
	oldPeer    []byte
	newDevice  []byte
	newSigning []byte
	newAge     []byte
}

// decodeV2ResetProposalFields reads a reset proposal and checks that every
// field is present with the width the protocol gives it. A proposal carries
// exactly sixteen keys, so one with any other count is a message this version
// cannot read in full rather than one it may interpret in part.
func decodeV2ResetProposalFields(proposal map[int]any) (v2ResetProposalFields, error) {
	var fields v2ResetProposalFields
	invalid := errors.New("peer relationship reset proposal is invalid")
	if len(proposal) != 16 || !v2UintEquals(proposal[1], 1) || !v2UintEquals(proposal[16], 0) {
		return fields, invalid
	}
	oldID, oldOK := proposal[2].([]byte)
	resetID, resetOK := proposal[3].([]byte)
	newID, newOK := proposal[4].([]byte)
	role, roleOK := asV2Uint(proposal[5])
	generation, generationOK := asV2Uint(proposal[6])
	oldLocal, oldLocalOK := proposal[9].([]byte)
	oldPeer, oldPeerOK := proposal[10].([]byte)
	newDevice, newDeviceOK := proposal[11].([]byte)
	newSigning, newSigningOK := proposal[12].([]byte)
	newAge, newAgeOK := proposal[13].([]byte)
	expires, expiresOK := asV2Uint(proposal[15])
	if !oldOK || !resetOK || len(resetID) != 16 || !newOK || len(newID) != 16 ||
		!roleOK || !generationOK || !expiresOK ||
		!oldLocalOK || len(oldLocal) != 16 || !oldPeerOK || len(oldPeer) != 16 ||
		!newDeviceOK || len(newDevice) != 16 || !newSigningOK || len(newSigning) != 32 ||
		!newAgeOK || len(newAge) != 1216 {
		return fields, invalid
	}
	return v2ResetProposalFields{
		resetID: resetID, oldID: oldID, newID: newID,
		role: role, generation: generation, expires: expires,
		oldLocal: oldLocal, oldPeer: oldPeer,
		newDevice: newDevice, newSigning: newSigning, newAge: newAge,
	}, nil
}

// validateV2ResetProposalTerms checks what a proposal asks for against the
// relationship it would replace. A proposal binds to one relationship, one
// origin, and the single generation after the current one, so a proposal for
// any other target cannot be signed into this relationship's history. The
// expiry bound keeps a proposal from being held back and activated later.
func (runtime *v2PeerRuntime) validateV2ResetProposalTerms(proposal map[int]any, fields v2ResetProposalFields) error {
	now := time.Now()
	if !bytes.Equal(fields.oldID, runtime.relationshipID) || fields.role > 1 ||
		fields.generation != runtime.state.Generation+1 || proposal[7] != runtime.origin ||
		fields.expires <= uint64(now.Unix()) ||
		fields.expires > uint64(now.Add(v2ResetLifetime+5*time.Minute).Unix()) ||
		validateV2ResetChainSnapshot(proposal[8]) != nil {
		return errors.New("peer relationship reset proposal is invalid")
	}
	return nil
}

// v2ResetProposalSigner reports which key must have signed a proposal. Either
// device may propose, and the proposal names the two device IDs of the
// relationship from the proposer's side, so the roles it states have to match
// this device's own view before its signature means anything.
func (runtime *v2PeerRuntime) v2ResetProposalSigner(fields v2ResetProposalFields) (ed25519.PublicKey, error) {
	invalid := errors.New("peer relationship reset proposal identity is invalid")
	if fields.role == runtime.state.Role {
		if !bytes.Equal(fields.oldLocal, runtime.localID) || !bytes.Equal(fields.oldPeer, runtime.peerID) {
			return nil, invalid
		}
		return runtime.signingKey.Public().(ed25519.PublicKey), nil
	}
	peerSigning, err := decodeV2Base64URL(runtime.peer.PeerSigningPublicKey, 32)
	if err != nil || !bytes.Equal(fields.oldLocal, runtime.peerID) || !bytes.Equal(fields.oldPeer, runtime.localID) {
		return nil, invalid
	}
	return ed25519.PublicKey(peerSigning), nil
}

// validateV2ResetProposal checks a reset proposal and reports the work the
// proposer says it is abandoning. A proposal this device made itself is checked
// against the identity it would derive for the new relationship, so a proposal
// that came back altered cannot make this device pair with a key it does not
// hold the seed for.
func (runtime *v2PeerRuntime) validateV2ResetProposal(proposal map[int]any, signature []byte) (v2ResetDisposition, error) {
	fields, err := decodeV2ResetProposalFields(proposal)
	if err != nil {
		return v2ResetDisposition{}, err
	}
	if err := runtime.validateV2ResetProposalTerms(proposal, fields); err != nil {
		return v2ResetDisposition{}, err
	}
	signer, err := runtime.v2ResetProposalSigner(fields)
	if err != nil {
		return v2ResetDisposition{}, err
	}
	if !v2ResetVerify("proposal", proposal, signature, signer) {
		return v2ResetDisposition{}, errors.New("peer relationship reset proposal signature is invalid")
	}
	if fields.role == runtime.state.Role {
		expectedDevice, expectedSigning, expectedAge, identityErr := v2ResetIdentity(runtime.seed, fields.newID)
		if identityErr != nil || !bytes.Equal(fields.newDevice, expectedDevice) || !bytes.Equal(fields.newSigning, expectedSigning) || !bytes.Equal(fields.newAge, expectedAge) {
			return v2ResetDisposition{}, errors.New("local peer relationship reset proposal identity is invalid")
		}
	}
	return decodeV2ResetDisposition(proposal[14])
}

func (runtime *v2PeerRuntime) acceptV2Reset(reset *v2RelationshipReset, proposal map[int]any) error {
	proposalBytes, err := v2EncMode.Marshal(proposal)
	if err != nil {
		return err
	}
	proposalDigest := sha256.Sum256(proposalBytes)
	newID, _ := proposal[4].([]byte)
	deviceID, signingPublic, agePublic, err := v2ResetIdentity(runtime.seed, newID)
	if err != nil {
		return err
	}
	disposition := v2ResetDispositionOf(runtime.state)
	acceptance := map[int]any{
		1: uint64(1), 2: proposalDigest[:], 3: runtime.state.Role,
		4: deviceID, 5: signingPublic, 6: agePublic,
		7: v2ResetChainSnapshot(runtime.state), 8: encodeV2ResetDisposition(disposition),
		9: uint64(time.Now().Add(v2ResetLifetime).Unix()),
	}
	signature, err := v2ResetSign("acceptance", acceptance, runtime.signingKey)
	if err != nil {
		return err
	}
	encoded, err := v2EncMode.Marshal(acceptance)
	if err != nil {
		return err
	}
	reset.Acceptance = v2Base64URL(encoded)
	reset.AcceptanceSignature = v2Base64URL(signature)
	reset.LocalConsent = true
	reset.PeerConsent = true
	reset.LocalDisposition = disposition
	reset.Phase = "accepted"
	return nil
}

func (runtime *v2PeerRuntime) validateV2ResetAcceptance(proposal, acceptance map[int]any, signature []byte) (v2ResetDisposition, error) {
	if len(acceptance) != 9 || !v2UintEquals(acceptance[1], 1) {
		return v2ResetDisposition{}, errors.New("peer relationship reset acceptance is invalid")
	}
	proposalBytes, err := v2EncMode.Marshal(proposal)
	if err != nil {
		return v2ResetDisposition{}, err
	}
	proposalDigest := sha256.Sum256(proposalBytes)
	boundDigest, digestOK := acceptance[2].([]byte)
	proposalRole, proposalRoleOK := asV2Uint(proposal[5])
	role, roleOK := asV2Uint(acceptance[3])
	newDevice, deviceOK := acceptance[4].([]byte)
	newSigning, signingOK := acceptance[5].([]byte)
	newAge, ageOK := acceptance[6].([]byte)
	expires, expiresOK := asV2Uint(acceptance[9])
	if !digestOK || !bytes.Equal(boundDigest, proposalDigest[:]) || !proposalRoleOK || !roleOK || role != 1-proposalRole ||
		!deviceOK || len(newDevice) != 16 || !signingOK || len(newSigning) != 32 || !ageOK || len(newAge) != 1216 ||
		!expiresOK || expires <= uint64(time.Now().Unix()) || expires > uint64(time.Now().Add(v2ResetLifetime+5*time.Minute).Unix()) ||
		validateV2ResetChainSnapshot(acceptance[7]) != nil {
		return v2ResetDisposition{}, errors.New("peer relationship reset acceptance is invalid")
	}
	var signer ed25519.PublicKey
	if role == runtime.state.Role {
		newID, _ := proposal[4].([]byte)
		localDevice, localSigning, localAge, deriveErr := v2ResetIdentity(runtime.seed, newID)
		if deriveErr != nil || !bytes.Equal(newDevice, localDevice) || !bytes.Equal(newSigning, localSigning) || !bytes.Equal(newAge, localAge) {
			return v2ResetDisposition{}, errors.New("local peer relationship reset acceptance identity is invalid")
		}
		signer = runtime.signingKey.Public().(ed25519.PublicKey)
	} else {
		peerSigning, decodeErr := decodeV2Base64URL(runtime.peer.PeerSigningPublicKey, 32)
		if decodeErr != nil {
			return v2ResetDisposition{}, errors.New("peer relationship reset acceptance identity is invalid")
		}
		signer = ed25519.PublicKey(peerSigning)
	}
	if !v2ResetVerify("acceptance", acceptance, signature, signer) {
		return v2ResetDisposition{}, errors.New("peer relationship reset acceptance signature is invalid")
	}
	return decodeV2ResetDisposition(acceptance[8])
}

func (runtime *v2PeerRuntime) validateV2ResetCancellation(request map[int]any, signature []byte, resetID []byte) error {
	if len(request) != 7 || !v2UintEquals(request[1], 1) {
		return errors.New("peer relationship reset cancellation is invalid")
	}
	oldID, oldOK := request[2].([]byte)
	boundResetID, resetOK := request[3].([]byte)
	role, roleOK := asV2Uint(request[4])
	nonce, nonceOK := request[5].([]byte)
	expires, expiresOK := asV2Uint(request[6])
	if !oldOK || !bytes.Equal(oldID, runtime.relationshipID) || !resetOK || !bytes.Equal(boundResetID, resetID) ||
		!roleOK || role > 1 || !nonceOK || len(nonce) != 16 || !expiresOK || expires+300 < uint64(time.Now().Unix()) ||
		expires > uint64(time.Now().Add(5*time.Minute).Unix()) || request[7] != runtime.origin {
		return errors.New("peer relationship reset cancellation binding is invalid")
	}
	var signer ed25519.PublicKey
	if role == runtime.state.Role {
		signer = runtime.signingKey.Public().(ed25519.PublicKey)
	} else {
		peerSigning, err := decodeV2Base64URL(runtime.peer.PeerSigningPublicKey, 32)
		if err != nil {
			return errors.New("peer relationship reset cancellation signer is invalid")
		}
		signer = ed25519.PublicKey(peerSigning)
	}
	if !v2ResetVerify("cancellation", request, signature, signer) {
		return errors.New("peer relationship reset cancellation signature is invalid")
	}
	return nil
}

func validateV2ResetReceipt(proposal map[int]any, proposalSignature []byte, acceptance map[int]any, acceptanceSignature, encoded []byte) (uint64, error) {
	var receipt map[int]any
	if err := v2DecMode.Unmarshal(encoded, &receipt); err != nil || len(receipt) != 7 || !v2UintEquals(receipt[1], 1) {
		return 0, errors.New("peer relationship reset activation receipt is invalid")
	}
	canonical, err := v2EncMode.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return 0, errors.New("peer relationship reset activation receipt is not deterministic CBOR")
	}
	resetID, resetOK := receipt[2].([]byte)
	oldID, oldOK := receipt[3].([]byte)
	newID, newOK := receipt[4].([]byte)
	generation, generationOK := asV2Uint(receipt[5])
	transcriptDigest, digestOK := receipt[6].([]byte)
	activatedAt, activatedOK := asV2Uint(receipt[7])
	expectedResetID, _ := proposal[3].([]byte)
	expectedOldID, _ := proposal[2].([]byte)
	expectedNewID, _ := proposal[4].([]byte)
	expectedGeneration, _ := asV2Uint(proposal[6])
	transcript := map[int]any{1: proposal, 2: proposalSignature, 3: acceptance, 4: acceptanceSignature}
	transcriptBytes, err := v2EncMode.Marshal(transcript)
	if err != nil {
		return 0, err
	}
	expectedDigest := sha256.Sum256(transcriptBytes)
	if !resetOK || !bytes.Equal(resetID, expectedResetID) || !oldOK || !bytes.Equal(oldID, expectedOldID) ||
		!newOK || !bytes.Equal(newID, expectedNewID) || !generationOK || generation != expectedGeneration ||
		!digestOK || !bytes.Equal(transcriptDigest, expectedDigest[:]) || !activatedOK || activatedAt == 0 {
		return 0, errors.New("peer relationship reset activation receipt binding is invalid")
	}
	return activatedAt, nil
}

func (runtime *v2PeerRuntime) v2ResetRequest(ctx context.Context, body map[int]any) (map[int]any, error) {
	encoded, err := v2EncMode.Marshal(body)
	if err != nil {
		return nil, err
	}
	response, err := doV2CBORRequest(ctx, runtime.transport, "POST", runtime.origin, "/v2/relationships/reset", nil, encoded, v2MaxDescriptorBytes)
	if err != nil {
		return nil, err
	}
	var result map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (runtime *v2PeerRuntime) findV2Reset(ctx context.Context) (map[int]any, bool, error) {
	body, err := runtime.resetStatusBody()
	if err != nil {
		return nil, false, err
	}
	result, err := runtime.v2ResetRequest(ctx, body)
	if err != nil {
		var unavailable *v2ProtocolError
		if errors.As(err, &unavailable) && unavailable.Code == 4 {
			return nil, false, nil
		}
		return nil, false, err
	}
	return result, true, nil
}

func (runtime *v2PeerRuntime) applyV2ResetResponse(result map[int]any) (*v2RelationshipReset, map[int]any, error) {
	phase, phaseOK := asV2Uint(result[1])
	proposal, err := normalizeV2Map(result[2])
	proposalSignature, signatureOK := result[3].([]byte)
	if !phaseOK || phase < 1 || phase > 3 || err != nil || !signatureOK {
		return nil, nil, errors.New("peer relationship reset response is invalid")
	}
	peerDisposition, err := runtime.validateV2ResetProposal(proposal, proposalSignature)
	if err != nil {
		return nil, nil, err
	}
	proposalBytes, _ := v2EncMode.Marshal(proposal)
	resetID := proposal[3].([]byte)
	newID := proposal[4].([]byte)
	initiatorRole, _ := asV2Uint(proposal[5])
	generation, _ := asV2Uint(proposal[6])
	created := uint64(time.Now().Unix())
	reset := &v2RelationshipReset{
		ResetID: hex.EncodeToString(resetID), OldRelationshipID: runtime.state.RelationshipID,
		NewRelationshipID: hex.EncodeToString(newID), Generation: generation,
		InitiatorRole: initiatorRole, Phase: "proposed", Proposal: v2Base64URL(proposalBytes),
		ProposalSignature: v2Base64URL(proposalSignature), CreatedAt: created,
	}
	if initiatorRole == runtime.state.Role {
		reset.LocalConsent = true
		reset.LocalDisposition = peerDisposition
	} else {
		reset.PeerConsent = true
		reset.PeerDisposition = peerDisposition
	}
	if phase == 2 {
		acceptance, acceptanceErr := normalizeV2Map(result[4])
		acceptanceSignature, acceptanceOK := result[5].([]byte)
		receipt, receiptOK := result[6].([]byte)
		if acceptanceErr != nil || !acceptanceOK || !receiptOK || len(receipt) == 0 {
			return nil, nil, errors.New("active peer relationship reset response is incomplete")
		}
		other, err := runtime.validateV2ResetAcceptance(proposal, acceptance, acceptanceSignature)
		if err != nil {
			return nil, nil, err
		}
		activatedAt, err := validateV2ResetReceipt(proposal, proposalSignature, acceptance, acceptanceSignature, receipt)
		if err != nil {
			return nil, nil, err
		}
		acceptanceBytes, _ := v2EncMode.Marshal(acceptance)
		reset.Acceptance = v2Base64URL(acceptanceBytes)
		reset.AcceptanceSignature = v2Base64URL(acceptanceSignature)
		reset.ServerReceipt = v2Base64URL(receipt)
		reset.LocalConsent = true
		reset.PeerConsent = true
		reset.ServerActivated = true
		reset.Phase = "active"
		reset.ActivatedAt = activatedAt
		if initiatorRole == runtime.state.Role {
			reset.PeerDisposition = other
		} else {
			reset.LocalDisposition = other
		}
	}
	if phase == 3 {
		cancellation, cancellationErr := normalizeV2Map(result[7])
		cancellationSignature, cancellationOK := result[8].([]byte)
		if cancellationErr != nil || !cancellationOK || runtime.validateV2ResetCancellation(cancellation, cancellationSignature, resetID) != nil {
			return nil, nil, errors.New("cancelled peer relationship reset response is invalid")
		}
		cancellationBytes, _ := v2EncMode.Marshal(cancellation)
		reset.Cancellation = v2Base64URL(cancellationBytes)
		reset.CancellationSig = v2Base64URL(cancellationSignature)
		reset.Phase = "cancelled"
	}
	return reset, proposal, nil
}

func (runtime *v2PeerRuntime) resetStatusBody() (map[int]any, error) {
	now := uint64(time.Now().Unix())
	nonce, err := randomV2Bytes(16)
	if err != nil {
		return nil, err
	}
	request := map[int]any{
		1: uint64(1), 2: runtime.relationshipID, 3: runtime.state.Role,
		4: nonce, 5: now + 60, 6: runtime.origin,
	}
	signature, err := v2ResetSign("status", request, runtime.signingKey)
	if err != nil {
		return nil, err
	}
	return map[int]any{1: uint64(2), 2: request, 3: signature}, nil
}

func (runtime *v2PeerRuntime) resetCancellationBody(reset *v2RelationshipReset) (map[int]any, error) {
	resetID, err := hex.DecodeString(reset.ResetID)
	if err != nil || len(resetID) != 16 {
		return nil, errors.New("peer relationship reset ID is invalid")
	}
	nonce, err := randomV2Bytes(16)
	if err != nil {
		return nil, err
	}
	now := uint64(time.Now().Unix())
	request := map[int]any{
		1: uint64(1), 2: runtime.relationshipID, 3: resetID, 4: runtime.state.Role,
		5: nonce, 6: now + 60, 7: runtime.origin,
	}
	signature, err := v2ResetSign("cancellation", request, runtime.signingKey)
	if err != nil {
		return nil, err
	}
	return map[int]any{1: uint64(4), 2: request, 3: signature}, nil
}

func cleanupV2ResetGitState(a *app, oldPeerID string) error {
	command := a.gitCommand("rev-parse", "--git-common-dir")
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_OPTIONAL_LOCKS=0")
	output, err := command.Output()
	if err != nil {
		return nil
	}
	rawCommon := strings.TrimSpace(string(output))
	if rawCommon == "" {
		return errors.New("Git returned an empty common directory")
	}
	common, err := filepath.Abs(rawCommon)
	if err != nil {
		return err
	}
	info, err := os.Lstat(common)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Git common directory is invalid")
	}
	repository := &v2GitRepository{CommonDir: common, DUDDir: filepath.Join(common, "dud")}
	peerPath := repository.peerStatePath(oldPeerID)
	if _, err := os.Lstat(peerPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	unlock, err := repository.acquirePeerLock(oldPeerID)
	if err != nil {
		return err
	}
	defer unlock()
	repositoryID, err := repository.loadRepositoryID()
	if err != nil {
		return err
	}
	state, err := repository.loadPeerState(repositoryID, oldPeerID)
	if err != nil {
		return err
	}
	staged := []v2StagedErasePath{}
	stage := func(path string, directory bool) error {
		item, exists, stageErr := stageV2ErasePath(path, directory)
		if stageErr != nil {
			return stageErr
		}
		if exists {
			staged = append(staged, item)
		}
		return nil
	}
	for digest, inbound := range state.Inbound {
		bundleDirectory, bundleErr := filepath.EvalSymlinks(filepath.Dir(inbound.BundlePath))
		transferDirectory, transferErr := filepath.EvalSymlinks(filepath.Join(repository.DUDDir, "transfers"))
		if inbound.BundlePath != "" && bundleErr == nil && transferErr == nil && bundleDirectory == transferDirectory {
			if err := stage(inbound.BundlePath, false); err != nil {
				_ = rollbackV2ErasePaths(staged)
				return err
			}
		}
		decoded, decodeErr := hex.DecodeString(digest)
		if decodeErr == nil && len(decoded) == 32 {
			if err := stage(filepath.Join(repository.DUDDir, "quarantine", digest), true); err != nil {
				_ = rollbackV2ErasePaths(staged)
				return err
			}
		}
	}
	if err := stage(peerPath, false); err != nil {
		_ = rollbackV2ErasePaths(staged)
		return err
	}
	result := &v2EraseResult{}
	return removeV2ErasePaths(staged, result)
}

func (runtime *v2PeerRuntime) activateV2ResetLocally(ctx context.Context, a *app, alias string, reset *v2RelationshipReset, proposal map[int]any) error {
	acceptance, err := decodeV2ResetMap(reset.Acceptance)
	if err != nil {
		return err
	}
	newRelationshipID, err := hex.DecodeString(reset.NewRelationshipID)
	if err != nil || len(newRelationshipID) != 16 {
		return errors.New("peer relationship reset has an invalid new relationship ID")
	}
	localID, localSigningPublic, localAgePublic, err := v2ResetIdentity(runtime.seed, newRelationshipID)
	if err != nil {
		return err
	}
	var peerID, peerSigningPublic, peerAgePublic []byte
	if reset.InitiatorRole == runtime.state.Role {
		peerID, _ = acceptance[4].([]byte)
		peerSigningPublic, _ = acceptance[5].([]byte)
		peerAgePublic, _ = acceptance[6].([]byte)
	} else {
		peerID, _ = proposal[11].([]byte)
		peerSigningPublic, _ = proposal[12].([]byte)
		peerAgePublic, _ = proposal[13].([]byte)
	}
	if len(peerID) != 16 || len(peerSigningPublic) != 32 || len(peerAgePublic) != 1216 {
		return errors.New("peer relationship reset identity is invalid")
	}
	resetID, _ := hex.DecodeString(reset.ResetID)
	outbound, err := decodeV2Base64URL(runtime.state.OutboundRelationshipSecret, 32)
	if err != nil {
		return err
	}
	inbound, err := decodeV2Base64URL(runtime.state.InboundRelationshipSecret, 32)
	if err != nil {
		return err
	}
	outbound, err = deriveV2ResetRelationshipSecret(outbound, resetID, newRelationshipID, v2OutboundDirection(runtime.state.Role))
	if err != nil {
		return err
	}
	inbound, err = deriveV2ResetRelationshipSecret(inbound, resetID, newRelationshipID, v2InboundDirection(runtime.state.Role))
	if err != nil {
		return err
	}
	pending := &v2PendingPairing{
		RelationshipID: reset.NewRelationshipID, Role: runtime.state.Role,
		OutboundRelationshipSecret: v2Base64URL(outbound), InboundRelationshipSecret: v2Base64URL(inbound),
		ServerContract: runtime.state.ServerContract, PeerFeatures: append([]uint64(nil), runtime.state.PeerFeatures...),
	}
	newState := newV2PeerDeliveryState(pending, map[string]string{})
	newState.Generation = reset.Generation
	initializeV2ResetChains(newState, newRelationshipID)
	newState.Reset = reset
	newState.ResetAudit = append(append([]v2ResetAuditRecord(nil), runtime.state.ResetAudit...), v2ResetAuditRecord{
		ResetID: reset.ResetID, OldRelationshipID: reset.OldRelationshipID,
		NewRelationshipID: reset.NewRelationshipID, Generation: reset.Generation,
		Proposal: reset.Proposal, ProposalSignature: reset.ProposalSignature,
		Acceptance: reset.Acceptance, AcceptanceSignature: reset.AcceptanceSignature,
		ServerReceipt: reset.ServerReceipt, LocalDisposition: reset.LocalDisposition,
		PeerDisposition: reset.PeerDisposition, ActivatedAt: reset.ActivatedAt,
	})
	if len(newState.ResetAudit) > 8 {
		newState.ResetAudit = newState.ResetAudit[len(newState.ResetAudit)-8:]
	}
	identity, err := deriveV2RelationshipIdentity(runtime.seed, newRelationshipID, 0)
	if err != nil {
		return err
	}
	peerRecipient, err := age.ParseHybridRecipient(bech32Encode("age1pq", peerAgePublic))
	if err != nil {
		return err
	}
	newSigning, err := deriveV2SigningKey(runtime.seed, newRelationshipID, 0)
	if err != nil {
		return err
	}
	newPeer := runtime.peer
	newPeer.RelationshipID = reset.NewRelationshipID
	newPeer.Generation = reset.Generation
	newPeer.PeerPseudonymousID = hex.EncodeToString(peerID)
	newPeer.PeerSigningPublicKey = v2Base64URL(peerSigningPublic)
	newPeer.PeerAgeRecipient = v2Base64URL(peerAgePublic)
	newPeer.InboxCapabilityReference = "deliveries/" + reset.NewRelationshipID + ".json"
	newRuntime := &v2PeerRuntime{
		cfg: runtime.cfg, paths: runtime.paths, peer: newPeer, state: newState, seed: runtime.seed,
		relationshipID: newRelationshipID, localID: localID, peerID: peerID,
		signingKey: newSigning, identity: identity, recipient: peerRecipient,
		origin: runtime.origin, transport: runtime.transport,
	}
	if !bytes.Equal(localSigningPublic, newSigning.Public().(ed25519.PublicKey)) || len(localAgePublic) != 1216 {
		return errors.New("local peer relationship reset identity derivation failed")
	}
	if err := newRuntime.reissueCapabilities(ctx); err != nil {
		return fmt.Errorf("activate reset relationship capabilities: %w", err)
	}
	oldMarker := *reset
	oldMarker.Phase = "activating"
	runtime.state.Reset = &oldMarker
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return err
	}
	if err := cleanupV2ResetGitState(a, runtime.peer.PeerPseudonymousID); err != nil {
		return fmt.Errorf("clean peer Git state after relationship reset: %w", err)
	}
	_, err = updateV2ConfigLocked(runtime.paths, func(cfg *v2LocalConfig) error {
		peer, exists := cfg.Peers[alias]
		if !exists || peer.RelationshipID != reset.OldRelationshipID {
			return errors.New("peer profile changed during relationship reset")
		}
		cfg.Peers[alias] = newPeer
		return nil
	})
	return err
}

// v2PeerResetOptions is one invocation of 'dud peer reset'.
type v2PeerResetOptions struct {
	alias     string
	confirmed bool
	json      bool
	cancel    bool
}

func parseV2PeerResetOptions(args []string) (v2PeerResetOptions, error) {
	var opts v2PeerResetOptions
	if len(args) == 0 {
		return opts, fatalError("dud peer reset requires NAME")
	}
	opts.alias = args[0]
	for _, option := range args[1:] {
		switch option {
		case "--yes":
			opts.confirmed = true
		case "--json":
			if err := markJSONOption(&opts.json); err != nil {
				return opts, err
			}
		case "--cancel":
			opts.cancel = true
		default:
			return opts, fatalError("Unknown peer reset option: " + option)
		}
	}
	return opts, nil
}

// cancelV2PeerReset withdraws a reset that has not been activated. The server
// records the cancellation, so both devices learn the relationship was kept
// rather than one of them continuing to expect a new generation.
func (a *app) cancelV2PeerReset(runtime *v2PeerRuntime, opts v2PeerResetOptions) error {
	if runtime.state.Reset == nil || runtime.state.Reset.Phase == "active" || runtime.state.Reset.Phase == "cancelled" {
		return errors.New("there is no pending peer relationship reset to cancel")
	}
	if !opts.confirmed {
		return fatalError("cancelling a peer relationship reset requires --yes")
	}
	body, err := runtime.resetCancellationBody(runtime.state.Reset)
	if err != nil {
		return err
	}
	result, err := runtime.v2ResetRequest(context.Background(), body)
	if err != nil {
		return err
	}
	reset, _, err := runtime.applyV2ResetResponse(result)
	if err != nil {
		return err
	}
	reset.RecoveryCommand = ""
	runtime.state.Reset = reset
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return err
	}
	if opts.json {
		return writeJSON(a.out, map[string]any{"peer": opts.alias, "reset_id": reset.ResetID, "phase": reset.Phase})
	}
	fmt.Fprintf(a.out, "Cancelled peer relationship reset %s for %q.\n", reset.ResetID, opts.alias)
	return nil
}

// reportV2ResetDisposition lists the work a reset would abandon and stops. A
// reset discards everything in flight on both devices, so the operator sees the
// count of each kind before the command that performs it is accepted.
func (a *app) reportV2ResetDisposition(opts v2PeerResetOptions, disposition v2ResetDisposition) error {
	if opts.json {
		return writeJSON(a.out, map[string]any{"peer": opts.alias, "confirmed": false, "abandons": disposition, "next": "dud peer reset " + opts.alias + " --yes"})
	}
	fmt.Fprintf(a.out, "Peer relationship reset for %q abandons:\n", opts.alias)
	report := &textReport{}
	section := report.section("")
	section.addf("queued deliveries", "%d", disposition.QueuedDeliveries)
	section.addf("queued completions", "%d", disposition.QueuedCompletions)
	section.addf("queued control events", "%d", disposition.QueuedControlEvents)
	section.addf("unacknowledged deliveries", "%d", disposition.Unacknowledged)
	section.addf("inbound transfers", "%d", disposition.InboundTransfers)
	section.addf("quarantined chains", "%d", disposition.QuarantinedChains)
	section.addf("resumable transfers", "%d", disposition.ResumableTransfers)
	section.addf("refused Git checkpoints", "%d", disposition.RefusedGitCheckpoints)
	if err := report.write(a.out); err != nil {
		return err
	}
	return fatalError("review the abandoned work, then rerun with --yes")
}

// proposeV2PeerReset finds the reset the server already holds for this
// relationship, or proposes one. Both devices run the same command, so the one
// that arrives second adopts the proposal already on the server instead of
// racing a second proposal against it.
func (runtime *v2PeerRuntime) proposeV2PeerReset(ctx context.Context) (*v2RelationshipReset, map[int]any, error) {
	result, found, err := runtime.findV2Reset(ctx)
	if err != nil {
		return nil, nil, err
	}
	canPropose := runtime.state.Reset == nil || runtime.state.Reset.Phase == "active" || runtime.state.Reset.Phase == "cancelled"
	if !found && !canPropose {
		return nil, nil, errors.New("pending peer relationship reset is unavailable on the server")
	}
	if !found {
		local, localErr := runtime.newV2ResetProposal()
		if localErr != nil {
			return nil, nil, localErr
		}
		proposal, _ := decodeV2ResetMap(local.Proposal)
		signature, _ := decodeV2Base64URL(local.ProposalSignature, 64)
		result, err = runtime.v2ResetRequest(ctx, map[int]any{1: uint64(1), 2: proposal, 3: signature})
		if err != nil {
			return nil, nil, err
		}
	}
	return runtime.applyV2ResetResponse(result)
}

// acceptV2PeerResetProposal signs the peer's proposal and sends the full
// transcript back. The device that did not propose is the one that consents,
// and its consent is written down before the request, so a reply that never
// arrives leaves a record of what this device already agreed to.
func (runtime *v2PeerRuntime) acceptV2PeerResetProposal(ctx context.Context, opts v2PeerResetOptions, reset *v2RelationshipReset, proposal map[int]any) (*v2RelationshipReset, map[int]any, error) {
	if err := runtime.acceptV2Reset(reset, proposal); err != nil {
		return nil, nil, err
	}
	reset.RecoveryCommand = "dud peer reset " + opts.alias + " --yes"
	runtime.state.Reset = reset
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return nil, nil, err
	}
	proposalSignature, _ := decodeV2Base64URL(reset.ProposalSignature, 64)
	acceptance, _ := decodeV2ResetMap(reset.Acceptance)
	acceptanceSignature, _ := decodeV2Base64URL(reset.AcceptanceSignature, 64)
	result, err := runtime.v2ResetRequest(ctx, map[int]any{
		1: uint64(3), 2: proposal, 3: proposalSignature,
		4: acceptance, 5: acceptanceSignature,
	})
	if err != nil {
		return nil, nil, err
	}
	return runtime.applyV2ResetResponse(result)
}

// reportV2PeerReset renders the state a reset reached. A reset the server has
// not activated is waiting for the other device, so the line names the command
// that device runs, and the same command re-entered here picks the reset up
// where it stands.
func (a *app) reportV2PeerReset(opts v2PeerResetOptions, reset *v2RelationshipReset) error {
	output := map[string]any{
		"peer": opts.alias, "reset_id": reset.ResetID, "generation": reset.Generation,
		"phase": reset.Phase, "local_consent": reset.LocalConsent,
		"peer_consent": reset.PeerConsent, "server_activated": reset.ServerActivated,
		"local_abandoned": reset.LocalDisposition, "peer_abandoned": reset.PeerDisposition,
	}
	if !reset.ServerActivated {
		output["next"] = "dud peer reset " + opts.alias + " --yes"
	}
	if opts.json {
		return writeJSON(a.out, output)
	}
	if reset.ServerActivated {
		fmt.Fprintf(a.out, "Activated peer relationship reset %s for %q at generation %d.\n", reset.ResetID, opts.alias, reset.Generation)
	} else {
		fmt.Fprintf(a.out, "Peer relationship reset %s for %q is waiting for peer consent.\n", reset.ResetID, opts.alias)
	}
	return nil
}

func (a *app) cmdPeerReset(args []string) error {
	opts, err := parseV2PeerResetOptions(args)
	if err != nil {
		return err
	}
	return a.withV2PeerForRecovery(opts.alias, 30*time.Second, func(runtime *v2PeerRuntime) error {
		capabilities, err := runtime.state.ServerContract.capabilities()
		if err != nil || !hasV2Feature(capabilities.Features, 12) {
			return errors.New("server does not support peer relationship reset; no reset state was written")
		}
		if !hasV2Feature(runtime.state.PeerFeatures, 12) {
			return errors.New("peer does not advertise peer relationship reset support; no reset state was written")
		}
		if opts.cancel {
			return a.cancelV2PeerReset(runtime, opts)
		}
		if !opts.confirmed {
			return a.reportV2ResetDisposition(opts, v2ResetDispositionOf(runtime.state))
		}
		ctx := context.Background()
		reset, proposal, err := runtime.proposeV2PeerReset(ctx)
		if err != nil {
			return err
		}
		reset.RecoveryCommand = "dud peer reset " + opts.alias + " --yes"
		if reset.InitiatorRole != runtime.state.Role && !reset.ServerActivated {
			reset, proposal, err = runtime.acceptV2PeerResetProposal(ctx, opts, reset, proposal)
			if err != nil {
				return err
			}
			reset.RecoveryCommand = "dud peer reset " + opts.alias + " --yes"
		}
		if reset.ServerActivated {
			if err := runtime.activateV2ResetLocally(ctx, a, opts.alias, reset, proposal); err != nil {
				return err
			}
		} else {
			runtime.state.Reset = reset
			if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
				return err
			}
		}
		return a.reportV2PeerReset(opts, reset)
	})
}
