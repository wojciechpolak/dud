// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

type pagedV2ControlTransport struct {
	events []map[int]any
}

func (transport *pagedV2ControlTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	if request.Path != "/v2/inbox" {
		return nil, errors.New("unexpected control drain request")
	}
	var query map[int]any
	if err := v2DecMode.Unmarshal(request.Body, &query); err != nil {
		return nil, err
	}
	processed := map[string]bool{}
	if ids, ok := query[3].([]any); ok {
		for _, id := range ids {
			processed[hex.EncodeToString(id.([]byte))] = true
		}
	}
	proofs := map[uint64]bool{}
	for _, raw := range query[2].([]any) {
		proof, err := normalizeV2Map(raw)
		if err != nil {
			return nil, err
		}
		epoch, _ := asV2Uint(proof[2])
		proofs[epoch] = true
	}
	retained := make([]map[int]any, 0, len(transport.events))
	page := []any{}
	for _, event := range transport.events {
		if processed[hex.EncodeToString(event[1].([]byte))] {
			continue
		}
		retained = append(retained, event)
		if proofs[event[3].(uint64)] && len(page) == 0 {
			page = append(page, event)
		}
	}
	transport.events = retained
	digest := sha256.Sum256(nil)
	body, err := encodeV2GranularFrame(map[int]any{
		1: []any{}, 2: page, 7: uint64(0), 8: digest[:], 9: []any{},
	}, nil, 7, 8)
	if err != nil {
		return nil, err
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
}

func TestV2ControlDrainKeepsOlderEpochReachableAcrossPagesAndRestarts(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	current := v2SlotEpoch(time.Now())
	older := current - 2
	state.ControlScanEpoch = older
	state.Chains["out:data"].SendSequence = 3
	transport := &pagedV2ControlTransport{}
	previous := make([]byte, 32)
	for index, epoch := range []uint64{older, older, current} {
		sequence := uint64(index + 1)
		ackedDigest := bytesRepeatV2(byte(0x80+index), 32)
		key := hex.EncodeToString(ackedDigest)
		state.Sent[key] = v2SentDelivery{Sequence: sequence, DescriptorDigest: key}
		descriptor := v2Descriptor{
			DescriptorID: bytesRepeatV2(byte(index+1), 16), PayloadType: 5,
			RelationshipID: crypto.relationshipID, Direction: v2InboundDirection(crypto.role),
			Chain: 1, Sequence: sequence, PreviousDigest: previous,
			SenderDeviceID: crypto.peerID, RecipientDeviceID: crypto.localID,
			CanonicalOrigin: crypto.origin, CreatedAt: uint64(time.Now().Unix()),
			TransportPolicy: v2TransportPolicy{ExpiresAt: uint64(time.Now().Unix()) + 86_400, Consume: 1, ClaimLeaseSeconds: 300},
			PayloadHash:     bytesRepeatV2(0, 32), ChunkHashes: [][]byte{bytesRepeatV2(0, 32)},
			TypeMetadata: map[int]any{
				1: sequence, 2: ackedDigest, 3: uint64(0), 4: bytesRepeatV2(0x90, 32),
				5: uint64(0), 6: sequence, 7: sequence - 1, 8: uint64(0),
			},
		}
		envelope, err := encryptV2Envelope(descriptor, crypto.signingKey, crypto.recipient)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := descriptorMap(descriptor, crypto.signingKey)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := v2EncMode.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		previous = digest[:]
		slot, err := deriveV2Slot(crypto.inboundSecret, "control", epoch)
		if err != nil {
			t.Fatal(err)
		}
		transport.events = append(transport.events, map[int]any{
			1: bytesRepeatV2(byte(index+1), 16), 2: slot, 3: epoch, 4: envelope, 5: uint64(time.Now().Unix()) + 86_400,
		})
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	a := newDrainingV2TestApp(t, transport, &bytes.Buffer{}, &bytes.Buffer{})
	for round := 0; round < 4; round++ {
		if err := a.withV2Peer("laptop", time.Second, func(runtime *v2PeerRuntime) error {
			return runtime.boundedControlDrain(context.Background())
		}); err != nil {
			t.Fatalf("drain %d: %v", round+1, err)
		}
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	chain := loaded.Chains["in:control"]
	if chain.ReceiveWatermark != 3 || chain.Quarantined || loaded.ControlScanEpoch != current || len(transport.events) != 0 {
		t.Fatalf("drained chain = %#v, scan epoch = %d, pending events = %d", chain, loaded.ControlScanEpoch, len(transport.events))
	}
	for digest, sent := range loaded.Sent {
		if !sent.Acknowledged {
			t.Errorf("delivery %s lacks its acknowledgement", digest)
		}
	}
}
