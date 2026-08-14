// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

type granularInboxTransport struct {
	request v2Request
	frame   []byte
}

type granularControlTransport struct {
	request  v2Request
	response []byte
}

type granularDeliveryTransport struct {
	request  v2Request
	response []byte
}

type granularCompletionTransport struct {
	request  v2Request
	response []byte
}

func (transport *granularCompletionTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.request = request
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.response}, nil
}

func (transport *granularDeliveryTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.request = request
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.response}, nil
}

func (transport *granularControlTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.request = request
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.response}, nil
}

func (transport *granularInboxTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.request = request
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.frame}, nil
}

func TestV2GranularInboxProofMatchesFrozenServerVector(t *testing.T) {
	input := v2GranularSlotProofInput{
		TokenSecret: sequentialV2TestBytes(1, 32),
		Direction:   "inviter->invitee",
		Scope:       "read",
		Chain:       3,
		Slot:        sequentialV2TestBytes(49, 16),
		Epoch:       20_000,
		Nonce:       sequentialV2TestBytes(65, 16),
		ExpiresAt:   1_728_000_000,
	}
	request, err := encodeV2GranularInboxRequest(
		"https://dud.example.com",
		[]v2GranularSlotProofInput{input},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("a10181a401503132333435363738393a3b3c3d3e3f4002194e200303045850a50150cd4bfbfb74dae371c2d9c422348b756102504142434445464748494a4b4c4d4e4f50031a66ff300004000558205efe8aefb0d87de3044db412bedd610b2e6b0e8a847867f819c70a924e4a0d4b")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request, want) {
		t.Fatalf("inbox request = %x", request)
	}
}

func TestV2GranularFrameRoundTripsAndRejectsPayloadTampering(t *testing.T) {
	payload := []byte("ciphertext")
	digest := sha256.Sum256(payload)
	frame, err := encodeV2GranularFrame(map[int]any{
		1: uint64(len(payload)),
		2: digest[:],
	}, payload, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	header, decoded, err := decodeV2GranularFrame(frame, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if length, ok := asV2Uint(header[1]); !ok || length != uint64(len(payload)) || !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded granular frame = %#v, %x", header, decoded)
	}
	frame[len(frame)-1] ^= 1
	if _, _, err := decodeV2GranularFrame(frame, 1, 2); err == nil {
		t.Fatal("tampered granular frame was accepted")
	}
}

func TestV2GranularInboxUsesOneFramedRequest(t *testing.T) {
	emptyDigest := sha256.Sum256(nil)
	frame, err := encodeV2GranularFrame(map[int]any{
		1: []any{},
		2: []any{},
		7: uint64(0),
		8: emptyDigest[:],
	}, nil, 7, 8)
	if err != nil {
		t.Fatal(err)
	}
	transport := &granularInboxTransport{frame: frame}
	response, err := queryV2GranularInbox(
		context.Background(),
		transport,
		"https://dud.example.com",
		[]v2GranularSlotProofInput{{
			TokenSecret: sequentialV2TestBytes(1, 32),
			Direction:   "inviter->invitee",
			Scope:       "read",
			Chain:       v2GranularDataChain,
			Slot:        sequentialV2TestBytes(49, 16),
			Epoch:       20_000,
			Nonce:       sequentialV2TestBytes(65, 16),
			ExpiresAt:   1_728_000_000,
		}},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if transport.request.Method != "POST" || transport.request.Path != "/v2/inbox" || transport.request.Headers.Get("Content-Type") != v2CBORContentType {
		t.Fatalf("inbox request = %#v", transport.request)
	}
	if len(transport.request.Body) == 0 || response == nil || len(response.Payload) != 0 {
		t.Fatalf("inbox response = %#v", response)
	}
}

func TestV2GranularInboxDeliveryRequiresCoherentPayloadFields(t *testing.T) {
	deliveryID := sequentialV2TestBytes(1, 16)
	response := &v2GranularInboxResponse{
		Header: map[int]any{
			1: []any{}, 2: []any{}, 3: deliveryID, 4: sequentialV2TestBytes(17, 16),
			5: []byte("encrypted-descriptor"), 6: map[int]any{1: uint64(1)},
			7: uint64(10), 8: bytesRepeatV2(0x51, 32),
		},
		Payload: []byte("ciphertext"),
	}
	delivery, err := decodeV2GranularInboxDelivery(response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(delivery.ID, deliveryID) || !bytes.Equal(delivery.Payload, response.Payload) {
		t.Fatalf("decoded inbox delivery = %#v", delivery)
	}
	response.Header = map[int]any{1: []any{}, 2: []any{}, 7: uint64(10), 8: bytesRepeatV2(0x51, 32)}
	if _, err := decodeV2GranularInboxDelivery(response); err == nil {
		t.Fatal("inbox payload without delivery ID was accepted")
	}
}

func TestV2GranularControlEventUsesOneIdempotentRequest(t *testing.T) {
	operationID := sequentialV2TestBytes(1, 16)
	response, err := v2EncMode.Marshal(map[int]any{1: operationID, 2: false})
	if err != nil {
		t.Fatal(err)
	}
	transport := &granularControlTransport{response: response}
	published, err := publishV2GranularControlEvent(
		context.Background(),
		transport,
		"https://dud.example.com",
		operationID,
		[]byte("encrypted-control"),
		v2GranularSlotProofInput{
			TokenSecret: sequentialV2TestBytes(17, 32),
			Direction:   "inviter->invitee",
			Scope:       "write",
			Chain:       v2GranularControlChain,
			Slot:        sequentialV2TestBytes(49, 16),
			Epoch:       20_000,
			Nonce:       sequentialV2TestBytes(65, 16),
			ExpiresAt:   1_728_000_000,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if transport.request.Method != "POST" || transport.request.Path != "/v2/control-events" || !bytes.Equal(published.EventID, operationID) || published.Idempotent {
		t.Fatalf("control publication = %#v, %#v", transport.request, published)
	}
}

func TestV2GranularDeliveryUsesOneFramedRequest(t *testing.T) {
	operationID := sequentialV2TestBytes(1, 16)
	response, err := v2EncMode.Marshal(map[int]any{
		1: operationID,
		2: map[int]any{1: uint64(1)},
		3: false,
		4: []any{},
		5: []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := &granularDeliveryTransport{response: response}
	published, err := publishV2GranularDelivery(
		context.Background(),
		transport,
		"https://dud.example.com",
		operationID,
		[]byte("encrypted-descriptor"),
		map[int]any{1: uint64(1)},
		[]byte("ciphertext"),
		v2GranularSlotProofInput{
			TokenSecret: sequentialV2TestBytes(17, 32),
			Direction:   "inviter->invitee",
			Scope:       "write",
			Chain:       v2GranularDataChain,
			Slot:        sequentialV2TestBytes(49, 16),
			Epoch:       20_000,
			Nonce:       sequentialV2TestBytes(65, 16),
			ExpiresAt:   1_728_000_000,
		},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if transport.request.Method != "POST" || transport.request.Path != "/v2/deliveries" || transport.request.Headers.Get("DUD-Content-SHA256") == "" || !bytes.Equal(published.DeliveryID, operationID) {
		t.Fatalf("delivery publication = %#v, %#v", transport.request, published)
	}
	if _, _, err := decodeV2GranularFrame(transport.request.Body, 4, 5); err != nil {
		t.Fatalf("published frame is invalid: %v", err)
	}
}

func TestV2GranularCompletionUsesBoundProofs(t *testing.T) {
	deliveryID := sequentialV2TestBytes(1, 16)
	controlEventID := sequentialV2TestBytes(17, 16)
	response, err := v2EncMode.Marshal(map[int]any{1: deliveryID, 2: controlEventID, 3: false})
	if err != nil {
		t.Fatal(err)
	}
	transport := &granularCompletionTransport{response: response}
	ackProof := v2GranularSlotProofInput{
		TokenSecret: sequentialV2TestBytes(33, 32), Direction: "inviter->invitee", Scope: "ack", Chain: v2GranularDataChain,
		Slot: sequentialV2TestBytes(65, 16), Epoch: 20_000, Nonce: sequentialV2TestBytes(81, 16), ExpiresAt: 1_728_000_000,
	}
	controlProof := v2GranularSlotProofInput{
		TokenSecret: sequentialV2TestBytes(97, 32), Direction: "invitee->inviter", Scope: "write", Chain: v2GranularControlChain,
		Slot: sequentialV2TestBytes(129, 16), Epoch: 20_000, Nonce: sequentialV2TestBytes(145, 16), ExpiresAt: 1_728_000_000,
	}
	completed, err := completeV2GranularDelivery(
		context.Background(), transport, "https://dud.example.com", deliveryID, ackProof.Slot, controlProof.Slot,
		bytesRepeatV2(0x61, 32), bytesRepeatV2(0x62, 32), 0, sequentialV2TestBytes(161, 16), []byte("encrypted-acknowledgement"), ackProof, controlProof,
	)
	if err != nil {
		t.Fatal(err)
	}
	if transport.request.Method != "POST" || transport.request.Path != "/v2/deliveries/0102030405060708090a0b0c0d0e0f10/complete" || !bytes.Equal(completed.ControlEventID, controlEventID) {
		t.Fatalf("completion = %#v, %#v", transport.request, completed)
	}
}

// Protocol §8 has a receiver poll the current slot plus a recovery window of
// roughly 30 past slots. A proof for one of those epochs must not inherit that
// epoch's end as its expiry: that puts it behind the server's clock the moment
// it is built, and every request carrying it is refused as "expired or
// misplaced". Because a relationship drained inside a single UTC day never
// queries a past epoch, only a day of inactivity reaches this.
func TestGranularSlotProofForAPastEpochIsNotBornExpired(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	slot := bytes.Repeat([]byte{9}, 16)
	now := time.Unix(1_800_000_000, 0)
	current := v2SlotEpoch(now)

	for _, offset := range []uint64{0, 1, 2, 29} {
		epoch := current - offset
		input, err := newV2GranularSlotProofInput(
			secret, "inbound", "read", v2GranularControlChain, slot, epoch, now,
		)
		if err != nil {
			t.Fatal(err)
		}
		if input.ExpiresAt <= uint64(now.Unix()) {
			t.Fatalf("epoch %d (%d behind) expires at %d, already past %d",
				epoch, offset, input.ExpiresAt, now.Unix())
		}
		// The server also refuses a proof that outlives its lifetime cap.
		if input.ExpiresAt > uint64(now.Unix())+300 {
			t.Fatalf("epoch %d expires at %d, beyond the 5 minute cap", epoch, input.ExpiresAt)
		}
	}
}

// The clamp still applies while the epoch is running, so a proof never claims
// authority past the epoch it names.
func TestGranularSlotProofClampsInsideTheRunningEpoch(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	slot := bytes.Repeat([]byte{9}, 16)
	current := v2SlotEpoch(time.Unix(1_800_000_000, 0))
	epochEnd := (current + 1) * v2SlotEpochSeconds
	// Thirty seconds before the epoch rolls over, a 60 second lifetime would
	// otherwise cross into the next one.
	now := time.Unix(int64(epochEnd-30), 0)

	input, err := newV2GranularSlotProofInput(
		secret, "inbound", "read", v2GranularControlChain, slot, current, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if input.ExpiresAt != epochEnd-1 {
		t.Fatalf("expiry = %d, want the epoch end %d", input.ExpiresAt, epochEnd-1)
	}
	if input.ExpiresAt <= uint64(now.Unix()) {
		t.Fatalf("clamped expiry %d is already past %d", input.ExpiresAt, now.Unix())
	}
}
