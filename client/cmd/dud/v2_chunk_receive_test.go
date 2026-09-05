// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

type v2ChunkDownloadTransport struct {
	bodies  map[string][]byte
	failID  string
	seenIDs []string
}

func (transport *v2ChunkDownloadTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	id := filepath.Base(request.Path)
	transport.seenIDs = append(transport.seenIDs, id)
	if id == transport.failID {
		return nil, errors.New("chunk download interrupted")
	}
	body, ok := transport.bodies[id]
	if !ok {
		return &v2Response{StatusCode: http.StatusNotFound}, nil
	}
	digest := sha256.Sum256(body)
	return &v2Response{
		StatusCode:  http.StatusOK,
		ContentType: "application/octet-stream",
		Headers: http.Header{
			"Content-Length":     {strconv.Itoa(len(body))},
			"Dud-Content-Sha256": {hex.EncodeToString(digest[:])},
		},
		Stream: io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func TestV2ChunkReceiveResumesWithoutDownloadingVerifiedPartsTwice(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := append(bytes.Repeat([]byte("a"), 1024*1024), 'b')
	spool, err := spoolV2ChunkedPayload(bytes.NewReader(plaintext), filepath.Join(t.TempDir(), "sender"), identity.Recipient(), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	manifest := make([]v2ChunkManifestPart, len(spool.Chunks))
	chunkIDs := make([][]byte, len(spool.Chunks))
	chunkHashes := make([][]byte, len(spool.Chunks))
	bodies := map[string][]byte{}
	for index, chunk := range spool.Chunks {
		body, readErr := os.ReadFile(chunk.Path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		id := hex.EncodeToString(chunk.ID)
		bodies[id] = body
		manifest[index] = v2ChunkManifestPart{ID: chunk.ID, Length: chunk.CiphertextLength, Digest: chunk.CiphertextHash}
		chunkIDs[index] = chunk.ID
		chunkHashes[index] = chunk.CiphertextHash
	}
	descriptorDigest := sha256.Sum256([]byte("chunk receive descriptor"))
	envelope := &validatedV2Envelope{
		Descriptor: map[int]any{
			kChunkSize:     uint64(1024 * 1024),
			kPlaintextSize: uint64(len(plaintext)),
			kChunkIDs:      chunkIDs,
			kChunkHashes:   chunkHashes,
			kPayloadHash:   spool.PlaintextHash,
		},
		DescriptorDigest: descriptorDigest,
	}
	delivery := &v2GranularInboxDelivery{
		ID:                  bytes.Repeat([]byte{0x71}, 16),
		Slot:                bytes.Repeat([]byte{0x72}, 16),
		EncryptedDescriptor: []byte("encrypted descriptor"),
		Chunks:              manifest,
	}
	policyDigest := sha256.Sum256([]byte("policy"))
	firstID := hex.EncodeToString(spool.Chunks[0].ID)
	secondID := hex.EncodeToString(spool.Chunks[1].ID)
	firstTransport := &v2ChunkDownloadTransport{bodies: bodies, failID: secondID}
	runtime := &v2PeerRuntime{paths: paths, state: state, identity: identity, origin: "https://dud.example.com", transport: firstTransport}
	_, _, _, _, err = runtime.receiveV2ChunkedPayload(context.Background(), delivery, envelope, v2SlotEpoch(time.Now()), policyDigest[:], 1, uint64(time.Now().Add(time.Hour).Unix()))
	if err == nil {
		t.Fatal("interrupted chunk receive succeeded")
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	transfer := loaded.InboundTransfers[hex.EncodeToString(descriptorDigest[:])]
	if !transfer.Chunks[0].Downloaded || transfer.Chunks[1].Downloaded {
		t.Fatalf("download progress = %#v", transfer.Chunks)
	}
	secondTransport := &v2ChunkDownloadTransport{bodies: bodies}
	runtime = &v2PeerRuntime{paths: paths, state: loaded, identity: identity, origin: "https://dud.example.com", transport: secondTransport}
	output, digest, transfer, resumed, err := runtime.receiveV2ChunkedPayload(context.Background(), delivery, envelope, v2SlotEpoch(time.Now()), policyDigest[:], 1, uint64(time.Now().Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if !resumed || len(secondTransport.seenIDs) != 1 || secondTransport.seenIDs[0] != secondID || secondTransport.seenIDs[0] == firstID {
		t.Fatalf("resume downloads = %#v", secondTransport.seenIDs)
	}
	assembled, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(plaintext)
	if !bytes.Equal(assembled, plaintext) || digest != wantDigest || transfer.Phase != "payload-verified" {
		t.Fatalf("assembled receive = %d bytes, digest %x, phase %s", len(assembled), digest, transfer.Phase)
	}
}

func TestV2GranularInboxDecodesOrderedChunkManifest(t *testing.T) {
	parts := v2ChunkTestParts()
	emptyDigest := sha256.Sum256(nil)
	rawParts := make([]any, len(parts))
	for index, part := range parts {
		rawParts[index] = map[int]any{1: part.ID, 2: part.Length, 3: part.Digest}
	}
	delivery, err := decodeV2GranularInboxDelivery(&v2GranularInboxResponse{
		Header: map[int]any{
			1: []any{}, 2: []any{}, 3: bytes.Repeat([]byte{1}, 16), 4: bytes.Repeat([]byte{2}, 16),
			5: []byte("descriptor"), 6: map[int]any{1: uint64(1)}, 7: uint64(0), 8: emptyDigest[:], 9: []any{}, 10: rawParts,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delivery.Chunks) != 2 || !bytes.Equal(delivery.Chunks[1].ID, parts[1].ID) {
		t.Fatalf("decoded chunks = %#v", delivery.Chunks)
	}
}

func TestV2PeerAbandonRemovesInboundResumeState(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	digest := strings.Repeat("33", 32)
	directory := filepath.Join(paths.StateDir, "transfers", state.RelationshipID, digest+".chunks")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	parts := v2ChunkTestParts()
	stored := make([]v2InboundChunkPart, len(parts))
	for index, part := range parts {
		path := filepath.Join(directory, hex.EncodeToString(part.ID)+".age")
		if err := atomicWriteV2File(path, bytes.Repeat([]byte{byte(index + 1)}, int(part.Length)), 0o600); err != nil {
			t.Fatal(err)
		}
		stored[index] = v2InboundChunkPart{ID: hex.EncodeToString(part.ID), Path: path, CiphertextLength: part.Length, CiphertextHash: hex.EncodeToString(part.Digest), Downloaded: true}
	}
	state.InboundTransfers[digest] = v2InboundTransfer{
		EntryID: strings.Repeat("11", 16), Slot: strings.Repeat("22", 16), DescriptorDigest: digest,
		Sequence: 1, Phase: "chunks-downloading", OutputDigest: strings.Repeat("44", 32), PolicyDigest: strings.Repeat("55", 32),
		ChunkSize: 1024 * 1024, PlaintextLength: 1024*1024 + 1, Chunks: stored, ExpiresAt: uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &stubV2Transport{}, nil }
	if err := a.cmdPeer([]string{"abandon", "phone", "--id", digest, "--yes", "--json"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.InboundTransfers[digest]; exists || !strings.Contains(stdout.String(), `"abandoned": true`) {
		t.Fatalf("abandon state = %#v, output = %s", loaded.InboundTransfers, stdout.String())
	}
}
