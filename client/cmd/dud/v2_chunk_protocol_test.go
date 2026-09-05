// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type v2ChunkTestTransport struct {
	do       func(v2Request) (*v2Response, error)
	requests []v2Request
}

func (transport *v2ChunkTestTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests = append(transport.requests, request)
	return transport.do(request)
}

func v2ChunkTestProof(scope string) v2GranularSlotProofInput {
	return v2GranularSlotProofInput{
		TokenSecret: bytes.Repeat([]byte{1}, 32),
		Direction:   "inviter->invitee",
		Scope:       scope,
		Chain:       0,
		Slot:        bytes.Repeat([]byte{2}, 16),
		Epoch:       20_000,
		Nonce:       bytes.Repeat([]byte{3}, 16),
		ExpiresAt:   1_728_000_000,
	}
}

func v2ChunkTestParts() []v2ChunkManifestPart {
	first := sha256.Sum256([]byte("first ciphertext"))
	second := sha256.Sum256([]byte("second ciphertext"))
	return []v2ChunkManifestPart{
		{ID: bytes.Repeat([]byte{4}, 16), Length: 16, Digest: first[:]},
		{ID: bytes.Repeat([]byte{5}, 16), Length: 17, Digest: second[:]},
	}
}

func TestV2ChunkUploadCreateAndPartUseBoundedStreamingWireForms(t *testing.T) {
	parts := v2ChunkTestParts()
	uploadID := bytes.Repeat([]byte{6}, 16)
	createResponse, err := v2EncMode.Marshal(map[int]any{1: uploadID, 2: uint64(1_728_000_100), 3: []any{parts[0].ID, parts[1].ID}, 4: false})
	if err != nil {
		t.Fatal(err)
	}
	transport := &v2ChunkTestTransport{}
	transport.do = func(request v2Request) (*v2Response, error) {
		switch request.Method {
		case "POST":
			return &v2Response{StatusCode: http.StatusCreated, ContentType: v2CBORContentType, Body: createResponse}, nil
		case "PUT":
			if request.BodyStream == nil || request.ContentLength != int64(parts[0].Length) || request.Body != nil {
				t.Fatalf("part request did not use an exact-length body stream: %#v", request)
			}
			body, readErr := io.ReadAll(request.BodyStream)
			if readErr != nil || string(body) != "first ciphertext" {
				t.Fatalf("part body = %q, %v", body, readErr)
			}
			return &v2Response{StatusCode: http.StatusNoContent}, nil
		default:
			t.Fatalf("unexpected method %s", request.Method)
			return nil, nil
		}
	}
	created, err := createV2ChunkUpload(context.Background(), transport, "https://dud.example.com", bytes.Repeat([]byte{7}, 16), 0, v2ChunkTestProof("write").Slot, 20_000, parts, v2ChunkTestProof("write"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(created.UploadID, uploadID) || len(created.MissingChunkIDs) != 2 || created.Idempotent {
		t.Fatalf("create response = %#v", created)
	}
	createRequest := transport.requests[0]
	if createRequest.BodyStream != nil {
		t.Fatal("create request used a body stream")
	}
	authorization := createRequest.Headers.Get("Dud-Authorization")
	if authorization == "" || strings.Contains(authorization, "=") {
		t.Fatalf("create request headers = %#v", createRequest.Headers)
	}
	if err := putV2ChunkUploadPart(context.Background(), transport, "https://dud.example.com", uploadID, parts[0], strings.NewReader("first ciphertext"), v2ChunkTestProof("write")); err != nil {
		t.Fatal(err)
	}
	partRequest := transport.requests[1]
	if partRequest.Headers.Get("Dud-Content-Sha256") != "4e353d12108efd76eb33f5aaadc89a61805e2db6f817484c1f339ca79c2d902b" {
		t.Fatalf("part digest header = %q", partRequest.Headers.Get("DUD-Content-SHA256"))
	}
}

func TestV2ChunkDownloadReturnsVerifiedResponseStream(t *testing.T) {
	part := v2ChunkTestParts()[0]
	transport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		if !request.StreamResponse || request.BodyStream != nil {
			t.Fatalf("download request = %#v", request)
		}
		return &v2Response{
			StatusCode:  http.StatusOK,
			ContentType: "application/octet-stream",
			Headers: http.Header{
				"Content-Length":     {"16"},
				"Dud-Content-Sha256": {"4e353d12108efd76eb33f5aaadc89a61805e2db6f817484c1f339ca79c2d902b"},
			},
			Stream: io.NopCloser(strings.NewReader("first ciphertext")),
		}, nil
	}}
	stream, err := getV2DeliveryChunk(context.Background(), transport, "https://dud.example.com", bytes.Repeat([]byte{8}, 16), part, v2ChunkTestProof("read"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	body, err := io.ReadAll(stream.Body)
	if err != nil || string(body) != "first ciphertext" {
		t.Fatalf("download body = %q, %v", body, err)
	}
}

func TestV2ChunkManifestRejectsDuplicatePartsAndOversizedCiphertext(t *testing.T) {
	parts := v2ChunkTestParts()
	parts[1].ID = append([]byte(nil), parts[0].ID...)
	if _, err := validateV2ChunkManifest(parts); err == nil {
		t.Fatal("duplicate chunk ID was accepted")
	}
	parts = v2ChunkTestParts()
	parts[0].Length = v2MaximumChunkCiphertextBytes + 1
	if _, err := validateV2ChunkManifest(parts); err == nil {
		t.Fatal("oversized chunk ciphertext was accepted")
	}
	tooMany := make([]v2ChunkManifestPart, v2MaximumChunkCount+1)
	for index := range tooMany {
		id := make([]byte, 16)
		binary.BigEndian.PutUint32(id, uint32(index))
		tooMany[index] = v2ChunkManifestPart{ID: id, Length: 1, Digest: bytes.Repeat([]byte{byte(index)}, 32)}
	}
	if _, err := validateV2ChunkManifest(tooMany); err == nil {
		t.Fatal("oversized chunk count was accepted")
	}
	tooLarge := make([]v2ChunkManifestPart, 65)
	for index := range tooLarge {
		id := make([]byte, 16)
		binary.BigEndian.PutUint32(id, uint32(index))
		tooLarge[index] = v2ChunkManifestPart{ID: id, Length: v2MaximumChunkCiphertextBytes, Digest: bytes.Repeat([]byte{byte(index)}, 32)}
	}
	if _, err := validateV2ChunkManifest(tooLarge); err == nil {
		t.Fatal("oversized aggregate chunk ciphertext was accepted")
	}
}

func TestV2PendingChunkDeliveryRoundTripsPrivateSpoolReferences(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	spoolDir := filepath.Join(paths.StateDir, "uploads", state.RelationshipID, strings.Repeat("09", 32))
	if err := ensureV2Directories(paths); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(spoolDir, "first.age")
	secondPath := filepath.Join(spoolDir, "second.age")
	if err := atomicWriteV2File(firstPath, []byte("first ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteV2File(secondPath, []byte("second ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	parts := v2ChunkTestParts()
	state.PendingChunkDeliveries = []v2PendingChunkDelivery{{
		CreateOperationID:   strings.Repeat("07", 16),
		CommitOperationID:   strings.Repeat("08", 16),
		CommitState:         v2ChunkCommitUnattempted,
		EncryptedDescriptor: v2Base64URL([]byte("encrypted descriptor")),
		DataSlot:            strings.Repeat("02", 16),
		SlotEpoch:           20_000,
		RequestedPolicy:     v2Base64URL([]byte{0xa0}),
		DescriptorDigest:    strings.Repeat("09", 32),
		PreviousDigest:      strings.Repeat("00", 32),
		Sequence:            1,
		ChunkSize:           16,
		PlaintextLength:     31,
		PlaintextHash:       strings.Repeat("0a", 32),
		Parts: []v2PendingChunkPart{
			{ID: strings.Repeat("04", 16), Path: firstPath, PlaintextLength: 16, CiphertextLength: 16, CiphertextHash: hex.EncodeToString(parts[0].Digest)},
			{ID: strings.Repeat("05", 16), Path: secondPath, PlaintextLength: 15, CiphertextLength: 17, CiphertextHash: hex.EncodeToString(parts[1].Digest)},
		},
		CreatedAt: 1_728_000_000,
	}}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.PendingChunkDeliveries) != 1 || loaded.PendingChunkDeliveries[0].Parts[1].Path != secondPath {
		t.Fatalf("loaded chunk state = %#v", loaded.PendingChunkDeliveries)
	}
}

func TestV2ChunkPublicationResumesAfterPersistedPartProgress(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	spoolDir := filepath.Join(paths.StateDir, "uploads", state.RelationshipID, strings.Repeat("09", 32))
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(spoolDir, "first.age")
	secondPath := filepath.Join(spoolDir, "second.age")
	if err := atomicWriteV2File(firstPath, []byte("first ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteV2File(secondPath, []byte("second ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	parts := v2ChunkTestParts()
	queued := v2PendingChunkDelivery{
		CreateOperationID:   strings.Repeat("07", 16),
		CommitOperationID:   strings.Repeat("08", 16),
		CommitState:         v2ChunkCommitUnattempted,
		EncryptedDescriptor: v2Base64URL([]byte("encrypted descriptor")),
		DataSlot:            strings.Repeat("02", 16),
		SlotEpoch:           v2SlotEpoch(time.Now()),
		RequestedPolicy:     v2Base64URL([]byte{0xa0}),
		DescriptorDigest:    strings.Repeat("09", 32),
		PreviousDigest:      strings.Repeat("00", 32),
		Sequence:            1,
		ChunkSize:           16,
		PlaintextLength:     31,
		PlaintextHash:       strings.Repeat("0a", 32),
		Parts: []v2PendingChunkPart{
			{ID: strings.Repeat("04", 16), Path: firstPath, PlaintextLength: 16, CiphertextLength: 16, CiphertextHash: hex.EncodeToString(parts[0].Digest)},
			{ID: strings.Repeat("05", 16), Path: secondPath, PlaintextLength: 15, CiphertextLength: 17, CiphertextHash: hex.EncodeToString(parts[1].Digest)},
		},
		CreatedAt: uint64(time.Now().Unix()),
	}
	state.PendingChunkDeliveries = []v2PendingChunkDelivery{queued}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	uploadID := bytes.Repeat([]byte{6}, 16)
	createResponse, err := v2EncMode.Marshal(map[int]any{1: uploadID, 2: uint64(time.Now().Add(time.Hour).Unix()), 3: []any{parts[0].ID, parts[1].ID}, 4: false})
	if err != nil {
		t.Fatal(err)
	}
	putCount := 0
	firstTransport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		switch request.Method {
		case "POST":
			return &v2Response{StatusCode: http.StatusCreated, ContentType: v2CBORContentType, Body: createResponse}, nil
		case "PUT":
			putCount++
			if putCount == 2 {
				return nil, errors.New("connection interrupted")
			}
			return &v2Response{StatusCode: http.StatusNoContent}, nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.Path)
			return nil, nil
		}
	}}
	runtime := &v2PeerRuntime{paths: paths, state: state, origin: "https://dud.example.com", transport: firstTransport}
	if err := runtime.flushPendingChunkDeliveries(context.Background()); err == nil {
		t.Fatal("interrupted upload succeeded")
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PendingChunkDeliveries[0].UploadID == "" || !loaded.PendingChunkDeliveries[0].Parts[0].Uploaded || loaded.PendingChunkDeliveries[0].Parts[1].Uploaded {
		t.Fatalf("persisted upload progress = %#v", loaded.PendingChunkDeliveries[0])
	}
	loaded.PendingChunkDeliveries[0].NextAttemptAt = 0
	if err := writeV2PeerDeliveryState(paths, loaded); err != nil {
		t.Fatal(err)
	}
	commitResponse, err := v2EncMode.Marshal(map[int]any{1: bytes.Repeat([]byte{10}, 16), 2: false})
	if err != nil {
		t.Fatal(err)
	}
	secondPutCount := 0
	secondTransport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		if request.Method == "PUT" {
			secondPutCount++
			if !strings.HasSuffix(request.Path, strings.Repeat("05", 16)) {
				t.Fatalf("resume uploaded the wrong part: %s", request.Path)
			}
			return &v2Response{StatusCode: http.StatusNoContent}, nil
		}
		if request.Method == "POST" && strings.HasSuffix(request.Path, "/commit") {
			return &v2Response{StatusCode: http.StatusOK, ContentType: v2CBORContentType, Body: commitResponse}, nil
		}
		t.Fatalf("resume repeated request %s %s", request.Method, request.Path)
		return nil, nil
	}}
	runtime = &v2PeerRuntime{paths: paths, state: loaded, origin: "https://dud.example.com", transport: secondTransport}
	if err := runtime.flushPendingChunkDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if secondPutCount != 1 || len(runtime.state.PendingChunkDeliveries) != 0 {
		t.Fatalf("resume sent %d parts with queue %#v", secondPutCount, runtime.state.PendingChunkDeliveries)
	}
	if _, err := os.Stat(firstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published chunk remains at %s", firstPath)
	}
}

func TestV2ChunkPublicationRetriesOnlyCommitAfterLostResponse(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	digest := strings.Repeat("09", 32)
	spoolDir := filepath.Join(paths.StateDir, "uploads", state.RelationshipID, digest)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	parts := v2ChunkTestParts()
	pathsByPart := []string{
		filepath.Join(spoolDir, "first.age"),
		filepath.Join(spoolDir, "second.age"),
	}
	for index, body := range [][]byte{[]byte("first ciphertext"), []byte("second ciphertext")} {
		if err := atomicWriteV2File(pathsByPart[index], body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state.PendingChunkDeliveries = []v2PendingChunkDelivery{{
		CreateOperationID: strings.Repeat("07", 16), UploadID: strings.Repeat("06", 16), CommitOperationID: strings.Repeat("08", 16), CommitState: v2ChunkCommitUnattempted,
		EncryptedDescriptor: v2Base64URL([]byte("encrypted descriptor")), DataSlot: strings.Repeat("02", 16), SlotEpoch: v2SlotEpoch(time.Now()),
		RequestedPolicy: v2Base64URL([]byte{0xa0}), DescriptorDigest: digest, PreviousDigest: strings.Repeat("00", 32), Sequence: 1,
		ChunkSize: 16, PlaintextLength: 31, PlaintextHash: strings.Repeat("0a", 32), LeaseExpiresAt: uint64(time.Now().Add(time.Hour).Unix()), CreatedAt: uint64(time.Now().Unix()),
		Parts: []v2PendingChunkPart{
			{ID: strings.Repeat("04", 16), Path: pathsByPart[0], PlaintextLength: 16, CiphertextLength: 16, CiphertextHash: hex.EncodeToString(parts[0].Digest), Uploaded: true},
			{ID: strings.Repeat("05", 16), Path: pathsByPart[1], PlaintextLength: 15, CiphertextLength: 17, CiphertextHash: hex.EncodeToString(parts[1].Digest), Uploaded: true},
		},
	}}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var firstCommitBody []byte
	firstTransport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		if request.Method != "POST" || !strings.HasSuffix(request.Path, "/commit") {
			t.Fatalf("lost-response run repeated %s %s", request.Method, request.Path)
		}
		firstCommitBody = append([]byte(nil), request.Body...)
		return nil, errors.New("commit response lost")
	}}
	runtime := &v2PeerRuntime{paths: paths, state: state, origin: "https://dud.example.com", transport: firstTransport}
	if err := runtime.flushPendingChunkDeliveries(context.Background()); err == nil {
		t.Fatal("lost commit response succeeded")
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.PendingChunkDeliveries) != 1 || loaded.PendingChunkDeliveries[0].CommitState != v2ChunkCommitAmbiguous || !loaded.PendingChunkDeliveries[0].Parts[0].Uploaded || !loaded.PendingChunkDeliveries[0].Parts[1].Uploaded {
		t.Fatalf("commit retry state = %#v", loaded.PendingChunkDeliveries)
	}
	loaded.PendingChunkDeliveries[0].NextAttemptAt = 0
	if err := writeV2PeerDeliveryState(paths, loaded); err != nil {
		t.Fatal(err)
	}
	commitResponse, err := v2EncMode.Marshal(map[int]any{1: bytes.Repeat([]byte{10}, 16), 2: true})
	if err != nil {
		t.Fatal(err)
	}
	secondTransport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		if request.Method != "POST" || !strings.HasSuffix(request.Path, "/commit") || !bytes.Equal(request.Body, firstCommitBody) {
			t.Fatalf("commit retry changed or repeated a transition: %s %s", request.Method, request.Path)
		}
		return &v2Response{StatusCode: http.StatusOK, ContentType: v2CBORContentType, Body: commitResponse}, nil
	}}
	runtime = &v2PeerRuntime{paths: paths, state: loaded, origin: "https://dud.example.com", transport: secondTransport}
	if err := runtime.flushPendingChunkDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runtime.state.PendingChunkDeliveries) != 0 {
		t.Fatalf("commit retry retained queue %#v", runtime.state.PendingChunkDeliveries)
	}
	for _, path := range pathsByPart {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("commit retry retained %s", path)
		}
	}
}

func TestV2ChunkPublicationReusesPersistedRenewalAfterLostResponse(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	digest := strings.Repeat("19", 32)
	spoolDir := filepath.Join(paths.StateDir, "uploads", state.RelationshipID, digest)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := v2ChunkTestParts()
	partPaths := []string{filepath.Join(spoolDir, "first.age"), filepath.Join(spoolDir, "second.age")}
	for index, body := range [][]byte{[]byte("first ciphertext"), []byte("second ciphertext")} {
		if err := atomicWriteV2File(partPaths[index], body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state.PendingChunkDeliveries = []v2PendingChunkDelivery{{
		CreateOperationID: strings.Repeat("17", 16), UploadID: strings.Repeat("16", 16), CommitOperationID: strings.Repeat("18", 16), CommitState: v2ChunkCommitUnattempted,
		EncryptedDescriptor: v2Base64URL([]byte("encrypted descriptor")), DataSlot: strings.Repeat("02", 16), SlotEpoch: v2SlotEpoch(time.Now()),
		RequestedPolicy: v2Base64URL([]byte{0xa0}), DescriptorDigest: digest, PreviousDigest: strings.Repeat("00", 32), Sequence: 1,
		ChunkSize: 16, PlaintextLength: 31, PlaintextHash: strings.Repeat("1a", 32), LeaseExpiresAt: uint64(time.Now().Add(time.Minute).Unix()), CreatedAt: uint64(time.Now().Unix()),
		Parts: []v2PendingChunkPart{
			{ID: strings.Repeat("04", 16), Path: partPaths[0], PlaintextLength: 16, CiphertextLength: 16, CiphertextHash: hex.EncodeToString(manifest[0].Digest), Uploaded: true},
			{ID: strings.Repeat("05", 16), Path: partPaths[1], PlaintextLength: 15, CiphertextLength: 17, CiphertextHash: hex.EncodeToString(manifest[1].Digest), Uploaded: true},
		},
	}}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var firstRenewalBody []byte
	firstTransport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		if request.Method != "POST" || !strings.HasSuffix(request.Path, "/renew") {
			t.Fatalf("renewal run repeated %s %s", request.Method, request.Path)
		}
		firstRenewalBody = append([]byte(nil), request.Body...)
		return nil, errors.New("renewal response lost")
	}}
	runtime := &v2PeerRuntime{paths: paths, state: state, origin: "https://dud.example.com", transport: firstTransport}
	if err := runtime.flushPendingChunkDeliveries(context.Background()); err == nil {
		t.Fatal("lost renewal response succeeded")
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PendingChunkDeliveries[0].RenewOperationID == "" {
		t.Fatal("renewal operation ID was not durable before the request")
	}
	loaded.PendingChunkDeliveries[0].NextAttemptAt = 0
	if err := writeV2PeerDeliveryState(paths, loaded); err != nil {
		t.Fatal(err)
	}
	renewResponse, err := v2EncMode.Marshal(map[int]any{1: uint64(time.Now().Add(time.Hour).Unix()), 2: true})
	if err != nil {
		t.Fatal(err)
	}
	commitResponse, err := v2EncMode.Marshal(map[int]any{1: bytes.Repeat([]byte{20}, 16), 2: false})
	if err != nil {
		t.Fatal(err)
	}
	requestCount := 0
	secondTransport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		requestCount++
		if strings.HasSuffix(request.Path, "/renew") {
			if !bytes.Equal(request.Body, firstRenewalBody) {
				t.Fatal("renewal retry changed its operation body")
			}
			return &v2Response{StatusCode: http.StatusOK, ContentType: v2CBORContentType, Body: renewResponse}, nil
		}
		if strings.HasSuffix(request.Path, "/commit") {
			return &v2Response{StatusCode: http.StatusOK, ContentType: v2CBORContentType, Body: commitResponse}, nil
		}
		t.Fatalf("renewal retry repeated %s %s", request.Method, request.Path)
		return nil, nil
	}}
	runtime = &v2PeerRuntime{paths: paths, state: loaded, origin: "https://dud.example.com", transport: secondTransport}
	if err := runtime.flushPendingChunkDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requestCount != 2 || len(runtime.state.PendingChunkDeliveries) != 0 {
		t.Fatalf("renewal retry made %d requests with queue %#v", requestCount, runtime.state.PendingChunkDeliveries)
	}
}

func TestV2PeerSendStreamsLargeRegularFileThroughChunkPublisher(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	capabilities := testV2Capabilities(t)
	capabilities.Features = []uint64{2, 3, 5, 7, 9, 10, 11}
	capabilities.Limits[10] = 16_782_955
	capabilities.Limits[11] = 1_024
	capabilities.Limits[12] = 1_073_741_824
	capabilities.Limits[13] = 3_600
	contract, contractErr := newV2ServerContract(capabilities)
	if contractErr != nil {
		t.Fatal(contractErr)
	}
	state.ServerContract = contract
	state.PeerFeatures = []uint64{5, 6, 7}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "large.bin")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(16*1024*1024 + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	uploadID := bytes.Repeat([]byte{11}, 16)
	requests := 0
	partsUploaded := 0
	transport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		requests++
		if request.Method == "POST" && request.Path == "/v2/deliveries/uploads" {
			var body map[int]any
			if err := v2DecMode.Unmarshal(request.Body, &body); err != nil {
				t.Fatal(err)
			}
			rawParts, ok := body[5].([]any)
			if !ok || len(rawParts) != 2 {
				t.Fatalf("create manifest = %#v", body[5])
			}
			missing := make([]any, len(rawParts))
			for index, raw := range rawParts {
				part, mapErr := normalizeV2Map(raw)
				if mapErr != nil {
					t.Fatal(mapErr)
				}
				missing[index] = part[1]
			}
			response, marshalErr := v2EncMode.Marshal(map[int]any{1: uploadID, 2: uint64(time.Now().Add(time.Hour).Unix()), 3: missing, 4: false})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			return &v2Response{StatusCode: http.StatusCreated, ContentType: v2CBORContentType, Body: response}, nil
		}
		if request.Method == "PUT" {
			body, readErr := io.ReadAll(request.BodyStream)
			if readErr != nil || int64(len(body)) != request.ContentLength {
				t.Fatalf("streamed part length = %d/%d, %v", len(body), request.ContentLength, readErr)
			}
			partsUploaded++
			return &v2Response{StatusCode: http.StatusNoContent}, nil
		}
		if request.Method == "POST" && strings.HasSuffix(request.Path, "/commit") {
			response, marshalErr := v2EncMode.Marshal(map[int]any{1: bytes.Repeat([]byte{12}, 16), 2: false})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			return &v2Response{StatusCode: http.StatusOK, ContentType: v2CBORContentType, Body: response}, nil
		}
		t.Fatalf("unexpected send request %s %s", request.Method, request.Path)
		return nil, nil
	}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
	if err := a.cmdPeerSend([]string{"phone", "--file", source}); err != nil {
		t.Fatalf("send failed: %v; stderr=%s", err, stderr.String())
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 4 || partsUploaded != 2 || len(loaded.PendingChunkDeliveries) != 0 || len(loaded.PendingGranularDeliveries) != 0 {
		t.Fatalf("large send made %d requests and %d parts with queues %d/%d", requests, partsUploaded, len(loaded.PendingChunkDeliveries), len(loaded.PendingGranularDeliveries))
	}
}

func TestV2PeerAbandonRollsBackUnpublishedUploadSequence(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	digest := strings.Repeat("09", 32)
	spoolDir := filepath.Join(paths.StateDir, "uploads", state.RelationshipID, digest)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(spoolDir, "first.age")
	secondPath := filepath.Join(spoolDir, "second.age")
	if err := atomicWriteV2File(firstPath, []byte("first ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteV2File(secondPath, []byte("second ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	parts := v2ChunkTestParts()
	state.PendingChunkDeliveries = []v2PendingChunkDelivery{{
		CreateOperationID: strings.Repeat("07", 16), CommitOperationID: strings.Repeat("08", 16), CommitState: v2ChunkCommitUnattempted,
		EncryptedDescriptor: v2Base64URL([]byte("encrypted descriptor")), DataSlot: strings.Repeat("02", 16), SlotEpoch: v2SlotEpoch(time.Now()),
		RequestedPolicy: v2Base64URL([]byte{0xa0}), DescriptorDigest: digest, PreviousDigest: strings.Repeat("00", 32), Sequence: 1,
		ChunkSize: 16, PlaintextLength: 31, PlaintextHash: strings.Repeat("0a", 32), CreatedAt: uint64(time.Now().Unix()),
		Parts: []v2PendingChunkPart{
			{ID: strings.Repeat("04", 16), Path: firstPath, PlaintextLength: 16, CiphertextLength: 16, CiphertextHash: hex.EncodeToString(parts[0].Digest)},
			{ID: strings.Repeat("05", 16), Path: secondPath, PlaintextLength: 15, CiphertextLength: 17, CiphertextHash: hex.EncodeToString(parts[1].Digest)},
		},
	}}
	state.Chains["out:data"].SendSequence = 1
	state.Chains["out:data"].SendDigest = digest
	state.Sent[digest] = v2SentDelivery{Sequence: 1, DescriptorDigest: digest}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &stubV2Transport{}, nil }
	if err := a.cmdPeer([]string{"abandon", "phone", "--id", digest, "--yes"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.PendingChunkDeliveries) != 0 || loaded.Chains["out:data"].SendSequence != 0 || loaded.Chains["out:data"].SendDigest != strings.Repeat("00", 32) {
		t.Fatalf("abandoned upload state = %#v, chain = %#v", loaded.PendingChunkDeliveries, loaded.Chains["out:data"])
	}
	if _, err := os.Stat(firstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned upload retained %s", firstPath)
	}
}

func TestV2PeerAbandonBurnsAmbiguousCommitSequence(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "phone")
	digest := strings.Repeat("19", 32)
	spoolDir := filepath.Join(paths.StateDir, "uploads", state.RelationshipID, digest)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(spoolDir, "first.age")
	secondPath := filepath.Join(spoolDir, "second.age")
	if err := atomicWriteV2File(firstPath, []byte("first ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteV2File(secondPath, []byte("second ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	parts := v2ChunkTestParts()
	state.PendingChunkDeliveries = []v2PendingChunkDelivery{{
		CreateOperationID: strings.Repeat("17", 16), UploadID: strings.Repeat("16", 16), CommitOperationID: strings.Repeat("18", 16),
		EncryptedDescriptor: v2Base64URL([]byte("encrypted descriptor")), DataSlot: strings.Repeat("02", 16), SlotEpoch: v2SlotEpoch(time.Now()),
		RequestedPolicy: v2Base64URL([]byte{0xa0}), DescriptorDigest: digest, PreviousDigest: strings.Repeat("00", 32), Sequence: 1,
		ChunkSize: 16, PlaintextLength: 31, PlaintextHash: strings.Repeat("1a", 32), LeaseExpiresAt: uint64(time.Now().Add(-time.Hour).Unix()), CreatedAt: uint64(time.Now().Unix()),
		Parts: []v2PendingChunkPart{
			{ID: strings.Repeat("04", 16), Path: firstPath, PlaintextLength: 16, CiphertextLength: 16, CiphertextHash: hex.EncodeToString(parts[0].Digest), Uploaded: true},
			{ID: strings.Repeat("05", 16), Path: secondPath, PlaintextLength: 15, CiphertextLength: 17, CiphertextHash: hex.EncodeToString(parts[1].Digest), Uploaded: true},
		},
	}}
	state.Chains["out:data"].SendSequence = 1
	state.Chains["out:data"].SendDigest = digest
	state.Sent[digest] = v2SentDelivery{Sequence: 1, DescriptorDigest: digest}
	state.Version = 9
	legacyBody, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var legacyState map[string]any
	if err := json.Unmarshal(legacyBody, &legacyState); err != nil {
		t.Fatal(err)
	}
	queuedState := legacyState["pending_chunk_deliveries"].([]any)[0].(map[string]any)
	delete(queuedState, "commit_state")
	legacyBody, err = json.MarshalIndent(legacyState, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	legacyBody = append(legacyBody, '\n')
	if err := atomicWriteV2File(peerDeliveryStatePath(paths, state.RelationshipID), legacyBody, 0o600); err != nil {
		t.Fatal(err)
	}
	transport := &v2ChunkTestTransport{do: func(request v2Request) (*v2Response, error) {
		t.Fatalf("ambiguous abandonment made %s %s", request.Method, request.Path)
		return nil, nil
	}}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
	if err := a.cmdPeer([]string{"abandon", "phone", "--id", digest, "--yes"}); err != nil {
		t.Fatal(err)
	}
	loaded, loadErr := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(loaded.PendingChunkDeliveries) != 0 || loaded.Chains["out:data"].SendSequence != 1 || loaded.Chains["out:data"].SendDigest != digest {
		t.Fatalf("ambiguous upload state = %#v, chain = %#v", loaded.PendingChunkDeliveries, loaded.Chains["out:data"])
	}
	if _, exists := loaded.Sent[digest]; !exists {
		t.Fatal("ambiguous abandonment removed the sent-chain record")
	}
	for _, path := range []string{firstPath, secondPath} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("ambiguous abandonment retained %s", path)
		}
	}
}
