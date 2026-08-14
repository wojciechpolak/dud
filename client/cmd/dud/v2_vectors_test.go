// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The frozen wire corpus is shared with the Node server tests
// (tests/v2-vectors.test.mjs) so both implementations are pinned to the same
// bytes. Regenerate with DUD_UPDATE_VECTORS=1 go test ./cmd/dud -run Vectors
// and review the diff: a change here is a wire-compatibility change.
const v2VectorCorpusPath = "../../../tests/vectors/v2-wire-vectors.json"

type v2VectorExpectation struct {
	RelationshipID    string `json:"relationshipId"`
	Direction         uint64 `json:"direction"`
	RecipientDeviceID string `json:"recipientDeviceId"`
	CanonicalOrigin   string `json:"canonicalOrigin"`
	SigningPublicKey  string `json:"signingPublicKey"`
}

type v2DescriptorVector struct {
	Name        string `json:"name"`
	Category    string `json:"category,omitempty"`
	PayloadType uint64 `json:"payloadType,omitempty"`
	// TextKeyedMaps marks descriptors carrying a CBOR map with text keys —
	// only Git `refs` and `fetched_refs` do. The server's protocol codec
	// accepts integer keys alone, because no structure the server parses uses
	// anything else, so it cannot decode these descriptors. It never needs to:
	// a descriptor reaches the server as opaque ciphertext.
	TextKeyedMaps bool                `json:"textKeyedMaps,omitempty"`
	Envelope      string              `json:"envelope"`
	Descriptor    string              `json:"descriptor,omitempty"`
	Digest        string              `json:"descriptorDigest,omitempty"`
	Signature     string              `json:"signature,omitempty"`
	Expect        v2VectorExpectation `json:"expect"`
}

type v2ProofVector struct {
	Name           string `json:"name"`
	TokenSecret    string `json:"tokenSecret"`
	Direction      string `json:"direction"`
	Scope          string `json:"scope"`
	Chain          uint64 `json:"chain"`
	Slot           string `json:"slot"`
	Epoch          uint64 `json:"epoch"`
	Method         string `json:"method"`
	Origin         string `json:"origin"`
	Path           string `json:"path"`
	OperationIndex uint64 `json:"operationIndex"`
	RequestDigest  string `json:"requestDigest"`
	Nonce          string `json:"nonce"`
	ExpiresAt      uint64 `json:"expiresAt"`
	LookupID       string `json:"lookupId"`
	Proof          string `json:"proof"`
}

type v2LookupVector struct {
	TokenSecret string `json:"tokenSecret"`
	Epoch       uint64 `json:"epoch"`
	LookupID    string `json:"lookupId"`
}

// v2EnrollmentVector pins the proof that gates rendezvous creation. The client
// produces it and the server verifies it, so the two must agree on the exact
// preimage down to the domain separator and the expiry encoding.
type v2EnrollmentVector struct {
	// Secret is the operator's passphrase verbatim, and Key is what it stretches
	// to. Pinning both keeps the two implementations agreeing on the PBKDF2 step
	// — its salt and iteration count included — as well as on the HMAC that
	// follows it.
	Secret    string `json:"secret"`
	Key       string `json:"key"`
	Locator   string `json:"locator"`
	ExpiresAt uint64 `json:"expiresAt"`
	Proof     string `json:"proof"`
}

type v2BodyVector struct {
	Name string `json:"name"`
	// Category is empty for valid vectors and names the defect otherwise.
	Category string `json:"category,omitempty"`
	Body     string `json:"body"`
	// The authorization context the embedded proof MACs were built from.
	// Present on valid vectors so the server can re-verify every proof and
	// thereby confirm both implementations redact identically.
	Origin      string `json:"origin,omitempty"`
	TokenSecret string `json:"tokenSecret,omitempty"`
	Direction   string `json:"direction,omitempty"`
	// GoRejects marks invalid vectors the Go client decoder also refuses; the
	// remainder exercise server-only header contracts.
	GoRejects bool `json:"goRejects,omitempty"`
}

// v2ChainVector is one link of the frozen data chain used to exercise the
// receiver's replay, fork and gap rules against real signed descriptors.
type v2ChainVector struct {
	Name     string `json:"name"`
	Sequence uint64 `json:"sequence"`
	// Outcome is one of accept, duplicate, stale, fork, predecessor-fork or gap.
	Outcome  string `json:"outcome"`
	Envelope string `json:"envelope"`
	Digest   string `json:"descriptorDigest"`
}

type v2VectorCorpus struct {
	Note                 string               `json:"note"`
	Chain                []v2ChainVector      `json:"chain"`
	LookupIDs            []v2LookupVector     `json:"lookupIds"`
	EnrollmentProofs     []v2EnrollmentVector `json:"enrollmentProofs"`
	Proofs               []v2ProofVector      `json:"proofs"`
	OperationIDs         []string             `json:"operationIds"`
	Descriptors          []v2DescriptorVector `json:"descriptors"`
	InvalidDescriptors   []v2DescriptorVector `json:"invalidDescriptors"`
	DeliveryFrames       []v2BodyVector       `json:"deliveryFrames"`
	InboxRequests        []v2BodyVector       `json:"inboxRequests"`
	InboxResponses       []v2BodyVector       `json:"inboxResponses"`
	CompletionRequests   []v2BodyVector       `json:"completionRequests"`
	ControlEventRequests []v2BodyVector       `json:"controlEventRequests"`
}

// ---------------------------------------------------------------------------
// Fixed inputs. Everything below is derived deterministically from these.
// ---------------------------------------------------------------------------

func v2VectorBytes(fill byte, length int) []byte {
	return bytes.Repeat([]byte{fill}, length)
}

func v2VectorCounted(start byte, length int) []byte {
	out := make([]byte, length)
	for index := range out {
		out[index] = start + byte(index)
	}
	return out
}

const (
	v2VectorOrigin = "https://dud.example.com"
	v2VectorEpoch  = uint64(20340)
)

var (
	v2VectorRelationshipID = v2VectorCounted(0x01, 16)
	v2VectorSenderDeviceID = v2VectorCounted(0x40, 16)
	v2VectorPeerDeviceID   = v2VectorCounted(0x60, 16)
	v2VectorTokenSecret    = v2VectorCounted(0xa0, 32)
	v2VectorSigningKey     = ed25519.NewKeyFromSeed(v2VectorCounted(0x11, 32))
	v2VectorOtherKey       = ed25519.NewKeyFromSeed(v2VectorCounted(0x99, 32))
)

func v2VectorPolicy() v2TransportPolicy {
	return v2TransportPolicy{ExpiresAt: 1_800_003_600, Consume: 1, ClaimLeaseSeconds: 300, AckMode: 1}
}

func v2VectorExpect() v2VectorExpectation {
	return v2VectorExpectation{
		RelationshipID:    hex.EncodeToString(v2VectorRelationshipID),
		Direction:         0,
		RecipientDeviceID: hex.EncodeToString(v2VectorPeerDeviceID),
		CanonicalOrigin:   v2VectorOrigin,
		SigningPublicKey:  hex.EncodeToString(v2VectorSigningKey.Public().(ed25519.PublicKey)),
	}
}

func v2VectorBaseDescriptor(payloadType, chain uint64) v2Descriptor {
	payloadHash := sha256.Sum256([]byte("vector plaintext"))
	chunkHash := sha256.Sum256([]byte("vector ciphertext"))
	return v2Descriptor{
		DescriptorID:      v2VectorCounted(0x10, 16),
		PayloadType:       payloadType,
		RelationshipID:    v2VectorRelationshipID,
		Direction:         0,
		Chain:             chain,
		KeyEpoch:          0,
		Sequence:          1,
		PreviousDigest:    make([]byte, 32),
		SenderDeviceID:    v2VectorSenderDeviceID,
		RecipientDeviceID: v2VectorPeerDeviceID,
		CanonicalOrigin:   v2VectorOrigin,
		CreatedAt:         1_800_000_000,
		TransportPolicy:   v2VectorPolicy(),
		PayloadHash:       payloadHash[:],
		ChunkHashes:       [][]byte{chunkHash[:]},
	}
}

// signV2VectorEnvelope encodes, signs and wraps a descriptor map without
// running validation, so deliberately malformed vectors can still be produced
// with an otherwise correct signature.
func signV2VectorEnvelope(t *testing.T, desc map[int]any, key ed25519.PrivateKey) (envelope, descriptorBytes, signature []byte) {
	t.Helper()
	descriptorBytes, err := v2EncMode.Marshal(desc)
	if err != nil {
		t.Fatalf("encode descriptor: %v", err)
	}
	digest := sha256.Sum256(descriptorBytes)
	signature = ed25519.Sign(key, append([]byte(v2DescriptorSigPrefix), digest[:]...))
	envelope, err = v2EncMode.Marshal(map[int]any{1: desc, 2: signature})
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return envelope, descriptorBytes, signature
}

func v2VectorDescriptorMap(t *testing.T, desc v2Descriptor) map[int]any {
	t.Helper()
	built, err := descriptorMap(desc, v2VectorSigningKey)
	if err != nil {
		t.Fatalf("build descriptor map: %v", err)
	}
	return built
}

func v2VectorDescriptor(t *testing.T, name string, desc v2Descriptor) v2DescriptorVector {
	t.Helper()
	built := v2VectorDescriptorMap(t, desc)
	envelope, descriptorBytes, signature := signV2VectorEnvelope(t, built, v2VectorSigningKey)
	digest := sha256.Sum256(descriptorBytes)
	return v2DescriptorVector{
		Name:        name,
		PayloadType: desc.PayloadType,
		Envelope:    hex.EncodeToString(envelope),
		Descriptor:  hex.EncodeToString(descriptorBytes),
		Digest:      hex.EncodeToString(digest[:]),
		Signature:   hex.EncodeToString(signature),
		Expect:      v2VectorExpect(),
	}
}

func v2VectorInvalidDescriptor(t *testing.T, name, category string, mutate func(map[int]any), expect *v2VectorExpectation) v2DescriptorVector {
	t.Helper()
	built := v2VectorDescriptorMap(t, v2VectorBaseDescriptor(2, 0))
	mutate(built)
	envelope, _, _ := signV2VectorEnvelope(t, built, v2VectorSigningKey)
	expectation := v2VectorExpect()
	if expect != nil {
		expectation = *expect
	}
	return v2DescriptorVector{
		Name:     name,
		Category: category,
		Envelope: hex.EncodeToString(envelope),
		Expect:   expectation,
	}
}

// ---------------------------------------------------------------------------
// Corpus construction
// ---------------------------------------------------------------------------

func buildV2VectorCorpus(t *testing.T) *v2VectorCorpus {
	t.Helper()
	corpus := &v2VectorCorpus{
		Note: "Frozen DUD v2 wire vectors shared by the Go client and Node server tests. " +
			"Any diff is a wire-compatibility change. Regenerate with DUD_UPDATE_VECTORS=1.",
	}
	corpus.Chain = buildV2ChainVectors(t)
	corpus.LookupIDs = buildV2LookupVectors(t)
	corpus.EnrollmentProofs = buildV2EnrollmentVectors(t)
	corpus.Proofs = buildV2ProofVectors(t)
	corpus.OperationIDs = []string{
		hex.EncodeToString(make([]byte, 16)),
		hex.EncodeToString(v2VectorCounted(0x10, 16)),
		hex.EncodeToString(v2VectorBytes(0xff, 16)),
	}
	corpus.Descriptors = buildV2DescriptorVectors(t)
	corpus.InvalidDescriptors = buildV2InvalidDescriptorVectors(t)
	corpus.DeliveryFrames = buildV2DeliveryFrameVectors(t)
	corpus.InboxRequests = buildV2InboxRequestVectors(t)
	corpus.InboxResponses = buildV2InboxResponseVectors(t)
	corpus.CompletionRequests = buildV2CompletionVectors(t)
	corpus.ControlEventRequests = buildV2ControlEventVectors(t)
	return corpus
}

// buildV2ChainVectors produces a real signed data chain plus the four ways a
// peer can diverge from it. Every link is a complete descriptor, so replaying
// the corpus drives the receiver's actual rejection rules rather than a
// synthetic stand-in for them.
func buildV2ChainVectors(t *testing.T) []v2ChainVector {
	t.Helper()
	link := func(name, outcome string, sequence uint64, previousDigest []byte, salt string) v2ChainVector {
		desc := v2VectorBaseDescriptor(1, 0)
		desc.Sequence = sequence
		desc.PreviousDigest = previousDigest
		desc.CreatedAt = 1_800_000_000 + sequence
		if salt != "" {
			desc.DisplayName = salt
		}
		envelope, descriptorBytes, _ := signV2VectorEnvelope(t, v2VectorDescriptorMap(t, desc), v2VectorSigningKey)
		digest := sha256.Sum256(descriptorBytes)
		return v2ChainVector{
			Name:     name,
			Sequence: sequence,
			Outcome:  outcome,
			Envelope: hex.EncodeToString(envelope),
			Digest:   hex.EncodeToString(digest[:]),
		}
	}

	first := link("sequence 1", "accept", 1, make([]byte, 32), "")
	firstDigest := mustHexV2Vector(t, first.Digest)
	second := link("sequence 2", "accept", 2, firstDigest, "")
	return []v2ChainVector{
		first,
		second,
		link("replayed sequence 2", "duplicate", 2, firstDigest, ""),
		link("forked sequence 2", "fork", 2, firstDigest, "forked"),
		link("stale sequence 1", "stale", 1, make([]byte, 32), "stale"),
		link("sequence 3 with the wrong predecessor", "predecessor-fork", 3, make([]byte, 32), ""),
		link("sequence 5 after a gap", "gap", 5, mustHexV2Vector(t, second.Digest), ""),
	}
}

func buildV2LookupVectors(t *testing.T) []v2LookupVector {
	t.Helper()
	var result []v2LookupVector
	for _, epoch := range []uint64{0, 1, v2VectorEpoch, v2VectorEpoch + 1, 4_294_967_296} {
		lookup, err := deriveV2DailyCapabilityLookupIDClient(v2VectorTokenSecret, epoch)
		if err != nil {
			t.Fatalf("derive lookup ID: %v", err)
		}
		result = append(result, v2LookupVector{
			TokenSecret: hex.EncodeToString(v2VectorTokenSecret),
			Epoch:       epoch,
			LookupID:    hex.EncodeToString(lookup),
		})
	}
	return result
}

func buildV2EnrollmentVectors(t *testing.T) []v2EnrollmentVector {
	t.Helper()
	var result []v2EnrollmentVector
	for _, input := range []struct {
		secret    string
		locator   []byte
		expiresAt uint64
	}{
		{"squid-lantern-rotate-9-mango", v2VectorCounted(0x01, 32), 1_800_000_900},
		// The same passphrase and locator under a different lifetime, so the
		// corpus proves the expiry is covered rather than merely present.
		{"squid-lantern-rotate-9-mango", v2VectorCounted(0x01, 32), 1_800_000_901},
		// Non-ASCII, because a passphrase is typed by a human and both sides
		// must agree it is UTF-8 before it reaches the KDF.
		{"pässwort-mit-ümlaut-2024-korrekt", v2VectorBytes(0xff, 32), 4_294_967_296},
		// The derived-key form of the first passphrase. Both implementations
		// must reach the same key it does, since a deployment configured this
		// way verifies proofs from clients that still hold the passphrase.
		{
			"dud2-enroll-key:_3iJ1c59CVqmBr68qGBeriqPHt5kLWa5j19Ql0PO31E",
			v2VectorCounted(0x01, 32),
			1_800_000_900,
		},
		// An explicitly stated work factor, so the corpus pins that both sides
		// read the count out of the secret rather than assuming the default.
		{
			"dud2-enroll-kdf:10000:squid-lantern-rotate-9-mango",
			v2VectorCounted(0x01, 32),
			1_800_000_900,
		},
	} {
		key, err := deriveV2EnrollmentKey(input.secret)
		if err != nil {
			t.Fatalf("derive enrollment key: %v", err)
		}
		proof, err := deriveV2EnrollmentProof(key, input.locator, input.expiresAt)
		if err != nil {
			t.Fatalf("derive enrollment proof: %v", err)
		}
		result = append(result, v2EnrollmentVector{
			Secret:    input.secret,
			Key:       hex.EncodeToString(key),
			Locator:   hex.EncodeToString(input.locator),
			ExpiresAt: input.expiresAt,
			Proof:     hex.EncodeToString(proof),
		})
	}
	return result
}

func buildV2ProofVectors(t *testing.T) []v2ProofVector {
	t.Helper()
	requestDigest := sha256.Sum256([]byte("frozen request"))
	cases := []struct {
		name           string
		direction      string
		scope          string
		chain          uint64
		path           string
		operationIndex uint64
		expiresAt      uint64
	}{
		{"write data slot", "inviter->invitee", "write", 0, "/v2/deliveries", 0, 1_757_379_600},
		{"read data slot", "invitee->inviter", "read", 0, "/v2/inbox", 3, 1_757_379_600},
		{"ack control slot", "inviter->invitee", "ack", 1, "/v2/control-events", 1, 1_757_379_600},
		{"boundary operation index", "inviter->invitee", "write", 1, "/v2/deliveries", 30, 1_757_379_599},
	}
	var result []v2ProofVector
	for _, item := range cases {
		input := v2GranularSlotProofInput{
			TokenSecret: v2VectorTokenSecret,
			Direction:   item.direction,
			Scope:       item.scope,
			Chain:       item.chain,
			Slot:        v2VectorCounted(0xc0, 16),
			Epoch:       v2VectorEpoch,
			Nonce:       v2VectorCounted(0xb0, 16),
			ExpiresAt:   item.expiresAt,
		}
		proof, err := encodeV2GranularSlotProof(input, "POST", v2VectorOrigin, item.path, requestDigest[:], item.operationIndex, false)
		if err != nil {
			t.Fatalf("encode proof: %v", err)
		}
		lookup, err := deriveV2DailyCapabilityLookupIDClient(v2VectorTokenSecret, v2VectorEpoch)
		if err != nil {
			t.Fatalf("derive lookup ID: %v", err)
		}
		result = append(result, v2ProofVector{
			Name:           item.name,
			TokenSecret:    hex.EncodeToString(v2VectorTokenSecret),
			Direction:      item.direction,
			Scope:          item.scope,
			Chain:          item.chain,
			Slot:           hex.EncodeToString(input.Slot),
			Epoch:          v2VectorEpoch,
			Method:         "POST",
			Origin:         v2VectorOrigin,
			Path:           item.path,
			OperationIndex: item.operationIndex,
			RequestDigest:  hex.EncodeToString(requestDigest[:]),
			Nonce:          hex.EncodeToString(input.Nonce),
			ExpiresAt:      item.expiresAt,
			LookupID:       hex.EncodeToString(lookup),
			Proof:          hex.EncodeToString(proof[4].([]byte)),
		})
	}
	return result
}

func buildV2DescriptorVectors(t *testing.T) []v2DescriptorVector {
	t.Helper()
	ackedDigest := sha256.Sum256([]byte("acked descriptor"))
	outputDigest := sha256.Sum256([]byte("committed output"))
	plaintextSize := uint64(4096)
	archiveTar := uint64(1)
	archiveNone := uint64(0)

	message := v2VectorBaseDescriptor(1, 0)

	file := v2VectorBaseDescriptor(2, 0)
	file.DisplayName = "report.pdf"
	file.ArchiveFormat = &archiveNone
	file.PlaintextSize = &plaintextSize

	collection := v2VectorBaseDescriptor(3, 0)
	collection.DisplayName = "bundle.tar"
	collection.ArchiveFormat = &archiveTar
	collection.PlaintextSize = &plaintextSize
	collection.TypeMetadata = map[int]any{
		1: uint64(2),
		2: []any{"first.txt", "nested/second.bin"},
	}

	gitBundle := v2VectorBaseDescriptor(4, 0)
	gitBundle.DisplayName = "repo.bundle"
	gitBundle.TypeMetadata = map[int]any{
		1: v2VectorCounted(0x70, 16),
		2: uint64(1),
		3: uint64(2),
		4: map[string]any{"refs/heads/main": v2VectorCounted(0x30, 20)},
		5: []any{},
	}

	// An incremental checkpoint must remain parseable even though this release
	// cannot apply one. Parsing it is what lets the receiver answer with a
	// signed refusal and advance its chain; rejecting it at the descriptor
	// layer would strand the delivery and silence the relationship. The refusal
	// itself is asserted in TestV2GitFetchRefusesAnUnapplicableCheckpointAndContinues.
	gitIncremental := v2VectorBaseDescriptor(4, 0)
	gitIncremental.DisplayName = "repo-incremental.bundle"
	gitIncremental.TypeMetadata = map[int]any{
		1: v2VectorCounted(0x70, 16),
		2: uint64(1),
		3: uint64(2),
		4: map[string]any{"refs/heads/main": v2VectorCounted(0x30, 20)},
		5: []any{v2VectorCounted(0x40, 20)},
	}

	gitBundleSHA256 := v2VectorBaseDescriptor(4, 0)
	gitBundleSHA256.DisplayName = "repo-sha256.bundle"
	gitBundleSHA256.TypeMetadata = map[int]any{
		1: v2VectorCounted(0x70, 16),
		2: uint64(2),
		3: uint64(3),
		4: map[string]any{
			"refs/heads/main": v2VectorCounted(0x30, 32),
			"refs/tags/v1":    v2VectorCounted(0x50, 32),
		},
		5: []any{},
	}

	acknowledgement := v2VectorBaseDescriptor(5, 1)
	acknowledgement.Sequence = 7
	acknowledgement.PreviousDigest = v2VectorCounted(0x90, 32)
	acknowledgement.TypeMetadata = map[int]any{
		1: uint64(4),
		2: ackedDigest[:],
		3: uint64(0),
		4: outputDigest[:],
		5: uint64(4),
		6: uint64(7),
		7: uint64(9),
		8: uint64(6),
	}

	rejected := v2VectorBaseDescriptor(5, 1)
	rejected.Sequence = 8
	rejected.PreviousDigest = v2VectorCounted(0x90, 32)
	rejected.TypeMetadata = map[int]any{
		1: uint64(5),
		2: ackedDigest[:],
		3: uint64(1),
		4: make([]byte, 32),
		5: uint64(4),
		6: uint64(8),
		7: uint64(9),
		8: uint64(7),
	}

	peerControl := v2VectorBaseDescriptor(6, 1)
	peerControl.Sequence = 9
	peerControl.PreviousDigest = v2VectorCounted(0x90, 32)
	peerControl.TypeMetadata = map[int]any{
		1: uint64(1),
		2: uint64(4),
		3: uint64(9),
		4: uint64(9),
		5: uint64(6),
		6: uint64(2),
	}

	gitSHA1Vector := v2VectorDescriptor(t, "git bundle sha1", gitBundle)
	gitSHA1Vector.TextKeyedMaps = true
	gitSHA256Vector := v2VectorDescriptor(t, "git bundle sha256", gitBundleSHA256)
	gitSHA256Vector.TextKeyedMaps = true
	gitIncrementalVector := v2VectorDescriptor(t, "git bundle with incremental prerequisites", gitIncremental)
	gitIncrementalVector.TextKeyedMaps = true

	vectors := []v2DescriptorVector{
		v2VectorDescriptor(t, "message", message),
		v2VectorDescriptor(t, "file with display metadata", file),
		v2VectorDescriptor(t, "collection with entry names", collection),
		gitSHA1Vector,
		gitSHA256Vector,
		gitIncrementalVector,
		v2VectorDescriptor(t, "acknowledgement committed", acknowledgement),
		v2VectorDescriptor(t, "acknowledgement rejected", rejected),
		v2VectorDescriptor(t, "peer control revoke", peerControl),
	}

	// A non-critical unknown extension must survive round-tripping untouched.
	extended := v2VectorDescriptorMap(t, v2VectorBaseDescriptor(1, 0))
	extended[128] = "forward compatible"
	envelope, descriptorBytes, signature := signV2VectorEnvelope(t, extended, v2VectorSigningKey)
	digest := sha256.Sum256(descriptorBytes)
	vectors = append(vectors, v2DescriptorVector{
		Name:        "message with non-critical extension",
		PayloadType: 1,
		Envelope:    hex.EncodeToString(envelope),
		Descriptor:  hex.EncodeToString(descriptorBytes),
		Digest:      hex.EncodeToString(digest[:]),
		Signature:   hex.EncodeToString(signature),
		Expect:      v2VectorExpect(),
	})
	return vectors
}

func buildV2InvalidDescriptorVectors(t *testing.T) []v2DescriptorVector {
	t.Helper()
	otherRelationship := v2VectorExpect()
	otherRelationship.RelationshipID = hex.EncodeToString(v2VectorBytes(0xee, 16))
	otherRecipient := v2VectorExpect()
	otherRecipient.RecipientDeviceID = hex.EncodeToString(v2VectorBytes(0xee, 16))
	otherDirection := v2VectorExpect()
	otherDirection.Direction = 1
	otherOrigin := v2VectorExpect()
	otherOrigin.CanonicalOrigin = "https://other.example.com"
	otherSigner := v2VectorExpect()
	otherSigner.SigningPublicKey = hex.EncodeToString(v2VectorOtherKey.Public().(ed25519.PublicKey))

	vectors := []v2DescriptorVector{
		v2VectorInvalidDescriptor(t, "unknown core key", "unknown-core-key", func(desc map[int]any) {
			desc[27] = uint64(1)
		}, nil),
		v2VectorInvalidDescriptor(t, "deferred chunk_size", "deferred-core-key", func(desc map[int]any) {
			desc[kChunkSize] = uint64(65536)
		}, nil),
		v2VectorInvalidDescriptor(t, "deferred chunk_ids", "deferred-core-key", func(desc map[int]any) {
			desc[kChunkIDs] = []any{v2VectorBytes(0x01, 16)}
		}, nil),
		v2VectorInvalidDescriptor(t, "deferred incremental_base", "deferred-core-key", func(desc map[int]any) {
			desc[kIncrementalBase] = v2VectorBytes(0x02, 32)
		}, nil),
		v2VectorInvalidDescriptor(t, "unsupported key epoch", "key-epoch", func(desc map[int]any) {
			desc[kKeyEpoch] = uint64(1)
		}, nil),
		v2VectorInvalidDescriptor(t, "unsupported protocol version", "protocol-version", func(desc map[int]any) {
			desc[kV] = uint64(3)
		}, nil),
		v2VectorInvalidDescriptor(t, "unsupported kem algorithm", "kem-algorithm", func(desc map[int]any) {
			desc[kKEMAlg] = uint64(2)
		}, nil),
		v2VectorInvalidDescriptor(t, "unsupported signature algorithm", "signature-algorithm", func(desc map[int]any) {
			desc[kSigAlg] = uint64(2)
		}, nil),
		v2VectorInvalidDescriptor(t, "unsupported critical extension", "critical-extension", func(desc map[int]any) {
			desc[200] = uint64(1)
			desc[kCriticalExtensions] = []any{uint64(200)}
		}, nil),
		v2VectorInvalidDescriptor(t, "payload type on the wrong chain", "wrong-chain", func(desc map[int]any) {
			desc[kChain] = uint64(1)
		}, nil),
		v2VectorInvalidDescriptor(t, "unsupported payload type", "payload-type", func(desc map[int]any) {
			desc[kPayloadType] = uint64(7)
		}, nil),
		v2VectorInvalidDescriptor(t, "two chunk hashes", "chunk-hash-count", func(desc map[int]any) {
			hash := sha256.Sum256([]byte("second chunk"))
			desc[kChunkHashes] = []any{desc[kChunkHashes].([][]byte)[0], hash[:]}
		}, nil),
		v2VectorInvalidDescriptor(t, "zero sequence", "sequence", func(desc map[int]any) {
			desc[kSequence] = uint64(0)
		}, nil),
		v2VectorInvalidDescriptor(t, "short descriptor ID", "field-length", func(desc map[int]any) {
			desc[kDescriptorID] = v2VectorBytes(0x10, 15)
		}, nil),
		v2VectorInvalidDescriptor(t, "non-canonical origin", "non-canonical-origin", func(desc map[int]any) {
			desc[kCanonicalOrigin] = "https://DUD.example.com"
		}, nil),
		v2VectorInvalidDescriptor(t, "transport policy missing ack mode", "policy-missing-key", func(desc map[int]any) {
			desc[kTransportPolicy] = map[int]any{1: uint64(1_800_003_600), 2: uint64(1), 3: uint64(300)}
		}, nil),
		v2VectorInvalidDescriptor(t, "transport policy unknown core key", "policy-unknown-key", func(desc map[int]any) {
			desc[kTransportPolicy] = map[int]any{
				1: uint64(1_800_003_600), 2: uint64(1), 3: uint64(300), 4: uint64(1), 5: uint64(1),
			}
		}, nil),
		v2VectorInvalidDescriptor(t, "relationship mismatch", "relationship-mismatch", func(map[int]any) {}, &otherRelationship),
		v2VectorInvalidDescriptor(t, "recipient mismatch", "recipient-mismatch", func(map[int]any) {}, &otherRecipient),
		v2VectorInvalidDescriptor(t, "direction mismatch", "direction-mismatch", func(map[int]any) {}, &otherDirection),
		v2VectorInvalidDescriptor(t, "origin mismatch", "origin-mismatch", func(map[int]any) {}, &otherOrigin),
		v2VectorInvalidDescriptor(t, "sender key mismatch", "sender-key-mismatch", func(map[int]any) {}, &otherSigner),
	}

	// Git-specific rejections need a Git descriptor as their base.
	gitBase := func(mutate func(map[int]any)) map[int]any {
		desc := v2VectorBaseDescriptor(4, 0)
		desc.TypeMetadata = map[int]any{
			1: v2VectorCounted(0x70, 16),
			2: uint64(1),
			3: uint64(2),
			4: map[string]any{"refs/heads/main": v2VectorCounted(0x30, 20)},
			5: []any{},
		}
		built, err := descriptorMap(desc, v2VectorSigningKey)
		if err != nil {
			t.Fatalf("build git descriptor: %v", err)
		}
		mutate(built)
		return built
	}
	for _, item := range []struct {
		name     string
		category string
		mutate   func(map[int]any)
	}{
		{"git descriptor without type metadata", "git-metadata", func(desc map[int]any) {
			delete(desc, kTypeMetadata)
		}},
		{"git ref outside permitted namespaces", "git-ref-namespace", func(desc map[int]any) {
			metadata := desc[kTypeMetadata].(map[int]any)
			metadata[4] = map[string]any{"refs/remotes/origin/main": v2VectorCounted(0x30, 20)}
		}},
		{"git object ID length mismatch", "git-object-length", func(desc map[int]any) {
			metadata := desc[kTypeMetadata].(map[int]any)
			metadata[4] = map[string]any{"refs/heads/main": v2VectorCounted(0x30, 32)}
		}},
	} {
		envelope, _, _ := signV2VectorEnvelope(t, gitBase(item.mutate), v2VectorSigningKey)
		vectors = append(vectors, v2DescriptorVector{
			Name:          item.name,
			Category:      item.category,
			TextKeyedMaps: item.category != "git-metadata",
			Envelope:      hex.EncodeToString(envelope),
			Expect:        v2VectorExpect(),
		})
	}

	// A correct map signed by the wrong key.
	wrongSignature, _, _ := signV2VectorEnvelope(t, v2VectorDescriptorMap(t, v2VectorBaseDescriptor(2, 0)), v2VectorOtherKey)
	vectors = append(vectors, v2DescriptorVector{
		Name:     "signature made by another key",
		Category: "signature-failure",
		Envelope: hex.EncodeToString(wrongSignature),
		Expect:   v2VectorExpect(),
	})

	// A correct envelope whose signature bytes were flipped.
	tampered, _, _ := signV2VectorEnvelope(t, v2VectorDescriptorMap(t, v2VectorBaseDescriptor(2, 0)), v2VectorSigningKey)
	var decoded map[int]cbor.RawMessage
	if err := v2DecMode.Unmarshal(tampered, &decoded); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	var signature []byte
	if err := v2DecMode.Unmarshal(decoded[2], &signature); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signature[0] ^= 0x01
	var descriptor map[int]any
	if err := v2DecMode.Unmarshal(decoded[1], &descriptor); err != nil {
		t.Fatalf("decode descriptor: %v", err)
	}
	flipped, err := v2EncMode.Marshal(map[int]any{1: descriptor, 2: signature})
	if err != nil {
		t.Fatalf("encode flipped envelope: %v", err)
	}
	vectors = append(vectors, v2DescriptorVector{
		Name:     "flipped signature bit",
		Category: "signature-failure",
		Envelope: hex.EncodeToString(flipped),
		Expect:   v2VectorExpect(),
	})

	// The outer envelope re-encoded with its two keys out of canonical order.
	nonDeterministic := []byte{0xa2, 0x02}
	nonDeterministic = append(nonDeterministic, decoded[2]...)
	nonDeterministic = append(nonDeterministic, 0x01)
	nonDeterministic = append(nonDeterministic, decoded[1]...)
	vectors = append(vectors, v2DescriptorVector{
		Name:     "envelope keys out of canonical order",
		Category: "non-deterministic-envelope",
		Envelope: hex.EncodeToString(nonDeterministic),
		Expect:   v2VectorExpect(),
	})
	return vectors
}

// ---------------------------------------------------------------------------
// Request/response body vectors
// ---------------------------------------------------------------------------

func v2VectorProofInput(scope string, chain uint64, slotFill byte) v2GranularSlotProofInput {
	return v2GranularSlotProofInput{
		TokenSecret: v2VectorTokenSecret,
		Direction:   "inviter->invitee",
		Scope:       scope,
		Chain:       chain,
		Slot:        v2VectorCounted(slotFill, 16),
		Epoch:       v2VectorEpoch,
		Nonce:       v2VectorCounted(0xb0, 16),
		ExpiresAt:   1_757_379_600,
	}
}

// v2VectorAuthContext records the inputs the embedded proof MACs were derived
// from, so the server suite can re-verify each proof against its own redaction.
func v2VectorAuthContext(name string, body []byte) v2BodyVector {
	return v2BodyVector{
		Name:        name,
		Body:        hex.EncodeToString(body),
		Origin:      v2VectorOrigin,
		TokenSecret: hex.EncodeToString(v2VectorTokenSecret),
		Direction:   "inviter->invitee",
	}
}

func buildV2DeliveryFrameVectors(t *testing.T) []v2BodyVector {
	t.Helper()
	payload := []byte("opaque ciphertext payload")
	descriptor := []byte{0xa1, 0x01, 0x02}
	policy := map[int]any{1: uint64(1_800_003_600), 2: uint64(1), 3: uint64(300), 4: uint64(1)}
	dataProof := v2VectorProofInput("write", 0, 0xc0)

	minimal, err := encodeV2GranularDeliveryRequest(
		v2VectorOrigin, v2VectorCounted(0x10, 16), descriptor, policy, payload, dataProof, nil, nil)
	if err != nil {
		t.Fatalf("encode delivery frame: %v", err)
	}

	controlProofs := []v2GranularSlotProofInput{v2VectorProofInput("read", 1, 0xd0)}
	batched, err := encodeV2GranularDeliveryRequest(
		v2VectorOrigin, v2VectorCounted(0x20, 16), descriptor, policy, payload, dataProof,
		controlProofs, [][]byte{v2VectorCounted(0x80, 16)})
	if err != nil {
		t.Fatalf("encode batched delivery frame: %v", err)
	}

	empty, err := encodeV2GranularDeliveryRequest(
		v2VectorOrigin, v2VectorCounted(0x30, 16), []byte{0x01}, policy, nil, dataProof, nil, nil)
	if err != nil {
		t.Fatalf("encode empty-payload delivery frame: %v", err)
	}

	// Exactly the maximum batched control queries, and one past it.
	maximumControl := make([]v2GranularSlotProofInput, v2GranularMaxSlotProofs)
	for index := range maximumControl {
		maximumControl[index] = v2VectorProofInput("read", 1, byte(0xd0+index))
	}
	saturated, err := encodeV2GranularDeliveryRequest(
		v2VectorOrigin, v2VectorCounted(0x40, 16), descriptor, policy, payload, dataProof,
		maximumControl, nil)
	if err != nil {
		t.Fatalf("encode saturated delivery frame: %v", err)
	}

	vectors := []v2BodyVector{
		v2VectorAuthContext("minimal delivery", minimal),
		v2VectorAuthContext("delivery with control batch", batched),
		v2VectorAuthContext("delivery with empty payload", empty),
		v2VectorAuthContext("delivery with maximum control queries", saturated),
	}

	// Invalid framings derived from the minimal valid frame.
	badMagic := append([]byte(nil), minimal...)
	badMagic[0] ^= 0xff
	badPayload := append([]byte(nil), minimal...)
	badPayload[len(badPayload)-1] ^= 0x01
	zeroHeader := append([]byte(nil), minimal...)
	zeroHeader[4], zeroHeader[5], zeroHeader[6], zeroHeader[7] = 0, 0, 0, 0
	oversizedHeader := append([]byte(nil), minimal...)
	oversizedHeader[4], oversizedHeader[5], oversizedHeader[6], oversizedHeader[7] = 0xff, 0xff, 0xff, 0xff
	nonDeterministic := append([]byte(nil), minimal...)
	// 0xa8 (map of 8) -> 0xb8 (map with a one-byte, non-minimal count).
	nonDeterministic[8] = 0xb8

	invalid := []v2BodyVector{
		{Name: "frame magic corrupted", Category: "frame-magic", Body: hex.EncodeToString(badMagic), GoRejects: true},
		{Name: "frame prefix truncated", Category: "frame-prefix", Body: hex.EncodeToString(minimal[:7]), GoRejects: true},
		{Name: "declared header length zero", Category: "frame-header-length", Body: hex.EncodeToString(zeroHeader), GoRejects: true},
		{Name: "declared header length past the frame", Category: "frame-header-length", Body: hex.EncodeToString(oversizedHeader), GoRejects: true},
		{Name: "payload byte flipped", Category: "payload-digest", Body: hex.EncodeToString(badPayload), GoRejects: true},
		{Name: "payload truncated", Category: "payload-length", Body: hex.EncodeToString(minimal[:len(minimal)-1]), GoRejects: true},
		{Name: "non-minimal header map count", Category: "non-deterministic-cbor", Body: hex.EncodeToString(nonDeterministic), GoRejects: true},
	}

	// Header-contract violations only the server decoder enforces. These are
	// re-framed so the payload declaration itself stays coherent.
	reframe := func(mutate func(map[int]any)) string {
		header, framePayload, err := decodeV2GranularFrame(minimal, 4, 5)
		if err != nil {
			t.Fatalf("decode minimal frame: %v", err)
		}
		mutate(header)
		reframed, err := encodeV2GranularFrame(header, framePayload, 4, 5)
		if err != nil {
			t.Fatalf("re-encode frame: %v", err)
		}
		return hex.EncodeToString(reframed)
	}
	invalid = append(invalid,
		v2BodyVector{Name: "unknown header key", Category: "unknown-header-key", Body: reframe(func(header map[int]any) {
			header[99] = uint64(1)
		})},
		v2BodyVector{Name: "missing data slot proof", Category: "missing-required-key", Body: reframe(func(header map[int]any) {
			delete(header, 6)
		})},
		v2BodyVector{Name: "operation ID of the wrong length", Category: "field-length", Body: reframe(func(header map[int]any) {
			header[1] = v2VectorCounted(0x10, 15)
		})},
		v2BodyVector{Name: "empty encrypted descriptor", Category: "descriptor-bounds", Body: reframe(func(header map[int]any) {
			header[2] = []byte{}
		})},
		v2BodyVector{Name: "transport policy is not a map", Category: "policy-shape", Body: reframe(func(header map[int]any) {
			header[3] = uint64(1)
		})},
		v2BodyVector{Name: "slot proof slot of the wrong length", Category: "field-length", Body: reframe(func(header map[int]any) {
			proof, err := normalizeV2Map(header[6])
			if err != nil {
				t.Fatalf("normalize slot proof: %v", err)
			}
			proof[1] = v2VectorCounted(0xc0, 15)
			header[6] = proof
		})},
		v2BodyVector{Name: "processed control event ID of the wrong length", Category: "field-length", Body: reframe(func(header map[int]any) {
			header[8] = []any{v2VectorCounted(0x80, 15)}
		})},
	)

	// One past the maximum batched control queries.
	overflowControl := make([]any, v2GranularMaxSlotProofs+1)
	for index := range overflowControl {
		proof, proofErr := encodeV2GranularSlotProof(
			v2VectorProofInput("read", 1, byte(0xd0+index)), "POST", v2VectorOrigin, "/v2/deliveries",
			make([]byte, 32), uint64(index+1), false)
		if proofErr != nil {
			t.Fatalf("encode control proof: %v", proofErr)
		}
		overflowControl[index] = proof
	}
	invalid = append(invalid, v2BodyVector{
		Name:     "control query batch over the limit",
		Category: "batch-limit",
		Body: reframe(func(header map[int]any) {
			header[7] = overflowControl
		}),
	})

	return append(vectors, invalid...)
}

func buildV2InboxRequestVectors(t *testing.T) []v2BodyVector {
	t.Helper()
	single, err := encodeV2GranularInboxRequest(
		v2VectorOrigin, []v2GranularSlotProofInput{v2VectorProofInput("read", 0, 0xc0)}, nil, nil)
	if err != nil {
		t.Fatalf("encode inbox request: %v", err)
	}
	combined, err := encodeV2GranularInboxRequest(
		v2VectorOrigin,
		[]v2GranularSlotProofInput{v2VectorProofInput("read", 0, 0xc0), v2VectorProofInput("read", 0, 0xc1)},
		[]v2GranularSlotProofInput{v2VectorProofInput("read", 1, 0xd0)},
		[][]byte{v2VectorCounted(0x80, 16), v2VectorCounted(0x90, 16)})
	if err != nil {
		t.Fatalf("encode combined inbox request: %v", err)
	}
	saturatedProofs := make([]v2GranularSlotProofInput, v2GranularMaxSlotProofs)
	for index := range saturatedProofs {
		saturatedProofs[index] = v2VectorProofInput("read", 0, byte(0xc0+index))
	}
	saturated, err := encodeV2GranularInboxRequest(v2VectorOrigin, saturatedProofs, nil, nil)
	if err != nil {
		t.Fatalf("encode saturated inbox request: %v", err)
	}

	vectors := []v2BodyVector{
		v2VectorAuthContext("single data slot query", single),
		v2VectorAuthContext("data, control and processed IDs", combined),
		v2VectorAuthContext("maximum data slot queries", saturated),
	}

	remarshal := func(mutate func(map[int]any)) string {
		var body map[int]any
		if err := v2DecMode.Unmarshal(single, &body); err != nil {
			t.Fatalf("decode inbox request: %v", err)
		}
		mutate(body)
		encoded, err := v2EncMode.Marshal(body)
		if err != nil {
			t.Fatalf("re-encode inbox request: %v", err)
		}
		return hex.EncodeToString(encoded)
	}

	overflow := make([]any, v2GranularMaxSlotProofs+1)
	for index := range overflow {
		proof, proofErr := encodeV2GranularSlotProof(
			v2VectorProofInput("read", 0, byte(0xc0+index)), "POST", v2VectorOrigin, "/v2/inbox",
			make([]byte, 32), uint64(index), false)
		if proofErr != nil {
			t.Fatalf("encode inbox proof: %v", proofErr)
		}
		overflow[index] = proof
	}

	empty, err := v2EncMode.Marshal(map[int]any{})
	if err != nil {
		t.Fatalf("encode empty inbox request: %v", err)
	}

	return append(vectors,
		v2BodyVector{Name: "no data slot proofs", Category: "missing-required-key", Body: hex.EncodeToString(empty)},
		v2BodyVector{Name: "unknown request key", Category: "unknown-header-key", Body: remarshal(func(body map[int]any) {
			body[9] = uint64(1)
		})},
		v2BodyVector{Name: "data slot proof batch over the limit", Category: "batch-limit", Body: remarshal(func(body map[int]any) {
			body[1] = overflow
		})},
		v2BodyVector{Name: "slot proof missing its epoch", Category: "missing-required-key", Body: remarshal(func(body map[int]any) {
			proofs := body[1].([]any)
			proof, err := normalizeV2Map(proofs[0])
			if err != nil {
				t.Fatalf("normalize slot proof: %v", err)
			}
			delete(proof, 2)
			proofs[0] = proof
		})},
		v2BodyVector{Name: "processed control event ID of the wrong length", Category: "field-length", Body: remarshal(func(body map[int]any) {
			body[3] = []any{v2VectorCounted(0x80, 17)}
		})},
	)
}

func buildV2InboxResponseVectors(t *testing.T) []v2BodyVector {
	t.Helper()
	payload := []byte("inbox ciphertext")
	digest := sha256.Sum256(payload)
	emptyDigest := sha256.Sum256(nil)

	slotResult := func(slotFill byte, more bool) map[int]any {
		return map[int]any{1: v2VectorCounted(slotFill, 16), 2: v2VectorEpoch, 3: more}
	}
	controlEvent := func(idFill byte, sequence uint64) map[int]any {
		return map[int]any{
			1: v2VectorCounted(idFill, 16),
			2: v2VectorCounted(0xd0, 16),
			3: v2VectorEpoch,
			4: []byte{0xa1, 0x01, 0x04},
			5: sequence,
		}
	}

	withDelivery := map[int]any{
		1: []any{slotResult(0xc0, true)},
		2: []any{controlEvent(0x80, 3)},
		3: v2VectorCounted(0x10, 16),
		4: v2VectorCounted(0xc0, 16),
		5: []byte{0xa1, 0x01, 0x02},
		6: map[int]any{1: uint64(1_800_003_600), 2: uint64(1), 3: uint64(300), 4: uint64(1)},
		7: uint64(len(payload)),
		8: digest[:],
		9: []any{v2VectorEpoch},
	}
	withoutDelivery := map[int]any{
		1: []any{},
		2: []any{},
		7: uint64(0),
		8: emptyDigest[:],
	}
	drained := map[int]any{
		1: []any{slotResult(0xc0, false)},
		2: []any{controlEvent(0x80, 4), controlEvent(0x90, 5)},
		7: uint64(0),
		8: emptyDigest[:],
	}

	frame := func(header map[int]any, body []byte) string {
		encoded, err := encodeV2GranularFrame(header, body, 7, 8)
		if err != nil {
			t.Fatalf("encode inbox response frame: %v", err)
		}
		return hex.EncodeToString(encoded)
	}

	vectors := []v2BodyVector{
		{Name: "response carrying a delivery", Body: frame(withDelivery, payload)},
		{Name: "empty response", Body: frame(withoutDelivery, nil)},
		{Name: "control events without a delivery", Body: frame(drained, nil)},
	}

	orphanSlot := map[int]any{}
	for key, value := range withoutDelivery {
		orphanSlot[key] = value
	}
	orphanSlot[4] = v2VectorCounted(0xc0, 16)

	shortDeliveryID := map[int]any{}
	for key, value := range withDelivery {
		shortDeliveryID[key] = value
	}
	shortDeliveryID[3] = v2VectorCounted(0x10, 15)

	unknownKey := map[int]any{}
	for key, value := range withoutDelivery {
		unknownKey[key] = value
	}
	unknownKey[42] = uint64(1)

	missingResults := map[int]any{7: uint64(0), 8: emptyDigest[:], 2: []any{}}

	return append(vectors,
		v2BodyVector{Name: "delivery field without a delivery ID", Category: "orphan-delivery-field", Body: frame(orphanSlot, nil)},
		v2BodyVector{Name: "delivery ID of the wrong length", Category: "field-length", Body: frame(shortDeliveryID, payload)},
		v2BodyVector{Name: "unknown response key", Category: "unknown-header-key", Body: frame(unknownKey, nil)},
		v2BodyVector{Name: "missing slot results", Category: "missing-required-key", Body: frame(missingResults, nil)},
	)
}

func buildV2CompletionVectors(t *testing.T) []v2BodyVector {
	t.Helper()
	policyDigest := sha256.Sum256([]byte("effective policy"))
	descriptorDigest := sha256.Sum256([]byte("acked descriptor"))
	acknowledgement := []byte{0xa1, 0x01, 0x03}
	build := func(result uint64) []byte {
		body, err := encodeV2GranularCompletionRequest(
			v2VectorOrigin, v2VectorCounted(0x10, 16), v2VectorCounted(0xc0, 16), v2VectorCounted(0xd0, 16),
			policyDigest[:], descriptorDigest[:], result, v2VectorCounted(0x20, 16), acknowledgement,
			v2VectorProofInput("ack", 0, 0xc0), v2VectorProofInput("write", 1, 0xd0))
		if err != nil {
			t.Fatalf("encode completion request: %v", err)
		}
		return body
	}
	committed := build(0)
	rejectedResult := build(1)

	vectors := []v2BodyVector{
		v2VectorAuthContext("committed completion", committed),
		v2VectorAuthContext("rejected completion", rejectedResult),
	}

	remarshal := func(mutate func(map[int]any)) string {
		var body map[int]any
		if err := v2DecMode.Unmarshal(committed, &body); err != nil {
			t.Fatalf("decode completion request: %v", err)
		}
		mutate(body)
		encoded, err := v2EncMode.Marshal(body)
		if err != nil {
			t.Fatalf("re-encode completion request: %v", err)
		}
		return hex.EncodeToString(encoded)
	}

	return append(vectors,
		v2BodyVector{Name: "missing control write proof", Category: "missing-required-key", Body: remarshal(func(body map[int]any) {
			delete(body, 3)
		})},
		v2BodyVector{Name: "unknown completion key", Category: "unknown-header-key", Body: remarshal(func(body map[int]any) {
			body[11] = uint64(1)
		})},
		v2BodyVector{Name: "result outside 0 and 1", Category: "result-range", Body: remarshal(func(body map[int]any) {
			body[8] = uint64(2)
		})},
		v2BodyVector{Name: "policy digest of the wrong length", Category: "field-length", Body: remarshal(func(body map[int]any) {
			body[6] = v2VectorBytes(0x11, 31)
		})},
		v2BodyVector{Name: "empty encrypted acknowledgement", Category: "acknowledgement-bounds", Body: remarshal(func(body map[int]any) {
			body[10] = []byte{}
		})},
	)
}

func buildV2ControlEventVectors(t *testing.T) []v2BodyVector {
	t.Helper()
	envelope := []byte{0xa1, 0x01, 0x04}
	body, err := encodeV2GranularControlEventRequest(
		v2VectorOrigin, v2VectorCounted(0x10, 16), envelope, v2VectorProofInput("write", 1, 0xd0))
	if err != nil {
		t.Fatalf("encode control event request: %v", err)
	}
	vectors := []v2BodyVector{v2VectorAuthContext("inline control envelope", body)}

	remarshal := func(mutate func(map[int]any)) string {
		var decoded map[int]any
		if err := v2DecMode.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("decode control event request: %v", err)
		}
		mutate(decoded)
		encoded, err := v2EncMode.Marshal(decoded)
		if err != nil {
			t.Fatalf("re-encode control event request: %v", err)
		}
		return hex.EncodeToString(encoded)
	}

	return append(vectors,
		v2BodyVector{Name: "missing control slot proof", Category: "missing-required-key", Body: remarshal(func(decoded map[int]any) {
			delete(decoded, 2)
		})},
		v2BodyVector{Name: "unknown control event key", Category: "unknown-header-key", Body: remarshal(func(decoded map[int]any) {
			decoded[4] = uint64(1)
		})},
		v2BodyVector{Name: "operation ID of the wrong length", Category: "field-length", Body: remarshal(func(decoded map[int]any) {
			decoded[1] = v2VectorCounted(0x10, 17)
		})},
		v2BodyVector{Name: "empty control envelope", Category: "envelope-bounds", Body: remarshal(func(decoded map[int]any) {
			decoded[3] = []byte{}
		})},
	)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestV2WireVectorsMatchFrozenCorpus(t *testing.T) {
	corpus := buildV2VectorCorpus(t)
	encoded, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv("DUD_UPDATE_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(v2VectorCorpusPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(v2VectorCorpusPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skip("frozen wire vectors regenerated")
	}
	frozen, err := os.ReadFile(v2VectorCorpusPath)
	if err != nil {
		t.Fatalf("read frozen vectors: %v", err)
	}
	if !bytes.Equal(frozen, encoded) {
		t.Fatal("generated wire vectors differ from the frozen corpus; " +
			"this is a wire-compatibility change. Re-run with DUD_UPDATE_VECTORS=1 to accept it.")
	}
}

func loadV2VectorCorpus(t *testing.T) *v2VectorCorpus {
	t.Helper()
	raw, err := os.ReadFile(v2VectorCorpusPath)
	if err != nil {
		t.Fatalf("read frozen vectors: %v", err)
	}
	var corpus v2VectorCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("decode frozen vectors: %v", err)
	}
	return &corpus
}

func mustHexV2Vector(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
}

func v2VectorExpectationOf(t *testing.T, expect v2VectorExpectation) v2DescriptorExpectation {
	t.Helper()
	return v2DescriptorExpectation{
		RelationshipID:    mustHexV2Vector(t, expect.RelationshipID),
		Direction:         expect.Direction,
		RecipientDeviceID: mustHexV2Vector(t, expect.RecipientDeviceID),
		CanonicalOrigin:   expect.CanonicalOrigin,
		SigningPublicKey:  mustHexV2Vector(t, expect.SigningPublicKey),
	}
}

func TestV2FrozenDescriptorVectorsValidate(t *testing.T) {
	corpus := loadV2VectorCorpus(t)
	if len(corpus.Descriptors) == 0 {
		t.Fatal("frozen corpus has no descriptor vectors")
	}
	seen := map[uint64]bool{}
	for _, vector := range corpus.Descriptors {
		t.Run(vector.Name, func(t *testing.T) {
			validated, err := validateSignedV2Envelope(
				mustHexV2Vector(t, vector.Envelope), v2VectorExpectationOf(t, vector.Expect))
			if err != nil {
				t.Fatalf("valid vector rejected: %v", err)
			}
			if got := hex.EncodeToString(validated.DescriptorBytes); got != vector.Descriptor {
				t.Fatalf("descriptor bytes = %s", got)
			}
			if got := hex.EncodeToString(validated.DescriptorDigest[:]); got != vector.Digest {
				t.Fatalf("descriptor digest = %s", got)
			}
			if got := hex.EncodeToString(validated.Signature); got != vector.Signature {
				t.Fatalf("signature = %s", got)
			}
			payloadType, _ := asV2Uint(validated.Descriptor[kPayloadType])
			if payloadType != vector.PayloadType {
				t.Fatalf("payload type = %d", payloadType)
			}
			seen[payloadType] = true
		})
	}
	for payloadType := uint64(1); payloadType <= 6; payloadType++ {
		if !seen[payloadType] {
			t.Errorf("no frozen vector covers payload type %d", payloadType)
		}
	}
}

var v2DescriptorRejectionPatterns = map[string]*regexp.Regexp{
	"unknown-core-key":           regexp.MustCompile(`unknown core key`),
	"deferred-core-key":          regexp.MustCompile(`deferred core key`),
	"key-epoch":                  regexp.MustCompile(`key epoch`),
	"protocol-version":           regexp.MustCompile(`protocol version`),
	"kem-algorithm":              regexp.MustCompile(`recipient algorithm`),
	"signature-algorithm":        regexp.MustCompile(`signature algorithm`),
	"critical-extension":         regexp.MustCompile(`critical extension`),
	"wrong-chain":                regexp.MustCompile(`wrong chain`),
	"payload-type":               regexp.MustCompile(`payload type is unsupported`),
	"chunk-hash-count":           regexp.MustCompile(`exactly one chunk hash`),
	"sequence":                   regexp.MustCompile(`sequence must be`),
	"field-length":               regexp.MustCompile(`must be exactly`),
	"non-canonical-origin":       regexp.MustCompile(`canonical origin is not canonical`),
	"policy-missing-key":         regexp.MustCompile(`transport policy is missing key`),
	"policy-unknown-key":         regexp.MustCompile(`transport policy has unknown core key`),
	"relationship-mismatch":      regexp.MustCompile(`relationship does not match`),
	"recipient-mismatch":         regexp.MustCompile(`recipient does not match`),
	"direction-mismatch":         regexp.MustCompile(`direction does not match`),
	"origin-mismatch":            regexp.MustCompile(`origin does not match`),
	"sender-key-mismatch":        regexp.MustCompile(`sender key does not match`),
	"git-metadata":               regexp.MustCompile(`missing type metadata`),
	"git-ref-namespace":          regexp.MustCompile(`outside the permitted namespaces`),
	"git-object-length":          regexp.MustCompile(`object ID of the wrong length`),
	"signature-failure":          regexp.MustCompile(`signature is invalid`),
	"non-deterministic-envelope": regexp.MustCompile(`not deterministic`),
}

func TestV2FrozenInvalidDescriptorVectorsAreRejected(t *testing.T) {
	corpus := loadV2VectorCorpus(t)
	if len(corpus.InvalidDescriptors) == 0 {
		t.Fatal("frozen corpus has no invalid descriptor vectors")
	}
	for _, vector := range corpus.InvalidDescriptors {
		t.Run(vector.Name, func(t *testing.T) {
			pattern, ok := v2DescriptorRejectionPatterns[vector.Category]
			if !ok {
				t.Fatalf("no rejection pattern for category %q", vector.Category)
			}
			_, err := validateSignedV2Envelope(
				mustHexV2Vector(t, vector.Envelope), v2VectorExpectationOf(t, vector.Expect))
			if err == nil {
				t.Fatal("invalid vector accepted")
			}
			if !pattern.MatchString(err.Error()) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}

func TestV2FrozenProofAndLookupVectorsReproduce(t *testing.T) {
	corpus := loadV2VectorCorpus(t)
	for _, vector := range corpus.LookupIDs {
		lookup, err := deriveV2DailyCapabilityLookupIDClient(mustHexV2Vector(t, vector.TokenSecret), vector.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(lookup); got != vector.LookupID {
			t.Fatalf("lookup ID for epoch %d = %s", vector.Epoch, got)
		}
	}
	for _, vector := range corpus.EnrollmentProofs {
		key, err := deriveV2EnrollmentKey(vector.Secret)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(key); got != vector.Key {
			t.Fatalf("enrollment key for %q = %s", vector.Secret, got)
		}
		locator := mustHexV2Vector(t, vector.Locator)
		proof, err := deriveV2EnrollmentProof(key, locator, vector.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(proof); got != vector.Proof {
			t.Fatalf("enrollment proof for %s = %s", vector.Locator, got)
		}
		other, err := deriveV2EnrollmentProof(key, locator, vector.ExpiresAt+1)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(other) == vector.Proof {
			t.Fatal("enrollment proof is not bound to the rendezvous expiry")
		}
	}
	for _, vector := range corpus.Proofs {
		t.Run(vector.Name, func(t *testing.T) {
			input := v2GranularSlotProofInput{
				TokenSecret: mustHexV2Vector(t, vector.TokenSecret),
				Direction:   vector.Direction,
				Scope:       vector.Scope,
				Chain:       vector.Chain,
				Slot:        mustHexV2Vector(t, vector.Slot),
				Epoch:       vector.Epoch,
				Nonce:       mustHexV2Vector(t, vector.Nonce),
				ExpiresAt:   vector.ExpiresAt,
			}
			proof, err := encodeV2GranularSlotProof(input, vector.Method, vector.Origin, vector.Path,
				mustHexV2Vector(t, vector.RequestDigest), vector.OperationIndex, false)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(proof[4].([]byte)); got != vector.Proof {
				t.Fatalf("proof = %s", got)
			}
			// A proof is bound to its path: changing it must change the MAC.
			other, err := encodeV2GranularSlotProof(input, vector.Method, vector.Origin, vector.Path+"/x",
				mustHexV2Vector(t, vector.RequestDigest), vector.OperationIndex, false)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(other[4].([]byte)) == vector.Proof {
				t.Fatal("proof is not bound to the request path")
			}
		})
	}
}

func TestV2FrozenFrameVectorsDecodeOnTheClient(t *testing.T) {
	corpus := loadV2VectorCorpus(t)
	for _, vector := range corpus.DeliveryFrames {
		t.Run(vector.Name, func(t *testing.T) {
			frame := mustHexV2Vector(t, vector.Body)
			_, _, err := decodeV2GranularFrame(frame, 4, 5)
			switch {
			case vector.Category == "":
				if err != nil {
					t.Fatalf("valid frame rejected: %v", err)
				}
			case vector.GoRejects:
				if err == nil {
					t.Fatal("malformed frame accepted by the client decoder")
				}
			default:
				// Server-only header contract: the client decoder is expected
				// to accept the framing itself.
				if err != nil {
					t.Fatalf("well-framed vector rejected: %v", err)
				}
			}
		})
	}
	for _, vector := range corpus.InboxResponses {
		if vector.Category != "" {
			continue
		}
		if _, _, err := decodeV2GranularFrame(mustHexV2Vector(t, vector.Body), 7, 8); err != nil {
			t.Fatalf("valid inbox response %q rejected: %v", vector.Name, err)
		}
	}
}

func TestV2FrozenInboxResponseVectorsMatchClientContract(t *testing.T) {
	corpus := loadV2VectorCorpus(t)
	for _, vector := range corpus.InboxResponses {
		t.Run(vector.Name, func(t *testing.T) {
			header, payload, err := decodeV2GranularFrame(mustHexV2Vector(t, vector.Body), 7, 8)
			if err != nil {
				if vector.Category == "" {
					t.Fatalf("valid vector rejected: %v", err)
				}
				return
			}
			_, err = decodeV2GranularInboxDelivery(&v2GranularInboxResponse{Header: header, Payload: payload})
			if vector.Category == "" {
				if err != nil {
					t.Fatalf("valid vector rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid vector %q accepted", vector.Category)
			}
		})
	}
}

func TestV2FrozenChainVectorsDriveReplayForkAndGapRules(t *testing.T) {
	corpus := loadV2VectorCorpus(t)
	expectation := v2VectorExpectationOf(t, v2VectorExpect())
	runtime := &v2PeerRuntime{state: &v2PeerDeliveryState{Chains: map[string]*v2ChainState{}}}

	validate := func(t *testing.T, vector v2ChainVector) *validatedV2Envelope {
		t.Helper()
		envelope, err := validateSignedV2Envelope(mustHexV2Vector(t, vector.Envelope), expectation)
		if err != nil {
			t.Fatalf("%s: descriptor did not validate: %v", vector.Name, err)
		}
		if got := hex.EncodeToString(envelope.DescriptorDigest[:]); got != vector.Digest {
			t.Fatalf("%s: digest = %s", vector.Name, got)
		}
		return envelope
	}

	// Replaying the accepted prefix produces the state every divergence is
	// judged against.
	acceptedChain := func(t *testing.T) *v2ChainState {
		t.Helper()
		chain := emptyV2ChainState()
		for _, vector := range corpus.Chain {
			if vector.Outcome != "accept" {
				continue
			}
			envelope := validate(t, vector)
			next, err := runtime.validateNextDescriptor(chain, envelope)
			if err != nil || !next {
				t.Fatalf("%s: expected acceptance, got next=%v err=%v", vector.Name, next, err)
			}
			chain.ReceiveWatermark = vector.Sequence
			chain.ReceiveDigest = vector.Digest
			chain.Replay[vector.Sequence] = v2ReplayEntry{
				Sequence: vector.Sequence, DescriptorDigest: vector.Digest,
			}
		}
		if chain.ReceiveWatermark == 0 {
			t.Fatal("frozen chain has no accepted links")
		}
		return chain
	}

	outcomes := map[string]*regexp.Regexp{
		"fork":             regexp.MustCompile(`^fork at sequence`),
		"predecessor-fork": regexp.MustCompile(`^predecessor fork at sequence`),
		"gap":              regexp.MustCompile(`^gap before sequence`),
	}
	covered := map[string]bool{}
	for _, vector := range corpus.Chain {
		covered[vector.Outcome] = true
		if vector.Outcome == "accept" {
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			chain := acceptedChain(t)
			next, err := runtime.validateNextDescriptor(chain, validate(t, vector))
			if next {
				t.Fatalf("%s was accepted as the next descriptor", vector.Outcome)
			}
			pattern, quarantines := outcomes[vector.Outcome]
			if !quarantines {
				// duplicate and stale are silently ignored, never quarantined.
				if err != nil {
					t.Fatalf("%s produced an error: %v", vector.Outcome, err)
				}
				if chain.Quarantined {
					t.Fatalf("%s quarantined the chain", vector.Outcome)
				}
				return
			}
			if err == nil || !pattern.MatchString(err.Error()) {
				t.Fatalf("%s error = %v", vector.Outcome, err)
			}
			if !chain.Quarantined {
				t.Fatalf("%s did not quarantine the chain", vector.Outcome)
			}
		})
	}
	for _, outcome := range []string{"accept", "duplicate", "stale", "fork", "predecessor-fork", "gap"} {
		if !covered[outcome] {
			t.Errorf("frozen chain does not cover outcome %q", outcome)
		}
	}
}

func TestV2DescriptorBoundsAreEnforcedBeyondTheFrozenCorpus(t *testing.T) {
	// Boundary sizes too large to freeze as hex are checked directly.
	oversized := v2VectorBaseDescriptor(2, 0)
	oversized.DisplayName = string(bytes.Repeat([]byte{'a'}, v2MaxTextOrBytes+1))
	built, err := descriptorMap(oversized, v2VectorSigningKey)
	if err != nil {
		t.Fatalf("build oversized descriptor: %v", err)
	}
	envelope, _, _ := signV2VectorEnvelope(t, built, v2VectorSigningKey)
	if _, err := validateSignedV2Envelope(envelope, v2VectorExpectationOf(t, v2VectorExpect())); err == nil {
		t.Fatal("descriptor with an over-long text field accepted")
	}
	if _, err := validateSignedV2Envelope(
		make([]byte, v2MaxDescriptorBytes+1), v2VectorExpectationOf(t, v2VectorExpect()),
	); err == nil {
		t.Fatal("over-sized descriptor envelope accepted")
	}
}
