// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestV2IdentityDerivationMatchesFrozenVector(t *testing.T) {
	seed, _ := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	relationshipID, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	raw, err := deriveV2Material(seed, "identity", relationshipID, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(raw); got != "5ced3a4fc8e68debd74dd16fbc2ce5438140c76cc289d38fafc992ec101afc40" {
		t.Fatalf("identity raw = %s", got)
	}
	identity, err := deriveV2RelationshipIdentity(seed, relationshipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := identity.String(); got != "AGE-SECRET-KEY-PQ-1TNKN5N7GU6X7H46D69HMCT89GWQ5P3MVC2YA8RA0EXFWCYQ6L3QQELH8KS" {
		t.Fatalf("identity = %s", got)
	}
	if !strings.HasPrefix(identity.Recipient().String(), "age1pq1") {
		t.Fatalf("recipient is not hybrid: %s", identity.Recipient())
	}
}

func TestV2IdentityDerivationIsDomainSeparatedAndScoped(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	relationshipA := bytes.Repeat([]byte{0x11}, 16)
	relationshipB := bytes.Repeat([]byte{0x12}, 16)
	identity, _ := deriveV2Material(seed, "identity", relationshipA, 0, 32)
	signing, _ := deriveV2Material(seed, "signing", relationshipA, 0, 32)
	deviceID, _ := deriveV2Material(seed, "deviceid", relationshipA, 0, 32)
	otherRelationship, _ := deriveV2Material(seed, "identity", relationshipB, 0, 32)
	for name, candidate := range map[string][]byte{
		"signing":            signing,
		"device ID":          deviceID,
		"other relationship": otherRelationship,
	} {
		if bytes.Equal(identity, candidate) {
			t.Fatalf("identity collides with %s derivation", name)
		}
	}
	if _, err := deriveV2Material(seed, "identity", relationshipA, 1, 32); err == nil {
		t.Fatal("non-zero key epoch accepted")
	}
}

func TestV2SignedEncryptedEnvelopeRoundTrip(t *testing.T) {
	senderSeed := bytes.Repeat([]byte{0x21}, 32)
	recipientSeed := bytes.Repeat([]byte{0x31}, 32)
	relationshipID := bytes.Repeat([]byte{0x41}, 16)
	senderSigning, err := deriveV2SigningKey(senderSeed, relationshipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	senderID, _ := deriveV2DeviceID(senderSeed, relationshipID, 0)
	recipientID, _ := deriveV2DeviceID(recipientSeed, relationshipID, 0)
	recipientIdentity, err := deriveV2RelationshipIdentity(recipientSeed, relationshipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	descriptorID := bytes.Repeat([]byte{0x51}, 16)
	payloadHash := sha256.Sum256([]byte("plaintext"))
	chunkHash := sha256.Sum256([]byte("ciphertext"))
	descriptor := v2Descriptor{
		DescriptorID:      descriptorID,
		PayloadType:       2,
		RelationshipID:    relationshipID,
		Direction:         0,
		Chain:             0,
		KeyEpoch:          0,
		Sequence:          1,
		PreviousDigest:    make([]byte, 32),
		SenderDeviceID:    senderID,
		RecipientDeviceID: recipientID,
		CanonicalOrigin:   "https://dud.example.com",
		CreatedAt:         1_800_000_000,
		TransportPolicy:   v2TransportPolicy{ExpiresAt: 1_800_003_600, ClaimLeaseSeconds: 300, AckMode: 1},
		PayloadHash:       payloadHash[:],
		ChunkHashes:       [][]byte{chunkHash[:]},
		DisplayName:       "report.pdf",
	}
	ciphertext, err := encryptV2Envelope(descriptor, senderSigning, recipientIdentity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	validated, err := decryptAndValidateV2Envelope(ciphertext, recipientIdentity, v2DescriptorExpectation{
		RelationshipID:    relationshipID,
		Direction:         0,
		RecipientDeviceID: recipientID,
		CanonicalOrigin:   "https://dud.example.com",
		SigningPublicKey:  senderSigning.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(validated.Descriptor[kDescriptorID].([]byte), descriptorID) {
		t.Fatal("descriptor ID changed")
	}
	if got := validated.Descriptor[kDisplayName]; got != "report.pdf" {
		t.Fatalf("display name = %v", got)
	}
}

func TestV2EnvelopeRejectsWrongSenderBeforeUse(t *testing.T) {
	signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x90}, 32))
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x91}, 32))
	descriptor := validTestV2Descriptor()
	body, err := encodeSignedV2Envelope(descriptor, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateSignedV2Envelope(body, v2DescriptorExpectation{
		RelationshipID:    descriptor.RelationshipID,
		Direction:         descriptor.Direction,
		RecipientDeviceID: descriptor.RecipientDeviceID,
		CanonicalOrigin:   descriptor.CanonicalOrigin,
		SigningPublicKey:  otherKey.Public().(ed25519.PublicKey),
	})
	if err == nil || !strings.Contains(err.Error(), "sender key") {
		t.Fatalf("wrong sender error = %v", err)
	}
}

func TestV2DescriptorRejectsDeferredAndUnknownRequiredFields(t *testing.T) {
	signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x90}, 32))
	desc, err := descriptorMap(validTestV2Descriptor(), signingKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []int{kChunkSize, kChunkIDs, kIncrementalBase} {
		clone := cloneV2Map(desc)
		clone[key] = uint64(1)
		if err := validateV2DescriptorMap(clone); err == nil {
			t.Fatalf("deferred key %d accepted", key)
		}
	}
	optional := cloneV2Map(desc)
	optional[128] = "ignored"
	if err := validateV2DescriptorMap(optional); err != nil {
		t.Fatalf("optional extension rejected: %v", err)
	}
	critical := cloneV2Map(optional)
	critical[kCriticalExtensions] = []any{uint64(128)}
	if err := validateV2DescriptorMap(critical); err == nil {
		t.Fatal("unknown critical extension accepted")
	}
}

func TestV2CBORDecoderRejectsDuplicateAndIndefiniteMaps(t *testing.T) {
	var value map[int]any
	// {1: 2, 1: 3}
	if err := v2DecMode.Unmarshal([]byte{0xa2, 0x01, 0x02, 0x01, 0x03}, &value); err == nil {
		t.Fatal("duplicate map key accepted")
	}
	// {_ 1: 2, break}
	if err := v2DecMode.Unmarshal([]byte{0xbf, 0x01, 0x02, 0xff}, &value); err == nil {
		t.Fatal("indefinite map accepted")
	}
}

func TestV2EnvelopeRejectsNonDeterministicOuterEncoding(t *testing.T) {
	signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x90}, 32))
	body, err := encodeSignedV2Envelope(validTestV2Descriptor(), signingKey)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[int]cbor.RawMessage
	if err := v2DecMode.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	nonCanonical := []byte{0xa2, 0x02}
	nonCanonical = append(nonCanonical, envelope[2]...)
	nonCanonical = append(nonCanonical, 0x01)
	nonCanonical = append(nonCanonical, envelope[1]...)
	desc := validTestV2Descriptor()
	_, err = validateSignedV2Envelope(nonCanonical, v2DescriptorExpectation{
		RelationshipID:    desc.RelationshipID,
		Direction:         desc.Direction,
		RecipientDeviceID: desc.RecipientDeviceID,
		CanonicalOrigin:   desc.CanonicalOrigin,
		SigningPublicKey:  signingKey.Public().(ed25519.PublicKey),
	})
	if err == nil || !strings.Contains(err.Error(), "envelope is not deterministic") {
		t.Fatalf("non-deterministic envelope error = %v", err)
	}
}

func TestV2TransportPolicyRejectsUnknownCoreFields(t *testing.T) {
	policy := map[int]any{
		1: uint64(1_800_000_000),
		2: uint64(0),
		3: uint64(300),
		4: uint64(1),
		5: uint64(1),
	}
	if err := validateV2TransportPolicy(policy); err == nil || !strings.Contains(err.Error(), "unknown core") {
		t.Fatalf("unknown policy field error = %v", err)
	}
}

func TestV2DescriptorValidationRejectsEveryCoreMismatch(t *testing.T) {
	signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x93}, 32))
	base, err := descriptorMap(validTestV2Descriptor(), signingKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[int]any)
	}{
		{"missing required", func(value map[int]any) { delete(value, kSequence) }},
		{"wrong protocol", func(value map[int]any) { value[kV] = uint64(1) }},
		{"wrong recipient algorithm", func(value map[int]any) { value[kKEMAlg] = uint64(2) }},
		{"wrong signature algorithm", func(value map[int]any) { value[kSigAlg] = uint64(2) }},
		{"wrong key epoch", func(value map[int]any) { value[kKeyEpoch] = uint64(1) }},
		{"short descriptor ID", func(value map[int]any) { value[kDescriptorID] = []byte{1} }},
		{"short relationship ID", func(value map[int]any) { value[kRelationshipID] = []byte{1} }},
		{"short previous digest", func(value map[int]any) { value[kPreviousDigest] = []byte{1} }},
		{"short sender ID", func(value map[int]any) { value[kSenderDeviceID] = []byte{1} }},
		{"short sender key ID", func(value map[int]any) { value[kSenderKeyID] = []byte{1} }},
		{"short recipient ID", func(value map[int]any) { value[kRecipientDeviceID] = []byte{1} }},
		{"short payload hash", func(value map[int]any) { value[kPayloadHash] = []byte{1} }},
		{"bad payload type", func(value map[int]any) { value[kPayloadType] = uint64(0) }},
		{"bad direction", func(value map[int]any) { value[kDirection] = uint64(2) }},
		{"bad chain", func(value map[int]any) { value[kChain] = uint64(2) }},
		{"data on control chain", func(value map[int]any) { value[kChain] = uint64(1) }},
		{"zero sequence", func(value map[int]any) { value[kSequence] = uint64(0) }},
		{"noncanonical origin", func(value map[int]any) { value[kCanonicalOrigin] = "https://DUD.example.com" }},
		{"bad chunks", func(value map[int]any) { value[kChunkHashes] = []any{} }},
		{"empty display name", func(value map[int]any) { value[kDisplayName] = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := cloneV2Map(base)
			test.mutate(value)
			if err := validateV2DescriptorMap(value); err == nil {
				t.Fatal("invalid descriptor was accepted")
			}
		})
	}
}

func TestV2TransportPolicyValidationRejectsEachSemanticViolation(t *testing.T) {
	base := map[int]any{1: uint64(10), 2: uint64(0), 3: uint64(1), 4: uint64(0)}
	for _, test := range []struct {
		name   string
		mutate func(map[int]any)
	}{
		{"missing expiry", func(value map[int]any) { delete(value, 1) }},
		{"missing consume", func(value map[int]any) { delete(value, 2) }},
		{"missing lease", func(value map[int]any) { delete(value, 3) }},
		{"missing acknowledgement", func(value map[int]any) { delete(value, 4) }},
		{"invalid critical extension type", func(value map[int]any) { value[0] = "bad" }},
		{"unsupported critical extension", func(value map[int]any) { value[0] = []any{uint64(128)}; value[128] = "extension" }},
		{"extension too large", func(value map[int]any) { value[65536] = "extension" }},
		{"zero expiry", func(value map[int]any) { value[1] = uint64(0) }},
		{"invalid consume", func(value map[int]any) { value[2] = uint64(3) }},
		{"zero lease", func(value map[int]any) { value[3] = uint64(0) }},
		{"invalid acknowledgement", func(value map[int]any) { value[4] = uint64(2) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := cloneV2Map(base)
			test.mutate(value)
			if err := validateV2TransportPolicy(value); err == nil {
				t.Fatal("invalid transport policy was accepted")
			}
		})
	}
}

func TestCanonicalV2OriginVectors(t *testing.T) {
	valid := map[string]string{
		"https://DUD.Example.COM":      "https://dud.example.com",
		"https://dud.example.com:443/": "https://dud.example.com",
		"https://dud.example.com:8443": "https://dud.example.com:8443",
		"https://bücher.example":       "https://xn--bcher-kva.example",
	}
	for input, expected := range valid {
		actual, err := canonicalV2Origin(input)
		if err != nil || actual != expected {
			t.Errorf("canonicalV2Origin(%q) = %q, %v", input, actual, err)
		}
	}
	for _, input := range []string{
		"http://dud.example.com",
		"https://u:p@dud.example.com",
		"https://dud.example.com/v2",
		"https://192.0.2.1",
		"https://dud.example.com?x=1",
		"https://dud.example.com.",
		"https://dud.example.com:65536",
	} {
		if output, err := canonicalV2Origin(input); err == nil {
			t.Errorf("canonicalV2Origin(%q) accepted as %q", input, output)
		}
	}
}

func validTestV2Descriptor() v2Descriptor {
	payloadHash := sha256.Sum256([]byte("payload"))
	chunkHash := sha256.Sum256([]byte("chunk"))
	return v2Descriptor{
		DescriptorID:      bytes.Repeat([]byte{0x10}, 16),
		PayloadType:       2,
		RelationshipID:    bytes.Repeat([]byte{0x20}, 16),
		Direction:         0,
		Chain:             0,
		KeyEpoch:          0,
		Sequence:          1,
		PreviousDigest:    make([]byte, 32),
		SenderDeviceID:    bytes.Repeat([]byte{0x40}, 16),
		RecipientDeviceID: bytes.Repeat([]byte{0x60}, 16),
		CanonicalOrigin:   "https://dud.example.com",
		CreatedAt:         1_800_000_000,
		TransportPolicy:   v2TransportPolicy{ExpiresAt: 1_800_003_600, ClaimLeaseSeconds: 300, AckMode: 1},
		PayloadHash:       payloadHash[:],
		ChunkHashes:       [][]byte{chunkHash[:]},
		DisplayName:       "test.bin",
	}
}

func cloneV2Map(input map[int]any) map[int]any {
	output := make(map[int]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
