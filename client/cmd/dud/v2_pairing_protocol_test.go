// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestV2PairingCodeFormattingAndParsing(t *testing.T) {
	raw := sequentialV2TestBytes(0, 16)
	canonical, err := formatV2PairingCode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "0001-0203-0405-0607-0809-0a0b-0c0d-0e0f" {
		t.Fatalf("canonical code = %q", canonical)
	}
	for _, value := range []string{canonical, "000102030405060708090a0b0c0d0e0f"} {
		parsed, err := parseV2PairingCode(value)
		if err != nil || !bytes.Equal(parsed, raw) {
			t.Fatalf("parse %q = %x, %v", value, parsed, err)
		}
	}
	for _, value := range []string{
		"0001-0203-0405-0607-0809-0A0B-0c0d-0e0f",
		" 0001-0203-0405-0607-0809-0a0b-0c0d-0e0f",
		"000102030405060708090a0b0c0d0e0",
		"000102030405060708090a0b0c0d0e0f0",
		"000102030405060708090a0b0c0d0e0g",
	} {
		if _, err := parseV2PairingCode(value); err == nil || err.Error() != v2PairingInvalidCodeMessage {
			t.Fatalf("invalid code %q produced %v", value, err)
		}
	}
}

func TestV2PairingCryptoFrozenVectors(t *testing.T) {
	code := sequentialV2TestBytes(0, 16)
	locator, err := deriveV2PairingLocator(code)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveV2PairingKey(code, locator, "invitation-envelope")
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0x55}, 32)
	binder, err := v2PairingBinder(code, locator, "invitee", digest)
	if err != nil {
		t.Fatal(err)
	}
	previousRandom := v2RandomReader
	v2RandomReader = bytes.NewReader(sequentialV2TestBytes(0xa0, 24))
	t.Cleanup(func() { v2RandomReader = previousRandom })
	nonce, ciphertext, err := encryptV2PairingInvitation(
		code,
		locator,
		"https://dud.example.com",
		2_000_000_000,
		[]byte("dud pairing invitation"),
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptV2PairingInvitation(
		code,
		locator,
		nonce,
		ciphertext,
		"https://dud.example.com",
		2_000_000_000,
	)
	if err != nil || string(plaintext) != "dud pairing invitation" {
		t.Fatalf("envelope round trip = %q, %v", plaintext, err)
	}
	got := map[string]string{
		"locator":    hex.EncodeToString(locator),
		"key":        hex.EncodeToString(key),
		"binder":     hex.EncodeToString(binder),
		"nonce":      hex.EncodeToString(nonce),
		"ciphertext": hex.EncodeToString(ciphertext),
	}
	want := map[string]string{
		"locator":    "5d2847ed1cdec16c884dd847d64262f4fb4ea177388cf16bc4e777d2408f0f58",
		"key":        "37c48b62318ef84a63dcf88d4364259cd76358ec2b5c375bb8a158417fd714f3",
		"binder":     "e440816fbc6d731ae06815ca5522a07001743ae9d4c23aba51836a73088c8ec2",
		"nonce":      "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
		"ciphertext": "811ddabcb6a8685dfae6a2369c186c5c48c88b5d802ec7c34610d764788fe8bd92e5f2c69a02",
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Errorf("%s vector = %s", name, got[name])
		}
	}

	for _, mutation := range []struct {
		name       string
		origin     string
		expiresAt  uint64
		ciphertext []byte
	}{
		{name: "origin", origin: "https://other.example.com", expiresAt: 2_000_000_000, ciphertext: ciphertext},
		{name: "expiry", origin: "https://dud.example.com", expiresAt: 2_000_000_001, ciphertext: ciphertext},
		{name: "ciphertext", origin: "https://dud.example.com", expiresAt: 2_000_000_000, ciphertext: append(append([]byte(nil), ciphertext[:1]...), ciphertext[1:]...)},
	} {
		if mutation.name == "ciphertext" {
			mutation.ciphertext[0] ^= 1
		}
		if _, err := decryptV2PairingInvitation(code, locator, nonce, mutation.ciphertext, mutation.origin, mutation.expiresAt); err == nil || err.Error() != v2PairingInvalidCodeMessage {
			t.Fatalf("%s mutation produced %v", mutation.name, err)
		}
	}
}

func TestV2AcceptancePlainEd25519KeyAndTranscriptVector(t *testing.T) {
	invitation := v2TestInvitation()
	encoded, err := encodeV2Invitation(invitation)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeV2Invitation(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded[8].([]byte); !ok {
		t.Fatalf("decoded Ed25519 key has type %T", decoded[8])
	}
	invitation[12] = uint64(2_000_000_000)
	encoded, err = encodeV2Invitation(invitation)
	if err != nil {
		t.Fatal(err)
	}
	invitationDigest := sha256.Sum256(encoded)
	acceptance := map[int]any{
		1: uint64(2), 2: uint64(1), 3: uint64(1),
		4: cloneV2Bytes(invitation[4]), 5: cloneV2Bytes(invitation[5]),
		6: bytes.Repeat([]byte{0x31}, 16), 7: bytes.Repeat([]byte{0x32}, 1216),
		8: append([]byte(nil), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, 32)).Public().(ed25519.PublicKey)...),
		9: bytes.Repeat([]byte{0x34}, 32), 10: invitationDigest[:],
		11: bytes.Repeat([]byte{0x35}, 1120), 12: bytes.Repeat([]byte{0x36}, 32),
		13: bytes.Repeat([]byte{0x37}, 32), 14: bytes.Repeat([]byte{0x38}, 32),
	}
	if err := validateV2AcceptanceMap(invitation, acceptance); err != nil {
		t.Fatalf("plain []byte signing key rejected: %v", err)
	}
	pre, err := v2PreTranscript(invitation, acceptance)
	if err != nil {
		t.Fatal(err)
	}
	_, transcriptHash, err := v2FullTranscript(pre, bytes.Repeat([]byte{0x41}, 1120), acceptance[11].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(transcriptHash); got != "b227af56e341deb0867a8d17feae7349d6f4d26f10852ce9800b7a480e2febe8" {
		t.Errorf("transcript vector = %s", got)
	}
}

func TestV2PairingRelationshipSecretsFrozenVector(t *testing.T) {
	secretA := sequentialV2TestBytes(0x01, 32)
	secretB := sequentialV2TestBytes(0x80, 32)
	pairingPSK := bytes.Repeat([]byte{0x44}, 32)
	transcript, _ := hex.DecodeString("51c0f13137c980d3750705042a8a515a2ac8f90b652366e5c91133f34d400738")
	outbound, inbound, err := deriveV2PairingOutputs(secretA, secretB, pairingPSK, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(outbound); got != "965f90a83e20723096061366e34c2b66cf0576e45451005948d11ec8f48f5b24" {
		t.Errorf("inviter direction vector = %s", got)
	}
	if got := hex.EncodeToString(inbound); got != "ea34a7c883ccf799ea0bf0c95492ae1325ab107d273a81f5bd0b3db8d40b0f4e" {
		t.Errorf("invitee direction vector = %s", got)
	}
}

func v2TestInvitation() map[int]any {
	signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, 32))
	return map[int]any{
		1: uint64(2), 2: uint64(1), 3: uint64(1),
		4: sequentialV2TestBytes(0x10, 32), 5: sequentialV2TestBytes(0x30, 16),
		6: sequentialV2TestBytes(0x50, 16), 7: bytes.Repeat([]byte{0x61}, 1216),
		8: append([]byte(nil), signingKey.Public().(ed25519.PublicKey)...),
		9: "https://dud.example.com", 10: sequentialV2TestBytes(0x70, 32),
		11: sequentialV2TestBytes(0x90, 32), 12: uint64(time.Now().Unix()) + 900,
	}
}

func TestV2PairingMapValidatorsRejectCoreMismatches(t *testing.T) {
	invitation := v2TestInvitation()
	for _, test := range []struct {
		name   string
		mutate func(map[int]any)
	}{
		{"missing field", func(value map[int]any) { delete(value, 12) }},
		{"unknown field", func(value map[int]any) { value[13] = uint64(1) }},
		{"wrong version", func(value map[int]any) { value[1] = uint64(1) }},
		{"short identity", func(value map[int]any) { value[4] = []byte{1} }},
		{"bad origin type", func(value map[int]any) { value[9] = []byte("bad") }},
		{"noncanonical origin", func(value map[int]any) { value[9] = "https://DUD.example.com" }},
		{"expired", func(value map[int]any) { value[12] = uint64(1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := cloneV2Map(invitation)
			test.mutate(value)
			if err := validateV2InvitationMap(value); err == nil {
				t.Fatal("invalid invitation accepted")
			}
		})
	}
	encoded, err := v2EncMode.Marshal(invitation)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	acceptance := map[int]any{1: uint64(2), 2: uint64(1), 3: uint64(1), 4: cloneV2Bytes(invitation[4]), 5: cloneV2Bytes(invitation[5]), 6: bytes.Repeat([]byte{1}, 16), 7: bytes.Repeat([]byte{2}, 1216), 8: bytes.Repeat([]byte{3}, 32), 9: bytes.Repeat([]byte{4}, 32), 10: digest[:], 11: bytes.Repeat([]byte{5}, 1120), 12: bytes.Repeat([]byte{6}, 32), 13: bytes.Repeat([]byte{7}, 32), 14: bytes.Repeat([]byte{8}, 32)}
	for _, test := range []struct {
		name   string
		mutate func(map[int]any)
	}{
		{"missing field", func(value map[int]any) { delete(value, 14) }}, {"wrong version", func(value map[int]any) { value[1] = uint64(1) }}, {"short field", func(value map[int]any) { value[11] = []byte{1} }}, {"wrong invitation", func(value map[int]any) { value[4] = bytes.Repeat([]byte{9}, 32) }},
	} {
		t.Run("acceptance "+test.name, func(t *testing.T) {
			value := cloneV2Map(acceptance)
			test.mutate(value)
			if err := validateV2AcceptanceMap(invitation, value); err == nil {
				t.Fatal("invalid acceptance accepted")
			}
		})
	}
	confirmation := map[int]any{1: uint64(2), 2: cloneV2Bytes(invitation[4]), 3: cloneV2Bytes(invitation[5]), 4: func() []byte {
		encoded, _ := v2EncMode.Marshal(acceptance)
		value := sha256.Sum256(encoded)
		return value[:]
	}(), 5: bytes.Repeat([]byte{1}, 1120), 6: bytes.Repeat([]byte{2}, 32), 7: bytes.Repeat([]byte{3}, 32)}
	if err := validateV2KeyConfirmationMap(invitation, acceptance, confirmation); err != nil {
		t.Fatal(err)
	}
	confirmation[7] = []byte{1}
	if err := validateV2KeyConfirmationMap(invitation, acceptance, confirmation); err == nil {
		t.Fatal("invalid confirmation accepted")
	}
}

func TestV2ServerAgeGrantInteropFixture(t *testing.T) {
	encoded := os.Getenv("DUD_TEST_AGE_CIPHERTEXT")
	if encoded == "" {
		t.Skip("exercised by the Node server interoperability test")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deriveV2RelationshipIdentity(sequentialV2TestBytes(0x42, 32), sequentialV2TestBytes(0x24, 16), 0)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "server-to-go capability grant" {
		t.Fatalf("decrypted grant = %q", plaintext)
	}
}

const v2EnrollmentTestSecret = "squid-lantern-rotate-9-mango"

// The enrollment secret is a typed passphrase, so the client enforces the same
// floor the server does and names the variable rather than letting a too-short
// value fail later as an indistinguishable refusal.
func TestV2EnrollmentSecretFailsClosed(t *testing.T) {
	key, err := v2EnrollmentKey("")
	if err != nil || key != nil {
		t.Fatalf("empty secret = %x, %v", key, err)
	}
	for _, invalid := range []string{
		"short",
		strings.Repeat("a", v2EnrollmentSecretMinLength-1),
		" " + strings.Repeat("a", v2EnrollmentSecretMinLength),
		strings.Repeat("a", v2EnrollmentSecretMinLength) + "\n",
	} {
		if _, err := v2EnrollmentKey(invalid); err == nil {
			t.Fatalf("accepted invalid enrollment secret %q", invalid)
		}
	}
	derived, err := v2EnrollmentKey(v2EnrollmentTestSecret)
	if err != nil || len(derived) != 32 {
		t.Fatalf("valid passphrase = %x, %v", derived, err)
	}
}

// The passphrase is stretched rather than hashed once, which is what keeps a
// captured proof from being a cheap offline verifier. Assert the work factor
// both implementations compile in, since a silent drop to a fast KDF would
// still interoperate and still pass every other test here.
func TestV2EnrollmentKeyUsesTheAgreedWorkFactor(t *testing.T) {
	if v2EnrollmentKDFIterations < 600_000 {
		t.Fatalf("enrollment KDF work factor dropped to %d", v2EnrollmentKDFIterations)
	}
	expected, err := pbkdf2.Key(
		sha256.New,
		v2EnrollmentTestSecret,
		[]byte(v2EnrollmentKDFSalt),
		v2EnrollmentKDFIterations,
		32,
	)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := v2EnrollmentKey(v2EnrollmentTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, expected) {
		t.Fatalf("enrollment key = %x, want %x", derived, expected)
	}
}

// The derived-key form must reach the key the passphrase reaches, because a
// deployment configured with it verifies proofs from clients that still hold the
// passphrase. That form is what lets a server skip the derivation entirely,
// which is the only way a free-tier Worker can afford to gate enrollment.
func TestV2EnrollmentKeyFormRoundTripsThePassphrase(t *testing.T) {
	stretched, err := v2EnrollmentKey(v2EnrollmentTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	value, err := formatV2EnrollmentKey(stretched)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, v2EnrollmentKeyPrefix) {
		t.Fatalf("formatted enrollment key = %q", value)
	}
	carried, err := v2EnrollmentKey(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(carried, stretched) {
		t.Fatalf("carried key = %x, want %x", carried, stretched)
	}
	if _, err := formatV2EnrollmentKey(stretched[:31]); err == nil {
		t.Fatal("formatted a key that is not 32 bytes")
	}
}

// A stated work factor travels inside the secret, so both sides read the same
// one. An unreadable or out-of-range count is refused rather than silently
// treated as the default, which would produce a key neither side agrees on.
func TestV2EnrollmentSecretStatesItsOwnWorkFactor(t *testing.T) {
	weak := fmt.Sprintf("dud2-enroll-kdf:10000:%s", v2EnrollmentTestSecret)
	credential, err := parseV2EnrollmentCredential(weak)
	if err != nil {
		t.Fatal(err)
	}
	if credential.iterations != 10_000 || credential.passphrase != v2EnrollmentTestSecret {
		t.Fatalf("parsed %+v", credential)
	}
	stated, err := v2EnrollmentKey(weak)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := pbkdf2.Key(sha256.New, v2EnrollmentTestSecret, []byte(v2EnrollmentKDFSalt), 10_000, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stated, expected) {
		t.Fatalf("stated work factor key = %x, want %x", stated, expected)
	}
	// The default is a different key, so a client that ignored the stated count
	// would be refused rather than quietly admitted.
	byDefault, err := v2EnrollmentKey(v2EnrollmentTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stated, byDefault) {
		t.Fatal("a stated work factor produced the default key")
	}
	if warning := v2EnrollmentWorkFactorWarning(weak); !strings.Contains(warning, "10000") {
		t.Fatalf("reduced work factor warning = %q", warning)
	}
	for _, quiet := range []string{
		v2EnrollmentTestSecret,
		fmt.Sprintf("dud2-enroll-kdf:600000:%s", v2EnrollmentTestSecret),
		v2EnrollmentKeyPrefix + v2Base64URL(byDefault),
	} {
		if warning := v2EnrollmentWorkFactorWarning(quiet); warning != "" {
			t.Fatalf("warned about %q: %s", quiet, warning)
		}
	}
	for _, invalid := range []string{
		"dud2-enroll-kdf:1:" + v2EnrollmentTestSecret,
		"dud2-enroll-kdf:99999999999:" + v2EnrollmentTestSecret,
		"dud2-enroll-kdf::" + v2EnrollmentTestSecret,
		"dud2-enroll-kdf:0x2710:" + v2EnrollmentTestSecret,
		// Accepted by Atoi but not by the server's parser, so it must be
		// rejected here too: the two implementations have to agree on which
		// secrets exist, not only on what the valid ones derive to.
		"dud2-enroll-kdf:+600000:" + v2EnrollmentTestSecret,
		"dud2-enroll-kdf: 600000:" + v2EnrollmentTestSecret,
		"dud2-enroll-kdf:600000",
		"dud2-enroll-kdf:600000:short",
		v2EnrollmentKeyPrefix + "truncated",
		v2EnrollmentKeyPrefix + v2Base64URL(byDefault) + "=",
	} {
		if _, err := v2EnrollmentKey(invalid); err == nil {
			t.Fatalf("accepted invalid enrollment secret %q", invalid)
		}
	}
}

// A proof authorizes exactly one rendezvous: change the locator, the expiry, or
// the secret and the MAC changes with it.
func TestV2EnrollmentProofIsBoundToItsRendezvous(t *testing.T) {
	key, err := v2EnrollmentKey(v2EnrollmentTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	other, err := v2EnrollmentKey("squid-lantern-rotate-9-mangp")
	if err != nil {
		t.Fatal(err)
	}
	locator := sequentialV2TestBytes(0x01, 32)
	base, err := deriveV2EnrollmentProof(key, locator, 1_800_000_900)
	if err != nil {
		t.Fatal(err)
	}
	for name, variant := range map[string]struct {
		key       []byte
		locator   []byte
		expiresAt uint64
	}{
		"locator": {key, sequentialV2TestBytes(0x02, 32), 1_800_000_900},
		"expiry":  {key, locator, 1_800_000_901},
		"secret":  {other, locator, 1_800_000_900},
	} {
		candidate, err := deriveV2EnrollmentProof(variant.key, variant.locator, variant.expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(candidate, base) {
			t.Fatalf("enrollment proof is not bound to the %s", name)
		}
	}
	for _, invalid := range [][2]int{{31, 32}, {32, 31}} {
		if _, err := deriveV2EnrollmentProof(
			sequentialV2TestBytes(0, invalid[0]),
			sequentialV2TestBytes(0, invalid[1]),
			1,
		); err == nil {
			t.Fatalf("accepted %d-byte secret and %d-byte locator", invalid[0], invalid[1])
		}
	}
}
