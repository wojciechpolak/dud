// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/hpke"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	v2PairingCodeBytes          = 16
	v2PairingEnvelopeMaxBytes   = 4096
	v2PairingMaximumLifetime    = time.Hour
	v2PairingExporterContext    = "dud/v2/pairing"
	v2PairingInvalidCodeMessage = "pairing code is invalid or expired"
)

func v2Base64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeV2Base64URL(value string, length int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || (length >= 0 && len(decoded) != length) || v2Base64URL(decoded) != value {
		if length >= 0 {
			return nil, fmt.Errorf("invalid %d-byte base64url value", length)
		}
		return nil, errors.New("invalid base64url value")
	}
	return decoded, nil
}

func randomV2Bytes(length int) ([]byte, error) {
	value := make([]byte, length)
	if _, err := io.ReadFull(v2RandomReader, value); err != nil {
		return nil, err
	}
	return value, nil
}

var v2RandomReader io.Reader = rand.Reader

func formatV2PairingCode(value []byte) (string, error) {
	if len(value) != v2PairingCodeBytes {
		return "", errors.New("pairing code must contain exactly 128 bits")
	}
	raw := hex.EncodeToString(value)
	groups := make([]string, 0, 8)
	for offset := 0; offset < len(raw); offset += 4 {
		groups = append(groups, raw[offset:offset+4])
	}
	return strings.Join(groups, "-"), nil
}

func parseV2PairingCode(value string) ([]byte, error) {
	normalized := strings.ReplaceAll(value, "-", "")
	if len(normalized) != 32 || normalized != strings.ToLower(normalized) {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != v2PairingCodeBytes {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	return decoded, nil
}

func deriveV2PairingLocator(code []byte) ([]byte, error) {
	if len(code) != v2PairingCodeBytes {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	digest := sha256.Sum256(append([]byte("dud/v2/pairing/rendezvous\x00"), code...))
	return digest[:], nil
}

func deriveV2PairingKey(code, locator []byte, label string) ([]byte, error) {
	if len(code) != v2PairingCodeBytes || len(locator) != 32 {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	return hkdf.Key(sha256.New, code, locator, "dud/v2/pairing/"+label, 32)
}

func v2PairingEnvelopeAAD(locator []byte, origin string, expiresAt uint64) ([]byte, error) {
	return v2EncMode.Marshal(map[int]any{
		1: uint64(2),
		2: locator,
		3: origin,
		4: expiresAt,
	})
}

func encryptV2PairingInvitation(code, locator []byte, origin string, expiresAt uint64, invitation []byte) ([]byte, []byte, error) {
	key, err := deriveV2PairingKey(code, locator, "invitation-envelope")
	if err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := randomV2Bytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, nil, err
	}
	aad, err := v2PairingEnvelopeAAD(locator, origin, expiresAt)
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, invitation, aad), nil
}

func decryptV2PairingInvitation(code, locator, nonce, ciphertext []byte, origin string, expiresAt uint64) ([]byte, error) {
	key, err := deriveV2PairingKey(code, locator, "invitation-envelope")
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX || len(ciphertext) > v2PairingEnvelopeMaxBytes {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	aad, err := v2PairingEnvelopeAAD(locator, origin, expiresAt)
	if err != nil {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	return plaintext, nil
}

func v2PairingBinder(code, locator []byte, role string, digest []byte) ([]byte, error) {
	key, err := deriveV2PairingKey(code, locator, role+"-binder")
	if err != nil || len(digest) != 32 {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("dud/v2/pairing/binder\x00"))
	mac.Write(digest)
	return mac.Sum(nil), nil
}

// v2EnrollmentKDFIterations and v2EnrollmentKDFSalt must match the server's
// constants exactly: the client produces the proof and the server verifies it,
// so the two have to agree on the whole derivation, not only on the HMAC.
const v2EnrollmentKDFIterations = 600_000

const v2EnrollmentKDFSalt = "dud/v2/enrollment-key"

// Bounds on a work factor stated in the secret itself. They mirror the server's.
const (
	v2EnrollmentKDFMinIterations = 10_000
	v2EnrollmentKDFMaxIterations = 10_000_000
)

// The two prefixes that make DUD_PEER_SECRET carry something other than a bare
// passphrase. They mirror the server's.
const (
	v2EnrollmentKeyPrefix = "dud2-enroll-key:"
	v2EnrollmentKDFPrefix = "dud2-enroll-kdf:"
)

// v2EnrollmentCredential is what an operator put in DUD_PEER_SECRET: either the
// derived key itself, or a passphrase and the work factor to stretch it by.
type v2EnrollmentCredential struct {
	key        []byte
	passphrase string
	iterations int
}

// v2EnrollmentSecretMinLength mirrors the server's floor. The client checks it
// too so a too-short passphrase is a local error naming the variable, rather
// than a refusal that looks like the wrong secret.
const v2EnrollmentSecretMinLength = 24

func isV2DecimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parseV2EnrollmentPassphrase(passphrase string, iterations int) (v2EnrollmentCredential, error) {
	if len(passphrase) < v2EnrollmentSecretMinLength {
		return v2EnrollmentCredential{}, fmt.Errorf(
			"DUD_PEER_SECRET must be at least %d characters; it is the passphrase the deployment operator issued",
			v2EnrollmentSecretMinLength,
		)
	}
	if strings.TrimSpace(passphrase) != passphrase {
		return v2EnrollmentCredential{}, errors.New("DUD_PEER_SECRET must not begin or end with whitespace")
	}
	return v2EnrollmentCredential{passphrase: passphrase, iterations: iterations}, nil
}

// parseV2EnrollmentCredential reads the three accepted forms of DUD_PEER_SECRET.
// A bare passphrase is stretched at the default work factor; "dud2-enroll-key:"
// carries the derived key directly, so a device that holds it does no
// derivation; "dud2-enroll-kdf:" states a work factor ahead of the passphrase.
//
// The parameters travel inside the value rather than in a second variable, so
// that they reach every device the secret does. A work factor configured
// separately on each side could disagree, and enrollment refusals are
// deliberately indistinguishable, so that disagreement would be unreadable.
func parseV2EnrollmentCredential(value string) (v2EnrollmentCredential, error) {
	if rest, found := strings.CutPrefix(value, v2EnrollmentKeyPrefix); found {
		key, err := decodeV2Base64URL(rest, 32)
		if err != nil {
			return v2EnrollmentCredential{}, fmt.Errorf(
				"DUD_PEER_SECRET starts with %s, so the rest must be a derived enrollment key: "+
					"32 bytes as 43 base64url characters, no padding",
				v2EnrollmentKeyPrefix,
			)
		}
		return v2EnrollmentCredential{key: key}, nil
	}
	if rest, found := strings.CutPrefix(value, v2EnrollmentKDFPrefix); found {
		digits, passphrase, found := strings.Cut(rest, ":")
		// Digits only, rather than whatever Atoi would take: it accepts a leading
		// sign that the server's parser does not, and the two must agree on which
		// secrets exist at all, not merely on what the valid ones derive to.
		iterations, err := strconv.Atoi(digits)
		if !found || err != nil || !isV2DecimalDigits(digits) ||
			iterations < v2EnrollmentKDFMinIterations ||
			iterations > v2EnrollmentKDFMaxIterations {
			return v2EnrollmentCredential{}, fmt.Errorf(
				"DUD_PEER_SECRET starts with %s, so the rest must be an iteration count between "+
					"%d and %d, a colon, and the passphrase",
				v2EnrollmentKDFPrefix,
				v2EnrollmentKDFMinIterations,
				v2EnrollmentKDFMaxIterations,
			)
		}
		return parseV2EnrollmentPassphrase(passphrase, iterations)
	}
	return parseV2EnrollmentPassphrase(value, v2EnrollmentKDFIterations)
}

// deriveV2EnrollmentKey produces the 32-byte HMAC key a proof is computed under.
// Unlike the two server-only v2 credentials this one is carried by hand to every
// device that may invite, so it is typed rather than copied. A captured proof
// lets an attacker test guesses offline, so the derivation is deliberately slow:
// that cost, not the passphrase's own entropy, is what makes guessing
// impractical. A secret that already carries the derived key skips it, having
// paid it once elsewhere.
func deriveV2EnrollmentKey(secret string) ([]byte, error) {
	credential, err := parseV2EnrollmentCredential(secret)
	if err != nil {
		return nil, err
	}
	if credential.key != nil {
		return credential.key, nil
	}
	return pbkdf2.Key(
		sha256.New,
		credential.passphrase,
		[]byte(v2EnrollmentKDFSalt),
		credential.iterations,
		32,
	)
}

// formatV2EnrollmentKey renders a derived key as the DUD_PEER_SECRET value that
// carries it.
func formatV2EnrollmentKey(key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("an enrollment key is 32 bytes")
	}
	return v2EnrollmentKeyPrefix + v2Base64URL(key), nil
}

// deriveV2EnrollmentProof authorizes creating one rendezvous on a deployment
// that gates enrollment. The proof is bound to that rendezvous, so the secret
// itself never reaches the wire and a captured proof opens nothing else. Only
// the inviter needs it: an invitee accepts with the pairing code alone.
func deriveV2EnrollmentProof(key, locator []byte, expiresAt uint64) ([]byte, error) {
	if len(key) != 32 || len(locator) != 32 {
		return nil, errors.New("enrollment proof input is invalid")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("dud/v2/enrollment|"))
	mac.Write(locator)
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], expiresAt)
	mac.Write(expiry[:])
	return mac.Sum(nil), nil
}

const v2EnrollmentRequiredMessage = "this deployment gates pairing enrollment; set DUD_PEER_SECRET to the enrollment secret its operator issued"

// isV2EnrollmentRefusal reads a rendezvous-creation refusal. Enrollment is the
// only credential that route checks, so an authentication failure there names
// the missing secret rather than a bare HTTP status.
func isV2EnrollmentRefusal(err error) bool {
	var protocolError *v2ProtocolError
	return errors.As(err, &protocolError) && protocolError.Code == 2
}

// v2EnrollmentKey validates DUD_PEER_SECRET and derives its key. The variable is
// absent on a deployment that runs open enrollment.
func v2EnrollmentKey(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if _, err := parseV2EnrollmentCredential(value); err != nil {
		return nil, err
	}
	return deriveV2EnrollmentKey(value)
}

// v2EnrollmentWorkFactorWarning describes a secret that states a work factor
// below the default, and is empty for every other secret including an invalid
// one, which the derivation reports instead.
//
// A reduced work factor is reported rather than refused: the operator who set it
// made that choice on the server, and a client that declined to match would only
// be unable to enroll at all.
func v2EnrollmentWorkFactorWarning(value string) string {
	credential, err := parseV2EnrollmentCredential(value)
	if err != nil || credential.key != nil ||
		credential.iterations >= v2EnrollmentKDFIterations {
		return ""
	}
	return fmt.Sprintf(
		"DUD_PEER_SECRET states %d KDF iterations, below the default %d, so a captured enrollment proof is that much cheaper to guess against offline.",
		credential.iterations,
		v2EnrollmentKDFIterations,
	)
}

func v2PairingBearerVerifier(bearer []byte) (map[int]any, error) {
	if len(bearer) != 32 {
		return nil, errors.New("pairing bearer must be exactly 32 bytes")
	}
	salt, err := randomV2Bytes(16)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(concatV2Bytes([]byte("dud/v2/bearer\x00"), salt, bearer))
	return map[int]any{1: salt, 2: digest[:]}, nil
}

func encodeV2Invitation(invitation map[int]any) ([]byte, error) {
	encoded, err := v2EncMode.Marshal(invitation)
	if err != nil {
		return nil, err
	}
	if len(encoded) > v2PairingEnvelopeMaxBytes-chacha20poly1305.Overhead {
		return nil, errors.New("encoded invitation exceeds pairing envelope limit")
	}
	return encoded, nil
}

func decodeV2Invitation(encoded []byte) (map[int]any, error) {
	if len(encoded) == 0 || len(encoded) > v2PairingEnvelopeMaxBytes {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	var invitation map[int]any
	if err := v2DecMode.Unmarshal(encoded, &invitation); err != nil {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	canonical, err := v2EncMode.Marshal(invitation)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	if err := validateV2InvitationMap(invitation); err != nil {
		return nil, errors.New(v2PairingInvalidCodeMessage)
	}
	return invitation, nil
}

func validateV2InvitationMap(invitation map[int]any) error {
	if len(invitation) != 12 {
		return errors.New("invitation must contain exactly 12 core fields")
	}
	for key := 1; key <= 12; key++ {
		if _, ok := invitation[key]; !ok {
			return fmt.Errorf("invitation is missing core field %d", key)
		}
	}
	for key := range invitation {
		if key < 1 || key > 12 {
			return fmt.Errorf("invitation contains unknown core field %d", key)
		}
	}
	if !v2UintEquals(invitation[1], 2) || !v2UintEquals(invitation[2], 1) || !v2UintEquals(invitation[3], 1) {
		return errors.New("invitation version or algorithms are unsupported")
	}
	for _, field := range []struct {
		key    int
		length int
		name   string
	}{
		{4, 32, "ID"},
		{5, 16, "relationship ID"},
		{6, 16, "inviter pairing ID"},
		{7, 1216, "age recipient"},
		{8, 32, "signing public key"},
		{10, 32, "bootstrap capability"},
		{11, 32, "nonce"},
	} {
		value, ok := invitation[field.key].([]byte)
		if !ok || len(value) != field.length {
			return fmt.Errorf("invitation %s must be exactly %d bytes", field.name, field.length)
		}
	}
	origin, ok := invitation[9].(string)
	if !ok {
		return errors.New("invitation origin must be text")
	}
	canonical, err := canonicalV2Origin(origin)
	if err != nil || canonical != origin {
		return errors.New("invitation origin is not canonical HTTPS")
	}
	expiresAt, ok := asV2Uint(invitation[12])
	if !ok {
		return errors.New("invitation expiry must be an unsigned integer")
	}
	now := uint64(time.Now().Unix())
	if expiresAt <= now || expiresAt > now+uint64(v2PairingMaximumLifetime/time.Second)+300 {
		return errors.New("invitation is expired or exceeds the one-hour lifetime")
	}
	return nil
}

func v2HPKEPrivateKey(seed, relationshipID []byte) (hpke.PrivateKey, error) {
	raw, err := deriveV2Material(seed, "identity", relationshipID, 0, 32)
	if err != nil {
		return nil, err
	}
	return hpke.MLKEM768X25519().NewPrivateKey(raw)
}

func v2PairingSign(name string, pairingMap map[int]any, signingKey ed25519.PrivateKey) ([]byte, error) {
	encoded, err := v2EncMode.Marshal(pairingMap)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	input := append([]byte("dud/v2/pairing/"+name+"\x00"), digest[:]...)
	return ed25519.Sign(signingKey, input), nil
}

func v2PairingVerify(name string, pairingMap map[int]any, signature []byte, publicKey ed25519.PublicKey) bool {
	if len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	encoded, err := v2EncMode.Marshal(pairingMap)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(encoded)
	input := append([]byte("dud/v2/pairing/"+name+"\x00"), digest[:]...)
	return ed25519.Verify(publicKey, input, signature)
}

func v2PreTranscript(invitation, acceptance map[int]any) (map[int]any, error) {
	if err := validateV2AcceptanceMap(invitation, acceptance); err != nil {
		return nil, err
	}
	return map[int]any{
		1:  uint64(2),
		2:  uint64(1),
		3:  uint64(1),
		4:  cloneV2Bytes(invitation[4]),
		5:  cloneV2Bytes(invitation[5]),
		6:  invitation[9],
		7:  cloneV2Bytes(invitation[6]),
		8:  cloneV2Bytes(acceptance[6]),
		9:  cloneV2Bytes(invitation[7]),
		10: cloneV2Bytes(acceptance[7]),
		11: cloneV2Bytes(invitation[8]),
		12: cloneV2Bytes(acceptance[8]),
		13: cloneV2Bytes(invitation[11]),
		14: cloneV2Bytes(acceptance[9]),
		15: invitation[12],
		16: uint64(0),
		17: "bootstrap",
		18: cloneV2Bytes(acceptance[14]),
		19: cloneV2Bytes(acceptance[13]),
	}, nil
}

func validateV2AcceptanceMap(invitation, acceptance map[int]any) error {
	if len(acceptance) != 14 {
		return errors.New("acceptance must contain exactly 14 core fields")
	}
	for key := 1; key <= 14; key++ {
		if _, ok := acceptance[key]; !ok {
			return fmt.Errorf("acceptance is missing core field %d", key)
		}
	}
	if !v2UintEquals(acceptance[1], 2) || !v2UintEquals(acceptance[2], 1) || !v2UintEquals(acceptance[3], 1) {
		return errors.New("acceptance version or algorithms are unsupported")
	}
	for _, field := range []struct {
		key    int
		length int
	}{
		{4, 32}, {5, 16}, {6, 16}, {7, 1216}, {8, 32}, {9, 32}, {10, 32}, {11, 1120}, {12, 32}, {13, 32}, {14, 32},
	} {
		value, ok := acceptance[field.key].([]byte)
		if !ok || len(value) != field.length {
			return fmt.Errorf("acceptance field %d has an invalid size", field.key)
		}
	}
	invitationBytes, err := v2EncMode.Marshal(invitation)
	if err != nil {
		return err
	}
	invitationDigest := sha256.Sum256(invitationBytes)
	if !bytes.Equal(acceptance[4].([]byte), invitation[4].([]byte)) ||
		!bytes.Equal(acceptance[5].([]byte), invitation[5].([]byte)) ||
		!bytes.Equal(acceptance[10].([]byte), invitationDigest[:]) {
		return errors.New("acceptance does not match the invitation")
	}
	return nil
}

func v2FullTranscript(pre map[int]any, encA, encB []byte) (map[int]any, []byte, error) {
	if len(encA) != 1120 || len(encB) != 1120 {
		return nil, nil, errors.New("pairing encapsulation has an invalid size")
	}
	full := make(map[int]any, len(pre)+2)
	for key, value := range pre {
		full[key] = value
	}
	full[20] = append([]byte(nil), encA...)
	full[21] = append([]byte(nil), encB...)
	encoded, err := v2EncMode.Marshal(full)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(encoded)
	return full, digest[:], nil
}

func validateV2KeyConfirmationMap(invitation, acceptance, confirmation map[int]any) error {
	if len(confirmation) != 7 {
		return errors.New("key confirmation must contain exactly 7 core fields")
	}
	for key := 1; key <= 7; key++ {
		if _, exists := confirmation[key]; !exists {
			return fmt.Errorf("key confirmation is missing core field %d", key)
		}
	}
	if !v2UintEquals(confirmation[1], 2) {
		return errors.New("key confirmation version is unsupported")
	}
	for _, field := range []struct {
		key    int
		length int
	}{
		{2, 32}, {3, 16}, {4, 32}, {5, 1120}, {6, 32}, {7, 32},
	} {
		value, ok := confirmation[field.key].([]byte)
		if !ok || len(value) != field.length {
			return fmt.Errorf("key confirmation field %d has an invalid size", field.key)
		}
	}
	invitationID, invitationIDOK := invitation[4].([]byte)
	relationshipID, relationshipIDOK := invitation[5].([]byte)
	acceptanceBytes, err := v2EncMode.Marshal(acceptance)
	if err != nil {
		return err
	}
	acceptanceDigest := sha256.Sum256(acceptanceBytes)
	if !invitationIDOK || !relationshipIDOK ||
		!bytes.Equal(confirmation[2].([]byte), invitationID) ||
		!bytes.Equal(confirmation[3].([]byte), relationshipID) ||
		!bytes.Equal(confirmation[4].([]byte), acceptanceDigest[:]) {
		return errors.New("key confirmation does not match the pending pairing")
	}
	return nil
}

func deriveV2PairingOutputs(secretA, secretB, pairingPSK, transcriptHash []byte) (inviterToInvitee, inviteeToInviter []byte, err error) {
	if len(secretA) != 32 || len(secretB) != 32 || len(pairingPSK) != 32 || len(transcriptHash) != 32 {
		return nil, nil, errors.New("pairing secret material has an invalid size")
	}
	input := concatV2Bytes(secretA, secretB, pairingPSK)
	inviterToInvitee, err = hkdf.Key(sha256.New, input, transcriptHash, "dud/v2/relationship|inviter->invitee|0", 32)
	if err != nil {
		return nil, nil, err
	}
	inviteeToInviter, err = hkdf.Key(sha256.New, input, transcriptHash, "dud/v2/relationship|invitee->inviter|0", 32)
	if err != nil {
		return nil, nil, err
	}
	return inviterToInvitee, inviteeToInviter, nil
}

func concatV2Bytes(parts ...[]byte) []byte {
	length := 0
	for _, part := range parts {
		length += len(part)
	}
	result := make([]byte, 0, length)
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}

func cloneV2Bytes(value any) []byte {
	bytesValue, _ := value.([]byte)
	return append([]byte(nil), bytesValue...)
}

func decodeV2StoredMap(value string) (map[int]any, error) {
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, err
	}
	var result map[int]any
	if err := v2DecMode.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	canonical, err := v2EncMode.Marshal(result)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, errors.New("stored pairing map is not deterministic CBOR")
	}
	return result, nil
}

func encodeV2StoredMap(value map[int]any) (string, error) {
	encoded, err := v2EncMode.Marshal(value)
	if err != nil {
		return "", err
	}
	return v2Base64URL(encoded), nil
}

func normalizeV2Map(value any) (map[int]any, error) {
	encoded, err := v2EncMode.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result map[int]any
	if err := v2DecMode.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func newV2PeerTransport(a *app, cfg *v2LocalConfig, peer *v2PeerProfile, timeout time.Duration) (v2Transport, error) {
	settings, err := resolveV2Network(cfg, peer, v2NetworkOverrides{})
	if err != nil {
		return nil, err
	}
	transport, err := a.newV2Transport(v2TransportOptions{
		DOHURL:        settings.DOHURL.Value,
		ECHMode:       settings.ECHMode.Value,
		CABundle:      a.cfg.CABundle,
		ConnectTo:     a.cfg.ConnectTo,
		DOHBootstrap:  v2BootstrapAddresses(cfg),
		Timeout:       timeout,
		OriginSource:  settings.BaseURL.Source,
		ECHModeSource: settings.ECHMode.Source,
	})
	if err != nil {
		return nil, err
	}
	return transport, nil
}

func doV2CBORRequest(ctx context.Context, transport v2Transport, method, origin, path string, bearer []byte, body []byte, maxResponse int64) (*v2Response, error) {
	authorization := ""
	if bearer != nil {
		authorization = "DUD2-Bearer " + v2Base64URL(bearer)
	}
	return doV2AuthorizedCBORRequest(ctx, transport, method, origin, path, authorization, body, maxResponse)
}

func doV2AuthorizedCBORRequest(ctx context.Context, transport v2Transport, method, origin, path, authorization string, body []byte, maxResponse int64) (*v2Response, error) {
	headers := http.Header{"Accept": []string{v2CBORContentType}}
	if authorization != "" {
		headers.Set("Authorization", authorization)
	}
	if body != nil {
		headers.Set("Content-Type", v2CBORContentType)
		headers.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}
	response, err := transport.Do(ctx, v2Request{
		Method:           method,
		Origin:           origin,
		Path:             path,
		Headers:          headers,
		Body:             body,
		MaxResponseBytes: maxResponse,
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, decodeV2HTTPError(response)
	}
	if len(response.Body) != 0 && response.ContentType != v2CBORContentType {
		return nil, fmt.Errorf("v2 endpoint returned unexpected Content-Type %q", response.ContentType)
	}
	return response, nil
}

// v2ProtocolError carries the server's stable error code alongside the message,
// so a caller can distinguish a refusal it can explain from a bare failure
// without matching on redaction-safe text.
type v2ProtocolError struct {
	Code    uint64
	Status  int
	Message string
}

func (e *v2ProtocolError) Error() string {
	return fmt.Sprintf("%s (HTTP %d, v2 error %d)", e.Message, e.Status, e.Code)
}

func decodeV2HTTPError(response *v2Response) error {
	if response.ContentType != v2CBORContentType || len(response.Body) == 0 {
		return fmt.Errorf("v2 endpoint returned HTTP %d", response.StatusCode)
	}
	var value map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &value); err != nil {
		return fmt.Errorf("v2 endpoint returned HTTP %d with an invalid error", response.StatusCode)
	}
	code, _ := asV2Uint(value[1])
	message, _ := value[2].(string)
	if message == "" {
		message = "v2 request failed"
	}
	return &v2ProtocolError{Code: code, Status: response.StatusCode, Message: message}
}

func decryptV2CapabilityGrant(ciphertext []byte, identity age.Identity, relationshipID []byte, role uint64, origin string) (map[string]string, error) {
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt capability grant: %w", err)
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, v2MaxDescriptorBytes+1))
	if err != nil {
		return nil, err
	}
	if len(plaintext) > v2MaxDescriptorBytes {
		return nil, errors.New("capability grant exceeds the descriptor limit")
	}
	var grant map[int]any
	if err := v2DecMode.Unmarshal(plaintext, &grant); err != nil {
		return nil, fmt.Errorf("decode capability grant: %w", err)
	}
	if len(grant) != 6 || !v2UintEquals(grant[1], 2) || !v2UintEquals(grant[3], role) || !v2UintEquals(grant[4], 0) {
		return nil, errors.New("capability grant header is invalid")
	}
	grantRelationship, ok := grant[2].([]byte)
	if !ok || !bytes.Equal(grantRelationship, relationshipID) || grant[5] != origin {
		return nil, errors.New("capability grant does not match the pending relationship")
	}
	rawGrants, ok := grant[6].([]any)
	if !ok || len(rawGrants) != 3 {
		return nil, errors.New("capability grant must contain exactly three scopes")
	}
	result := map[string]string{}
	for _, raw := range rawGrants {
		item, ok := raw.(map[any]any)
		if ok {
			converted := map[int]any{}
			for key, value := range item {
				number, ok := key.(uint64)
				if !ok {
					return nil, errors.New("capability grant key is invalid")
				}
				converted[int(number)] = value
			}
			item = nil
			raw = converted
		}
		entry, ok := raw.(map[int]any)
		if !ok || len(entry) != 3 {
			return nil, errors.New("capability grant entry is invalid")
		}
		directionNumber, ok := asV2Uint(entry[1])
		scope, scopeOK := entry[2].(string)
		secret, secretOK := entry[3].([]byte)
		if !ok || directionNumber > 1 || !scopeOK || !secretOK || len(secret) != 32 {
			return nil, errors.New("capability grant entry fields are invalid")
		}
		direction := "inviter->invitee"
		if directionNumber == 1 {
			direction = "invitee->inviter"
		}
		switch scope {
		case "write", "read", "ack":
		default:
			return nil, fmt.Errorf("capability grant contains unsupported scope %q", scope)
		}
		key := direction + "|" + scope
		if _, exists := result[key]; exists {
			return nil, errors.New("capability grant contains a duplicate tuple")
		}
		result[key] = v2Base64URL(secret)
	}
	return result, nil
}
