// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"filippo.io/age"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/net/idna"
)

const (
	v2ProtocolVersion     = 2
	v2KEMAlgorithm        = 1
	v2SignatureAlgorithm  = 1
	v2MaxDescriptorBytes  = 262144
	v2MaxTextOrBytes      = 65536
	v2DescriptorSigPrefix = "dud/v2/descriptor\x00"
)

const (
	kCriticalExtensions = 0
	kV                  = 1
	kKEMAlg             = 2
	kSigAlg             = 3
	kDescriptorID       = 4
	kPayloadType        = 5
	kRelationshipID     = 6
	kDirection          = 7
	kChain              = 8
	kKeyEpoch           = 9
	kSequence           = 10
	kPreviousDigest     = 11
	kSenderDeviceID     = 12
	kSenderKeyID        = 13
	kRecipientDeviceID  = 14
	kCanonicalOrigin    = 15
	kCreatedAt          = 16
	kTransportPolicy    = 17
	kPayloadHash        = 18
	kChunkHashes        = 19
	kDisplayName        = 20
	kArchiveFormat      = 21
	kPlaintextSize      = 22
	kTypeMetadata       = 23
	kChunkSize          = 24
	kChunkIDs           = 25
	kIncrementalBase    = 26
)

// v2MinimumExtensionKey is the first key of the optional extension range shared
// by the descriptor and by every type_meta map. Keys below it are the frozen
// core namespace: an unrecognised one is a rejection. Keys at or above it are
// ignored when unknown, which is what lets a later release add a field without
// a protocol version bump. See protocol-v2.md §2.
const v2MinimumExtensionKey = 128

// kPeerFeatures is the acknowledgement type_meta extension carrying the feature
// IDs the acknowledging peer implements. It exists because the protocol
// negotiates capabilities between a client and a server but never between two
// peers, so this is the only channel by which a sender learns what its peer can
// accept. An absent key means "assume nothing beyond the 2.0.0 baseline".
const kPeerFeatures = 128

// validateV2MetadataKeys applies the extension rule of protocol-v2.md §2 to a
// type_meta map. Applying the same rule the descriptor already uses keeps one
// convention rather than a second per-payload-type one, and it is what allows a
// later release to add a type_meta field that this release ignores instead of
// rejecting outright.
func validateV2MetadataKeys(keys []int, required, optional []int) error {
	for _, key := range keys {
		if key >= v2MinimumExtensionKey {
			continue
		}
		if !slices.Contains(required, key) && !slices.Contains(optional, key) {
			return fmt.Errorf("metadata key %d is not defined for this payload type", key)
		}
	}
	for _, key := range required {
		if !slices.Contains(keys, key) {
			return fmt.Errorf("metadata is missing key %d", key)
		}
	}
	return nil
}

// v2MetadataFeatures reads the optional peer feature list from a type_meta map.
// An absent, empty, or malformed list yields no features: a sender that cannot
// read a clean advertisement must fall back to the baseline behaviour rather
// than guess, so this never reports an error.
func v2MetadataFeatures(metadata map[int]any) []uint64 {
	raw, ok := metadata[kPeerFeatures].([]any)
	if !ok {
		return nil
	}
	features := make([]uint64, 0, len(raw))
	for _, entry := range raw {
		value, valid := asV2Uint(entry)
		if !valid {
			return nil
		}
		features = append(features, value)
	}
	return features
}

type v2TransportPolicy struct {
	ExpiresAt         uint64 `cbor:"1,keyasint"`
	Consume           uint64 `cbor:"2,keyasint"`
	ClaimLeaseSeconds uint64 `cbor:"3,keyasint"`
	AckMode           uint64 `cbor:"4,keyasint"`
}

type v2Descriptor struct {
	DescriptorID      []byte
	PayloadType       uint64
	RelationshipID    []byte
	Direction         uint64
	Chain             uint64
	KeyEpoch          uint64
	Sequence          uint64
	PreviousDigest    []byte
	SenderDeviceID    []byte
	RecipientDeviceID []byte
	CanonicalOrigin   string
	CreatedAt         uint64
	TransportPolicy   v2TransportPolicy
	PayloadHash       []byte
	ChunkHashes       [][]byte
	DisplayName       string
	ArchiveFormat     *uint64
	PlaintextSize     *uint64
	TypeMetadata      map[int]any
}

type v2DescriptorExpectation struct {
	RelationshipID    []byte
	Direction         uint64
	RecipientDeviceID []byte
	CanonicalOrigin   string
	SigningPublicKey  ed25519.PublicKey
}

type validatedV2Envelope struct {
	Descriptor       map[int]any
	DescriptorBytes  []byte
	DescriptorDigest [32]byte
	Signature        []byte
}

var (
	v2EncMode = mustV2EncMode()
	v2DecMode = mustV2DecMode()
)

func mustV2EncMode() cbor.EncMode {
	mode, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}

func mustV2DecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		MaxNestedLevels:  8,
		MaxArrayElements: 4096,
		MaxMapPairs:      128,
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}

func canonicalV2Origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid origin: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("origin scheme must be https")
	}
	if u.User != nil {
		return "", errors.New("origin userinfo is not permitted")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("origin query and fragment are not permitted")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("origin path is not permitted")
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("origin hostname is empty")
	}
	if strings.HasSuffix(host, ".") {
		return "", errors.New("origin trailing root label is not permitted")
	}
	if net.ParseIP(host) != nil {
		return "", errors.New("origin IP literals are not permitted")
	}
	profile := idna.New(
		idna.MapForLookup(),
		idna.Transitional(false),
		idna.StrictDomainName(true),
		idna.BidiRule(),
		idna.VerifyDNSLength(true),
	)
	host, err = profile.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid origin hostname: %w", err)
	}
	host = strings.ToLower(host)
	if host == "" || !strings.Contains(host, ".") {
		return "", errors.New("origin must contain a fully qualified DNS hostname")
	}
	port := u.Port()
	if port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return "", errors.New("origin port must be between 1 and 65535")
		}
	}
	if port == "443" {
		port = ""
	}
	if port != "" {
		return "https://" + host + ":" + port, nil
	}
	return "https://" + host, nil
}

func deriveV2Material(seed []byte, label string, relationshipID []byte, keyEpoch uint64, size int) ([]byte, error) {
	if len(seed) != 32 {
		return nil, errors.New("master seed must be exactly 32 bytes")
	}
	if len(relationshipID) != 16 {
		return nil, errors.New("relationship ID must be exactly 16 bytes")
	}
	if keyEpoch != 0 {
		return nil, fmt.Errorf("key epoch %d is unsupported in DUD 2.0", keyEpoch)
	}
	info := fmt.Sprintf("dud/v2/%s|%s|%d", label, hex.EncodeToString(relationshipID), keyEpoch)
	return hkdf.Key(sha256.New, seed, nil, info, size)
}

func deriveV2RelationshipIdentity(seed, relationshipID []byte, keyEpoch uint64) (*age.HybridIdentity, error) {
	raw, err := deriveV2Material(seed, "identity", relationshipID, keyEpoch, 32)
	if err != nil {
		return nil, err
	}
	encoded := strings.ToUpper(bech32Encode("age-secret-key-pq-", raw))
	identity, err := age.ParseHybridIdentity(encoded)
	if err != nil {
		return nil, fmt.Errorf("construct hybrid identity: %w", err)
	}
	return identity, nil
}

func deriveV2SigningKey(seed, relationshipID []byte, keyEpoch uint64) (ed25519.PrivateKey, error) {
	raw, err := deriveV2Material(seed, "signing", relationshipID, keyEpoch, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

func deriveV2DeviceID(seed, relationshipID []byte, keyEpoch uint64) ([]byte, error) {
	return deriveV2Material(seed, "deviceid", relationshipID, keyEpoch, 16)
}

func v2SenderKeyID(publicKey ed25519.PublicKey) []byte {
	digest := sha256.Sum256(publicKey)
	return append([]byte(nil), digest[:8]...)
}

func newV2DescriptorID() ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return id, nil
}

func descriptorMap(desc v2Descriptor, signingKey ed25519.PrivateKey) (map[int]any, error) {
	publicKey, ok := signingKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	result := map[int]any{
		kV:                 uint64(v2ProtocolVersion),
		kKEMAlg:            uint64(v2KEMAlgorithm),
		kSigAlg:            uint64(v2SignatureAlgorithm),
		kDescriptorID:      append([]byte(nil), desc.DescriptorID...),
		kPayloadType:       desc.PayloadType,
		kRelationshipID:    append([]byte(nil), desc.RelationshipID...),
		kDirection:         desc.Direction,
		kChain:             desc.Chain,
		kKeyEpoch:          desc.KeyEpoch,
		kSequence:          desc.Sequence,
		kPreviousDigest:    append([]byte(nil), desc.PreviousDigest...),
		kSenderDeviceID:    append([]byte(nil), desc.SenderDeviceID...),
		kSenderKeyID:       v2SenderKeyID(publicKey),
		kRecipientDeviceID: append([]byte(nil), desc.RecipientDeviceID...),
		kCanonicalOrigin:   desc.CanonicalOrigin,
		kCreatedAt:         desc.CreatedAt,
		kTransportPolicy:   desc.TransportPolicy,
		kPayloadHash:       append([]byte(nil), desc.PayloadHash...),
		kChunkHashes:       cloneByteSlices(desc.ChunkHashes),
	}
	if desc.DisplayName != "" {
		result[kDisplayName] = desc.DisplayName
	}
	if desc.ArchiveFormat != nil {
		result[kArchiveFormat] = *desc.ArchiveFormat
	}
	if desc.PlaintextSize != nil {
		result[kPlaintextSize] = *desc.PlaintextSize
	}
	if desc.TypeMetadata != nil {
		result[kTypeMetadata] = desc.TypeMetadata
	}
	if err := validateV2DescriptorMap(result); err != nil {
		return nil, err
	}
	return result, nil
}

func encodeSignedV2Envelope(desc v2Descriptor, signingKey ed25519.PrivateKey) ([]byte, error) {
	descMap, err := descriptorMap(desc, signingKey)
	if err != nil {
		return nil, err
	}
	descBytes, err := v2EncMode.Marshal(descMap)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(descBytes)
	input := append([]byte(v2DescriptorSigPrefix), digest[:]...)
	signature := ed25519.Sign(signingKey, input)
	return v2EncMode.Marshal(map[int]any{1: descMap, 2: signature})
}

func encryptV2Envelope(desc v2Descriptor, signingKey ed25519.PrivateKey, recipient age.Recipient) ([]byte, error) {
	plaintext, err := encodeSignedV2Envelope(desc, signingKey)
	if err != nil {
		return nil, err
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, fmt.Errorf("encrypt descriptor: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypt descriptor: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("encrypt descriptor: %w", err)
	}
	return ciphertext.Bytes(), nil
}

func decryptAndValidateV2Envelope(ciphertext []byte, identity age.Identity, expected v2DescriptorExpectation) (*validatedV2Envelope, error) {
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt descriptor: %w", err)
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, v2MaxDescriptorBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read descriptor: %w", err)
	}
	if len(plaintext) > v2MaxDescriptorBytes {
		return nil, errors.New("descriptor envelope exceeds 262144 bytes")
	}
	return validateSignedV2Envelope(plaintext, expected)
}

func validateSignedV2Envelope(body []byte, expected v2DescriptorExpectation) (*validatedV2Envelope, error) {
	if len(body) > v2MaxDescriptorBytes {
		return nil, errors.New("descriptor envelope exceeds 262144 bytes")
	}
	var envelope map[int]cbor.RawMessage
	if err := v2DecMode.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode descriptor envelope: %w", err)
	}
	if len(envelope) != 2 || envelope[1] == nil || envelope[2] == nil {
		return nil, errors.New("descriptor envelope must contain exactly map keys 1 and 2")
	}
	var signature []byte
	if err := v2DecMode.Unmarshal(envelope[2], &signature); err != nil {
		return nil, fmt.Errorf("decode descriptor signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("descriptor signature must be exactly 64 bytes")
	}
	var desc map[int]any
	if err := v2DecMode.Unmarshal(envelope[1], &desc); err != nil {
		return nil, fmt.Errorf("decode descriptor map: %w", err)
	}
	if err := validateDecodedV2Value(desc, 0); err != nil {
		return nil, err
	}
	if err := validateV2DescriptorMap(desc); err != nil {
		return nil, err
	}
	canonical, err := v2EncMode.Marshal(desc)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, envelope[1]) {
		return nil, errors.New("descriptor map is not deterministic CBOR")
	}
	canonicalEnvelope, err := v2EncMode.Marshal(map[int]any{1: desc, 2: signature})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonicalEnvelope, body) {
		return nil, errors.New("descriptor envelope is not deterministic CBOR")
	}
	if err := validateV2Expectation(desc, expected); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	input := append([]byte(v2DescriptorSigPrefix), digest[:]...)
	if !ed25519.Verify(expected.SigningPublicKey, input, signature) {
		return nil, errors.New("descriptor sender signature is invalid")
	}
	return &validatedV2Envelope{
		Descriptor:       desc,
		DescriptorBytes:  canonical,
		DescriptorDigest: digest,
		Signature:        append([]byte(nil), signature...),
	}, nil
}

func validateV2Expectation(desc map[int]any, expected v2DescriptorExpectation) error {
	if len(expected.SigningPublicKey) != ed25519.PublicKeySize {
		return errors.New("expected signing public key must be exactly 32 bytes")
	}
	checks := []struct {
		key  int
		want []byte
		name string
	}{
		{kRelationshipID, expected.RelationshipID, "relationship"},
		{kRecipientDeviceID, expected.RecipientDeviceID, "recipient"},
		{kSenderKeyID, v2SenderKeyID(expected.SigningPublicKey), "sender key"},
	}
	for _, check := range checks {
		got, ok := desc[check.key].([]byte)
		if !ok || !bytes.Equal(got, check.want) {
			return fmt.Errorf("descriptor %s does not match the peer profile", check.name)
		}
	}
	direction, ok := asV2Uint(desc[kDirection])
	if !ok || direction != expected.Direction {
		return errors.New("descriptor direction does not match the receive direction")
	}
	origin, ok := desc[kCanonicalOrigin].(string)
	if !ok || origin != expected.CanonicalOrigin {
		return errors.New("descriptor origin does not match the peer profile")
	}
	return nil
}

func validateV2DescriptorMap(desc map[int]any) error {
	required := []int{
		kV, kKEMAlg, kSigAlg, kDescriptorID, kPayloadType, kRelationshipID,
		kDirection, kChain, kKeyEpoch, kSequence, kPreviousDigest,
		kSenderDeviceID, kSenderKeyID, kRecipientDeviceID, kCanonicalOrigin,
		kCreatedAt, kTransportPolicy, kPayloadHash, kChunkHashes,
	}
	for _, key := range required {
		if _, ok := desc[key]; !ok {
			return fmt.Errorf("descriptor is missing required core key %d", key)
		}
	}
	critical, err := v2CriticalExtensions(desc[kCriticalExtensions])
	if err != nil {
		return err
	}
	for key := range desc {
		switch {
		case key >= 0 && key <= kTypeMetadata:
		case key == kChunkSize || key == kChunkIDs || key == kIncrementalBase:
			return fmt.Errorf("descriptor uses deferred core key %d, unsupported in DUD 2.0", key)
		case key < 128:
			return fmt.Errorf("descriptor contains unknown core key %d", key)
		case key > 65535:
			return fmt.Errorf("descriptor extension key %d exceeds 65535", key)
		case critical[key]:
			return fmt.Errorf("descriptor uses unsupported critical extension key %d", key)
		}
	}
	if !v2UintEquals(desc[kV], v2ProtocolVersion) {
		return errors.New("descriptor protocol version is not 2")
	}
	if !v2UintEquals(desc[kKEMAlg], v2KEMAlgorithm) {
		return errors.New("descriptor recipient algorithm is unsupported")
	}
	if !v2UintEquals(desc[kSigAlg], v2SignatureAlgorithm) {
		return errors.New("descriptor signature algorithm is unsupported")
	}
	if !v2UintEquals(desc[kKeyEpoch], 0) {
		return errors.New("descriptor key epoch is unsupported in DUD 2.0")
	}
	for _, item := range []struct {
		key    int
		length int
		name   string
	}{
		{kDescriptorID, 16, "descriptor ID"},
		{kRelationshipID, 16, "relationship ID"},
		{kPreviousDigest, 32, "previous digest"},
		{kSenderDeviceID, 16, "sender device ID"},
		{kSenderKeyID, 8, "sender key ID"},
		{kRecipientDeviceID, 16, "recipient device ID"},
		{kPayloadHash, 32, "payload hash"},
	} {
		value, ok := desc[item.key].([]byte)
		if !ok || len(value) != item.length {
			return fmt.Errorf("descriptor %s must be exactly %d bytes", item.name, item.length)
		}
	}
	payloadType, ok := asV2Uint(desc[kPayloadType])
	if !ok || payloadType < 1 || payloadType > 6 {
		return errors.New("descriptor payload type is unsupported")
	}
	direction, ok := asV2Uint(desc[kDirection])
	if !ok || direction > 1 {
		return errors.New("descriptor direction must be 0 or 1")
	}
	chain, ok := asV2Uint(desc[kChain])
	if !ok || chain > 1 {
		return errors.New("descriptor chain must be 0 or 1")
	}
	if (payloadType <= 4 && chain != 0) || (payloadType >= 5 && chain != 1) {
		return errors.New("descriptor payload type is on the wrong chain")
	}
	if payloadType == 4 {
		if _, exists := desc[kTypeMetadata]; !exists {
			return errors.New("Git descriptor is missing type metadata")
		}
		if _, err := decodeV2GitMetadata(desc[kTypeMetadata]); err != nil {
			return err
		}
	}
	sequence, ok := asV2Uint(desc[kSequence])
	if !ok || sequence == 0 {
		return errors.New("descriptor sequence must be a positive integer")
	}
	if _, ok := asV2Uint(desc[kCreatedAt]); !ok {
		return errors.New("descriptor created_at must be an unsigned integer")
	}
	origin, ok := desc[kCanonicalOrigin].(string)
	if !ok {
		return errors.New("descriptor canonical origin must be text")
	}
	normalized, err := canonicalV2Origin(origin)
	if err != nil || normalized != origin {
		return errors.New("descriptor canonical origin is not canonical")
	}
	if err := validateV2TransportPolicy(desc[kTransportPolicy]); err != nil {
		return err
	}
	chunks, ok := desc[kChunkHashes].([]any)
	if !ok {
		// Values constructed in Go are often [][]byte until a round trip.
		if typed, typedOK := desc[kChunkHashes].([][]byte); typedOK {
			chunks = make([]any, len(typed))
			for i := range typed {
				chunks[i] = typed[i]
			}
		} else {
			return errors.New("descriptor chunk_hashes must be an array")
		}
	}
	if len(chunks) != 1 {
		return errors.New("DUD 2.0 descriptors must contain exactly one chunk hash")
	}
	hash, ok := chunks[0].([]byte)
	if !ok || len(hash) != 32 {
		return errors.New("descriptor chunk hash must be exactly 32 bytes")
	}
	if value, ok := desc[kDisplayName]; ok {
		name, ok := value.(string)
		if !ok || name == "" {
			return errors.New("descriptor display name must be non-empty text")
		}
	}
	return nil
}

func validateV2TransportPolicy(value any) error {
	encoded, err := v2EncMode.Marshal(value)
	if err != nil {
		return errors.New("descriptor transport policy is invalid")
	}
	var policyMap map[int]any
	if err := v2DecMode.Unmarshal(encoded, &policyMap); err != nil {
		return errors.New("descriptor transport policy is invalid")
	}
	for _, key := range []int{1, 2, 3, 4} {
		if _, exists := policyMap[key]; !exists {
			return fmt.Errorf("descriptor transport policy is missing key %d", key)
		}
	}
	critical, err := v2CriticalExtensions(policyMap[0])
	if err != nil {
		return fmt.Errorf("descriptor transport policy: %w", err)
	}
	for key := range policyMap {
		switch {
		case key >= 0 && key <= 4:
		case key < 128:
			return fmt.Errorf("descriptor transport policy has unknown core key %d", key)
		case key > 65535:
			return fmt.Errorf("descriptor transport policy extension key %d exceeds 65535", key)
		case critical[key]:
			return fmt.Errorf("descriptor transport policy has unsupported critical extension key %d", key)
		}
	}
	expiresAt, ok := asV2Uint(policyMap[1])
	if !ok || expiresAt == 0 {
		return errors.New("descriptor transport policy expiry must be non-zero")
	}
	consume, ok := asV2Uint(policyMap[2])
	if !ok || consume > 2 {
		return errors.New("descriptor consume policy is unsupported")
	}
	claimLease, ok := asV2Uint(policyMap[3])
	if !ok || claimLease == 0 {
		return errors.New("descriptor claim lease must be non-zero")
	}
	ackMode, ok := asV2Uint(policyMap[4])
	if !ok || ackMode > 1 {
		return errors.New("descriptor acknowledgement mode is unsupported")
	}
	return nil
}

func v2CriticalExtensions(raw any) (map[int]bool, error) {
	result := map[int]bool{}
	if raw == nil {
		return result, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, errors.New("critical_extensions must be an array")
	}
	for _, item := range values {
		value, ok := asV2Uint(item)
		if !ok || value < 128 || value > 65535 {
			return nil, errors.New("critical extension keys must be unique integers from 128 through 65535")
		}
		key := int(value)
		if result[key] {
			return nil, fmt.Errorf("duplicate critical extension key %d", key)
		}
		result[key] = true
	}
	return result, nil
}

func validateDecodedV2Value(value any, depth int) error {
	if depth > 8 {
		return errors.New("CBOR nesting exceeds 8 levels")
	}
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return nil
	}
	switch rv.Kind() {
	case reflect.String:
		if len(rv.String()) > v2MaxTextOrBytes {
			return errors.New("CBOR text string exceeds 65536 bytes")
		}
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			if rv.Len() > v2MaxTextOrBytes {
				return errors.New("CBOR byte string exceeds 65536 bytes")
			}
			return nil
		}
		for i := 0; i < rv.Len(); i++ {
			if err := validateDecodedV2Value(rv.Index(i).Interface(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := rv.MapRange()
		for iter.Next() {
			if err := validateDecodedV2Value(iter.Key().Interface(), depth+1); err != nil {
				return err
			}
			if err := validateDecodedV2Value(iter.Value().Interface(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func asV2Uint(value any) (uint64, bool) {
	switch number := value.(type) {
	case uint64:
		return number, true
	case uint32:
		return uint64(number), true
	case uint:
		return uint64(number), true
	case int:
		if number >= 0 {
			return uint64(number), true
		}
	}
	return 0, false
}

func v2UintEquals(value any, expected uint64) bool {
	actual, ok := asV2Uint(value)
	return ok && actual == expected
}

func cloneByteSlices(input [][]byte) [][]byte {
	output := make([][]byte, len(input))
	for i := range input {
		output[i] = append([]byte(nil), input[i]...)
	}
	return output
}

// BIP-173 Bech32 encoding is used only to construct the exact age hybrid
// identity string from 32 seed-derived bytes.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Encode(hrp string, data []byte) string {
	values := convertBech32Bits(data, 8, 5, true)
	checksumInput := append(append(bech32HRPExpand(hrp), values...), 0, 0, 0, 0, 0, 0)
	checksum := bech32Polymod(checksumInput) ^ 1
	var result strings.Builder
	result.WriteString(hrp)
	result.WriteByte('1')
	for _, value := range values {
		result.WriteByte(bech32Charset[value])
	}
	for i := 0; i < 6; i++ {
		result.WriteByte(bech32Charset[(checksum>>uint(5*(5-i)))&31])
	}
	return result.String()
}

func bech32Polymod(values []byte) uint32 {
	generators := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				checksum ^= generators[i]
			}
		}
	}
	return checksum
}

func bech32HRPExpand(hrp string) []byte {
	result := make([]byte, 0, len(hrp)*2+1)
	for _, value := range []byte(hrp) {
		result = append(result, value>>5)
	}
	result = append(result, 0)
	for _, value := range []byte(hrp) {
		result = append(result, value&31)
	}
	return result
}

func convertBech32Bits(data []byte, from, to uint, pad bool) []byte {
	var accumulator, bits uint
	result := make([]byte, 0, (len(data)*8+4)/5)
	maxValue := byte(1<<to - 1)
	for _, value := range data {
		accumulator = accumulator<<from | uint(value)
		bits += from
		for bits >= to {
			bits -= to
			result = append(result, byte(accumulator>>bits)&maxValue)
		}
	}
	if pad && bits > 0 {
		result = append(result, byte(accumulator<<(to-bits))&maxValue)
	}
	return result
}
