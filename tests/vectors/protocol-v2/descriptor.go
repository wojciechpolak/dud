// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/net/idna"
)

// Descriptor map keys. Integer keys keep the encoding compact and make
// deterministic ordering unambiguous: RFC 8949 4.2 sorts by encoded key bytes,
// which for small unsigned integers is numeric order.
const (
	kCriticalExtensions = 0  // array of extension keys that are mandatory
	kV                  = 1  // uint, protocol version
	kKemAlg             = 2  // uint
	kSigAlg             = 3  // uint
	kDescriptorID       = 4  // bytes(16)
	kPayloadType        = 5  // uint
	kRelationshipID     = 6  // bytes(16)
	kDirection          = 7  // uint, 0 = inviter->invitee, 1 = invitee->inviter
	kChain              = 8  // uint, 0 = data, 1 = control
	kKeyEpoch           = 9  // uint
	kSeq                = 10 // uint
	kPrevDigest         = 11 // bytes(32)
	kSenderDeviceID     = 12 // bytes(16)
	kSenderKeyID        = 13 // bytes(8)
	kRecipientDevID     = 14 // bytes(16)
	kCanonicalOrigin    = 15 // text
	kCreatedAt          = 16 // uint
	kTransportPolicy    = 17 // map, signed requested transport policy
	kPayloadHash        = 18 // bytes(32)
	kChunkHashes        = 19 // array of bytes(32)
	kDisplayName        = 20 // text, optional
	kArchiveFormat      = 21 // uint, optional: 0 none, 1 tar
	kPlaintextSize      = 22 // uint, optional
	kTypeMeta           = 23 // map, optional, payload-type specific
	kChunkSize          = 24 // uint, PRESENCE MEANS CHUNKED -> 2.0.0 rejects
	kChunkIDs           = 25 // array, PRESENCE MEANS CHUNKED -> 2.0.0 rejects
	kIncrementalBase    = 26 // bytes, PRESENCE MEANS INCREMENTAL GIT -> 2.0.0 rejects
)

// transportPolicy is the canonical structure whose digest the descriptor binds
// and whose values the server echoes in commit metadata.
type transportPolicy struct {
	ExpiresAt         uint64 `cbor:"1,keyasint"`
	Consume           uint64 `cbor:"2,keyasint"` // 0 none, 1 delete-after-read, 2 strict
	ClaimLeaseSeconds uint64 `cbor:"3,keyasint"`
	AckMode           uint64 `cbor:"4,keyasint"` // 0 none, 1 after output commit
}

func detEnc() cbor.EncMode {
	em, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	must(err)
	return em
}

// strictDec enforces structural allocation limits. decodeDescriptor adds the
// total-size and post-decode string limits required by protocol section 3.
func strictDec() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		MaxNestedLevels:  8,
		MaxArrayElements: 4096,
		MaxMapPairs:      128,
	}.DecMode()
	must(err)
	return dm
}

func validateDecodedValue(v any, depth int) error {
	if depth > 8 {
		return fmt.Errorf("nesting exceeds 8")
	}
	switch x := v.(type) {
	case string:
		if len(x) > 65536 {
			return fmt.Errorf("text string exceeds 65536 bytes")
		}
	case []any:
		for _, item := range x {
			if err := validateDecodedValue(item, depth+1); err != nil {
				return err
			}
		}
	case map[any]any:
		for key, value := range x {
			if err := validateDecodedValue(key, depth+1); err != nil {
				return err
			}
			if err := validateDecodedValue(value, depth+1); err != nil {
				return err
			}
		}
	case map[int]any:
		for _, value := range x {
			if err := validateDecodedValue(value, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func criticalExtensionSet(raw any) (map[int]bool, error) {
	out := map[int]bool{}
	if raw == nil {
		return out, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("critical_extensions must be an array")
	}
	for _, value := range values {
		var key int
		switch n := value.(type) {
		case uint64:
			key = int(n)
		case int:
			key = n
		default:
			return nil, fmt.Errorf("critical extension key must be uint")
		}
		if key < 128 || key > 65535 {
			return nil, fmt.Errorf("critical extension key %d is outside 128..65535", key)
		}
		if out[key] {
			return nil, fmt.Errorf("duplicate critical extension key %d", key)
		}
		out[key] = true
	}
	return out, nil
}

func validateDescriptorMap(desc map[int]any) error {
	critical, err := criticalExtensionSet(desc[kCriticalExtensions])
	if err != nil {
		return err
	}
	switch epoch := desc[kKeyEpoch].(type) {
	case int:
		if epoch != 0 {
			return fmt.Errorf("key_epoch %d is unsupported in 2.0", epoch)
		}
	case uint64:
		if epoch != 0 {
			return fmt.Errorf("key_epoch %d is unsupported in 2.0", epoch)
		}
	default:
		return fmt.Errorf("key_epoch must be uint")
	}
	for key := range desc {
		switch {
		case key == kCriticalExtensions:
		case key >= kV && key <= kTypeMeta:
		case key == kChunkSize || key == kChunkIDs || key == kIncrementalBase:
			return fmt.Errorf("deferred core key %d is unsupported in 2.0", key)
		case key < 128:
			return fmt.Errorf("unknown core key %d", key)
		case key > 65535:
			return fmt.Errorf("extension key %d exceeds 65535", key)
		case critical[key]:
			return fmt.Errorf("unsupported critical extension key %d", key)
		}
	}
	return nil
}

func decodeDescriptor(body []byte) (map[int]any, error) {
	if len(body) > 262144 {
		return nil, fmt.Errorf("descriptor exceeds 262144 bytes")
	}
	var desc map[int]any
	if err := strictDec().Unmarshal(body, &desc); err != nil {
		return nil, err
	}
	if err := validateDecodedValue(desc, 0); err != nil {
		return nil, err
	}
	if err := validateDescriptorMap(desc); err != nil {
		return nil, err
	}
	return desc, nil
}

// canonicalOrigin normalizes an origin for binding. Two implementations that
// normalize differently would silently fail to interoperate, so the rules are
// fixed here and exercised by a vector.
func canonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("scheme must be https, got %q", u.Scheme)
	}
	if u.User != nil {
		return "", fmt.Errorf("userinfo not permitted")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("query and fragment not permitted")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("path not permitted")
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if strings.HasSuffix(host, ".") {
		return "", fmt.Errorf("trailing root label not permitted")
	}
	// Reject IP literals: an origin must be a DNS hostname.
	if strings.Count(host, ":") > 0 || isAllDigitsAndDots(host) {
		return "", fmt.Errorf("IP literal not permitted")
	}
	idnaProfile := idna.New(
		idna.MapForLookup(),
		idna.Transitional(false),
		idna.BidiRule(),
		idna.VerifyDNSLength(true),
	)
	host, err = idnaProfile.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid IDNA hostname: %w", err)
	}
	host = strings.ToLower(host)
	port := u.Port()
	if port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return "", fmt.Errorf("port must be 1..65535")
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

func isAllDigitsAndDots(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return len(s) > 0
}

func descriptorVectors() {
	em := detEnc()

	fmt.Printf("\n### Vector 6 — canonical origin normalization (deterministic)\n")
	for _, in := range []string{
		"https://DUD.Example.COM",
		"https://dud.example.com:443/",
		"https://dud.example.com:8443",
		"https://bücher.example",
	} {
		out, err := canonicalOrigin(in)
		must(err)
		fmt.Printf("%-32s -> %s\n", in, out)
	}
	for _, bad := range []string{
		"http://dud.example.com",
		"https://u:p@dud.example.com",
		"https://dud.example.com/v2",
		"https://192.0.2.1",
		"https://dud.example.com?x=1",
		"https://dud.example.com.",
		"https://dud.example.com:65536",
	} {
		_, err := canonicalOrigin(bad)
		fmt.Printf("%-32s -> REJECT (%v)\n", bad, err)
	}

	// --- transport policy
	pol := transportPolicy{
		ExpiresAt:         1800000000,
		Consume:           1,
		ClaimLeaseSeconds: 300,
		AckMode:           1,
	}
	polBytes, err := em.Marshal(pol)
	must(err)
	polDigest := sha256.Sum256(polBytes)
	fmt.Printf("\n### Vector 7 — transport policy digest (deterministic)\n")
	fmt.Printf("policy{expires_at=%d, consume=%d, claim_lease_seconds=%d, ack_mode=%d}\n",
		pol.ExpiresAt, pol.Consume, pol.ClaimLeaseSeconds, pol.AckMode)
	fmt.Printf("policy_cbor   = %s\n", h(polBytes))
	fmt.Printf("policy_digest = %s\n", h(polDigest[:]))

	// --- descriptor
	origin, err := canonicalOrigin("https://dud.example.com")
	must(err)

	// Deterministic signing key for the vector. sender_key_id is defined from
	// this public key, so construct it before the descriptor.
	signSeed := fixedBytes(0x90, 32)
	priv := ed25519.NewKeyFromSeed(signSeed)
	signPublic := priv.Public().(ed25519.PublicKey)
	signPublicDigest := sha256.Sum256(signPublic)

	desc := map[int]any{
		kV:               2,
		kKemAlg:          1,
		kSigAlg:          1,
		kDescriptorID:    fixedBytes(0x10, 16),
		kPayloadType:     2, // file
		kRelationshipID:  fixedBytes(0x20, 16),
		kDirection:       0,
		kChain:           0,
		kKeyEpoch:        0,
		kSeq:             7,
		kPrevDigest:      fixedBytes(0x30, 32),
		kSenderDeviceID:  fixedBytes(0x40, 16),
		kSenderKeyID:     signPublicDigest[:8],
		kRecipientDevID:  fixedBytes(0x60, 16),
		kCanonicalOrigin: origin,
		kCreatedAt:       1799999000,
		kTransportPolicy: pol,
		kPayloadHash:     fixedBytes(0x70, 32),
		kChunkHashes:     []any{fixedBytes(0x80, 32)},
		kDisplayName:     "report.pdf",
		kArchiveFormat:   0,
		kPlaintextSize:   4096,
	}

	body, err := em.Marshal(desc)
	must(err)
	bodyDigest := sha256.Sum256(body)

	// Signature input: a domain-separated prefix over the digest of the
	// deterministic encoding. Everything bound is a field, so there is no
	// concatenation format to get wrong.
	sigInput := append([]byte("dud/v2/descriptor\x00"), bodyDigest[:]...)

	sig := ed25519.Sign(priv, sigInput)

	fmt.Printf("\n### Vector 8 — descriptor encoding and signature (deterministic)\n")
	fmt.Printf("descriptor_cbor_len = %d bytes\n", len(body))
	fmt.Printf("descriptor_cbor     = %s\n", h(body))
	fmt.Printf("descriptor_digest   = %s\n", h(bodyDigest[:]))
	fmt.Printf("sig_input           = \"dud/v2/descriptor\" || 0x00 || descriptor_digest\n")
	fmt.Printf("signing_seed        = %s\n", h(signSeed))
	fmt.Printf("signing_public_key  = %s\n", h(signPublic))
	fmt.Printf("sender_key_id       = %s\n", h(signPublicDigest[:8]))
	fmt.Printf("signature           = %s\n", h(sig))

	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), sigInput, sig) {
		panic("signature does not verify")
	}
	fmt.Println("PASS: signature verifies")
	if !bytes.Equal(desc[kSenderKeyID].([]byte), signPublicDigest[:8]) {
		panic("sender_key_id does not match signing_public_key")
	}
	fmt.Println("PASS: sender_key_id matches signing_public_key")

	// Deterministic encoding must be stable across re-encode.
	again, err := em.Marshal(desc)
	must(err)
	if h(again) != h(body) {
		panic("encoding not deterministic")
	}
	fmt.Println("PASS: encoding is stable across re-encode")

	// Strict decoder must accept our own output.
	round, err := decodeDescriptor(body)
	must(err)
	fmt.Printf("PASS: strict decoder accepts (%d fields)\n", len(round))

	// --- 2.0.0 rejection rules
	fmt.Printf("\n### Vector 9 — fields a 2.0.0 receiver must reject (deterministic)\n")
	for _, deferred := range []struct {
		name string
		key  int
	}{
		{name: "chunk_size", key: kChunkSize},
		{name: "chunk_ids", key: kChunkIDs},
		{name: "incremental_base", key: kIncrementalBase},
	} {
		d2 := map[int]any{}
		for k, v := range desc {
			d2[k] = v
		}
		d2[deferred.key] = 1
		b2, err := em.Marshal(d2)
		must(err)
		dg := sha256.Sum256(b2)
		fmt.Printf("key %2d (%-16s) present -> REJECT; digest %s\n",
			deferred.key, deferred.name, h(dg[:])[:32])
	}
	fmt.Println("A 2.0.0 receiver rejects on presence of any of keys 24, 25, 26.")
	d2 := map[int]any{}
	for k, value := range desc {
		d2[k] = value
	}
	d2[kKeyEpoch] = uint64(1)
	fmt.Printf("key_epoch=1 -> REJECT (%v)\n", validateDescriptorMap(d2))

	fmt.Printf("\n### Vector 10 — extension criticality (deterministic)\n")
	for _, tc := range []struct {
		name string
		key  int
		crit []any
	}{
		{name: "unknown core", key: 27},
		{name: "unknown optional extension", key: 128},
		{name: "unknown critical extension", key: 128, crit: []any{uint64(128)}},
	} {
		d2 := map[int]any{}
		for k, value := range desc {
			d2[k] = value
		}
		d2[tc.key] = uint64(1)
		if tc.crit != nil {
			d2[kCriticalExtensions] = tc.crit
		}
		err := validateDescriptorMap(d2)
		if tc.name == "unknown optional extension" && err == nil {
			fmt.Printf("%-28s -> IGNORE\n", tc.name)
		} else {
			fmt.Printf("%-28s -> REJECT (%v)\n", tc.name, err)
		}
	}

	// --- capability
	fmt.Printf("\n### Vector 12 — capability discovery response (deterministic)\n")
	capabilities := map[int]any{
		1: []uint64{1, 2},
		2: []uint64{1, 2, 3, 4, 5},
		3: map[int]uint64{
			1: 104857600,
			2: 262144,
			3: 2592000,
			4: 64,
			5: 256,
			6: 4,
			7: 60,
			8: 209715200,
			9: 4096,
		},
		4: map[int]uint64{1: 2, 2: 1},
	}
	capabilitiesCBOR, err := em.Marshal(capabilities)
	must(err)
	capabilitiesDigest := sha256.Sum256(capabilitiesCBOR)
	fmt.Printf("capabilities_cbor   = %s\n", h(capabilitiesCBOR))
	fmt.Printf("capabilities_digest = %s\n", h(capabilitiesDigest[:]))

}
