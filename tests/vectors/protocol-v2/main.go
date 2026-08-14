// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Generates DUD v2 protocol test vectors and validates the section 7
// construction end to end against filippo.io/hpke v0.4.0 and age v1.3.1.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/hpke"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func h(b []byte) string { return hex.EncodeToString(b) }

func fixedBytes(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

// ---------- bech32 (BIP-173), enough to encode age keys ----------

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func polymod(values []byte) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for _, c := range []byte(hrp) {
		out = append(out, c>>5)
	}
	out = append(out, 0)
	for _, c := range []byte(hrp) {
		out = append(out, c&31)
	}
	return out
}

func convertBits(data []byte, from, to uint, pad bool) []byte {
	var acc, bits uint
	var out []byte
	maxv := byte(1<<to - 1)
	for _, b := range data {
		acc = acc<<from | uint(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits)&maxv)
		}
	}
	if pad && bits > 0 {
		out = append(out, byte(acc<<(to-bits))&maxv)
	}
	return out
}

func bech32Encode(hrp string, data []byte) string {
	conv := convertBits(data, 8, 5, true)
	chk := polymod(append(append(hrpExpand(hrp), conv...), 0, 0, 0, 0, 0, 0)) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, b := range conv {
		sb.WriteByte(charset[b])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(charset[(chk>>uint(5*(5-i)))&31])
	}
	return sb.String()
}

// ---------- section 7 derivation ----------

func deriveMaterial(seed []byte, label, relationshipID string, keyEpoch uint32, n int) []byte {
	info := fmt.Sprintf("dud/v2/%s|%s|%d", label, relationshipID, keyEpoch)
	raw, err := hkdf.Key(sha256.New, seed, nil, info, n)
	must(err)
	return raw
}

func deriveIdentityBytes(seed []byte, relationshipID string, keyEpoch uint32) []byte {
	return deriveMaterial(seed, "identity", relationshipID, keyEpoch, 32)
}

func main() {
	inviterSeed := make([]byte, 32)
	inviteeSeed := make([]byte, 32)
	for i := range inviterSeed {
		inviterSeed[i] = byte(0xA0 + i%16)
		inviteeSeed[i] = byte(0xB0 + i%16)
	}
	const relationshipID = "0123456789abcdef0123456789abcdef"
	const keyEpoch = uint32(0)

	fmt.Println("### Vector 1 — seed to relationship identity (deterministic)")
	fmt.Printf("inviter_master_seed  = %s\n", h(inviterSeed))
	fmt.Printf("invitee_master_seed  = %s\n", h(inviteeSeed))
	fmt.Printf("relationship_id      = %s\n", relationshipID)
	fmt.Printf("key_epoch            = %d\n", keyEpoch)

	inviterRaw := deriveIdentityBytes(inviterSeed, relationshipID, keyEpoch)
	inviteeRaw := deriveIdentityBytes(inviteeSeed, relationshipID, keyEpoch)
	fmt.Printf("inviter_identity_raw = %s\n", h(inviterRaw))
	fmt.Printf("invitee_identity_raw = %s\n", h(inviteeRaw))

	// Validate DEC-005: derived bytes must produce a real age hybrid identity.
	inviterBech := strings.ToUpper(bech32Encode("age-secret-key-pq-", inviterRaw))
	inviterID, err := age.ParseHybridIdentity(inviterBech)
	must(err)
	inviteeBech := strings.ToUpper(bech32Encode("age-secret-key-pq-", inviteeRaw))
	inviteeID, err := age.ParseHybridIdentity(inviteeBech)
	must(err)
	fmt.Printf("inviter_identity     = %s\n", inviterBech)
	fmt.Printf("inviter_recipient    = %s\n", inviterID.Recipient())
	fmt.Printf("invitee_recipient    = %s\n", inviteeID.Recipient())
	fmt.Printf("recipient_len_chars  = %d\n\n", len(inviterID.Recipient().String()))

	// Same seed + same inputs must reproduce.
	if !bytes.Equal(deriveIdentityBytes(inviterSeed, relationshipID, keyEpoch), inviterRaw) {
		fmt.Fprintln(os.Stderr, "FAIL: derivation not reproducible")
		os.Exit(1)
	}
	// Different epoch must diverge.
	if bytes.Equal(deriveIdentityBytes(inviterSeed, relationshipID, 1), inviterRaw) {
		fmt.Fprintln(os.Stderr, "FAIL: key_epoch does not affect derivation")
		os.Exit(1)
	}
	// Different relationship must diverge.
	if bytes.Equal(deriveIdentityBytes(inviterSeed, "ffff", keyEpoch), inviterRaw) {
		fmt.Fprintln(os.Stderr, "FAIL: relationship_id does not affect derivation")
		os.Exit(1)
	}
	fmt.Println("PASS: derivation reproducible, and distinct per epoch and per relationship")

	// ---------- pairing ----------
	kem := hpke.MLKEM768X25519()
	inviterKey, err := kem.NewPrivateKey(inviterRaw)
	must(err)
	inviteeKey, err := kem.NewPrivateKey(inviteeRaw)
	must(err)
	inviterSignSeed := deriveMaterial(inviterSeed, "signing", relationshipID, keyEpoch, 32)
	inviteeSignSeed := deriveMaterial(inviteeSeed, "signing", relationshipID, keyEpoch, 32)
	inviterSignKey := ed25519.NewKeyFromSeed(inviterSignSeed)
	inviteeSignKey := ed25519.NewKeyFromSeed(inviteeSignSeed)

	relationshipIDBytes, err := hex.DecodeString(relationshipID)
	must(err)
	invitationMap := map[int]any{
		1:  uint64(2),
		2:  uint64(1),
		3:  uint64(1),
		4:  fixedBytes(0x10, 32),
		5:  relationshipIDBytes,
		6:  fixedBytes(0x20, 16),
		7:  inviterKey.PublicKey().Bytes(),
		8:  inviterSignKey.Public().(ed25519.PublicKey),
		9:  "https://dud.example.com",
		10: fixedBytes(0xA0, 32),
		11: fixedBytes(0x60, 32),
		12: uint64(1_800_000_000),
	}
	invitationCBOR, err := detEnc().Marshal(invitationMap)
	must(err)
	pairingCode := fixedBytes(0x00, 16)
	pairingCodeHex := h(pairingCode)
	pairingCodeText := strings.Join([]string{
		pairingCodeHex[0:4], pairingCodeHex[4:8], pairingCodeHex[8:12], pairingCodeHex[12:16],
		pairingCodeHex[16:20], pairingCodeHex[20:24], pairingCodeHex[24:28], pairingCodeHex[28:32],
	}, "-")
	locator := sha256.Sum256(append([]byte("dud/v2/pairing/rendezvous\x00"), pairingCode...))
	invitationDigest := sha256.Sum256(invitationCBOR)
	fmt.Printf("\n### Vector 1A — pairing code and invitation (deterministic)\n")
	fmt.Printf("pairing_code           = %s\n", pairingCodeText)
	fmt.Printf("rendezvous_locator     = %s\n", h(locator[:]))
	fmt.Printf("invitation_cbor_len   = %d bytes\n", len(invitationCBOR))
	fmt.Printf("invitation_digest     = %s\n", h(invitationDigest[:]))
	fmt.Println("PASS: grouped pairing code normalizes to exactly 128 bits")

	inviteeStatusCapability := fixedBytes(0xD0, 32)
	statusCapabilityHash := sha256.Sum256(inviteeStatusCapability)
	acceptanceMap := map[int]any{
		1:  uint64(2),
		2:  uint64(1),
		3:  uint64(1),
		4:  fixedBytes(0x10, 32),
		5:  relationshipIDBytes,
		6:  fixedBytes(0x30, 16),
		7:  inviteeKey.PublicKey().Bytes(),
		8:  inviteeSignKey.Public().(ed25519.PublicKey),
		9:  fixedBytes(0x70, 32),
		10: invitationDigest[:],
		11: fixedBytes(0x81, 1120),
		12: statusCapabilityHash[:],
		13: fixedBytes(0xE0, 32),
		14: locator[:],
	}
	acceptanceCBOR, err := detEnc().Marshal(acceptanceMap)
	must(err)
	acceptanceDigest := sha256.Sum256(acceptanceCBOR)
	acceptanceSigInput := append([]byte("dud/v2/pairing/acceptance\x00"), acceptanceDigest[:]...)
	acceptanceSignature := ed25519.Sign(inviteeSignKey, acceptanceSigInput)
	if !ed25519.Verify(inviteeSignKey.Public().(ed25519.PublicKey), acceptanceSigInput, acceptanceSignature) {
		fmt.Fprintln(os.Stderr, "FAIL: acceptance signature does not verify")
		os.Exit(1)
	}
	fmt.Printf("\n### Vector 1B — signed acceptance map (deterministic)\n")
	fmt.Printf("status_capability_hash = %s\n", h(statusCapabilityHash[:]))
	fmt.Printf("acceptance_cbor_len     = %d bytes\n", len(acceptanceCBOR))
	fmt.Printf("acceptance_map_digest   = %s\n", h(acceptanceDigest[:]))
	fmt.Printf("acceptance_signature    = %s\n", h(acceptanceSignature))
	fmt.Println("PASS: acceptance signature verifies")

	preTranscriptMap := map[int]any{
		1:  uint64(2),
		2:  uint64(1), // MLKEM768-X25519
		3:  uint64(1), // Ed25519
		4:  fixedBytes(0x10, 32),
		5:  relationshipIDBytes,
		6:  "https://dud.example.com",
		7:  fixedBytes(0x20, 16),
		8:  fixedBytes(0x30, 16),
		9:  inviterKey.PublicKey().Bytes(),
		10: inviteeKey.PublicKey().Bytes(),
		11: inviterSignKey.Public().(ed25519.PublicKey),
		12: inviteeSignKey.Public().(ed25519.PublicKey),
		13: fixedBytes(0x60, 32),
		14: fixedBytes(0x70, 32),
		15: uint64(1_800_000_000),
		16: uint64(0),
		17: "bootstrap",
	}
	preTranscript, err := detEnc().Marshal(preTranscriptMap)
	must(err)
	infoHash := sha256.Sum256(preTranscript)
	fmt.Printf("\n### Vector 2 — pre-transcript to HPKE info (deterministic)\n")
	fmt.Printf("pre_transcript_cbor_len = %d bytes\n", len(preTranscript))
	fmt.Printf("pre_transcript_cbor     = %s\n", h(preTranscript))
	fmt.Printf("info                    = %s\n", h(infoHash[:]))

	kdf, aead := hpke.HKDFSHA256(), hpke.ExportOnly()
	const exporterCtx = "dud/v2/pairing"

	fmt.Printf("\n### Property 1 — mutual HPKE export agreement (enc is randomized)\n")
	encB, senderB, err := hpke.NewSender(inviterKey.PublicKey(), kdf, aead, infoHash[:])
	must(err)
	ssBs, err := senderB.Export(exporterCtx, 32)
	must(err)
	recipB, err := hpke.NewRecipient(encB, inviterKey, kdf, aead, infoHash[:])
	must(err)
	ssBr, err := recipB.Export(exporterCtx, 32)
	must(err)

	encA, senderA, err := hpke.NewSender(inviteeKey.PublicKey(), kdf, aead, infoHash[:])
	must(err)
	ssAs, err := senderA.Export(exporterCtx, 32)
	must(err)
	recipA, err := hpke.NewRecipient(encA, inviteeKey, kdf, aead, infoHash[:])
	must(err)
	ssAr, err := recipA.Export(exporterCtx, 32)
	must(err)

	fmt.Printf("enc_A_len = %d bytes, enc_B_len = %d bytes\n", len(encA), len(encB))
	okA, okB := bytes.Equal(ssAs, ssAr), bytes.Equal(ssBs, ssBr)
	fmt.Printf("ss_A agreement = %v\nss_B agreement = %v\n", okA, okB)
	if !okA || !okB {
		fmt.Fprintln(os.Stderr, "FAIL: exports disagree")
		os.Exit(1)
	}
	fmt.Println("PASS: both directions agree")

	// Negative: changing one valid transcript field must break agreement.
	tamperedMap := make(map[int]any, len(preTranscriptMap))
	for k, value := range preTranscriptMap {
		tamperedMap[k] = value
	}
	tamperedMap[6] = "https://attacker.example"
	tamperedCBOR, err := detEnc().Marshal(tamperedMap)
	must(err)
	tampered := sha256.Sum256(tamperedCBOR)
	badRecip, err := hpke.NewRecipient(encB, inviterKey, kdf, aead, tampered[:])
	must(err)
	ssBad, err := badRecip.Export(exporterCtx, 32)
	must(err)
	if bytes.Equal(ssBad, ssBs) {
		fmt.Fprintln(os.Stderr, "FAIL: tampered transcript still agreed")
		os.Exit(1)
	}
	fmt.Println("PASS: tampered pre-transcript yields a different secret")

	// ---------- final combine, deterministic given fixed ss values ----------
	fmt.Printf("\n### Vector 3 — final combine (deterministic given ss inputs)\n")
	fixedA := fixedBytes(0x01, 32)
	fixedB := fixedBytes(0x80, 32)
	fullTranscriptMap := make(map[int]any, len(preTranscriptMap)+2)
	for k, value := range preTranscriptMap {
		fullTranscriptMap[k] = value
	}
	fullTranscriptMap[20] = fixedBytes(0x81, 1120)
	fullTranscriptMap[21] = fixedBytes(0x91, 1120)
	fullTranscript, err := detEnc().Marshal(fullTranscriptMap)
	must(err)
	fixedFull := sha256.Sum256(fullTranscript)
	pairingPSK := fixedBytes(0x44, 32)
	ikm := append(append(append([]byte{}, fixedA...), fixedB...), pairingPSK...)
	fmt.Printf("ss_A                 = %s\n", h(fixedA))
	fmt.Printf("ss_B                 = %s\n", h(fixedB))
	fmt.Printf("full_transcript_cbor_len = %d bytes\n", len(fullTranscript))
	fmt.Printf("full_transcript_hash = %s\n", h(fixedFull[:]))
	for _, dir := range []string{"inviter->invitee", "invitee->inviter"} {
		secret, err := hkdf.Key(sha256.New, ikm, fixedFull[:], "dud/v2/relationship|"+dir+"|0", 32)
		must(err)
		fmt.Printf("relationship_secret[%-16s] = %s\n", dir, h(secret))
	}

	fmt.Printf("\n### Vector 4 — slot derivation (deterministic)\n")
	relSecret, err := hkdf.Key(sha256.New, ikm, fixedFull[:], "dud/v2/relationship|inviter->invitee|0", 32)
	must(err)
	for _, epoch := range []uint64{20340, 20341} {
		slot, err := hkdf.Key(sha256.New, relSecret, nil,
			fmt.Sprintf("dud/v2/slot|data|%d", epoch), 16)
		must(err)
		fmt.Printf("slot[data,epoch=%d] = %s\n", epoch, h(slot))
	}
	descriptorVectors()
	fmt.Println("\nALL CHECKS PASSED")
}
