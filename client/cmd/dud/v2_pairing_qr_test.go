// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// maximumV2TestOrigin returns the longest canonical origin the protocol
// accepts: a 253-character DNS name plus the highest port. Every invitation
// field except the origin is fixed size, so this is the largest invitation a
// deployment can produce.
func maximumV2TestOrigin(t *testing.T) string {
	t.Helper()
	host := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	if len(host) != 253 {
		t.Fatalf("maximum host length = %d", len(host))
	}
	origin, err := canonicalV2Origin("https://" + host + ":65535")
	if err != nil {
		t.Fatal(err)
	}
	return origin
}

// installV2TestQREncoder installs a qrencode stand-in that records the exact
// payload it was asked to render, so a test can compare what a scanner would
// read with what the terminal and JSON output display.
func installV2TestQREncoder(t *testing.T, a *app) string {
	t.Helper()
	directory := t.TempDir()
	recorded := filepath.Join(directory, "payload")
	script := "#!/bin/sh\nprintf '%s' \"$3\" > " + recorded + "\nprintf 'QR:%s\\n' \"$3\"\n"
	binary := filepath.Join(directory, "qrencode")
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	a.cfg.QREncodeBin = binary
	return recorded
}

func TestV2MaximumHybridInvitationFitsThePairingEnvelope(t *testing.T) {
	setTestV2Homes(t)
	origin := maximumV2TestOrigin(t)
	cfg, paths, err := initializeV2Config("desktop", origin, "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	pending, code, requestBody, err := a.newV2Invitation(cfg, paths, "laptop", origin, v2PairingMaximumLifetime)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := decodeV2StoredMap(pending.InvitationMap)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateV2InvitationMap(invitation); err != nil {
		t.Fatal(err)
	}
	hybrid, ok := invitation[7].([]byte)
	if !ok || len(hybrid) != 1216 {
		t.Fatalf("hybrid recipient = %d bytes", len(hybrid))
	}
	if signing, ok := invitation[8].([]byte); !ok || len(signing) != ed25519.PublicKeySize {
		t.Fatalf("signing key = %d bytes", len(signing))
	}
	if invitation[9] != origin {
		t.Fatalf("invitation origin = %v", invitation[9])
	}
	invitationCBOR, err := decodeV2Base64URL(pending.InvitationMap, -1)
	if err != nil {
		t.Fatal(err)
	}
	if len(invitationCBOR) > v2PairingEnvelopeMaxBytes-chacha20poly1305.Overhead {
		t.Fatalf("maximum invitation is %d bytes", len(invitationCBOR))
	}
	t.Logf("maximum invitation = %d bytes, rendezvous request = %d bytes", len(invitationCBOR), len(requestBody))
	// The envelope and the rendezvous request must both stay inside the
	// limits the server enforces on /v2/pairing/rendezvous.
	if len(requestBody) > v2PairingEnvelopeMaxBytes+512 {
		t.Fatalf("maximum rendezvous request is %d bytes", len(requestBody))
	}
	envelope, err := decodeV2StoredMap(v2Base64URL(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, ok := envelope[4].([]byte)
	if !ok || len(ciphertext) > v2PairingEnvelopeMaxBytes {
		t.Fatalf("maximum envelope ciphertext = %d bytes", len(ciphertext))
	}
	if len(ciphertext) != len(invitationCBOR)+chacha20poly1305.Overhead {
		t.Fatalf("envelope ciphertext = %d bytes for a %d-byte invitation", len(ciphertext), len(invitationCBOR))
	}
	// The scanned payload is the pairing code alone, so the largest possible
	// invitation does not change what the QR code has to carry.
	if len(code) != 39 || code != pending.PairingCode {
		t.Fatalf("pairing code = %q", code)
	}
}

func TestV2InvitationQRPayloadMatchesTheScannedCode(t *testing.T) {
	pending := &v2PendingPairing{
		Alias:       "laptop",
		PairingCode: "0001-0203-0405-0607-0809-0a0b-0c0d-0e0f",
		ExpiresAt:   2_000_000_000,
	}
	var output bytes.Buffer
	a := newApp(strings.NewReader(""), &output, &bytes.Buffer{})
	recorded := installV2TestQREncoder(t, a)
	if err := a.displayV2PairingCode(pending, false); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(recorded)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != pending.PairingCode {
		t.Fatalf("QR payload = %q", payload)
	}
	displayed := ""
	for _, line := range strings.Split(output.String(), "\n") {
		if value, found := strings.CutPrefix(line, "Pairing code: "); found {
			displayed = value
		}
	}
	if displayed != pending.PairingCode {
		t.Fatalf("displayed code = %q", displayed)
	}
	// A scanner reads the QR payload and a person reads the displayed line;
	// both must parse to the same 128-bit code, with or without grouping and
	// with the carriage return a scanner appends.
	scanned, err := parseV2PairingCode(strings.TrimRight(string(payload)+"\r\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	typed, err := parseV2PairingCode(strings.ReplaceAll(displayed, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(scanned, typed) || len(scanned) != v2PairingCodeBytes {
		t.Fatalf("scanned %x differs from typed %x", scanned, typed)
	}
	for _, mangled := range []string{
		strings.ToUpper(displayed),
		displayed + " ",
		" " + displayed,
		displayed + "0",
		displayed[:len(displayed)-1],
	} {
		if _, err := parseV2PairingCode(mangled); err == nil {
			t.Fatalf("scanner input %q was accepted", mangled)
		}
	}
}

func TestV2MaximumInvitationPairsFromTheScannedCode(t *testing.T) {
	root := t.TempDir()
	origin := maximumV2TestOrigin(t)

	setPairingTestHome(t, filepath.Join(root, "inviter"))
	inviterConfig, inviterPaths, err := initializeV2Config(
		"desktop",
		origin,
		"https://dns.google/dns-query",
		"hard",
	)
	if err != nil {
		t.Fatal(err)
	}
	var inviterOutput bytes.Buffer
	inviterApp := newApp(strings.NewReader(""), &inviterOutput, &bytes.Buffer{})
	recorded := installV2TestQREncoder(t, inviterApp)
	inviterPending, code, createBody, err := inviterApp.newV2Invitation(
		inviterConfig,
		inviterPaths,
		"laptop",
		origin,
		15*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	inviterPending.PairingCode = code
	if err := writeV2PendingPairing(inviterPaths, inviterPending); err != nil {
		t.Fatal(err)
	}
	if err := inviterApp.displayV2PairingCode(inviterPending, false); err != nil {
		t.Fatal(err)
	}
	scannedPayload, err := os.ReadFile(recorded)
	if err != nil {
		t.Fatal(err)
	}
	if string(scannedPayload) != code {
		t.Fatalf("scanned payload = %q, displayed code = %q", scannedPayload, code)
	}
	var createMap map[int]any
	if err := v2DecMode.Unmarshal(createBody, &createMap); err != nil {
		t.Fatal(err)
	}

	setPairingTestHome(t, filepath.Join(root, "invitee"))
	_, inviteePaths, err := initializeV2Config(
		"laptop",
		origin,
		"https://dns.google/dns-query",
		"hard",
	)
	if err != nil {
		t.Fatal(err)
	}
	acceptTransport := &pairingFlowTransport{
		locator:    inviterPending.RendezvousLocator,
		nonce:      createMap[3].([]byte),
		ciphertext: createMap[4].([]byte),
		expiresAt:  createMap[5].(uint64),
		stopStatus: true,
	}
	inviteeApp := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	inviteeApp.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return acceptTransport, nil
	}
	// The invitee enters exactly what the scanner read from the QR code.
	if err := inviteeApp.acceptV2PeerInvitation("desktop", string(scannedPayload), false); err == nil ||
		!strings.Contains(err.Error(), "stop after acceptance") {
		t.Fatalf("accept flow stop = %v", err)
	}
	inviteePending, err := loadV2PendingPairing(inviteePaths, "desktop")
	if err != nil {
		t.Fatal(err)
	}
	if inviteePending.CanonicalOrigin != origin {
		t.Fatalf("invitee origin = %q", inviteePending.CanonicalOrigin)
	}
	var acceptWrapper map[int]any
	if err := v2DecMode.Unmarshal(acceptTransport.acceptBody, &acceptWrapper); err != nil {
		t.Fatal(err)
	}

	setPairingTestHome(t, filepath.Join(root, "inviter"))
	inviterPending, err = loadV2PendingPairing(inviterPaths, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	confirmTransport := &pairingFlowTransport{locator: inviterPending.RendezvousLocator}
	if err := inviterApp.completeInviterKeyConfirmation(
		inviterPaths,
		inviterPending,
		map[int]any{1: acceptWrapper[2], 2: acceptWrapper[3]},
		confirmTransport,
	); err != nil {
		t.Fatal(err)
	}
	var confirmWrapper map[int]any
	if err := v2DecMode.Unmarshal(confirmTransport.confirmBody, &confirmWrapper); err != nil {
		t.Fatal(err)
	}

	setPairingTestHome(t, filepath.Join(root, "invitee"))
	inviteePending, err = loadV2PendingPairing(inviteePaths, "desktop")
	if err != nil {
		t.Fatal(err)
	}
	if err := completeInviteeKeyConfirmation(
		inviteePaths,
		inviteePending,
		map[int]any{1: confirmWrapper[1], 2: confirmWrapper[2]},
	); err != nil {
		t.Fatal(err)
	}
	if inviterPending.OutboundRelationshipSecret != inviteePending.InboundRelationshipSecret ||
		inviterPending.InboundRelationshipSecret != inviteePending.OutboundRelationshipSecret {
		t.Fatal("maximum-size invitation produced disagreeing relationship secrets")
	}
}
