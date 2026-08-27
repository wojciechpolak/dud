// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestV2PairingCodeOutputUsesIdenticalQRPayload(t *testing.T) {
	pending := &v2PendingPairing{
		Alias:       "laptop",
		PairingCode: "0001-0203-0405-0607-0809-0a0b-0c0d-0e0f",
		ExpiresAt:   2_000_000_000,
	}
	var output bytes.Buffer
	a := newApp(strings.NewReader(""), &output, &bytes.Buffer{})
	if err := a.displayV2PairingCode(pending, true); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(output.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if value["pairing_code"] != pending.PairingCode || value["qr_payload"] != pending.PairingCode {
		t.Fatalf("JSON pairing output = %#v", value)
	}
	if strings.Contains(output.String(), "QR Code:") {
		t.Fatalf("JSON output contains terminal graphics: %s", output.String())
	}
}

func TestV2HumanPairingOutputAlwaysIncludesTextAndQR(t *testing.T) {
	directory := t.TempDir()
	qr := filepath.Join(directory, "qrencode")
	if err := os.WriteFile(qr, []byte("#!/bin/sh\nprintf 'QR:%s\\n' \"$3\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	pending := &v2PendingPairing{Alias: "laptop", PairingCode: "0001-0203-0405-0607-0809-0a0b-0c0d-0e0f"}
	var output bytes.Buffer
	a := newApp(strings.NewReader(""), &output, &bytes.Buffer{})
	a.cfg.QREncodeBin = qr
	if err := a.displayV2PairingCode(pending, false); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"Pairing code: " + pending.PairingCode, "QR Code:", "QR:" + pending.PairingCode} {
		if !strings.Contains(output.String(), fragment) {
			t.Fatalf("human output omitted %q: %s", fragment, output.String())
		}
	}
}

func TestNewV2InvitationNeedsNoAdminCapability(t *testing.T) {
	setTestV2Homes(t)
	cfg, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	pending, code, request, err := a.newV2Invitation(cfg, paths, "laptop", cfg.BaseURL, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.AdminCapability); !os.IsNotExist(err) {
		t.Fatalf("admin capability unexpectedly required: %v", err)
	}
	if pending.PairingCode != code || pending.CreationRequest == "" || len(request) == 0 {
		t.Fatalf("pending invitation = %#v", pending)
	}
	if parsed, err := parseV2PairingCode(code); err != nil || len(parsed) != 16 {
		t.Fatalf("generated code = %q, %v", code, err)
	}
}

func TestFinalizeV2PairingPersistsActivePeerAndDeliveryState(t *testing.T) {
	setTestV2Homes(t)
	cfg, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	pending, _, _, err := a.newV2Invitation(cfg, paths, "laptop", cfg.BaseURL, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureV2InviterPendingProfile("laptop", pending, cfg.ECHMode); err != nil {
		t.Fatal(err)
	}
	pending.PeerPairingID = v2Base64URL(bytes.Repeat([]byte{0x71}, 16))
	pending.PeerAgeRecipient = v2Base64URL(bytes.Repeat([]byte{0x72}, 1216))
	pending.PeerSigningPublicKey = v2Base64URL(bytes.Repeat([]byte{0x73}, 32))
	pending.OutboundRelationshipSecret = v2Base64URL(bytes.Repeat([]byte{0x74}, 32))
	pending.InboundRelationshipSecret = v2Base64URL(bytes.Repeat([]byte{0x75}, 32))
	pending.ServerContract = mustV2TestServerContract(t)
	relationshipID, err := hex.DecodeString(pending.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := deriveV2RelationshipIdentity(seed, relationshipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := v2EncMode.Marshal(map[int]any{
		1: uint64(2), 2: relationshipID, 3: uint64(0), 4: uint64(0), 5: pending.CanonicalOrigin,
		6: []any{
			map[int]any{1: uint64(0), 2: "write", 3: bytes.Repeat([]byte{1}, 32)},
			map[int]any{1: uint64(0), 2: "read", 3: bytes.Repeat([]byte{2}, 32)},
			map[int]any{1: uint64(0), 2: "ack", 3: bytes.Repeat([]byte{3}, 32)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(grant); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.finalizeV2PairingStatus(cfg, paths, pending, map[int]any{1: uint64(3), 6: encrypted.Bytes()}, true); err != nil {
		t.Fatal(err)
	}
	updated, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if updated.Peers["laptop"].Status != "active" {
		t.Fatalf("peer = %#v", updated.Peers["laptop"])
	}
	if _, err := loadV2PeerDeliveryState(paths, pending.RelationshipID); err != nil {
		t.Fatal(err)
	}
}

func TestRemovedV2PairingCLIOptionsAreRejected(t *testing.T) {
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	for _, args := range [][]string{
		{"peer", "invite", "laptop", "--out", "invite"},
		{"peer", "invite", "laptop", "--qr"},
		{"peer", "accept", "desktop", "--invite-file", "invite"},
		{"peer", "confirm", "desktop"},
	} {
		if err := a.run(args); err == nil {
			t.Fatalf("removed CLI surface accepted: %v", args)
		}
	}
}

func TestPeerResumeAuthorizesOnlyQuarantinedChains(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	state.Chains["in:data"].Quarantined = true
	state.Chains["in:data"].QuarantineReason = "missing data sequence 2"
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	a := newDrainingV2TestApp(t, &emptySlotTransport{}, &output, &bytes.Buffer{})
	if err := a.run([]string{"peer", "resume", "laptop", "--yes", "--json"}); err != nil {
		t.Fatal(err)
	}
	resumed, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	chain := resumed.Chains["in:data"]
	if chain.Quarantined || !chain.ResumeApproved || chain.QuarantineReason != "" {
		t.Fatalf("resumed chain = %#v", chain)
	}
	if !strings.Contains(output.String(), `"peer": "laptop"`) {
		t.Fatalf("resume output = %s", output.String())
	}
}

func TestPeerRevokePublishesControlEventThenDisablesPeer(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.AdminCapability, []byte(v2Base64URL(bytes.Repeat([]byte{0x84}, 32))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	transport := &revocationTestTransport{}
	var output bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &output, &bytes.Buffer{})
	if err := a.run([]string{"peer", "revoke", "laptop", "--yes", "--json"}); err != nil {
		t.Fatal(err)
	}
	if transport.controlEvents != 1 || transport.adminRequests != 1 {
		t.Fatalf("revoke requests: controls=%d admin=%d", transport.controlEvents, transport.adminRequests)
	}
	cfg, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peers["laptop"].Status != "revoked" {
		t.Fatalf("peer = %#v", cfg.Peers["laptop"])
	}
	stored, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Halted || stored.HaltReason != "relationship revoked locally" {
		t.Fatalf("delivery state = %#v", stored)
	}
}

func TestPeerInviteCreatesPendingProfileAndRendezvous(t *testing.T) {
	setTestV2Homes(t)
	if _, _, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard"); err != nil {
		t.Fatal(err)
	}
	transport := &inviteTestTransport{}
	var output bytes.Buffer
	a := newApp(strings.NewReader(""), &output, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
	err := a.run([]string{"peer", "invite", "laptop", "--json"})
	if err == nil || !strings.Contains(err.Error(), "pairing was cancelled") {
		t.Fatalf("invite error = %v", err)
	}
	if transport.rendezvous != 1 || transport.statuses != 1 {
		t.Fatalf("invite requests: rendezvous=%d statuses=%d", transport.rendezvous, transport.statuses)
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peers["laptop"].Status != "pending" {
		t.Fatalf("peer profile = %#v", cfg.Peers["laptop"])
	}
	if _, err := loadV2PendingPairing(paths, "laptop"); err != nil {
		t.Fatal(err)
	}
}

// Only the inviter needs the enrollment secret, and it reaches the wire as a
// proof bound to the rendezvous it creates. The secret itself never reaches the
// wire or the pending pairing state.
func TestPeerInviteProvesEnrollmentWithoutStoringTheProof(t *testing.T) {
	setTestV2Homes(t)
	if _, _, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard"); err != nil {
		t.Fatal(err)
	}
	const secret = "squid-lantern-rotate-9-mango"
	t.Setenv("DUD_PEER_SECRET", secret)
	key, err := v2EnrollmentKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	transport := &inviteTestTransport{gated: true}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
	if err := a.run([]string{"peer", "invite", "laptop", "--json"}); err == nil ||
		!strings.Contains(err.Error(), "pairing was cancelled") {
		t.Fatalf("invite error = %v", err)
	}
	_, paths, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := loadV2PendingPairing(paths, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	locator, err := hex.DecodeString(pending.RendezvousLocator)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := deriveV2EnrollmentProof(key, locator, pending.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	want := "DUD2-Enroll " + v2Base64URL(proof)
	if len(transport.enrollHeaders) != 1 || transport.enrollHeaders[0] != want {
		t.Fatalf("enrollment headers = %#v, want %q", transport.enrollHeaders, want)
	}
	stored, err := os.ReadFile(pairingStatePath(paths, "laptop"))
	if err != nil {
		t.Fatal(err)
	}
	// Neither the proof nor the credential it came from may survive the request.
	for _, leak := range []string{v2Base64URL(proof), secret} {
		if strings.Contains(string(stored), leak) {
			t.Fatalf("pending pairing state retained an enrollment credential: %s", stored)
		}
	}
}

// The command exists so an operator can hand a server the derived key instead of
// the passphrase, which is what lets a deployment with too little CPU for the
// derivation still gate enrollment. What it prints must therefore be usable as
// DUD_PEER_SECRET and reach the same key the passphrase does.
func TestPeerEnrollmentKeyPrintsAUsableSecret(t *testing.T) {
	setTestV2Homes(t)
	const secret = "squid-lantern-rotate-9-mango"
	t.Setenv("DUD_PEER_SECRET", secret)
	out := &bytes.Buffer{}
	a := newApp(strings.NewReader(""), out, &bytes.Buffer{})
	if err := a.run([]string{"peer", "enrollment-key"}); err != nil {
		t.Fatal(err)
	}
	printed := strings.TrimSpace(out.String())
	carried, err := v2EnrollmentKey(printed)
	if err != nil {
		t.Fatalf("printed value %q is not a usable secret: %v", printed, err)
	}
	stretched, err := v2EnrollmentKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(carried, stretched) {
		t.Fatalf("printed key = %x, want %x", carried, stretched)
	}
	// The passphrase itself must not be what gets printed: the point of the
	// command is that the server holds something it cannot type back.
	if strings.Contains(printed, secret) {
		t.Fatalf("printed value leaked the passphrase: %s", printed)
	}

	out.Reset()
	jsonApp := newApp(strings.NewReader(""), out, &bytes.Buffer{})
	if err := jsonApp.run([]string{"peer", "enrollment-key", "--json"}); err != nil {
		t.Fatal(err)
	}
	var report struct {
		EnrollmentKey string `json:"enrollment_key"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.EnrollmentKey != printed {
		t.Fatalf("JSON enrollment key = %q, want %q", report.EnrollmentKey, printed)
	}

	// Nothing to derive from is an error naming the variable, not an empty key.
	t.Setenv("DUD_PEER_SECRET", "")
	missing := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := missing.run([]string{"peer", "enrollment-key"}); err == nil ||
		!strings.Contains(err.Error(), "DUD_PEER_SECRET") {
		t.Fatalf("missing secret error = %v", err)
	}
}

// A gated deployment must read as a missing credential, both from discovery
// before anything is created and from the server's own refusal.
func TestPeerInviteReportsAGatedServerAsAMissingCredential(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		transport *inviteTestTransport
		secret    string
		creates   int
	}{
		{name: "discovery", transport: &inviteTestTransport{gated: true}},
		{
			name:      "server refusal",
			transport: &inviteTestTransport{refuseEnrollment: true},
			// A server that omits enforcement 3 leaves the refusal itself as
			// the only signal; the client still names the credential rather
			// than the HTTP status.
			secret:  "squid-lantern-rotate-9-mango",
			creates: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			setTestV2Homes(t)
			if _, _, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard"); err != nil {
				t.Fatal(err)
			}
			t.Setenv("DUD_PEER_SECRET", testCase.secret)
			a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
			a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return testCase.transport, nil }
			err := a.run([]string{"peer", "invite", "laptop", "--json"})
			if err == nil || !strings.Contains(err.Error(), "DUD_PEER_SECRET") {
				t.Fatalf("invite error = %v", err)
			}
			if testCase.transport.rendezvous != testCase.creates {
				t.Fatalf("rendezvous creations = %d, want %d", testCase.transport.rendezvous, testCase.creates)
			}
		})
	}
}

// An alias with no relationship pins nothing, so the ambient environment still
// selects the deployment an invitation is created on. Only a paired profile
// outranks DUD_BASE_URL, and seeding a fresh profile from the configuration would
// quietly take that choice away.
func TestPeerInviteFollowsTheEnvironmentBeforeAnythingIsPinned(t *testing.T) {
	setTestV2Homes(t)
	if _, _, err := initializeV2Config("desktop", "https://config.example.com", "https://dns.google/dns-query", "hard"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DUD_BASE_URL", "https://env.example.com")
	t.Setenv("DUD_ECH_MODE", "off")
	transport := &inviteTestTransport{}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var echModes []string
	a.newV2Transport = func(options v2TransportOptions) (v2Transport, error) {
		echModes = append(echModes, options.ECHMode)
		return transport, nil
	}
	err := a.run([]string{"peer", "invite", "laptop", "--json"})
	if err == nil || !strings.Contains(err.Error(), "pairing was cancelled") {
		t.Fatalf("invite error = %v", err)
	}
	if transport.origins["https://env.example.com"] == 0 || len(transport.origins) != 1 {
		t.Fatalf("invitation origins = %#v", transport.origins)
	}
	for _, mode := range echModes {
		if mode != "off" {
			t.Fatalf("invitation transport ECH modes = %#v", echModes)
		}
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	// What the invitation used is what the pending profile pins, so the next run
	// reproduces this pairing without the variables being set again.
	peer := cfg.Peers["laptop"]
	if peer.BaseURL != "https://env.example.com" || peer.ECHMode != "off" {
		t.Fatalf("pending peer profile = %#v", peer)
	}
	pending, err := loadV2PendingPairing(paths, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if pending.CanonicalOrigin != "https://env.example.com" {
		t.Fatalf("pending canonical origin = %q", pending.CanonicalOrigin)
	}
}

func TestPeerInviteValidatesOptionsAndActivePeersBeforeNetworkUse(t *testing.T) {
	setTestV2Homes(t)
	cfg, _, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	for _, args := range [][]string{
		{}, {"--json"}, {"laptop", "--expires"}, {"laptop", "--expires", "0s"},
		{"laptop", "--expires", "2h"}, {"laptop", "--bad"}, {"bad/name"},
	} {
		if err := a.cmdPeerInvite(args); err == nil {
			t.Fatalf("invalid invite args accepted: %v", args)
		}
	}
	if _, err := updateV2Config(func(current *v2LocalConfig) error {
		current.Peers["laptop"] = v2PeerProfile{Status: "active", BaseURL: cfg.BaseURL}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.cmdPeerInvite([]string{"laptop"}); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("active peer invite error = %v", err)
	}
}

type inviteTestTransport struct {
	rendezvous int
	statuses   int
	origins    map[string]int
	// gated makes discovery advertise enforcement 3, the way a deployment that
	// requires the enrollment secret does.
	gated bool
	// refuseEnrollment answers rendezvous creation with the server's refusal.
	refuseEnrollment bool
	enrollHeaders    []string
}

func (transport *inviteTestTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	if transport.origins == nil {
		transport.origins = map[string]int{}
	}
	transport.origins[request.Origin]++
	switch {
	case request.Path == "/v2/capabilities":
		body, err := hex.DecodeString(v2CapabilitiesVectorHex)
		if err != nil {
			return nil, err
		}
		if transport.gated {
			capabilities, decodeErr := decodeV2Capabilities(body)
			if decodeErr != nil {
				return nil, decodeErr
			}
			capabilities.Enforcement[3] = 1
			if body, err = v2CapabilityDocumentBytes(capabilities); err != nil {
				return nil, err
			}
		}
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
	case request.Method == "POST" && request.Path == "/v2/pairing/rendezvous":
		transport.rendezvous++
		transport.enrollHeaders = append(transport.enrollHeaders, request.Headers.Get("Authorization"))
		if transport.refuseEnrollment {
			body, err := v2EncMode.Marshal(map[int]any{1: uint64(2), 2: "authentication failed"})
			if err != nil {
				return nil, err
			}
			return &v2Response{StatusCode: 401, ContentType: v2CBORContentType, Body: body}, nil
		}
		return &v2Response{StatusCode: 201}, nil
	case request.Method == "GET" && strings.HasSuffix(request.Path, "/status"):
		transport.statuses++
		body, err := v2EncMode.Marshal(map[int]any{1: uint64(4)})
		if err != nil {
			return nil, err
		}
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
	default:
		return nil, errors.New("unexpected invite request: " + request.Method + " " + request.Path)
	}
}

type revocationTestTransport struct {
	emptySlotTransport
	controlEvents int
	adminRequests int
}

func (transport *revocationTestTransport) Do(ctx context.Context, request v2Request) (*v2Response, error) {
	switch request.Path {
	case "/v2/inbox":
		return transport.emptySlotTransport.Do(ctx, request)
	case "/v2/control-events":
		var body map[int]any
		if err := v2DecMode.Unmarshal(request.Body, &body); err != nil {
			return nil, err
		}
		operationID, ok := body[1].([]byte)
		if !ok || len(operationID) != 16 {
			return nil, errors.New("control publication omitted its operation ID")
		}
		transport.controlEvents++
		response, err := v2EncMode.Marshal(map[int]any{1: operationID, 2: false})
		if err != nil {
			return nil, err
		}
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: response}, nil
	case "/v2/admin/relationships/revoke":
		transport.adminRequests++
		return &v2Response{StatusCode: 204}, nil
	default:
		return nil, errors.New("unexpected revocation request: " + request.Path)
	}
}

func TestV2InviteAcceptKeyConfirmAndSignedCompletion(t *testing.T) {
	root := t.TempDir()
	setPairingTestHome(t, filepath.Join(root, "inviter"))
	inviterConfig, inviterPaths, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	)
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	inviterPending, code, createBody, err := a.newV2Invitation(
		inviterConfig,
		inviterPaths,
		"laptop",
		inviterConfig.BaseURL,
		15*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeV2PendingPairing(inviterPaths, inviterPending); err != nil {
		t.Fatal(err)
	}
	var createMap map[int]any
	if err := v2DecMode.Unmarshal(createBody, &createMap); err != nil {
		t.Fatal(err)
	}

	setPairingTestHome(t, filepath.Join(root, "invitee"))
	_, inviteePaths, err := initializeV2Config(
		"laptop",
		"https://dud.example.com",
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
	if err := inviteeApp.acceptV2PeerInvitation("desktop", code, false); err == nil || !strings.Contains(err.Error(), "stop after acceptance") {
		t.Fatalf("accept flow stop = %v", err)
	}
	inviteePending, err := loadV2PendingPairing(inviteePaths, "desktop")
	if err != nil {
		t.Fatal(err)
	}
	var acceptWrapper map[int]any
	if err := v2DecMode.Unmarshal(acceptTransport.acceptBody, &acceptWrapper); err != nil {
		t.Fatal(err)
	}
	acceptance, err := normalizeV2Map(acceptWrapper[2])
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := acceptance[8].([]byte); !ok || len(key) != 32 {
		t.Fatalf("acceptance field 8 = %T, %d", acceptance[8], len(key))
	}

	setPairingTestHome(t, filepath.Join(root, "inviter"))
	inviterPending, err = loadV2PendingPairing(inviterPaths, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	confirmTransport := &pairingFlowTransport{locator: inviterPending.RendezvousLocator}
	if err := a.completeInviterKeyConfirmation(
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
		t.Fatal("directional relationship secrets do not agree across devices")
	}

	inviteeComplete := &pairingFlowTransport{locator: inviteePending.RendezvousLocator}
	if err := inviteeApp.submitV2PairingCompletion(inviteePaths, inviteePending, inviteeComplete); err != nil {
		t.Fatal(err)
	}
	setPairingTestHome(t, filepath.Join(root, "inviter"))
	inviterComplete := &pairingFlowTransport{locator: inviterPending.RendezvousLocator}
	if err := a.submitV2PairingCompletion(inviterPaths, inviterPending, inviterComplete); err != nil {
		t.Fatal(err)
	}
	for role, body := range map[uint64][]byte{0: inviterComplete.completeBody, 1: inviteeComplete.completeBody} {
		var wrapper map[int]any
		if err := v2DecMode.Unmarshal(body, &wrapper); err != nil {
			t.Fatal(err)
		}
		completion, err := normalizeV2Map(wrapper[1])
		if err != nil {
			t.Fatal(err)
		}
		if !v2UintEquals(completion[5], role) {
			t.Fatalf("completion role = %v, want %d", completion[5], role)
		}
		publicKey := inviterPending.PeerSigningPublicKey
		if role == 0 {
			invitation, _ := decodeV2StoredMap(inviterPending.InvitationMap)
			publicKey = v2Base64URL(invitation[8].([]byte))
		}
		key, err := decodeV2Base64URL(publicKey, 32)
		if err != nil {
			t.Fatal(err)
		}
		signature, ok := wrapper[2].([]byte)
		if !ok || !v2PairingVerify("pairing-complete", completion, signature, ed25519.PublicKey(key)) {
			t.Fatalf("role %d completion signature did not verify", role)
		}
	}
}

func TestPeerAcceptResumesSavedAcceptance(t *testing.T) {
	root := t.TempDir()
	setPairingTestHome(t, filepath.Join(root, "inviter"))
	inviterCfg, inviterPaths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	inviter := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	pending, code, creation, err := inviter.newV2Invitation(inviterCfg, inviterPaths, "laptop", inviterCfg.BaseURL, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var created map[int]any
	if err := v2DecMode.Unmarshal(creation, &created); err != nil {
		t.Fatal(err)
	}
	setPairingTestHome(t, filepath.Join(root, "invitee"))
	if _, _, err := initializeV2Config("laptop", "https://dud.example.com", "https://dns.google/dns-query", "hard"); err != nil {
		t.Fatal(err)
	}
	first := &pairingFlowTransport{locator: pending.RendezvousLocator, nonce: created[3].([]byte), ciphertext: created[4].([]byte), expiresAt: created[5].(uint64), stopStatus: true}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return first, nil }
	if err := a.acceptV2PeerInvitation("desktop", code, true); err == nil {
		t.Fatal("initial acceptance unexpectedly completed")
	}
	resumed := &pairingFlowTransport{locator: pending.RendezvousLocator, statusPhase: 4}
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return resumed, nil }
	err = a.cmdPeerAccept([]string{"desktop", "--json"})
	if err == nil || !strings.Contains(err.Error(), "pairing was cancelled") {
		t.Fatalf("resumed acceptance error = %v", err)
	}
	if len(resumed.acceptBody) == 0 {
		t.Fatal("resumed acceptance did not republish the signed acceptance")
	}
}

func setPairingTestHome(t *testing.T, root string) {
	t.Helper()
	setV2TestHomes(t, root)
}

type pairingFlowTransport struct {
	locator      string
	nonce        []byte
	ciphertext   []byte
	expiresAt    uint64
	stopStatus   bool
	statusPhase  uint64
	acceptBody   []byte
	confirmBody  []byte
	completeBody []byte
}

func (transport *pairingFlowTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	switch {
	case request.Method == "GET" && request.Path == "/v2/capabilities":
		body, err := hex.DecodeString(v2CapabilitiesVectorHex)
		if err != nil {
			return nil, err
		}
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
	case request.Method == "GET" && request.Path == "/v2/pairing/rendezvous/"+transport.locator:
		body, err := v2EncMode.Marshal(map[int]any{1: uint64(2), 2: transport.nonce, 3: transport.ciphertext, 4: transport.expiresAt})
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, err
	case request.Method == "POST" && strings.HasSuffix(request.Path, "/accept"):
		transport.acceptBody = append([]byte(nil), request.Body...)
		return &v2Response{StatusCode: 202}, nil
	case request.Method == "POST" && strings.HasSuffix(request.Path, "/key-confirm"):
		transport.confirmBody = append([]byte(nil), request.Body...)
		return &v2Response{StatusCode: 202}, nil
	case request.Method == "POST" && strings.HasSuffix(request.Path, "/complete"):
		transport.completeBody = append([]byte(nil), request.Body...)
		return &v2Response{StatusCode: 202}, nil
	case request.Method == "GET" && strings.HasSuffix(request.Path, "/status") && transport.statusPhase != 0:
		body, err := v2EncMode.Marshal(map[int]any{1: transport.statusPhase})
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, err
	case request.Method == "GET" && strings.HasSuffix(request.Path, "/status") && transport.stopStatus:
		return nil, errors.New("stop after acceptance")
	default:
		return nil, errors.New("unexpected pairing flow request: " + request.Method + " " + request.Path)
	}
}
