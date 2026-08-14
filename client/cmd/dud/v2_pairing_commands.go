// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"filippo.io/hpke"
)

func loadV2AdminCapability(paths v2Paths) ([]byte, error) {
	if err := validatePrivateV2File(paths.AdminCapability); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf(
				"server administration requires the private capability file %s",
				paths.AdminCapability,
			)
		}
		return nil, err
	}
	body, err := os.ReadFile(paths.AdminCapability)
	if err != nil {
		return nil, err
	}
	capability, err := decodeV2Base64URL(strings.TrimSpace(string(body)), 32)
	if err != nil {
		return nil, errors.New("v2 admin capability file is invalid")
	}
	return capability, nil
}

func (a *app) cmdPeerInvite(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fatalError("dud peer invite requires NAME")
	}
	alias := args[0]
	args = args[1:]
	expires := 15 * time.Minute
	jsonOutput := false
	for len(args) != 0 {
		switch args[0] {
		case "--expires":
			if err := needValue(args, "--expires"); err != nil {
				return err
			}
			value, err := time.ParseDuration(args[1])
			if err != nil || value <= 0 || value > v2PairingMaximumLifetime {
				return fatalError("--expires must be a duration from 1ns through 1h")
			}
			expires, args = value, args[2:]
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
			args = args[1:]
		default:
			return fatalError("Unknown peer invite option: " + args[0])
		}
	}
	if err := validateV2PeerAlias(alias); err != nil {
		return err
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	peer, exists := cfg.Peers[alias]
	if !exists {
		// An alias with no relationship pins nothing: copying the configuration
		// into the peer layer here would make it outrank DUD_BASE_URL and
		// DUD_ECH_MODE, which are the only way to invite against a deployment
		// other than the one this configuration names.
		peer = v2PeerProfile{
			Status:    "unpaired",
			KeyEpoch:  0,
			GitRemote: alias,
		}
	}
	if peer.Status == "active" {
		return fmt.Errorf("peer %q is already active; revoke it before replacing its identity", alias)
	}
	origin, _, echMode, err := effectiveV2NetworkConfig(cfg, &peer)
	if err != nil {
		return err
	}
	transport, err := newV2PeerTransport(a, cfg, &peer, 30*time.Second)
	if err != nil {
		return err
	}
	serverCapabilities, err := requireV2Features(
		context.Background(),
		transport,
		origin,
		2,
		3,
		9,
		10,
		11,
	)
	if err != nil {
		return err
	}
	serverContract, err := newV2ServerContract(serverCapabilities)
	if err != nil {
		return err
	}
	// Enforcement ID 3 reports whether this deployment gates enrollment. Reading
	// it here turns a missing credential into one sentence before any state is
	// created, instead of a refusal after the invitation was already written.
	if serverCapabilities.Enforcement[3] == 1 && a.cfg.V2Secret == "" {
		return fatalError(v2EnrollmentRequiredMessage)
	}
	if pending, pendingErr := loadV2PendingPairing(paths, alias); pendingErr == nil && pending.Role == 0 && pending.ExpiresAt > uint64(time.Now().Unix()) {
		if err := a.createV2Rendezvous(pending, transport); err != nil {
			return err
		}
		if err := ensureV2InviterPendingProfile(alias, pending, echMode); err != nil {
			return err
		}
		return a.displayAndWaitV2Invitation(cfg, paths, pending, transport, jsonOutput)
	}
	pending, code, _, err := a.newV2Invitation(cfg, paths, alias, origin, expires)
	if err != nil {
		return err
	}
	pending.ServerContract = serverContract
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return err
	}
	if err := writeV2PendingPairing(paths, pending); err != nil {
		unlock()
		return err
	}
	unlock()
	if err := a.createV2Rendezvous(pending, transport); err != nil {
		return err
	}
	if err := ensureV2InviterPendingProfile(alias, pending, echMode); err != nil {
		return err
	}
	pending.PairingCode = code
	return a.displayAndWaitV2Invitation(cfg, paths, pending, transport, jsonOutput)
}

// ensureV2InviterPendingProfile records the profile of a peer whose pairing is
// in flight. It pins the transport the invitation actually used — the resolved
// ECH mode next to the origin the rendezvous was created on — rather than a copy
// of the configuration, so a later run reproduces this pairing instead of
// whatever the configuration says by then.
func ensureV2InviterPendingProfile(alias string, pending *v2PendingPairing, echMode string) error {
	_, err := updateV2Config(func(current *v2LocalConfig) error {
		value, exists := current.Peers[alias]
		if !exists {
			value = v2PeerProfile{
				KeyEpoch:  0,
				ECHMode:   echMode,
				GitRemote: alias,
			}
		}
		if value.Status == "active" {
			return fmt.Errorf("peer %q is already active", alias)
		}
		value.Status = "pending"
		value.RelationshipID = pending.RelationshipID
		value.BaseURL = pending.CanonicalOrigin
		current.Peers[alias] = value
		return nil
	})
	return err
}

func (a *app) displayAndWaitV2Invitation(cfg *v2LocalConfig, paths v2Paths, pending *v2PendingPairing, transport v2Transport, jsonOutput bool) error {
	if err := a.displayV2PairingCode(pending, jsonOutput); err != nil {
		return err
	}
	return a.waitV2Pairing(cfg, paths, pending, transport, jsonOutput)
}

func (a *app) displayV2PairingCode(pending *v2PendingPairing, jsonOutput bool) error {
	if jsonOutput {
		if err := writeJSON(a.out, map[string]any{"event": "pairing_code", "alias": pending.Alias, "pairing_code": pending.PairingCode, "qr_payload": pending.PairingCode, "expires_at": pending.ExpiresAt}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.out, "Pairing code: %s\n\nQR Code:\n", pending.PairingCode)
		if err := a.runCommand(a.cfg.QREncodeBin, []string{"-t", "ansiutf8", pending.PairingCode}, nil, a.out, a.errOut); err != nil {
			return err
		}
		fmt.Fprintln(a.out, "Waiting for the peer to accept...")
	}
	return nil
}

func (a *app) newV2Invitation(cfg *v2LocalConfig, paths v2Paths, alias, origin string, expires time.Duration) (*v2PendingPairing, string, []byte, error) {
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		return nil, "", nil, err
	}
	invitationID, err := randomV2Bytes(32)
	if err != nil {
		return nil, "", nil, err
	}
	relationshipID, err := randomV2Bytes(16)
	if err != nil {
		return nil, "", nil, err
	}
	pairingID, err := deriveV2DeviceID(seed, relationshipID, 0)
	if err != nil {
		return nil, "", nil, err
	}
	nonce, err := randomV2Bytes(32)
	if err != nil {
		return nil, "", nil, err
	}
	bootstrap, err := randomV2Bytes(32)
	if err != nil {
		return nil, "", nil, err
	}
	statusCapability, err := randomV2Bytes(32)
	if err != nil {
		return nil, "", nil, err
	}
	hpkeKey, err := v2HPKEPrivateKey(seed, relationshipID)
	if err != nil {
		return nil, "", nil, err
	}
	signingKey, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		return nil, "", nil, err
	}
	expiresAt := uint64(time.Now().Add(expires).Unix())
	codeBytes, err := randomV2Bytes(v2PairingCodeBytes)
	if err != nil {
		return nil, "", nil, err
	}
	code, err := formatV2PairingCode(codeBytes)
	if err != nil {
		return nil, "", nil, err
	}
	locator, err := deriveV2PairingLocator(codeBytes)
	if err != nil {
		return nil, "", nil, err
	}
	invitation := map[int]any{
		1:  uint64(2),
		2:  uint64(1),
		3:  uint64(1),
		4:  invitationID,
		5:  relationshipID,
		6:  pairingID,
		7:  hpkeKey.PublicKey().Bytes(),
		8:  append([]byte(nil), signingKey.Public().(ed25519.PublicKey)...),
		9:  origin,
		10: bootstrap,
		11: nonce,
		12: expiresAt,
	}
	invitationCBOR, err := encodeV2Invitation(invitation)
	if err != nil {
		return nil, "", nil, err
	}
	envelopeNonce, envelopeCiphertext, err := encryptV2PairingInvitation(codeBytes, locator, origin, expiresAt, invitationCBOR)
	if err != nil {
		return nil, "", nil, err
	}
	bootstrapVerifier, err := v2PairingBearerVerifier(bootstrap)
	if err != nil {
		return nil, "", nil, err
	}
	statusVerifier, err := v2PairingBearerVerifier(statusCapability)
	if err != nil {
		return nil, "", nil, err
	}
	requestBody, err := v2EncMode.Marshal(map[int]any{
		1: uint64(2),
		2: locator,
		3: envelopeNonce,
		4: envelopeCiphertext,
		5: expiresAt,
		6: bootstrapVerifier,
		7: statusVerifier,
	})
	if err != nil {
		return nil, "", nil, err
	}
	pending := &v2PendingPairing{
		Version:           v2PairingStateVersion,
		Alias:             alias,
		Role:              0,
		PairingCode:       code,
		RendezvousLocator: hex.EncodeToString(locator),
		CreationRequest:   v2Base64URL(requestBody),
		InvitationID:      hex.EncodeToString(invitationID),
		RelationshipID:    hex.EncodeToString(relationshipID),
		CanonicalOrigin:   origin,
		ExpiresAt:         expiresAt,
		InvitationMap:     v2Base64URL(invitationCBOR),
		StatusCapability:  v2Base64URL(statusCapability),
		LocalPairingID:    v2Base64URL(pairingID),
		LocalNonce:        v2Base64URL(nonce),
	}
	return pending, code, requestBody, nil
}

// cmdPeerEnrollmentKey stretches DUD_PEER_SECRET once, here, and prints the value
// that carries the result. A server configured with it verifies enrollment
// proofs without deriving anything, which is what makes a gated deployment
// affordable on a free-tier Worker; the work factor still prices every guess an
// attacker makes, because the devices holding the passphrase still pay it.
//
// The passphrase is read from the environment rather than an argument, the way
// the server's own administrative commands read theirs: an argument reaches the
// shell history and the process table.
func (a *app) cmdPeerEnrollmentKey(args []string) error {
	jsonOutput, err := onlyJSONOption(args)
	if err != nil {
		return err
	}
	if a.cfg.V2Secret == "" {
		return fatalError("dud peer enrollment-key reads the passphrase from DUD_PEER_SECRET, which is unset")
	}
	key, err := v2EnrollmentKey(a.cfg.V2Secret)
	if err != nil {
		return err
	}
	value, err := formatV2EnrollmentKey(key)
	if err != nil {
		return err
	}
	if warning := v2EnrollmentWorkFactorWarning(a.cfg.V2Secret); warning != "" {
		fmt.Fprintf(a.errOut, "WARNING: %s\n", warning)
	}
	if jsonOutput {
		return writeJSON(a.out, map[string]any{"enrollment_key": value})
	}
	fmt.Fprintln(a.out, value)
	return nil
}

// createV2Rendezvous is the one call site that creates a rendezvous, so the
// enrollment proof is computed here, at send time, from the pending record. It
// is never persisted: a stored proof would outlive the request that needed it
// while the secret it proves is already in the environment.
func (a *app) createV2Rendezvous(pending *v2PendingPairing, transport v2Transport) error {
	requestBody, err := decodeV2Base64URL(pending.CreationRequest, -1)
	if err != nil || len(requestBody) == 0 || len(requestBody) > v2PairingEnvelopeMaxBytes+512 {
		return errors.New("pending pairing creation request is invalid")
	}
	authorization := ""
	key, err := v2EnrollmentKey(a.cfg.V2Secret)
	if err != nil {
		return err
	}
	if warning := v2EnrollmentWorkFactorWarning(a.cfg.V2Secret); warning != "" {
		fmt.Fprintf(a.errOut, "WARNING: %s\n", warning)
	}
	if key != nil {
		locator, decodeErr := hex.DecodeString(pending.RendezvousLocator)
		if decodeErr != nil {
			return errors.New("pending pairing creation request is invalid")
		}
		proof, proofErr := deriveV2EnrollmentProof(key, locator, pending.ExpiresAt)
		if proofErr != nil {
			return proofErr
		}
		authorization = "DUD2-Enroll " + v2Base64URL(proof)
	}
	if _, err := doV2AuthorizedCBORRequest(
		context.Background(),
		transport,
		"POST",
		pending.CanonicalOrigin,
		"/v2/pairing/rendezvous",
		authorization,
		requestBody,
		v2MaxDescriptorBytes,
	); err != nil {
		if isV2EnrollmentRefusal(err) {
			return errors.New(v2EnrollmentRequiredMessage)
		}
		return fmt.Errorf("create pairing invitation: %w", err)
	}
	return nil
}

func (a *app) acceptV2PeerInvitation(alias, codeText string, jsonOutput bool) error {
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	code, err := parseV2PairingCode(codeText)
	if err != nil {
		return err
	}
	canonicalCode, err := formatV2PairingCode(code)
	if err != nil {
		return err
	}
	// A pairing code names a rendezvous, not a server: both sides meet on the
	// origin their own invocation resolves to. Nothing is pinned yet, so an empty
	// profile lets the environment select the deployment the way it does for the
	// inviter.
	origin, _, echMode, err := effectiveV2NetworkConfig(cfg, &v2PeerProfile{})
	if err != nil {
		return err
	}
	locator, err := deriveV2PairingLocator(code)
	if err != nil {
		return err
	}
	transport, err := newV2PeerTransport(a, cfg, nil, 30*time.Second)
	if err != nil {
		return err
	}
	serverCapabilities, err := requireV2Features(
		context.Background(),
		transport,
		origin,
		2,
		3,
		9,
		10,
		11,
	)
	if err != nil {
		return err
	}
	serverContract, err := newV2ServerContract(serverCapabilities)
	if err != nil {
		return err
	}
	retrievalPath := "/v2/pairing/rendezvous/" + hex.EncodeToString(locator)
	retrieval, err := doV2CBORRequest(context.Background(), transport, "GET", origin, retrievalPath, nil, nil, v2MaxDescriptorBytes)
	if err != nil {
		return errors.New(v2PairingInvalidCodeMessage)
	}
	var envelope map[int]any
	if err := v2DecMode.Unmarshal(retrieval.Body, &envelope); err != nil {
		return errors.New(v2PairingInvalidCodeMessage)
	}
	nonce, nonceOK := envelope[2].([]byte)
	ciphertext, ciphertextOK := envelope[3].([]byte)
	expiresAt, expiresOK := asV2Uint(envelope[4])
	if !v2UintEquals(envelope[1], 2) || !nonceOK || !ciphertextOK || !expiresOK || expiresAt <= uint64(time.Now().Unix()) {
		return errors.New(v2PairingInvalidCodeMessage)
	}
	invitationCBOR, err := decryptV2PairingInvitation(code, locator, nonce, ciphertext, origin, expiresAt)
	if err != nil {
		return err
	}
	invitation, err := decodeV2Invitation(invitationCBOR)
	if err != nil || invitation[9] != origin || invitation[12] != expiresAt {
		return errors.New(v2PairingInvalidCodeMessage)
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		return err
	}
	relationshipID := invitation[5].([]byte)
	localHPKE, err := v2HPKEPrivateKey(seed, relationshipID)
	if err != nil {
		return err
	}
	localSigning, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	localPairingID, err := deriveV2DeviceID(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	localNonce, err := randomV2Bytes(32)
	if err != nil {
		return err
	}
	statusCapability, err := randomV2Bytes(32)
	if err != nil {
		return err
	}
	statusHash := sha256.Sum256(statusCapability)
	invitationDigest := sha256.Sum256(invitationCBOR)
	acceptanceForBinder := map[int]any{
		1:  uint64(2),
		2:  uint64(1),
		3:  uint64(1),
		4:  cloneV2Bytes(invitation[4]),
		5:  cloneV2Bytes(invitation[5]),
		6:  localPairingID,
		7:  localHPKE.PublicKey().Bytes(),
		8:  append([]byte(nil), localSigning.Public().(ed25519.PublicKey)...),
		9:  localNonce,
		10: invitationDigest[:],
		12: statusHash[:],
		14: locator,
	}
	binderBytes, err := v2EncMode.Marshal(acceptanceForBinder)
	if err != nil {
		return err
	}
	binderDigest := sha256.Sum256(binderBytes)
	binder, err := v2PairingBinder(code, locator, "invitee", binderDigest[:])
	if err != nil {
		return err
	}
	acceptanceWithoutEnc := make(map[int]any, len(acceptanceForBinder)+1)
	for key, value := range acceptanceForBinder {
		acceptanceWithoutEnc[key] = value
	}
	acceptanceWithoutEnc[13] = binder
	// The HPKE info excludes enc_B but includes every other acceptance field.
	placeholder := make(map[int]any, len(acceptanceWithoutEnc)+1)
	for key, value := range acceptanceWithoutEnc {
		placeholder[key] = value
	}
	placeholder[11] = make([]byte, 1120)
	pre, err := v2PreTranscript(invitation, placeholder)
	if err != nil {
		return err
	}
	preCBOR, err := v2EncMode.Marshal(pre)
	if err != nil {
		return err
	}
	info := sha256.Sum256(preCBOR)
	peerPublic, err := hpke.MLKEM768X25519().NewPublicKey(invitation[7].([]byte))
	if err != nil {
		return err
	}
	encB, senderB, err := hpke.NewSender(peerPublic, hpke.HKDFSHA256(), hpke.ExportOnly(), info[:])
	if err != nil {
		return err
	}
	secretB, err := senderB.Export(v2PairingExporterContext, 32)
	if err != nil {
		return err
	}
	acceptance := acceptanceWithoutEnc
	acceptance[11] = encB
	signature, err := v2PairingSign("acceptance", acceptance, localSigning)
	if err != nil {
		return err
	}
	acceptanceCBOR, err := v2EncMode.Marshal(acceptance)
	if err != nil {
		return err
	}
	pending := &v2PendingPairing{
		Version:              v2PairingStateVersion,
		Alias:                alias,
		Role:                 1,
		PairingCode:          canonicalCode,
		RendezvousLocator:    hex.EncodeToString(locator),
		InvitationID:         hex.EncodeToString(invitation[4].([]byte)),
		RelationshipID:       hex.EncodeToString(relationshipID),
		CanonicalOrigin:      origin,
		ExpiresAt:            invitation[12].(uint64),
		InvitationMap:        v2Base64URL(invitationCBOR),
		AcceptanceMap:        v2Base64URL(acceptanceCBOR),
		StatusCapability:     v2Base64URL(statusCapability),
		LocalPairingID:       v2Base64URL(localPairingID),
		PeerPairingID:        v2Base64URL(invitation[6].([]byte)),
		LocalNonce:           v2Base64URL(localNonce),
		PeerNonce:            v2Base64URL(invitation[11].([]byte)),
		PeerAgeRecipient:     v2Base64URL(invitation[7].([]byte)),
		PeerSigningPublicKey: v2Base64URL(invitation[8].([]byte)),
		EncB:                 v2Base64URL(encB),
		SecretB:              v2Base64URL(secretB),
		ServerContract:       serverContract,
	}
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return err
	}
	if err := writeV2PendingPairing(paths, pending); err != nil {
		unlock()
		return err
	}
	unlock()
	bootstrap := invitation[10].([]byte)
	body, err := v2EncMode.Marshal(map[int]any{
		1: invitation,
		2: acceptance,
		3: signature,
		4: statusCapability,
	})
	if err != nil {
		return err
	}
	path := "/v2/pairing/rendezvous/" + pending.RendezvousLocator + "/accept"
	if _, err := doV2CBORRequest(context.Background(), transport, "POST", origin, path, bootstrap, body, v2MaxDescriptorBytes); err != nil {
		return fmt.Errorf("accept pairing invitation: %w", err)
	}
	if err := ensureV2InviteePendingProfile(alias, pending, echMode); err != nil {
		return err
	}
	if !jsonOutput {
		fmt.Fprintf(a.out, "Pairing response sent for %q. Waiting for authentication to finish...\n", alias)
	}
	return a.waitV2Pairing(cfg, paths, pending, transport, jsonOutput)
}

// ensureV2InviteePendingProfile is the acceptor's counterpart to
// ensureV2InviterPendingProfile and pins the same resolved transport.
func ensureV2InviteePendingProfile(alias string, pending *v2PendingPairing, echMode string) error {
	invitation, err := decodeV2StoredMap(pending.InvitationMap)
	if err != nil {
		return err
	}
	_, err = updateV2Config(func(current *v2LocalConfig) error {
		if existing, ok := current.Peers[alias]; ok && existing.Status == "active" {
			return nil
		}
		current.Peers[alias] = v2PeerProfile{
			Status:                   "pending",
			RelationshipID:           pending.RelationshipID,
			KeyEpoch:                 0,
			PeerPseudonymousID:       hex.EncodeToString(invitation[6].([]byte)),
			PeerAgeRecipient:         v2Base64URL(invitation[7].([]byte)),
			PeerSigningPublicKey:     v2Base64URL(invitation[8].([]byte)),
			BaseURL:                  pending.CanonicalOrigin,
			ECHMode:                  echMode,
			InboxCapabilityReference: "<pending>",
			GitRemote:                alias,
		}
		return nil
	})
	return err
}

func (a *app) resumeV2Acceptance(paths v2Paths, pending *v2PendingPairing, transport v2Transport) error {
	invitation, err := decodeV2StoredMap(pending.InvitationMap)
	if err != nil {
		return err
	}
	acceptance, err := decodeV2StoredMap(pending.AcceptanceMap)
	if err != nil {
		return err
	}
	relationshipID, err := hex.DecodeString(pending.RelationshipID)
	if err != nil || len(relationshipID) != 16 {
		return errors.New("pending relationship ID is invalid")
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		return err
	}
	signingKey, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	signature, err := v2PairingSign("acceptance", acceptance, signingKey)
	if err != nil {
		return err
	}
	statusCapability, err := decodeV2Base64URL(pending.StatusCapability, 32)
	if err != nil {
		return err
	}
	body, err := v2EncMode.Marshal(map[int]any{
		1: invitation,
		2: acceptance,
		3: signature,
		4: statusCapability,
	})
	if err != nil {
		return err
	}
	bootstrap, ok := invitation[10].([]byte)
	if !ok || len(bootstrap) != 32 {
		return errors.New("pending invitation bootstrap is invalid")
	}
	path := "/v2/pairing/rendezvous/" + pending.RendezvousLocator + "/accept"
	if _, err := doV2CBORRequest(context.Background(), transport, "POST", pending.CanonicalOrigin, path, bootstrap, body, v2MaxDescriptorBytes); err != nil {
		return fmt.Errorf("resume pairing acceptance: %w", err)
	}
	return nil
}

func fetchV2PairingStatus(pending *v2PendingPairing, transport v2Transport) (map[int]any, error) {
	bearer, err := decodeV2Base64URL(pending.StatusCapability, 32)
	if err != nil {
		return nil, err
	}
	path := "/v2/pairing/rendezvous/" + pending.RendezvousLocator + "/status"
	response, err := doV2CBORRequest(context.Background(), transport, "GET", pending.CanonicalOrigin, path, bearer, nil, v2MaxDescriptorBytes)
	if err != nil {
		return nil, err
	}
	var status map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &status); err != nil {
		return nil, fmt.Errorf("decode pairing status: %w", err)
	}
	return status, nil
}

func (a *app) progressV2Pairing(cfg *v2LocalConfig, paths v2Paths, pending *v2PendingPairing, transport v2Transport) (uint64, error) {
	status, err := fetchV2PairingStatus(pending, transport)
	if err != nil {
		return 0, err
	}
	phase, ok := asV2Uint(status[1])
	if !ok || phase > 5 {
		return 0, errors.New("pairing status phase is invalid")
	}
	if phase == 4 {
		return phase, errors.New("pairing was cancelled")
	}
	if phase == 5 {
		return phase, errors.New("pairing invitation expired")
	}
	if phase == 3 {
		return phase, nil
	}
	if pending.FullTranscriptHash == "" && pending.Role == 0 {
		envelope, exists := status[2]
		if !exists {
			return phase, nil
		}
		if err := a.completeInviterKeyConfirmation(paths, pending, envelope, transport); err != nil {
			return phase, err
		}
		phase = 2
	}
	if pending.FullTranscriptHash == "" && pending.Role == 1 {
		envelope, exists := status[3]
		if !exists {
			return phase, nil
		}
		if err := completeInviteeKeyConfirmation(paths, pending, envelope); err != nil {
			return phase, err
		}
		phase = 2
	}
	if pending.FullTranscriptHash != "" && !pending.Completed {
		if err := a.submitV2PairingCompletion(paths, pending, transport); err != nil {
			return phase, err
		}
	}
	return phase, nil
}

func (a *app) completeInviterKeyConfirmation(paths v2Paths, pending *v2PendingPairing, rawEnvelope any, transport v2Transport) error {
	envelope, err := normalizeV2Map(rawEnvelope)
	if err != nil {
		return err
	}
	acceptance, err := normalizeV2Map(envelope[1])
	if err != nil {
		return err
	}
	signature, ok := envelope[2].([]byte)
	if !ok {
		return errors.New("acceptance signature is invalid")
	}
	invitation, err := decodeV2StoredMap(pending.InvitationMap)
	if err != nil {
		return err
	}
	if err := validateV2AcceptanceMap(invitation, acceptance); err != nil {
		return err
	}
	code, err := parseV2PairingCode(pending.PairingCode)
	if err != nil {
		return err
	}
	locator, err := hex.DecodeString(pending.RendezvousLocator)
	if err != nil || len(locator) != 32 {
		return errors.New("pending pairing locator is invalid")
	}
	binderInput := make(map[int]any, 12)
	for key, value := range acceptance {
		if key != 11 && key != 13 {
			binderInput[key] = value
		}
	}
	binderBytes, err := v2EncMode.Marshal(binderInput)
	if err != nil {
		return err
	}
	binderDigest := sha256.Sum256(binderBytes)
	expectedBinder, err := v2PairingBinder(code, locator, "invitee", binderDigest[:])
	if err != nil || !bytes.Equal(expectedBinder, acceptance[13].([]byte)) {
		return errors.New("pairing acceptance authentication failed")
	}
	peerSigning, ok := acceptance[8].([]byte)
	if !ok || !v2PairingVerify("acceptance", acceptance, signature, ed25519.PublicKey(peerSigning)) {
		return errors.New("acceptance signature verification failed")
	}
	pre, err := v2PreTranscript(invitation, acceptance)
	if err != nil {
		return err
	}
	preBytes, err := v2EncMode.Marshal(pre)
	if err != nil {
		return err
	}
	info := sha256.Sum256(preBytes)
	relationshipID, _ := hex.DecodeString(pending.RelationshipID)
	cfg, _, err := loadV2Config()
	if err != nil {
		return err
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		return err
	}
	localPrivate, err := v2HPKEPrivateKey(seed, relationshipID)
	if err != nil {
		return err
	}
	encB := acceptance[11].([]byte)
	recipientB, err := hpke.NewRecipient(encB, localPrivate, hpke.HKDFSHA256(), hpke.ExportOnly(), info[:])
	if err != nil {
		return err
	}
	secretB, err := recipientB.Export(v2PairingExporterContext, 32)
	if err != nil {
		return err
	}
	peerPublic, err := hpke.MLKEM768X25519().NewPublicKey(acceptance[7].([]byte))
	if err != nil {
		return err
	}
	encA, senderA, err := hpke.NewSender(peerPublic, hpke.HKDFSHA256(), hpke.ExportOnly(), info[:])
	if err != nil {
		return err
	}
	secretA, err := senderA.Export(v2PairingExporterContext, 32)
	if err != nil {
		return err
	}
	_, transcriptHash, err := v2FullTranscript(pre, encA, encB)
	if err != nil {
		return err
	}
	pairingPSK, err := deriveV2PairingKey(code, locator, "relationship-psk")
	if err != nil {
		return err
	}
	outbound, inbound, err := deriveV2PairingOutputs(secretA, secretB, pairingPSK, transcriptHash)
	if err != nil {
		return err
	}
	acceptanceBytes, _ := v2EncMode.Marshal(acceptance)
	acceptanceDigest := sha256.Sum256(acceptanceBytes)
	confirmation := map[int]any{
		1: uint64(2),
		2: cloneV2Bytes(invitation[4]),
		3: cloneV2Bytes(invitation[5]),
		4: acceptanceDigest[:],
		5: encA,
		6: transcriptHash,
	}
	confirmationBinder, err := v2PairingBinder(code, locator, "inviter", transcriptHash)
	if err != nil {
		return err
	}
	confirmation[7] = confirmationBinder
	signingKey, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	confirmationSignature, err := v2PairingSign("key-confirmation", confirmation, signingKey)
	if err != nil {
		return err
	}
	confirmationEncoded, _ := v2EncMode.Marshal(confirmation)
	pending.AcceptanceMap = v2Base64URL(acceptanceBytes)
	pending.KeyConfirmationMap = v2Base64URL(confirmationEncoded)
	pending.PeerPairingID = v2Base64URL(acceptance[6].([]byte))
	pending.PeerNonce = v2Base64URL(acceptance[9].([]byte))
	pending.PeerAgeRecipient = v2Base64URL(acceptance[7].([]byte))
	pending.PeerSigningPublicKey = v2Base64URL(peerSigning)
	pending.EncA = v2Base64URL(encA)
	pending.EncB = v2Base64URL(encB)
	pending.SecretA = v2Base64URL(secretA)
	pending.SecretB = v2Base64URL(secretB)
	pending.OutboundRelationshipSecret = v2Base64URL(outbound)
	pending.InboundRelationshipSecret = v2Base64URL(inbound)
	pending.FullTranscriptHash = hex.EncodeToString(transcriptHash)
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return err
	}
	if err := writeV2PendingPairing(paths, pending); err != nil {
		unlock()
		return err
	}
	unlock()
	body, err := v2EncMode.Marshal(map[int]any{1: confirmation, 2: confirmationSignature})
	if err != nil {
		return err
	}
	bearer, _ := decodeV2Base64URL(pending.StatusCapability, 32)
	path := "/v2/pairing/rendezvous/" + pending.RendezvousLocator + "/key-confirm"
	if _, err := doV2CBORRequest(context.Background(), transport, "POST", pending.CanonicalOrigin, path, bearer, body, v2MaxDescriptorBytes); err != nil {
		return err
	}
	_ = cfg
	return nil
}

func completeInviteeKeyConfirmation(paths v2Paths, pending *v2PendingPairing, rawEnvelope any) error {
	envelope, err := normalizeV2Map(rawEnvelope)
	if err != nil {
		return err
	}
	confirmation, err := normalizeV2Map(envelope[1])
	if err != nil {
		return err
	}
	signature, ok := envelope[2].([]byte)
	if !ok {
		return errors.New("key-confirmation signature is invalid")
	}
	invitation, err := decodeV2StoredMap(pending.InvitationMap)
	if err != nil {
		return err
	}
	acceptance, err := decodeV2StoredMap(pending.AcceptanceMap)
	if err != nil {
		return err
	}
	if err := validateV2InvitationMap(invitation); err != nil {
		return err
	}
	if err := validateV2AcceptanceMap(invitation, acceptance); err != nil {
		return err
	}
	if err := validateV2KeyConfirmationMap(invitation, acceptance, confirmation); err != nil {
		return err
	}
	peerSigning, _ := invitation[8].([]byte)
	if !v2PairingVerify("key-confirmation", confirmation, signature, ed25519.PublicKey(peerSigning)) {
		return errors.New("key-confirmation signature verification failed")
	}
	encA, ok := confirmation[5].([]byte)
	if !ok {
		return errors.New("key confirmation encapsulation is invalid")
	}
	pre, err := v2PreTranscript(invitation, acceptance)
	if err != nil {
		return err
	}
	encB, err := decodeV2Base64URL(pending.EncB, 1120)
	if err != nil {
		return err
	}
	_, transcriptHash, err := v2FullTranscript(pre, encA, encB)
	if err != nil {
		return err
	}
	confirmedTranscript, _ := confirmation[6].([]byte)
	if !bytes.Equal(confirmedTranscript, transcriptHash) {
		return errors.New("key confirmation transcript hash is invalid")
	}
	code, err := parseV2PairingCode(pending.PairingCode)
	if err != nil {
		return err
	}
	locator, err := hex.DecodeString(pending.RendezvousLocator)
	if err != nil || len(locator) != 32 {
		return errors.New("pending pairing locator is invalid")
	}
	expectedBinder, err := v2PairingBinder(code, locator, "inviter", transcriptHash)
	if err != nil || !bytes.Equal(expectedBinder, confirmation[7].([]byte)) {
		return errors.New("pairing key confirmation authentication failed")
	}
	relationshipID, _ := hex.DecodeString(pending.RelationshipID)
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		return err
	}
	localPrivate, err := v2HPKEPrivateKey(seed, relationshipID)
	if err != nil {
		return err
	}
	preBytes, err := v2EncMode.Marshal(pre)
	if err != nil {
		return err
	}
	preDigest := sha256.Sum256(preBytes)
	recipientA, err := hpke.NewRecipient(encA, localPrivate, hpke.HKDFSHA256(), hpke.ExportOnly(), preDigest[:])
	if err != nil {
		return err
	}
	secretA, err := recipientA.Export(v2PairingExporterContext, 32)
	if err != nil {
		return err
	}
	secretB, err := decodeV2Base64URL(pending.SecretB, 32)
	if err != nil {
		return err
	}
	pairingPSK, err := deriveV2PairingKey(code, locator, "relationship-psk")
	if err != nil {
		return err
	}
	inviterToInvitee, inviteeToInviter, err := deriveV2PairingOutputs(secretA, secretB, pairingPSK, transcriptHash)
	if err != nil {
		return err
	}
	pending.KeyConfirmationMap, _ = encodeV2StoredMap(confirmation)
	pending.EncA = v2Base64URL(encA)
	pending.SecretA = v2Base64URL(secretA)
	pending.OutboundRelationshipSecret = v2Base64URL(inviteeToInviter)
	pending.InboundRelationshipSecret = v2Base64URL(inviterToInvitee)
	pending.FullTranscriptHash = hex.EncodeToString(transcriptHash)
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return err
	}
	defer unlock()
	return writeV2PendingPairing(paths, pending)
}

func (a *app) submitV2PairingCompletion(paths v2Paths, pending *v2PendingPairing, transport v2Transport) error {
	relationshipID, err := hex.DecodeString(pending.RelationshipID)
	if err != nil {
		return err
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		return err
	}
	signingKey, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	var completion map[int]any
	var signature []byte
	if pending.CompletionMap == "" {
		transcriptHash, err := hex.DecodeString(pending.FullTranscriptHash)
		if err != nil || len(transcriptHash) != 32 {
			return errors.New("pending pairing transcript is invalid")
		}
		invitationID, err := hex.DecodeString(pending.InvitationID)
		if err != nil || len(invitationID) != 32 {
			return errors.New("pending invitation ID is invalid")
		}
		completion = map[int]any{
			1: uint64(2),
			2: invitationID,
			3: relationshipID,
			4: transcriptHash,
			5: pending.Role,
			6: uint64(time.Now().Unix()),
		}
		signature, err = v2PairingSign("pairing-complete", completion, signingKey)
		if err != nil {
			return err
		}
		pending.CompletionMap, _ = encodeV2StoredMap(completion)
		pending.CompletionSignature = v2Base64URL(signature)
		unlock, err := acquireV2ConfigLock(paths)
		if err != nil {
			return err
		}
		if err := writeV2PendingPairing(paths, pending); err != nil {
			unlock()
			return err
		}
		unlock()
	} else {
		completion, err = decodeV2StoredMap(pending.CompletionMap)
		if err != nil {
			return err
		}
		signature, err = decodeV2Base64URL(pending.CompletionSignature, 64)
		if err != nil {
			return err
		}
	}
	body, err := v2EncMode.Marshal(map[int]any{1: completion, 2: signature})
	if err != nil {
		return err
	}
	bearer, err := decodeV2Base64URL(pending.StatusCapability, 32)
	if err != nil {
		return err
	}
	path := "/v2/pairing/rendezvous/" + pending.RendezvousLocator + "/complete"
	if _, err := doV2CBORRequest(context.Background(), transport, "POST", pending.CanonicalOrigin, path, bearer, body, v2MaxDescriptorBytes); err != nil {
		return err
	}
	pending.Completed = true
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return err
	}
	defer unlock()
	return writeV2PendingPairing(paths, pending)
}

func (a *app) finalizeV2Pairing(cfg *v2LocalConfig, paths v2Paths, pending *v2PendingPairing, transport v2Transport, jsonOutput bool) error {
	status, err := fetchV2PairingStatus(pending, transport)
	if err != nil {
		return err
	}
	return a.finalizeV2PairingStatus(cfg, paths, pending, status, jsonOutput)
}

func (a *app) finalizeV2PairingStatus(cfg *v2LocalConfig, paths v2Paths, pending *v2PendingPairing, status map[int]any, jsonOutput bool) error {
	phase, _ := asV2Uint(status[1])
	if phase != 3 {
		return errors.New("pairing is not active on both devices")
	}
	grant, ok := status[6].([]byte)
	if !ok || len(grant) == 0 {
		return errors.New("active pairing status omitted the encrypted capability grant")
	}
	relationshipID, err := hex.DecodeString(pending.RelationshipID)
	if err != nil {
		return err
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		return err
	}
	identity, err := deriveV2RelationshipIdentity(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	capabilities, err := decryptV2CapabilityGrant(grant, identity, relationshipID, pending.Role, pending.CanonicalOrigin)
	if err != nil {
		return err
	}
	state := newV2PeerDeliveryState(pending, capabilities)
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return err
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		unlock()
		return err
	}
	unlock()
	_, err = updateV2Config(func(current *v2LocalConfig) error {
		peer, exists := current.Peers[pending.Alias]
		if !exists {
			return fmt.Errorf("peer %q disappeared during pairing", pending.Alias)
		}
		peer.Status = "active"
		peer.RelationshipID = pending.RelationshipID
		peer.KeyEpoch = 0
		peerPairingID, err := decodeV2Base64URL(pending.PeerPairingID, 16)
		if err != nil {
			return errors.New("pending peer pairing identity is invalid")
		}
		peer.PeerPseudonymousID = hex.EncodeToString(peerPairingID)
		peer.PeerAgeRecipient = pending.PeerAgeRecipient
		peer.PeerSigningPublicKey = pending.PeerSigningPublicKey
		peer.BaseURL = pending.CanonicalOrigin
		peer.InboxCapabilityReference = "deliveries/" + pending.RelationshipID + ".json"
		current.Peers[pending.Alias] = peer
		return nil
	})
	if err != nil {
		return err
	}
	if err := removeV2PendingPairing(paths, pending.Alias); err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(a.out, map[string]any{
			"alias":            pending.Alias,
			"active":           true,
			"relationship":     pending.RelationshipID,
			"capabilities":     "<redacted>",
			"canonical_origin": pending.CanonicalOrigin,
		})
	}
	fmt.Fprintf(a.out, "Peer %q is active after mutual pairing-code authentication.\n", pending.Alias)
	return nil
}

func (a *app) waitV2Pairing(cfg *v2LocalConfig, paths v2Paths, pending *v2PendingPairing, transport v2Transport, jsonOutput bool) error {
	for {
		if pending.ExpiresAt <= uint64(time.Now().Unix()) {
			_ = removeV2PendingPairing(paths, pending.Alias)
			return errors.New(v2PairingInvalidCodeMessage)
		}
		phase, err := a.progressV2Pairing(cfg, paths, pending, transport)
		if err != nil {
			return err
		}
		if phase == 3 {
			return a.finalizeV2Pairing(cfg, paths, pending, transport, jsonOutput)
		}
		time.Sleep(time.Second)
	}
}

func (a *app) cmdPeerRevoke(args []string) error {
	if len(args) == 0 {
		return fatalError("dud peer revoke requires NAME --yes")
	}
	alias := args[0]
	confirmed := false
	jsonOutput := false
	for _, option := range args[1:] {
		switch option {
		case "--yes":
			confirmed = true
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
		default:
			return fatalError("Unknown peer revoke option: " + option)
		}
	}
	if !confirmed {
		return fatalError("peer revocation preserves but disables pending delivery state; rerun with --yes")
	}
	if err := a.withV2Peer(alias, 30*time.Second, func(runtime *v2PeerRuntime) error {
		_ = runtime.boundedControlDrain(context.Background())
		if err := runtime.flushPendingCompletions(context.Background()); err != nil {
			return fmt.Errorf("flush queued completions before revocation: %w", err)
		}
		if err := runtime.flushPendingGranularDeliveries(context.Background()); err != nil {
			return fmt.Errorf("flush queued deliveries before revocation: %w", err)
		}
		if err := runtime.flushPendingControlPublications(context.Background()); err != nil {
			return fmt.Errorf("flush queued control events before revocation: %w", err)
		}
		if err := runtime.publishPeerRevocation(context.Background(), 0); err != nil {
			return fmt.Errorf("publish signed peer revocation before disabling its capabilities: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	peer, exists := cfg.Peers[alias]
	if !exists {
		return fmt.Errorf("unknown peer %q", alias)
	}
	relationshipID, err := hex.DecodeString(peer.RelationshipID)
	if err != nil || len(relationshipID) != 16 {
		return errors.New("peer relationship ID is invalid")
	}
	admin, err := loadV2AdminCapability(paths)
	if err != nil {
		return err
	}
	transport, err := newV2PeerTransport(a, cfg, &peer, 30*time.Second)
	if err != nil {
		return err
	}
	body, err := v2EncMode.Marshal(map[int]any{1: relationshipID})
	if err != nil {
		return err
	}
	if _, err := doV2CBORRequest(
		context.Background(),
		transport,
		"POST",
		peer.BaseURL,
		"/v2/admin/relationships/revoke",
		admin,
		body,
		v2MaxDescriptorBytes,
	); err != nil {
		return err
	}
	if peer.Status == "active" {
		state, stateErr := loadV2PeerDeliveryState(paths, peer.RelationshipID)
		if stateErr == nil {
			state.Halted = true
			state.HaltReason = "relationship revoked locally"
			if err := writeV2PeerDeliveryState(paths, state); err != nil {
				return err
			}
		}
	}
	if _, err := updateV2Config(func(current *v2LocalConfig) error {
		value := current.Peers[alias]
		value.Status = "revoked"
		current.Peers[alias] = value
		return nil
	}); err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(a.out, map[string]any{"alias": alias, "revoked": true})
	}
	fmt.Fprintf(a.out, "Revoked peer %q. Retained local state for recovery evidence.\n", alias)
	return nil
}

// cmdPeerResume clears a quarantined delivery chain after the operator accepts
// that the sequences it stopped on are gone for good.
//
// A gap quarantine is not a fault to retry past: deliveries are strictly
// ordered, so a missing sequence means the chain cannot continue without
// abandoning it. That is the operator's call, never the client's, so this
// names exactly what is being given up and requires the peer alias typed back
// before it touches anything.
func (a *app) cmdPeerResume(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fatalError("dud peer resume requires NAME")
	}
	alias := args[0]
	confirmed := false
	jsonOutput := false
	for _, option := range args[1:] {
		switch option {
		case "--yes":
			confirmed = true
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
		default:
			return fatalError("Unknown peer resume option: " + option)
		}
	}

	return a.withV2Peer(alias, 30*time.Second, func(runtime *v2PeerRuntime) error {
		quarantined := make([]string, 0, len(runtime.state.Chains))
		for name, chain := range runtime.state.Chains {
			if chain != nil && chain.Quarantined {
				quarantined = append(quarantined, name)
			}
		}
		sort.Strings(quarantined)
		if len(quarantined) == 0 {
			return fatalError("peer \"" + alias + "\" has no quarantined delivery chain")
		}

		for _, name := range quarantined {
			fmt.Fprintf(a.out, "Chain %s is quarantined: %s\n", name, runtime.state.Chains[name].QuarantineReason)
		}
		fmt.Fprintln(a.out, "Resuming abandons the skipped deliveries. They are not")
		fmt.Fprintln(a.out, "recoverable, and ordering will not cover them. Later deliveries")
		fmt.Fprintln(a.out, "stay ordered from the next one accepted.")

		if !confirmed {
			fmt.Fprintf(a.out, "Type the peer name %q to confirm: ", alias)
			reader, ok := a.in.(*bufio.Reader)
			if !ok {
				reader = bufio.NewReader(a.in)
			}
			if readLine(reader) != alias {
				return fatalError("peer resume was not confirmed")
			}
		}

		for _, name := range quarantined {
			chain := runtime.state.Chains[name]
			chain.Quarantined = false
			chain.QuarantineReason = ""
			// Authorizes exactly one forward jump, spent by the next accepted
			// delivery on this chain.
			chain.ResumeApproved = true
		}
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(a.out, map[string]any{
				"peer":            alias,
				"resumed_chains":  quarantined,
				"pending_receive": "the next delivery on each chain is accepted even if it skips a sequence",
			})
		}
		fmt.Fprintf(a.out, "Resumed %d chain(s) for %q. Run dud receive %s to continue.\n",
			len(quarantined), alias, alias)
		return nil
	})
}
