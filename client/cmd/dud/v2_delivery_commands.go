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
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

const (
	v2MaximumObjectBytes = 100 * 1024 * 1024
	v2MaximumTTLSeconds  = 30 * 24 * 60 * 60
)

type v2PeerRuntime struct {
	cfg            *v2LocalConfig
	paths          v2Paths
	peer           v2PeerProfile
	state          *v2PeerDeliveryState
	seed           []byte
	relationshipID []byte
	localID        []byte
	peerID         []byte
	signingKey     ed25519.PrivateKey
	identity       age.Identity
	recipient      age.Recipient
	origin         string
	transport      v2Transport
	maxTTL         uint64
}

type v2PeerSendOptions struct {
	alias           string
	message         string
	stdin           bool
	files           []string
	displayName     string
	deleteAfterRead bool
	ttl             time.Duration
	json            bool
	verbose         bool
}

type v2PeerReceiveOptions struct {
	alias       string
	out         string
	outDir      string
	id          string
	wait        time.Duration
	max         int
	noExtract   bool
	onConflict  string
	interactive bool
	json        bool
	verbose     bool
}

func (a *app) withV2Peer(alias string, timeout time.Duration, operation func(*v2PeerRuntime) error) error {
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	peer, exists := cfg.Peers[alias]
	if !exists {
		return fmt.Errorf("unknown peer %q", alias)
	}
	if peer.Status != "active" {
		return fmt.Errorf("peer %q is not active; complete pairing first", alias)
	}
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return err
	}
	defer unlock()
	relationshipID, err := hex.DecodeString(peer.RelationshipID)
	if err != nil || len(relationshipID) != 16 {
		return errors.New("peer relationship ID is invalid")
	}
	state, err := loadV2PeerDeliveryState(paths, peer.RelationshipID)
	if err != nil {
		return err
	}
	changed, pruneProblems := pruneV2ExpiredInboundTransfers(state, uint64(time.Now().Unix()))
	if changed {
		if err := writeV2PeerDeliveryState(paths, state); err != nil {
			return err
		}
	}
	for _, problem := range pruneProblems {
		fmt.Fprintf(a.errOut, "WARNING: %v; the plaintext stays on disk and the next peer operation retries it\n", problem)
	}
	if state.Halted {
		return fmt.Errorf("peer relationship is halted: %s; revoke and pair again", state.HaltReason)
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		return err
	}
	localID, err := deriveV2DeviceID(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	peerID, err := hex.DecodeString(peer.PeerPseudonymousID)
	if err != nil || len(peerID) != 16 {
		return errors.New("peer pseudonymous ID is invalid")
	}
	signingKey, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	identity, err := deriveV2RelationshipIdentity(seed, relationshipID, 0)
	if err != nil {
		return err
	}
	rawRecipient, err := decodeV2Base64URL(peer.PeerAgeRecipient, 1216)
	if err != nil {
		return errors.New("peer hybrid recipient is invalid")
	}
	recipient, err := age.ParseHybridRecipient(bech32Encode("age1pq", rawRecipient))
	if err != nil {
		return fmt.Errorf("parse peer hybrid recipient: %w", err)
	}
	origin, _, _, err := effectiveV2NetworkConfig(cfg, &peer)
	if err != nil {
		return err
	}
	transport, err := newV2PeerTransport(a, cfg, &peer, timeout)
	if err != nil {
		return err
	}
	runtime := &v2PeerRuntime{
		cfg:            cfg,
		paths:          paths,
		peer:           peer,
		state:          state,
		seed:           seed,
		relationshipID: relationshipID,
		localID:        localID,
		peerID:         peerID,
		signingKey:     signingKey,
		identity:       identity,
		recipient:      recipient,
		origin:         origin,
		transport:      transport,
	}
	if err := runtime.requirePeerFeatures(); err != nil {
		return err
	}
	serverExpiry := state.CapabilitiesIssuedAt + runtime.maxTTL
	if state.CapabilitiesIssuedAt > 0 &&
		(state.CapabilitiesExpireAt == 0 || state.CapabilitiesExpireAt > serverExpiry) {
		state.CapabilitiesExpireAt = serverExpiry
		if err := writeV2PeerDeliveryState(paths, state); err != nil {
			return err
		}
	}
	if state.CapabilitiesExpireAt <= uint64(time.Now().Add(24*time.Hour).Unix()) {
		if err := runtime.reissueCapabilities(context.Background()); err != nil {
			return fmt.Errorf("recover expiring peer capabilities: %w", err)
		}
	}
	return operation(runtime)
}

func (runtime *v2PeerRuntime) requirePeerFeatures() error {
	capabilities, err := runtime.state.ServerContract.capabilities()
	if err != nil {
		return fmt.Errorf("stored peer server contract is invalid; re-pair this peer to refresh its protocol contract: %w", err)
	}
	if err := requireV2CapabilityFeatures(capabilities, 2, 3, 9, 10, 11); err != nil {
		return err
	}
	if capabilities.Limits[2] < v2MaxDescriptorBytes {
		return errors.New("peer server descriptor limit is below the v2 requirement")
	}
	runtime.maxTTL = capabilities.Limits[3]
	return nil
}

func (runtime *v2PeerRuntime) requireGitFeatures() error {
	capabilities, err := runtime.state.ServerContract.capabilities()
	if err != nil {
		return fmt.Errorf("stored peer server contract is invalid; re-pair this peer to refresh its protocol contract: %w", err)
	}
	return requireV2CapabilityFeatures(capabilities, 5)
}

func (runtime *v2PeerRuntime) reissueCapabilities(ctx context.Context) error {
	serverCapabilities, err := requireV2Features(
		ctx,
		runtime.transport,
		runtime.origin,
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
	if serverCapabilities.Limits[2] < v2MaxDescriptorBytes {
		return errors.New("peer server descriptor limit is below the v2 requirement")
	}
	nonce, err := randomV2Bytes(32)
	if err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	reissueMap := map[int]any{
		1: uint64(2),
		2: runtime.relationshipID,
		3: runtime.state.Role,
		4: nonce,
		5: now + 60,
		6: []string{"ack", "read", "write"},
		7: runtime.origin,
	}
	encoded, err := v2EncMode.Marshal(reissueMap)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	signatureInput := append(
		[]byte("dud/v2/capability-reissue\x00"),
		digest[:]...,
	)
	signature := ed25519.Sign(runtime.signingKey, signatureInput)
	body, err := v2EncMode.Marshal(map[int]any{
		1: reissueMap,
		2: signature,
	})
	if err != nil {
		return err
	}
	response, err := doV2CBORRequest(
		ctx,
		runtime.transport,
		"POST",
		runtime.origin,
		"/v2/capabilities/reissue",
		nil,
		body,
		v2MaxDescriptorBytes,
	)
	if err != nil {
		return err
	}
	var result map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &result); err != nil {
		return err
	}
	grant, ok := result[1].([]byte)
	if !ok || len(grant) == 0 {
		return errors.New("capability reissue response omitted its encrypted grant")
	}
	capabilities, err := decryptV2CapabilityGrant(
		grant,
		runtime.identity,
		runtime.relationshipID,
		runtime.state.Role,
		runtime.origin,
	)
	if err != nil {
		return err
	}
	runtime.state.Capabilities = capabilities
	runtime.state.ServerContract = serverContract
	runtime.state.CapabilitiesIssuedAt = now
	runtime.maxTTL = serverCapabilities.Limits[3]
	runtime.state.CapabilitiesExpireAt = now + runtime.maxTTL
	runtime.state.CapabilityReissues++
	return writeV2PeerDeliveryState(runtime.paths, runtime.state)
}

func encryptV2Payload(plaintext []byte, recipient age.Recipient) ([]byte, error) {
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return ciphertext.Bytes(), nil
}

func decryptV2Payload(ciphertext []byte, identity age.Identity, maximum int64) ([]byte, error) {
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt peer payload: %w", err)
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(plaintext)) > maximum {
		return nil, errors.New("peer payload exceeds the local size limit")
	}
	return plaintext, nil
}

func parseV2PeerSendOptions(args []string) (v2PeerSendOptions, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return v2PeerSendOptions{}, fatalError("dud send requires a positional peer alias")
	}
	opts := v2PeerSendOptions{alias: args[0], ttl: 7 * 24 * time.Hour}
	for args = args[1:]; len(args) != 0; {
		switch args[0] {
		case "-m", "--message":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			if opts.message != "" {
				return opts, errors.New("a message may be specified only once")
			}
			opts.message, args = args[1], args[2:]
		case "--stdin":
			opts.stdin, args = true, args[1:]
		case "--file":
			if err := needValue(args, "--file"); err != nil {
				return opts, err
			}
			opts.files = append(opts.files, args[1])
			args = args[2:]
		case "--name":
			if err := needValue(args, "--name"); err != nil {
				return opts, err
			}
			opts.displayName, args = args[1], args[2:]
		case "--ttl":
			if err := needValue(args, "--ttl"); err != nil {
				return opts, err
			}
			value, err := time.ParseDuration(args[1])
			if err != nil || value <= 0 || value > 30*24*time.Hour {
				return opts, errors.New("--ttl must be between 1 second and 720 hours")
			}
			opts.ttl, args = value, args[2:]
		case "--delete-after-read":
			opts.deleteAfterRead, args = true, args[1:]
		case "--json":
			if err := markJSONOption(&opts.json); err != nil {
				return opts, err
			}
			args = args[1:]
		case "-v", "--verbose":
			if err := markVerboseOption(&opts.verbose); err != nil {
				return opts, err
			}
			args = args[1:]
		case "--recipient", "-r", "--recipients-file", "-R", "--passphrase", "--url", "--doh-url", "--ech-mode":
			return opts, v2PeerNetworkOptionError(args[0])
		default:
			if !strings.HasPrefix(args[0], "-") {
				return opts, errors.New("peer send accepts exactly one positional peer alias")
			}
			return opts, fatalError("Unknown peer send option: " + args[0])
		}
	}
	sources := 0
	if opts.message != "" {
		sources++
	}
	if opts.stdin {
		sources++
	}
	if len(opts.files) != 0 {
		sources++
	}
	if sources != 1 {
		return opts, errors.New("peer send requires exactly one of -m TEXT, --stdin, or --file PATH")
	}
	return opts, nil
}

func (a *app) readV2PeerSendPayload(opts v2PeerSendOptions) ([]byte, uint64, string, map[int]any, *uint64, error) {
	if opts.message != "" {
		return []byte(opts.message), 1, opts.displayName, nil, nil, nil
	}
	// --stdin carries the same text payload a one-line -m does, so the read is
	// bounded by the object limit the delivery would hit anyway. That keeps a
	// pipe that never ends from buffering without limit.
	if opts.stdin {
		if stdinIsTTY() {
			fmt.Fprintln(a.errOut, "Enter plaintext, then press Ctrl-D when finished.")
		}
		message, err := io.ReadAll(io.LimitReader(a.in, v2MaximumObjectBytes+1))
		if err != nil {
			return nil, 0, "", nil, nil, err
		}
		if len(message) > v2MaximumObjectBytes {
			return nil, 0, "", nil, nil, errors.New("peer payload exceeds the server object limit")
		}
		if len(message) == 0 {
			return nil, 0, "", nil, nil, errors.New("peer send read an empty payload from standard input")
		}
		return message, 1, opts.displayName, nil, nil, nil
	}
	collection := len(opts.files) > 1
	for _, raw := range opts.files {
		info, err := os.Lstat(absPathIfRelative(raw))
		if err != nil {
			return nil, 0, "", nil, nil, err
		}
		if info.IsDir() {
			collection = true
		}
	}
	if collection {
		body, names, err := createV2CollectionArchive(opts.files)
		if err != nil {
			return nil, 0, "", nil, nil, err
		}
		format := uint64(1)
		name := opts.displayName
		if name == "" {
			name = "collection"
		}
		return body, 3, name, map[int]any{
			1: uint64(len(names)),
			2: names,
		}, &format, nil
	}
	path := absPathIfRelative(opts.files[0])
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, "", nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, "", nil, nil, errors.New("peer send requires regular files or directories")
	}
	if info.Size() > v2MaximumObjectBytes {
		return nil, 0, "", nil, nil, errors.New("peer plaintext exceeds the 100 MiB object limit")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, "", nil, nil, err
	}
	name := opts.displayName
	if name == "" {
		name = filepath.Base(path)
	}
	if name == "." || name == string(filepath.Separator) || strings.ContainsAny(name, `/\`) {
		return nil, 0, "", nil, nil, errors.New("peer display name must be a single path component")
	}
	return body, 2, name, nil, nil, nil
}

func v2TransportPolicyMap(policy v2TransportPolicy) map[int]any {
	return map[int]any{
		1: policy.ExpiresAt,
		2: policy.Consume,
		3: policy.ClaimLeaseSeconds,
		4: policy.AckMode,
	}
}

// The separator set covers both conventions, because a name chosen by the peer
// is not bound to the receiving host's.
func v2SafeReceivedFileName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return errors.New("peer display name must be a single path component")
	}
	return nil
}

func v2PolicyDigest(policy map[int]any) ([]byte, error) {
	body, err := v2EncMode.Marshal(policy)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	return digest[:], nil
}

func validateV2EffectivePolicy(signed, effective map[int]any) error {
	for _, key := range []int{2, 3, 4} {
		want, wantOK := asV2Uint(signed[key])
		got, gotOK := asV2Uint(effective[key])
		if !wantOK || !gotOK || want != got {
			return errors.New("server effective policy weakens or changes signed semantics")
		}
	}
	wantExpiry, wantOK := asV2Uint(signed[1])
	gotExpiry, gotOK := asV2Uint(effective[1])
	if !wantOK || !gotOK || gotExpiry == 0 || gotExpiry > wantExpiry {
		return errors.New("server effective policy has an invalid expiry")
	}
	return nil
}

func (runtime *v2PeerRuntime) granularControlQueryProofs(now time.Time) ([]v2GranularSlotProofInput, error) {
	secret, err := decodeV2Base64URL(runtime.state.InboundRelationshipSecret, 32)
	if err != nil {
		return nil, err
	}
	readSecret, err := v2CapabilitySecret(runtime.state, v2InboundDirection(runtime.state.Role), "read")
	if err != nil {
		return nil, err
	}
	current := v2SlotEpoch(now)
	proofs := make([]v2GranularSlotProofInput, 0, v2DeliveryRecoveryDays)
	for _, epoch := range v2ControlRecoveryEpochs(runtime.state.ControlScanEpoch, current) {
		slot, slotErr := deriveV2Slot(secret, "control", epoch)
		if slotErr != nil {
			return nil, slotErr
		}
		proof, proofErr := newV2GranularSlotProofInput(
			readSecret,
			v2DirectionName(v2InboundDirection(runtime.state.Role)),
			"read",
			v2GranularControlChain,
			slot,
			epoch,
			now,
		)
		if proofErr != nil {
			return nil, proofErr
		}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}

func (runtime *v2PeerRuntime) granularDataQueryProofs(now time.Time) ([]v2GranularSlotProofInput, error) {
	secret, err := decodeV2Base64URL(runtime.state.InboundRelationshipSecret, 32)
	if err != nil {
		return nil, err
	}
	readSecret, err := v2CapabilitySecret(runtime.state, v2InboundDirection(runtime.state.Role), "read")
	if err != nil {
		return nil, err
	}
	current := v2SlotEpoch(now)
	epochs := v2ControlRecoveryEpochs(runtime.state.DataScanEpoch, current)
	seen := make(map[uint64]bool, len(epochs))
	for _, epoch := range epochs {
		seen[epoch] = true
	}
	for _, epoch := range runtime.state.PendingDataEpochs {
		if epoch <= current && !seen[epoch] && len(epochs) < v2GranularMaxSlotProofs {
			epochs = append(epochs, epoch)
			seen[epoch] = true
		}
	}
	sort.Slice(epochs, func(left, right int) bool { return epochs[left] < epochs[right] })
	proofs := make([]v2GranularSlotProofInput, 0, len(epochs))
	for _, epoch := range epochs {
		slot, slotErr := deriveV2Slot(secret, "data", epoch)
		if slotErr != nil {
			return nil, slotErr
		}
		proof, proofErr := newV2GranularSlotProofInput(readSecret, v2DirectionName(v2InboundDirection(runtime.state.Role)), "read", v2GranularDataChain, slot, epoch, now)
		if proofErr != nil {
			return nil, proofErr
		}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}

func (runtime *v2PeerRuntime) applyV2GranularControlResponse(rawEvents []any) error {
	events, err := decodeV2GranularControlEvents(map[int]any{2: rawEvents})
	if err != nil {
		return err
	}
	pending := make([]string, 0, len(events))
	for _, event := range events {
		if err := runtime.applyV2GranularControlEnvelope(event.Envelope); err != nil {
			return err
		}
		pending = append(pending, event.ID)
	}
	runtime.state.PendingControlEventIDs = pending
	return nil
}

func (runtime *v2PeerRuntime) flushPendingGranularDeliveries(ctx context.Context) error {
	for len(runtime.state.PendingGranularDeliveries) != 0 {
		queued := runtime.state.PendingGranularDeliveries[0]
		now := time.Now()
		if queued.NextAttemptAt > uint64(now.Unix()) {
			return fmt.Errorf("next granular delivery retry is scheduled at %d", queued.NextAttemptAt)
		}
		operationID, operationErr := hex.DecodeString(queued.OperationID)
		descriptor, descriptorErr := decodeV2Base64URL(queued.EncryptedDescriptor, -1)
		payload, payloadErr := decodeV2Base64URL(queued.PayloadCiphertext, -1)
		slot, slotErr := hex.DecodeString(queued.DataSlot)
		policyBytes, policyErr := decodeV2Base64URL(queued.RequestedPolicy, -1)
		if operationErr != nil || len(operationID) != 16 || descriptorErr != nil || len(descriptor) == 0 || payloadErr != nil || slotErr != nil || len(slot) != 16 || policyErr != nil {
			return errors.New("queued granular delivery is invalid")
		}
		var policy map[int]any
		if err := v2DecMode.Unmarshal(policyBytes, &policy); err != nil {
			return errors.New("queued granular delivery policy is invalid")
		}
		canonicalPolicy, err := v2EncMode.Marshal(policy)
		if err != nil || !bytes.Equal(canonicalPolicy, policyBytes) {
			return errors.New("queued granular delivery policy is not deterministic")
		}
		publish := func(at time.Time) error {
			writeSecret, secretErr := v2CapabilitySecret(runtime.state, v2OutboundDirection(runtime.state.Role), "write")
			if secretErr != nil {
				return secretErr
			}
			dataProof, proofErr := newV2GranularSlotProofInput(
				writeSecret,
				v2DirectionName(v2OutboundDirection(runtime.state.Role)),
				"write",
				v2GranularDataChain,
				slot,
				queued.SlotEpoch,
				at,
			)
			if proofErr != nil {
				return proofErr
			}
			controls, controlsErr := runtime.granularControlQueryProofs(at)
			if controlsErr != nil {
				return controlsErr
			}
			processed, processErr := decodeV2ControlEventIDs(runtime.state.PendingControlEventIDs)
			if processErr != nil {
				return processErr
			}
			published, publishErr := publishV2GranularDelivery(
				ctx,
				runtime.transport,
				runtime.origin,
				operationID,
				descriptor,
				policy,
				payload,
				dataProof,
				controls,
				processed,
			)
			if publishErr != nil {
				return publishErr
			}
			if policyErr := validateV2EffectivePolicy(policy, published.EffectivePolicy); policyErr != nil {
				return policyErr
			}
			return runtime.applyV2GranularControlResponse(published.ControlEvents)
		}
		err = publish(now)
		if isRetryableV2ConnectionError(err) {
			if retiree, ok := runtime.transport.(v2ResolutionRetirer); ok {
				retiree.retireV2Resolution(runtime.origin)
			}
			err = publish(time.Now())
		}
		if err != nil {
			queued.Attempts++
			delay := v2BackoffWithJitter(queued.Attempts)
			queued.NextAttemptAt = uint64(now.Unix()) + uint64((delay+time.Second-1)/time.Second)
			runtime.state.PendingGranularDeliveries[0] = queued
			if writeErr := writeV2PeerDeliveryState(runtime.paths, runtime.state); writeErr != nil {
				return writeErr
			}
			return err
		}
		runtime.state.PendingGranularDeliveries = runtime.state.PendingGranularDeliveries[1:]
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return err
		}
	}
	return nil
}

// Only retry connection failures here. HTTP and protocol errors are definite
// outcomes, while a timeout or a temporary network failure can have reached
// the server after it committed the operation.
func isRetryableV2ConnectionError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var networkError interface {
		error
		Timeout() bool
		Temporary() bool
	}
	if errors.As(err, &networkError) {
		return networkError.Timeout() || networkError.Temporary()
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func (runtime *v2PeerRuntime) flushPendingCompletions(ctx context.Context) error {
	for len(runtime.state.PendingCompletions) != 0 {
		queued := runtime.state.PendingCompletions[0]
		now := time.Now()
		if queued.NextAttemptAt > uint64(now.Unix()) {
			return fmt.Errorf("next completion retry is scheduled at %d", queued.NextAttemptAt)
		}
		decode := func(value string, size int) ([]byte, error) {
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != size {
				return nil, errors.New("queued completion is invalid")
			}
			return decoded, nil
		}
		deliveryID, err := decode(queued.DeliveryID, 16)
		if err == nil {
			var sourceSlot, targetSlot, policyDigest, descriptorDigest, operationID []byte
			sourceSlot, err = decode(queued.SourceSlot, 16)
			if err == nil {
				targetSlot, err = decode(queued.TargetSlot, 16)
			}
			if err == nil {
				policyDigest, err = decode(queued.PolicyDigest, 32)
			}
			if err == nil {
				descriptorDigest, err = decode(queued.DescriptorDigest, 32)
			}
			if err == nil {
				operationID, err = decode(queued.OperationID, 16)
			}
			if err == nil {
				acknowledgement, ackErr := decodeV2Base64URL(queued.Acknowledgement, -1)
				if ackErr != nil || len(acknowledgement) == 0 || len(acknowledgement) > v2MaxDescriptorBytes {
					err = errors.New("queued completion acknowledgement is invalid")
				} else {
					publish := func(at time.Time) error {
						ackSecret, secretErr := v2CapabilitySecret(runtime.state, v2InboundDirection(runtime.state.Role), "ack")
						if secretErr != nil {
							return secretErr
						}
						controlSecret, secretErr := v2CapabilitySecret(runtime.state, v2OutboundDirection(runtime.state.Role), "write")
						if secretErr != nil {
							return secretErr
						}
						ackProof, proofErr := newV2GranularSlotProofInput(ackSecret, v2DirectionName(v2InboundDirection(runtime.state.Role)), "ack", v2GranularDataChain, sourceSlot, queued.SourceSlotEpoch, at)
						if proofErr != nil {
							return proofErr
						}
						controlProof, proofErr := newV2GranularSlotProofInput(controlSecret, v2DirectionName(v2OutboundDirection(runtime.state.Role)), "write", v2GranularControlChain, targetSlot, queued.TargetSlotEpoch, at)
						if proofErr != nil {
							return proofErr
						}
						_, completionErr := completeV2GranularDelivery(ctx, runtime.transport, runtime.origin, deliveryID, sourceSlot, targetSlot, policyDigest, descriptorDigest, queued.Result, operationID, acknowledgement, ackProof, controlProof)
						return completionErr
					}
					err = publish(now)
					if isRetryableV2ConnectionError(err) {
						if retiree, ok := runtime.transport.(v2ResolutionRetirer); ok {
							retiree.retireV2Resolution(runtime.origin)
						}
						err = publish(time.Now())
					}
				}
			}
		}
		if err != nil {
			queued.Attempts++
			delay := v2BackoffWithJitter(queued.Attempts)
			queued.NextAttemptAt = uint64(now.Unix()) + uint64((delay+time.Second-1)/time.Second)
			runtime.state.PendingCompletions[0] = queued
			if writeErr := writeV2PeerDeliveryState(runtime.paths, runtime.state); writeErr != nil {
				return writeErr
			}
			return err
		}
		runtime.state.PendingCompletions = runtime.state.PendingCompletions[1:]
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) cmdPeerSend(args []string) error {
	opts, err := parseV2PeerSendOptions(args)
	if err != nil {
		return err
	}
	plaintext, payloadType, displayName, typeMetadata, archiveFormat, err := a.readV2PeerSendPayload(opts)
	if err != nil {
		return err
	}
	return a.withV2Peer(opts.alias, 2*time.Minute, func(runtime *v2PeerRuntime) error {
		ctx := context.Background()
		if runtime.state.Halted {
			return fmt.Errorf("peer relationship is halted: %s", runtime.state.HaltReason)
		}
		if len(runtime.state.PendingGranularDeliveries) != 0 {
			if err := runtime.flushPendingGranularDeliveries(ctx); err != nil {
				return fmt.Errorf("retry pending atomic delivery: %w", err)
			}
		}
		payloadCiphertext, err := encryptV2Payload(plaintext, runtime.recipient)
		if err != nil {
			return err
		}
		if len(payloadCiphertext) > v2MaximumObjectBytes {
			return errors.New("encrypted peer payload exceeds the server object limit")
		}
		now := uint64(time.Now().Unix())
		consume := uint64(0)
		if opts.deleteAfterRead {
			consume = 1
		}
		policy := v2TransportPolicy{
			ExpiresAt:         now + uint64(opts.ttl/time.Second),
			Consume:           consume,
			ClaimLeaseSeconds: 300,
			AckMode:           1,
		}
		policyMap := v2TransportPolicyMap(policy)
		chain := runtime.state.Chains["out:data"]
		descriptorID, err := newV2DescriptorID()
		if err != nil {
			return err
		}
		plainDigest := sha256.Sum256(plaintext)
		cipherDigest := sha256.Sum256(payloadCiphertext)
		descriptor := v2Descriptor{
			DescriptorID:      descriptorID,
			PayloadType:       payloadType,
			RelationshipID:    runtime.relationshipID,
			Direction:         v2OutboundDirection(runtime.state.Role),
			Chain:             0,
			KeyEpoch:          0,
			Sequence:          chain.SendSequence + 1,
			PreviousDigest:    mustDecodeHexV2(chain.SendDigest, 32),
			SenderDeviceID:    runtime.localID,
			RecipientDeviceID: runtime.peerID,
			CanonicalOrigin:   runtime.origin,
			CreatedAt:         now,
			TransportPolicy:   policy,
			PayloadHash:       plainDigest[:],
			ChunkHashes:       [][]byte{cipherDigest[:]},
			DisplayName:       displayName,
			ArchiveFormat:     archiveFormat,
			TypeMetadata:      typeMetadata,
		}
		plaintextSize := uint64(len(plaintext))
		descriptor.PlaintextSize = &plaintextSize
		descriptorCiphertext, err := encryptV2Envelope(descriptor, runtime.signingKey, runtime.recipient)
		if err != nil {
			return err
		}
		signedMap, err := descriptorMap(descriptor, runtime.signingKey)
		if err != nil {
			return err
		}
		signedBytes, err := v2EncMode.Marshal(signedMap)
		if err != nil {
			return err
		}
		descriptorDigest := sha256.Sum256(signedBytes)
		secret, err := decodeV2Base64URL(runtime.state.OutboundRelationshipSecret, 32)
		if err != nil {
			return err
		}
		slotEpoch := v2SlotEpoch(time.Now())
		slot, err := deriveV2Slot(secret, "data", slotEpoch)
		if err != nil {
			return err
		}
		policyBytes, err := v2EncMode.Marshal(policyMap)
		if err != nil {
			return err
		}
		key := hex.EncodeToString(descriptorDigest[:])
		operationID, err := randomV2Bytes(16)
		if err != nil {
			return err
		}
		runtime.state.PendingGranularDeliveries = append(runtime.state.PendingGranularDeliveries, v2PendingGranularDelivery{
			OperationID:         hex.EncodeToString(operationID),
			EncryptedDescriptor: v2Base64URL(descriptorCiphertext),
			PayloadCiphertext:   v2Base64URL(payloadCiphertext),
			DataSlot:            hex.EncodeToString(slot),
			SlotEpoch:           slotEpoch,
			RequestedPolicy:     v2Base64URL(policyBytes),
			DescriptorDigest:    key,
			Sequence:            descriptor.Sequence,
			CreatedAt:           now,
		})
		chain.SendSequence = descriptor.Sequence
		chain.SendDigest = key
		runtime.state.Sent[key] = v2SentDelivery{
			Sequence:         descriptor.Sequence,
			DescriptorDigest: key,
			PayloadType:      payloadType,
		}
		if typeMetadata != nil {
			metadataBytes, metadataErr := v2EncMode.Marshal(typeMetadata)
			if metadataErr != nil {
				return metadataErr
			}
			sent := runtime.state.Sent[key]
			sent.TypeMetadata = v2Base64URL(metadataBytes)
			runtime.state.Sent[key] = sent
		}
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return err
		}
		if err := runtime.flushPendingGranularDeliveries(ctx); err != nil {
			return fmt.Errorf("delivery committed locally and will retry publication: %w", err)
		}
		status := v2DeliveryStatusOf(runtime.state)
		if opts.json {
			return writeJSON(a.out, status.merge(map[string]any{
				"peer":              opts.alias,
				"sequence":          descriptor.Sequence,
				"descriptor_digest": key,
				"acknowledged":      false,
			}))
		}
		// Nothing here waits for the acknowledgement: the delivery is published
		// and this command is done. The peer signs an acknowledgement when it
		// receives, and a later drain on this device applies it, so the line
		// names both halves rather than implying this run blocks on either.
		if err := fprintWrapped(a.out, "Sent to %s as data sequence %d.", opts.alias, descriptor.Sequence); err != nil {
			return err
		}
		if err := fprintWrapped(a.out,
			"Not acknowledged yet; 'dud sync %s' collects the acknowledgement.",
			opts.alias); err != nil {
			return err
		}
		return status.reportWhen(opts.verbose, "Status").write(a.out)
	})
}

func mustDecodeHexV2(value string, size int) []byte {
	result, err := hex.DecodeString(value)
	if err != nil || len(result) != size {
		panic("validated peer state contains an invalid digest")
	}
	return result
}

func parseV2PeerReceiveOptions(args []string) (v2PeerReceiveOptions, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return v2PeerReceiveOptions{}, fatalError("dud receive requires a positional peer alias")
	}
	opts := v2PeerReceiveOptions{alias: args[0], onConflict: "skip"}
	for args = args[1:]; len(args) != 0; {
		switch args[0] {
		case "--max":
			if err := needValue(args, "--max"); err != nil {
				return opts, err
			}
			value, err := strconv.Atoi(args[1])
			if err != nil || value < 1 {
				return opts, errors.New("--max must be a positive count of deliveries")
			}
			opts.max, args = value, args[2:]
		case "--on-conflict":
			if err := needValue(args, "--on-conflict"); err != nil {
				return opts, err
			}
			switch args[1] {
			case "refuse", "skip", "overwrite":
				opts.onConflict, args = args[1], args[2:]
			default:
				return opts, errors.New("--on-conflict must be refuse, skip, or overwrite")
			}
		case "--out", "-o":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.out, args = absPathIfRelative(args[1]), args[2:]
		case "--out-dir":
			if err := needValue(args, "--out-dir"); err != nil {
				return opts, err
			}
			opts.outDir, args = absPathIfRelative(args[1]), args[2:]
		case "--id":
			if err := needValue(args, "--id"); err != nil {
				return opts, err
			}
			opts.id, args = strings.ToLower(args[1]), args[2:]
		case "--wait":
			if err := needValue(args, "--wait"); err != nil {
				return opts, err
			}
			value, err := time.ParseDuration(args[1])
			if err != nil || value < 0 {
				return opts, errors.New("--wait must be a non-negative duration")
			}
			opts.wait, args = value, args[2:]
		case "--no-extract":
			opts.noExtract, args = true, args[1:]
		case "--collection-overwrite":
			// A narrow alias for --on-conflict, which covers files and
			// collections alike. Only 'refuse' is accepted under this spelling.
			if err := needValue(args, "--collection-overwrite"); err != nil {
				return opts, err
			}
			if args[1] != "refuse" {
				return opts, errors.New("--collection-overwrite only accepts 'refuse'; use --on-conflict instead")
			}
			opts.onConflict, args = "refuse", args[2:]
		case "--interactive":
			opts.interactive, args = true, args[1:]
		case "--json":
			if err := markJSONOption(&opts.json); err != nil {
				return opts, err
			}
			args = args[1:]
		case "-v", "--verbose":
			if err := markVerboseOption(&opts.verbose); err != nil {
				return opts, err
			}
			args = args[1:]
		case "--url", "--doh-url", "--ech-mode":
			return opts, v2PeerNetworkOptionError(args[0])
		default:
			if !strings.HasPrefix(args[0], "-") {
				return opts, errors.New("peer receive accepts exactly one positional peer alias")
			}
			return opts, fatalError("Unknown peer receive option: " + args[0])
		}
	}
	if opts.out != "" && opts.outDir != "" {
		return opts, errors.New("--out and --out-dir cannot be combined")
	}
	if opts.id != "" {
		if _, err := hex.DecodeString(opts.id); err != nil || len(opts.id) != 64 {
			return opts, errors.New("--id must be a 64-character descriptor digest")
		}
		if opts.wait != 0 {
			return opts, errors.New("--id and --wait cannot be combined")
		}
		if opts.max != 0 {
			return opts, errors.New("--id and --max cannot be combined")
		}
	}
	return opts, nil
}

func (a *app) confirmV2CollectionExtraction(entries []v2CollectionEntry) bool {
	fmt.Fprintln(a.out, "Verified collection contents:")
	for _, entry := range entries {
		if entry.dir {
			fmt.Fprintf(a.out, "  dir  %s/\n", safeTerminalText(entry.name))
			continue
		}
		fmt.Fprintf(a.out, "  file %s (%d bytes)\n", safeTerminalText(entry.name), entry.size)
	}
	fmt.Fprint(a.out, "Extract this collection? [y/N]: ")
	reader, ok := a.in.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(a.in)
	}
	answer := strings.ToLower(readLine(reader))
	return answer == "y" || answer == "yes"
}

func (a *app) cmdPeerReceive(args []string) error {
	opts, err := parseV2PeerReceiveOptions(args)
	if err != nil {
		return err
	}
	return a.withV2Peer(opts.alias, 2*time.Minute+opts.wait, func(runtime *v2PeerRuntime) error {
		ctx := context.Background()
		if runtime.state.Halted {
			return fmt.Errorf("peer relationship is halted: %s", runtime.state.HaltReason)
		}
		if len(runtime.state.PendingCompletions) != 0 {
			if err := runtime.flushPendingCompletions(ctx); err != nil {
				return fmt.Errorf("retry pending atomic completion: %w", err)
			}
		}
		if opts.id != "" {
			return runtime.exportCommittedTransfer(a, opts)
		}
		// One invocation drains the whole queue. The server hands back the
		// oldest delivery per request and retires it only when the completion
		// lands, so this is a plain loop over that pair rather than anything the
		// wire format has to know about.
		drained := []v2ReceivedItem{}
		var stop *v2ReceiveStop
		deadline := time.Now().Add(opts.wait)
		for stop == nil {
			item, sawDelivery, err := runtime.receiveAvailable(ctx, a, opts)
			if err != nil {
				if !errors.As(err, &stop) {
					return err
				}
				// Nothing was committed, so there is no partial result worth
				// reporting: fail the way a single-delivery receive always has.
				if len(drained) == 0 {
					return err
				}
				break
			}
			if item != nil {
				drained = append(drained, *item)
				// Reaching --max is the operator's own bound, not a condition
				// worth reporting: whether anything is still queued is already
				// the 'inbound waiting' row, and reporting a stop here would
				// change what --max 1 prints for no one's benefit.
				if opts.max != 0 && len(drained) >= opts.max {
					break
				}
				continue
			}
			if sawDelivery {
				// The queue head is a replay of something already applied. The
				// server will not retire it in response to a read, so looping
				// would spin on the same entry forever.
				stop = &v2ReceiveStop{Reason: "replay", Next: "dud receive " + opts.alias}
				break
			}
			if len(drained) != 0 {
				break
			}
			if opts.wait == 0 || time.Now().After(deadline) {
				break
			}
			delay := 850*time.Millisecond + time.Duration(time.Now().UnixNano()%300_000_000)
			if remaining := time.Until(deadline); delay > remaining {
				delay = remaining
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		return a.renderV2ReceiveReport(opts, drained, stop, v2DeliveryStatusOf(runtime.state))
	})
}

// receiveAvailable performs one inbox round trip. It reports the delivery it
// committed, if any, and separately whether the queue head held a delivery at
// all: a head this device has already applied is never retired by a read, so a
// caller that drains has to tell "nothing waiting" apart from "waiting, but not
// applicable" instead of polling the same entry forever.
func (runtime *v2PeerRuntime) receiveAvailable(ctx context.Context, a *app, opts v2PeerReceiveOptions) (*v2ReceivedItem, bool, error) {
	now := time.Now()
	dataProofs, err := runtime.granularDataQueryProofs(now)
	if err != nil {
		return nil, false, err
	}
	controlProofs, err := runtime.granularControlQueryProofs(now)
	if err != nil {
		return nil, false, err
	}
	processed, err := decodeV2ControlEventIDs(runtime.state.PendingControlEventIDs)
	if err != nil {
		return nil, false, err
	}
	response, err := queryV2GranularInbox(ctx, runtime.transport, runtime.origin, dataProofs, controlProofs, processed)
	if err != nil {
		return nil, false, err
	}
	rawControls, controlsOK := response.Header[2].([]any)
	if !controlsOK {
		return nil, false, errors.New("granular inbox control events are invalid")
	}
	if err := runtime.applyV2GranularControlResponse(rawControls); err != nil {
		return nil, false, err
	}
	if runtime.state.Halted {
		return nil, false, fmt.Errorf("peer relationship is halted: %s", runtime.state.HaltReason)
	}
	pendingEpochs, err := validateV2GranularDataSlotResults(response.Header, dataProofs)
	if err != nil {
		return nil, false, err
	}
	delivery, err := decodeV2GranularInboxDelivery(response)
	if err != nil {
		return nil, false, err
	}
	runtime.state.DataScanEpoch = v2SlotEpoch(now)
	runtime.state.PendingDataEpochs = pendingEpochs
	if delivery == nil {
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	var sourceEpoch uint64
	for _, proof := range dataProofs {
		if bytes.Equal(proof.Slot, delivery.Slot) {
			sourceEpoch = proof.Epoch
			break
		}
	}
	if sourceEpoch == 0 {
		return nil, true, errors.New("inbox delivery slot was not requested")
	}
	item, err := runtime.applyV2GranularDataDelivery(ctx, a, opts, delivery, sourceEpoch)
	return item, true, err
}

func validateV2GranularDataSlotResults(header map[int]any, proofs []v2GranularSlotProofInput) ([]uint64, error) {
	rawResults, resultsOK := header[1].([]any)
	rawPending, pendingOK := header[9].([]any)
	if !resultsOK || !pendingOK || len(rawResults) != len(proofs) || len(rawPending) > len(proofs) {
		return nil, errors.New("granular inbox slot results are invalid")
	}
	pending := make([]uint64, 0, len(rawPending))
	pendingSet := make(map[uint64]bool, len(rawPending))
	for _, raw := range rawPending {
		epoch, ok := asV2Uint(raw)
		if !ok || pendingSet[epoch] {
			return nil, errors.New("granular inbox pending epochs are invalid")
		}
		pendingSet[epoch] = true
		pending = append(pending, epoch)
	}
	for index, raw := range rawResults {
		entry, err := normalizeV2Map(raw)
		if err != nil || len(entry) != 3 {
			return nil, errors.New("granular inbox slot result is invalid")
		}
		slot, slotOK := entry[1].([]byte)
		epoch, epochOK := asV2Uint(entry[2])
		more, moreOK := entry[3].(bool)
		if !slotOK || !epochOK || !moreOK || !bytes.Equal(slot, proofs[index].Slot) || epoch != proofs[index].Epoch || more != pendingSet[epoch] {
			return nil, errors.New("granular inbox slot result does not match its query")
		}
	}
	sort.Slice(pending, func(left, right int) bool { return pending[left] < pending[right] })
	return pending, nil
}

func (runtime *v2PeerRuntime) descriptorExpectation() (v2DescriptorExpectation, error) {
	signingPublicKey, err := decodeV2Base64URL(runtime.peer.PeerSigningPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return v2DescriptorExpectation{}, errors.New("peer signing public key is invalid")
	}
	return v2DescriptorExpectation{
		RelationshipID:    runtime.relationshipID,
		Direction:         v2InboundDirection(runtime.state.Role),
		RecipientDeviceID: runtime.localID,
		CanonicalOrigin:   runtime.origin,
		SigningPublicKey:  ed25519.PublicKey(signingPublicKey),
	}, nil
}

func descriptorUint(desc map[int]any, key int, name string) (uint64, error) {
	value, ok := asV2Uint(desc[key])
	if !ok {
		return 0, fmt.Errorf("descriptor %s is invalid", name)
	}
	return value, nil
}

func descriptorPolicy(desc map[int]any) (map[int]any, error) {
	return normalizeV2Map(desc[kTransportPolicy])
}

// v2ExistingOutputMatches reports whether the file already at target holds
// exactly the payload about to be written there, which makes the write a
// no-op. Anything it cannot read — a directory, a broken symlink, a file it
// has no permission for — is not a match, so the caller still refuses rather
// than clobbering something it could not inspect.
func v2ExistingOutputMatches(target string, payloadDigest []byte) bool {
	existing, err := os.ReadFile(target)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(existing)
	return bytes.Equal(digest[:], payloadDigest)
}

func (runtime *v2PeerRuntime) validateNextDescriptor(chain *v2ChainState, envelope *validatedV2Envelope) (bool, error) {
	sequence, err := descriptorUint(envelope.Descriptor, kSequence, "sequence")
	if err != nil {
		return false, err
	}
	digest := hex.EncodeToString(envelope.DescriptorDigest[:])
	if sequence < chain.ReceiveWatermark {
		return false, nil
	}
	if sequence == chain.ReceiveWatermark {
		prior, exists := chain.Replay[sequence]
		if exists && prior.DescriptorDigest == digest {
			return false, nil
		}
		if !exists {
			return false, nil
		}
		chain.Quarantined = true
		chain.QuarantineReason = fmt.Sprintf("fork at sequence %d", sequence)
		return false, errors.New(chain.QuarantineReason)
	}
	if sequence > chain.ReceiveWatermark+v2SequenceAheadLimit {
		chain.Quarantined = true
		chain.QuarantineReason = fmt.Sprintf("sequence %d is outside the acceptance window", sequence)
		return false, errors.New(chain.QuarantineReason)
	}
	previous, _ := envelope.Descriptor[kPreviousDigest].([]byte)
	if sequence != chain.ReceiveWatermark+1 {
		if !chain.ResumeApproved {
			chain.Quarantined = true
			chain.QuarantineReason = fmt.Sprintf("gap before sequence %d", sequence)
			return false, errors.New(chain.QuarantineReason)
		}
		// The operator accepted that the skipped sequences are gone. Adopt
		// this delivery's predecessor digest so the chain continues from here:
		// ordering still holds from this point on, but it no longer covers
		// what was skipped. The approval is spent by this one jump.
		chain.ResumeApproved = false
		chain.Quarantined = false
		chain.QuarantineReason = ""
		chain.ReceiveWatermark = sequence - 1
		chain.ReceiveDigest = hex.EncodeToString(previous)
	}
	if !bytes.Equal(previous, mustDecodeHexV2(chain.ReceiveDigest, 32)) {
		chain.Quarantined = true
		chain.QuarantineReason = fmt.Sprintf("predecessor fork at sequence %d", sequence)
		return false, errors.New(chain.QuarantineReason)
	}
	if chain.Quarantined {
		return false, fmt.Errorf("delivery chain is quarantined: %s", chain.QuarantineReason)
	}
	return true, nil
}

// applyV2GranularDataDelivery commits one delivery and reports what it did. It
// deliberately renders nothing itself apart from a message payload, which owns
// stdout at the moment it arrives: a run drains as many deliveries as it can
// reach, so the report belongs to the run rather than to any one delivery.
func (runtime *v2PeerRuntime) applyV2GranularDataDelivery(ctx context.Context, a *app, opts v2PeerReceiveOptions, delivery *v2GranularInboxDelivery, sourceSlotEpoch uint64) (*v2ReceivedItem, error) {
	descriptorCiphertext := delivery.EncryptedDescriptor
	expectation, err := runtime.descriptorExpectation()
	if err != nil {
		return nil, err
	}
	envelope, err := decryptAndValidateV2Envelope(descriptorCiphertext, runtime.identity, expectation)
	if err != nil {
		return nil, err
	}
	chainID, err := descriptorUint(envelope.Descriptor, kChain, "chain")
	if err != nil || chainID != 0 {
		return nil, errors.New("inbox contains a non-data descriptor")
	}
	next, err := runtime.validateNextDescriptor(runtime.state.Chains["in:data"], envelope)
	if err != nil {
		_ = writeV2PeerDeliveryState(runtime.paths, runtime.state)
		return nil, err
	}
	policy, err := descriptorPolicy(envelope.Descriptor)
	if err != nil {
		return nil, err
	}
	if err := validateV2EffectivePolicy(policy, delivery.EffectivePolicy); err != nil {
		return nil, err
	}
	// validateV2EffectivePolicy has already rejected an absent, non-integer or
	// zero expiry, so this cannot yield the zero that the pruner reads as
	// "retain indefinitely".
	expiresAt, _ := asV2Uint(delivery.EffectivePolicy[1])
	policyDigest, err := v2PolicyDigest(policy)
	if err != nil {
		return nil, err
	}
	if !next {
		return nil, nil
	}
	sequence, err := descriptorUint(envelope.Descriptor, kSequence, "sequence")
	if err != nil {
		return nil, err
	}
	payloadType, err := descriptorUint(envelope.Descriptor, kPayloadType, "payload type")
	if err != nil {
		return nil, err
	}
	if payloadType == 4 {
		// Git checkpoints share the data chain with files, so one sits in the
		// queue like any other delivery. Applying it needs a repository this
		// command does not have, so the drain stops here and names the command
		// that does rather than failing everything already committed.
		return nil, &v2ReceiveStop{
			Reason:   "git_checkpoint",
			Sequence: sequence,
			Next:     "dud git fetch " + opts.alias,
		}
	}
	payloadCiphertext := delivery.Payload
	chunks, ok := envelope.Descriptor[kChunkHashes].([]any)
	if !ok || len(chunks) != 1 {
		return nil, errors.New("descriptor ciphertext hash list is invalid")
	}
	expectedCipherDigest, _ := chunks[0].([]byte)
	actualCipherDigest := sha256.Sum256(payloadCiphertext)
	if !bytes.Equal(expectedCipherDigest, actualCipherDigest[:]) {
		return nil, errors.New("peer payload ciphertext digest does not match the signed descriptor")
	}
	plaintext, err := decryptV2Payload(payloadCiphertext, runtime.identity, v2MaximumObjectBytes)
	if err != nil {
		return nil, err
	}
	plainDigest := sha256.Sum256(plaintext)
	expectedPlainDigest, _ := envelope.Descriptor[kPayloadHash].([]byte)
	if !bytes.Equal(expectedPlainDigest, plainDigest[:]) {
		return nil, errors.New("peer plaintext digest does not match the signed descriptor")
	}
	if size, exists := envelope.Descriptor[kPlaintextSize]; exists {
		value, ok := asV2Uint(size)
		if !ok || value != uint64(len(plaintext)) {
			return nil, errors.New("peer plaintext size does not match the signed descriptor")
		}
	}
	if payloadType != 1 && payloadType != 2 && payloadType != 3 {
		return nil, errors.New("peer delivery payload type is unsupported by this command")
	}
	digestString := hex.EncodeToString(envelope.DescriptorDigest[:])
	transferDir := filepath.Join(runtime.paths.StateDir, "transfers", runtime.state.RelationshipID)
	if err := os.MkdirAll(transferDir, 0o700); err != nil {
		return nil, err
	}
	durableOutput := filepath.Join(transferDir, digestString)
	if existing, readErr := os.ReadFile(durableOutput); readErr == nil {
		existingDigest := sha256.Sum256(existing)
		if !bytes.Equal(existingDigest[:], plainDigest[:]) {
			return nil, errors.New("durable peer output conflicts with the signed delivery")
		}
	} else {
		if !errors.Is(readErr, os.ErrNotExist) {
			return nil, readErr
		}
		if err := atomicWriteV2File(durableOutput, plaintext, 0o600); err != nil {
			return nil, err
		}
	}
	transfer, resume := runtime.state.InboundTransfers[digestString]
	if resume {
		if transfer.Sequence != sequence ||
			transfer.OutputDigest != hex.EncodeToString(plainDigest[:]) ||
			transfer.PolicyDigest != hex.EncodeToString(policyDigest) {
			return nil, errors.New("durable inbound transfer state conflicts with the signed descriptor")
		}
	} else {
		transfer = v2InboundTransfer{
			EntryID:              hex.EncodeToString(delivery.ID),
			Slot:                 hex.EncodeToString(delivery.Slot),
			DescriptorDigest:     digestString,
			Sequence:             sequence,
			Phase:                "payload-verified",
			TemporaryOutput:      durableOutput,
			OutputDigest:         hex.EncodeToString(plainDigest[:]),
			PolicyDigest:         hex.EncodeToString(policyDigest),
			DescriptorCiphertext: v2Base64URL(descriptorCiphertext),
			PlaintextPayload:     durableOutput,
			ExpiresAt:            expiresAt,
		}
		runtime.state.InboundTransfers[digestString] = transfer
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return nil, err
		}
	}
	committedOutput := durableOutput
	conflict := ""
	if payloadType == 3 && !opts.noExtract {
		if opts.out != "" {
			return nil, errors.New("collection extraction uses --out-dir; use --no-extract with --out to retain the tar archive")
		}
		archiveFormat, archiveOK := asV2Uint(envelope.Descriptor[kArchiveFormat])
		plainSize, sizeOK := asV2Uint(envelope.Descriptor[kPlaintextSize])
		metadata, metadataErr := normalizeV2Map(envelope.Descriptor[kTypeMetadata])
		entryCount, countOK := asV2Uint(metadata[1])
		names, namesOK := metadata[2].([]any)
		if !archiveOK || archiveFormat != 1 || !sizeOK || metadataErr != nil ||
			!countOK || !namesOK || entryCount != uint64(len(names)) {
			return nil, errors.New("collection metadata is invalid")
		}
		entries, err := inspectV2CollectionArchive(plaintext, plainSize)
		if err != nil {
			return nil, err
		}
		if err := validateV2CollectionNames(entries, names); err != nil {
			return nil, err
		}
		if opts.interactive && !a.confirmV2CollectionExtraction(entries) {
			return nil, errors.New("collection extraction cancelled")
		}
		destination := opts.outDir
		if destination == "" {
			destination = absPathIfRelative("dud-" + digestString[:12])
		}
		// Extraction keeps its own rules rather than following --on-conflict:
		// --out-dir names a directory that normally already exists, so an
		// existing destination is the ordinary case here, not a collision.
		if _, statErr := os.Lstat(destination); statErr == nil && resume {
			if err := verifyV2ExtractedCollection(plaintext, destination, plainSize); err != nil {
				return nil, err
			}
		} else {
			if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
				return nil, statErr
			}
			if _, err := extractV2CollectionArchive(plaintext, destination, plainSize); err != nil {
				return nil, err
			}
		}
		committedOutput = destination
	} else if opts.out != "" || payloadType == 2 || payloadType == 3 {
		target := opts.out
		if target == "" {
			if payloadType == 3 {
				target = absPathIfRelative("dud-" + digestString[:12] + ".tar")
			} else {
				name, _ := envelope.Descriptor[kDisplayName].(string)
				if err := v2SafeReceivedFileName(name); err != nil {
					return nil, err
				}
				if opts.outDir != "" {
					target = filepath.Join(opts.outDir, name)
				} else {
					target = absPathIfRelative(name)
				}
			}
			if payloadType == 3 && opts.outDir != "" {
				target = filepath.Join(opts.outDir, filepath.Base(target))
			} else if payloadType != 3 && opts.outDir != "" {
				name, _ := envelope.Descriptor[kDisplayName].(string)
				target = filepath.Join(opts.outDir, name)
			}
		}
		if target == "" {
			return nil, errors.New("file delivery has no safe output path")
		}
		if _, statErr := os.Lstat(target); statErr == nil {
			// Writing a file whose contents already hash to this payload is a
			// no-op, so there is nothing to protect. Deciding that on the
			// first attempt matters: the durable transfer record is written
			// just above, so a second identical run would otherwise take the
			// resume path and succeed where the first one refused — one
			// delivery, two invocations, for no reason the operator could see.
			switch {
			case v2ExistingOutputMatches(target, plainDigest[:]):
				committedOutput = target
			case resume:
				return nil, fmt.Errorf("existing output %s conflicts with the durable transfer", safeTerminalText(target))
			case opts.onConflict == "overwrite":
				if err := atomicWriteV2File(target, plaintext, 0o600); err != nil {
					return nil, err
				}
				committedOutput = target
			case opts.onConflict == "refuse":
				return nil, &v2ReceiveStop{Reason: "conflict", Sequence: sequence, Detail: target}
			default:
				// Skipping leaves the file alone but still commits and
				// acknowledges the delivery, because the chain accepts only the
				// next sequence: refusing to advance would block every delivery
				// behind this one. The payload stays in the durable store, so
				// 'receive --id' can still write it wherever the operator wants.
				conflict = target
			}
		} else {
			if !errors.Is(statErr, os.ErrNotExist) {
				return nil, statErr
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return nil, err
			}
			if err := atomicWriteV2File(target, plaintext, 0o600); err != nil {
				return nil, err
			}
			committedOutput = target
		}
	}
	transfer.Phase = "output-committed"
	transfer.CommittedOutput = committedOutput
	runtime.state.InboundTransfers[digestString] = transfer
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return nil, err
	}
	if err := runtime.queueV2GranularCompletion(envelope, delivery.ID, delivery.Slot, sourceSlotEpoch, policyDigest, plainDigest[:], nil); err != nil {
		return nil, err
	}
	dataChain := runtime.state.Chains["in:data"]
	dataChain.ReceiveWatermark = sequence
	dataChain.ReceiveDigest = digestString
	dataChain.Replay[sequence] = v2ReplayEntry{
		Sequence:         sequence,
		DescriptorDigest: digestString,
		ExpiresAt:        uint64(time.Now().Unix()) + v2MaximumTTLSeconds,
		OutputDigest:     hex.EncodeToString(plainDigest[:]),
	}
	pruneV2ReplayHistory(runtime.state, uint64(time.Now().Unix()))
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return nil, err
	}
	// The durable copy is discarded only once the watermark above is persisted:
	// until then a crash would resume through it, and after it a redelivery is
	// refused as a replay instead. A removal that does not reach the state file
	// is harmless in the other direction too, because the export path treats a
	// missing copy exactly as a cleared one.
	discarded, discardErr := discardRedundantV2DurableCopy(&transfer, durableOutput, committedOutput, plainDigest[:])
	if discardErr != nil {
		// This delivery is committed and acknowledged, so upkeep that fails must
		// not fail it. Leaving the record's paths intact hands the removal back
		// to the expiry pruner rather than losing track of plaintext on disk.
		fmt.Fprintf(a.errOut, "WARNING: %v\n", discardErr)
	}
	if discarded {
		runtime.state.InboundTransfers[digestString] = transfer
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return nil, err
		}
	}
	if err := runtime.flushPendingCompletions(ctx); err != nil {
		fmt.Fprintf(a.errOut, "WARNING: output committed; atomic completion queued for automatic retry: %v\n", err)
	}
	displayName, _ := envelope.Descriptor[kDisplayName].(string)
	item := &v2ReceivedItem{
		Sequence:         sequence,
		DescriptorDigest: digestString,
		PayloadType:      payloadType,
		DisplayName:      displayName,
		PlaintextSize:    uint64(len(plaintext)),
		Output:           committedOutput,
		Outcome:          "received",
		Conflict:         conflict,
	}
	if !discarded {
		item.OutputExpiresAt = expiresAt
		if committedOutput != durableOutput {
			item.RetainedPayload = durableOutput
		}
	}
	if conflict != "" {
		item.Outcome = "skipped"
	}
	if payloadType == 1 && opts.out == "" && !opts.json {
		// A message payload is the output, so it goes to stdout as it arrives
		// rather than being held for the report. The report moves to stderr in
		// response, which keeps a piped receive yielding only the messages.
		item.Outcome = "message"
		if _, err := a.out.Write(plaintext); err != nil {
			return nil, err
		}
		if len(plaintext) == 0 || plaintext[len(plaintext)-1] != '\n' {
			fmt.Fprintln(a.out)
		}
	}
	return item, nil
}

func (runtime *v2PeerRuntime) acknowledgementMetadata(ackedSequence uint64, ackedDigest, outputDigest []byte, result uint64, resultMetadata map[int]any) map[int]any {
	metadata := map[int]any{
		1: ackedSequence,
		2: ackedDigest,
		3: result,
		4: outputDigest,
		5: runtime.state.Chains["out:data"].SendSequence,
		6: runtime.state.Chains["out:control"].SendSequence + 1,
		7: runtime.state.Chains["in:data"].ReceiveWatermark,
		8: runtime.state.Chains["in:control"].ReceiveWatermark,
	}
	if resultMetadata != nil {
		metadata[9] = resultMetadata
	}
	// Extension key 128 is optional by protocol-v2.md §2, so a peer that does
	// not know it ignores it. It is how a later release learns, without a
	// separate handshake, whether this peer implements a payload-type feature.
	metadata[kPeerFeatures] = v2LocalPeerFeatureList()
	return metadata
}

// queueV2GranularRejection acknowledges a delivery this device will never be
// able to commit. The chain watermark advances on a rejection exactly as it
// does on a commit, so one unprocessable delivery cannot wedge the chain; the
// caller is responsible for advancing it. Only the causes enumerated in
// permanentV2GitRejection may reach here — see docs/threat-model-v2.md §3.19.
func (runtime *v2PeerRuntime) queueV2GranularRejection(dataEnvelope *validatedV2Envelope, deliveryID, dataSlot []byte, dataSlotEpoch uint64, policyDigest []byte) error {
	return runtime.queueV2GranularAcknowledgement(dataEnvelope, deliveryID, dataSlot, dataSlotEpoch, policyDigest, make([]byte, 32), 1, nil)
}

func (runtime *v2PeerRuntime) queueV2GranularCompletion(dataEnvelope *validatedV2Envelope, deliveryID, dataSlot []byte, dataSlotEpoch uint64, policyDigest, outputDigest []byte, resultMetadata map[int]any) error {
	return runtime.queueV2GranularAcknowledgement(dataEnvelope, deliveryID, dataSlot, dataSlotEpoch, policyDigest, outputDigest, 0, resultMetadata)
}

func (runtime *v2PeerRuntime) queueV2GranularAcknowledgement(dataEnvelope *validatedV2Envelope, deliveryID, dataSlot []byte, dataSlotEpoch uint64, policyDigest, outputDigest []byte, result uint64, resultMetadata map[int]any) error {
	if len(deliveryID) != 16 || len(dataSlot) != 16 || dataSlotEpoch == 0 || len(policyDigest) != 32 || len(outputDigest) != 32 {
		return errors.New("granular completion binding is invalid")
	}
	if result > 1 || (result == 1 && (resultMetadata != nil || !bytes.Equal(outputDigest, make([]byte, 32)))) {
		return errors.New("granular rejection carries a committed result")
	}
	sequence, _ := descriptorUint(dataEnvelope.Descriptor, kSequence, "sequence")
	control := runtime.state.Chains["out:control"]
	now := uint64(time.Now().Unix())
	payloadCiphertext, err := encryptV2Payload(nil, runtime.recipient)
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(nil)
	chunkHash := sha256.Sum256(payloadCiphertext)
	descriptorID, err := newV2DescriptorID()
	if err != nil {
		return err
	}
	policy := v2TransportPolicy{ExpiresAt: now + v2MaximumTTLSeconds, Consume: 1, ClaimLeaseSeconds: 300, AckMode: 0}
	descriptor := v2Descriptor{
		DescriptorID: descriptorID, PayloadType: 5, RelationshipID: runtime.relationshipID,
		Direction: v2OutboundDirection(runtime.state.Role), Chain: 1, KeyEpoch: 0,
		Sequence: control.SendSequence + 1, PreviousDigest: mustDecodeHexV2(control.SendDigest, 32),
		SenderDeviceID: runtime.localID, RecipientDeviceID: runtime.peerID,
		CanonicalOrigin: runtime.origin, CreatedAt: now, TransportPolicy: policy,
		PayloadHash: payloadHash[:], ChunkHashes: [][]byte{chunkHash[:]},
		TypeMetadata: runtime.acknowledgementMetadata(sequence, dataEnvelope.DescriptorDigest[:], outputDigest, result, resultMetadata),
	}
	acknowledgement, err := encryptV2Envelope(descriptor, runtime.signingKey, runtime.recipient)
	if err != nil {
		return err
	}
	signedMap, err := descriptorMap(descriptor, runtime.signingKey)
	if err != nil {
		return err
	}
	signedBytes, err := v2EncMode.Marshal(signedMap)
	if err != nil {
		return err
	}
	descriptorDigest := sha256.Sum256(signedBytes)
	secret, err := decodeV2Base64URL(runtime.state.OutboundRelationshipSecret, 32)
	if err != nil {
		return err
	}
	targetEpoch := v2SlotEpoch(time.Now())
	targetSlot, err := deriveV2Slot(secret, "control", targetEpoch)
	if err != nil {
		return err
	}
	operationID, err := randomV2Bytes(16)
	if err != nil {
		return err
	}
	runtime.state.PendingCompletions = append(runtime.state.PendingCompletions, v2PendingCompletion{
		DeliveryID:       hex.EncodeToString(deliveryID),
		SourceSlot:       hex.EncodeToString(dataSlot),
		SourceSlotEpoch:  dataSlotEpoch,
		TargetSlot:       hex.EncodeToString(targetSlot),
		TargetSlotEpoch:  targetEpoch,
		PolicyDigest:     hex.EncodeToString(policyDigest),
		DescriptorDigest: hex.EncodeToString(dataEnvelope.DescriptorDigest[:]),
		OperationID:      hex.EncodeToString(operationID),
		Acknowledgement:  v2Base64URL(acknowledgement),
		CreatedAt:        now,
	})
	control.SendSequence = descriptor.Sequence
	control.SendDigest = hex.EncodeToString(descriptorDigest[:])
	return nil
}

func (runtime *v2PeerRuntime) flushPendingControlPublications(ctx context.Context) error {
	for len(runtime.state.PendingControlPublications) != 0 {
		queued := runtime.state.PendingControlPublications[0]
		now := uint64(time.Now().Unix())
		if queued.NextAttemptAt > now {
			return fmt.Errorf("next control event retry is scheduled at %d", queued.NextAttemptAt)
		}
		operationID, operationErr := hex.DecodeString(queued.OperationID)
		envelope, envelopeErr := decodeV2Base64URL(queued.EncryptedEvent, -1)
		slot, slotErr := hex.DecodeString(queued.ControlSlot)
		if operationErr != nil || len(operationID) != 16 || envelopeErr != nil || len(envelope) == 0 || len(envelope) > v2MaxDescriptorBytes || slotErr != nil || len(slot) != 16 {
			return errors.New("queued control publication is invalid")
		}
		publish := func(at time.Time) error {
			secret, secretErr := v2CapabilitySecret(runtime.state, v2OutboundDirection(runtime.state.Role), "write")
			if secretErr != nil {
				return secretErr
			}
			proof, proofErr := newV2GranularSlotProofInput(
				secret,
				v2DirectionName(v2OutboundDirection(runtime.state.Role)),
				"write",
				v2GranularControlChain,
				slot,
				queued.SlotEpoch,
				at,
			)
			if proofErr != nil {
				return proofErr
			}
			published, publishErr := publishV2GranularControlEvent(ctx, runtime.transport, runtime.origin, operationID, envelope, proof)
			if publishErr != nil {
				return publishErr
			}
			if !bytes.Equal(published.EventID, operationID) {
				return errors.New("control event response does not match its operation ID")
			}
			return nil
		}
		err := publish(time.Now())
		if isRetryableV2ConnectionError(err) {
			if retiree, ok := runtime.transport.(v2ResolutionRetirer); ok {
				retiree.retireV2Resolution(runtime.origin)
			}
			err = publish(time.Now())
		}
		if err != nil {
			queued.Attempts++
			delay := v2BackoffWithJitter(queued.Attempts)
			queued.NextAttemptAt = now + uint64((delay+time.Second-1)/time.Second)
			runtime.state.PendingControlPublications[0] = queued
			if writeErr := writeV2PeerDeliveryState(runtime.paths, runtime.state); writeErr != nil {
				return writeErr
			}
			return err
		}
		runtime.state.PendingControlPublications = runtime.state.PendingControlPublications[1:]
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *v2PeerRuntime) boundedControlDrain(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, v2ControlDrainTimeout)
	defer cancel()
	secret, err := decodeV2Base64URL(runtime.state.InboundRelationshipSecret, 32)
	if err != nil {
		return err
	}
	current := v2SlotEpoch(time.Now())
	readSecret, err := v2CapabilitySecret(runtime.state, v2InboundDirection(runtime.state.Role), "read")
	if err != nil {
		return err
	}
	proofs := make([]v2GranularSlotProofInput, 0, v2DeliveryRecoveryDays)
	for _, epoch := range v2ControlRecoveryEpochs(runtime.state.ControlScanEpoch, current) {
		slot, slotErr := deriveV2Slot(secret, "control", epoch)
		if slotErr != nil {
			return slotErr
		}
		proof, proofErr := newV2GranularSlotProofInput(
			readSecret,
			v2DirectionName(v2InboundDirection(runtime.state.Role)),
			"read",
			v2GranularControlChain,
			slot,
			epoch,
			time.Now(),
		)
		if proofErr != nil {
			return proofErr
		}
		proofs = append(proofs, proof)
	}
	processed, err := decodeV2ControlEventIDs(runtime.state.PendingControlEventIDs)
	if err != nil {
		return err
	}
	response, err := queryV2GranularInbox(ctx, runtime.transport, runtime.origin, nil, proofs, processed)
	if err != nil {
		runtime.state.UndrainedControl = true
		runtime.state.ConsecutiveDrainFailures++
		_ = writeV2PeerDeliveryState(runtime.paths, runtime.state)
		return err
	}
	events, err := decodeV2GranularControlEvents(response.Header)
	if err != nil {
		runtime.state.UndrainedControl = true
		runtime.state.ConsecutiveDrainFailures++
		_ = writeV2PeerDeliveryState(runtime.paths, runtime.state)
		return err
	}
	pending := make([]string, 0, len(events))
	for _, event := range events {
		if err := runtime.applyV2GranularControlEnvelope(event.Envelope); err != nil {
			runtime.state.UndrainedControl = true
			runtime.state.ConsecutiveDrainFailures++
			_ = writeV2PeerDeliveryState(runtime.paths, runtime.state)
			if runtime.state.Halted {
				_ = runtime.revokeHaltedRelationship(ctx)
			}
			return err
		}
		pending = append(pending, event.ID)
	}
	runtime.state.ControlScanEpoch = current
	runtime.state.PendingControlEventIDs = pending
	runtime.state.LastSuccessfulDrain = uint64(time.Now().Unix())
	runtime.state.UndrainedControl = false
	runtime.state.ConsecutiveDrainFailures = 0
	return writeV2PeerDeliveryState(runtime.paths, runtime.state)
}

func v2ControlRecoveryEpochs(start, current uint64) []uint64 {
	if start > current {
		start = current
	}
	if current-start >= v2DeliveryRecoveryDays {
		start = current - v2DeliveryRecoveryDays + 1
	}
	epochs := make([]uint64, 0, current-start+1)
	for epoch := start; epoch <= current; epoch++ {
		epochs = append(epochs, epoch)
	}
	return epochs
}

func decodeV2ControlEventIDs(ids []string) ([][]byte, error) {
	result := make([][]byte, 0, len(ids))
	for _, id := range ids {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 16 {
			return nil, errors.New("pending control event ID is invalid")
		}
		result = append(result, decoded)
	}
	return result, nil
}

type v2GranularControlEvent struct {
	ID       string
	Envelope []byte
}

func decodeV2GranularControlEvents(header map[int]any) ([]v2GranularControlEvent, error) {
	rawEvents, ok := header[2].([]any)
	if !ok || len(rawEvents) > v2GranularMaxSlotProofs {
		return nil, errors.New("granular inbox control events are invalid")
	}
	events := make([]v2GranularControlEvent, 0, len(rawEvents))
	seen := map[string]bool{}
	for _, raw := range rawEvents {
		event, err := normalizeV2Map(raw)
		if err != nil {
			return nil, errors.New("granular inbox control event is invalid")
		}
		id, idOK := event[1].([]byte)
		envelope, envelopeOK := event[4].([]byte)
		if len(event) != 5 || !idOK || len(id) != 16 || !envelopeOK || len(envelope) == 0 || len(envelope) > v2MaxDescriptorBytes {
			return nil, errors.New("granular inbox control event is invalid")
		}
		encodedID := hex.EncodeToString(id)
		if seen[encodedID] {
			return nil, errors.New("granular inbox repeated a control event")
		}
		seen[encodedID] = true
		events = append(events, v2GranularControlEvent{ID: encodedID, Envelope: envelope})
	}
	return events, nil
}

func (runtime *v2PeerRuntime) revokeHaltedRelationship(ctx context.Context) error {
	admin, err := loadV2AdminCapability(runtime.paths)
	if err != nil {
		return err
	}
	body, err := v2EncMode.Marshal(map[int]any{1: runtime.relationshipID})
	if err != nil {
		return err
	}
	_, err = doV2CBORRequest(
		ctx,
		runtime.transport,
		"POST",
		runtime.origin,
		"/v2/admin/relationships/revoke",
		admin,
		body,
		v2MaxDescriptorBytes,
	)
	return err
}

func (runtime *v2PeerRuntime) applyV2GranularControlEnvelope(ciphertext []byte) error {
	expectation, err := runtime.descriptorExpectation()
	if err != nil {
		return err
	}
	envelope, err := decryptAndValidateV2Envelope(ciphertext, runtime.identity, expectation)
	if err != nil {
		return err
	}
	chainID, err := descriptorUint(envelope.Descriptor, kChain, "chain")
	if err != nil || chainID != 1 {
		return errors.New("inline control event contains a non-control descriptor")
	}
	next, err := runtime.validateNextDescriptor(runtime.state.Chains["in:control"], envelope)
	if err != nil {
		return err
	}
	if !next {
		return nil
	}
	payloadType, err := descriptorUint(envelope.Descriptor, kPayloadType, "payload type")
	if err != nil {
		return err
	}
	metadata, err := normalizeV2Map(envelope.Descriptor[kTypeMetadata])
	if err != nil {
		return err
	}
	switch payloadType {
	case 5:
		if err := runtime.applySignedAcknowledgement(envelope, metadata); err != nil {
			return err
		}
	case 6:
		if len(metadata) != 6 {
			return errors.New("peer-control metadata has unexpected fields")
		}
		operation, operationOK := asV2Uint(metadata[1])
		reason, reasonOK := asV2Uint(metadata[6])
		if !operationOK || operation != 1 || !reasonOK || reason > 2 {
			return errors.New("unsupported peer-control operation")
		}
		var watermarks [4]uint64
		for index, key := range []int{2, 3, 4, 5} {
			watermarks[index], err = metadataUint(metadata, key)
			if err != nil {
				return err
			}
		}
		if err := runtime.validatePeerWatermarks(watermarks); err != nil {
			return err
		}
		runtime.state.Halted = true
		runtime.state.HaltReason = "peer revoked the relationship"
	default:
		return errors.New("unsupported inline control payload type")
	}
	sequence, _ := descriptorUint(envelope.Descriptor, kSequence, "sequence")
	chain := runtime.state.Chains["in:control"]
	chain.ReceiveWatermark = sequence
	chain.ReceiveDigest = hex.EncodeToString(envelope.DescriptorDigest[:])
	chain.Replay[sequence] = v2ReplayEntry{
		Sequence:         sequence,
		DescriptorDigest: chain.ReceiveDigest,
		ExpiresAt:        uint64(time.Now().Unix()) + v2MaximumTTLSeconds,
	}
	signedEnvelope, err := v2EncMode.Marshal(map[int]any{
		1: envelope.Descriptor,
		2: envelope.Signature,
	})
	if err != nil {
		return err
	}
	runtime.state.SignedAcknowledgements[chain.ReceiveDigest] = v2Base64URL(signedEnvelope)
	return nil
}

func metadataUint(metadata map[int]any, key int) (uint64, error) {
	value, ok := asV2Uint(metadata[key])
	if !ok {
		return 0, fmt.Errorf("control metadata key %d is invalid", key)
	}
	return value, nil
}

func (runtime *v2PeerRuntime) applySignedAcknowledgement(envelope *validatedV2Envelope, metadata map[int]any) error {
	keys := make([]int, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	if err := validateV2MetadataKeys(keys, []int{1, 2, 3, 4, 5, 6, 7, 8}, []int{9}); err != nil {
		return fmt.Errorf("acknowledgement metadata has unexpected fields: %w", err)
	}
	if raw, exists := metadata[9]; exists && raw == nil {
		return errors.New("acknowledgement result metadata is empty")
	}
	ackedSequence, err := metadataUint(metadata, 1)
	if err != nil {
		return err
	}
	ackedDigest, ok := metadata[2].([]byte)
	result, resultOK := asV2Uint(metadata[3])
	outputDigest, outputOK := metadata[4].([]byte)
	if !ok || len(ackedDigest) != 32 || !resultOK || result > 1 || !outputOK || len(outputDigest) != 32 {
		return errors.New("acknowledgement metadata is invalid")
	}
	if result == 1 && !bytes.Equal(outputDigest, make([]byte, 32)) {
		return errors.New("rejected acknowledgement has a non-zero output digest")
	}
	var hwm [4]uint64
	for index, key := range []int{5, 6, 7, 8} {
		hwm[index], err = metadataUint(metadata, key)
		if err != nil {
			return err
		}
	}
	if err := runtime.validatePeerWatermarks(hwm); err != nil {
		return err
	}
	key := hex.EncodeToString(ackedDigest)
	sent, exists := runtime.state.Sent[key]
	if !exists || sent.Sequence != ackedSequence {
		return errors.New("acknowledgement does not match a committed outbound delivery")
	}
	if result == 0 {
		sent.Acknowledged = true
		sent.AcknowledgedAt = uint64(time.Now().Unix())
		sent.OutputDigest = hex.EncodeToString(outputDigest)
		if raw, exists := metadata[9]; exists {
			encoded, encodeErr := v2EncMode.Marshal(raw)
			if encodeErr != nil {
				return encodeErr
			}
			sent.ResultMetadata = v2Base64URL(encoded)
		}
		runtime.state.Sent[key] = sent
	} else {
		// A refusal is recorded rather than ignored: an unacknowledged delivery
		// is one still in flight, and reporting a refused one the same way would
		// leave the operator waiting for an acknowledgement that never comes.
		sent.Rejected = true
		sent.RejectedAt = uint64(time.Now().Unix())
		runtime.state.Sent[key] = sent
	}
	signedEnvelope, err := v2EncMode.Marshal(map[int]any{
		1: envelope.Descriptor,
		2: envelope.Signature,
	})
	if err != nil {
		return err
	}
	// Recorded only once the acknowledgement has fully validated, so a refused
	// one cannot teach this device anything about the peer.
	if features := v2MetadataFeatures(metadata); features != nil {
		runtime.state.PeerFeatures = features
	}
	runtime.state.SignedAcknowledgements[hex.EncodeToString(envelope.DescriptorDigest[:])] = v2Base64URL(signedEnvelope)
	return nil
}

func (runtime *v2PeerRuntime) validatePeerWatermarks(hwm [4]uint64) error {
	local := [4]uint64{
		runtime.state.Chains["in:data"].ReceiveWatermark,
		runtime.state.Chains["in:control"].ReceiveWatermark + 1,
		runtime.state.Chains["out:data"].SendSequence,
		runtime.state.Chains["out:control"].SendSequence,
	}
	for index := range hwm {
		if hwm[index] > local[index] {
			runtime.state.Halted = true
			runtime.state.HaltReason = fmt.Sprintf("signed peer watermark %d proves local rollback", index+5)
			return errors.New(runtime.state.HaltReason)
		}
	}
	var highestAcknowledged uint64
	for _, sent := range runtime.state.Sent {
		if sent.Acknowledged && sent.Sequence > highestAcknowledged {
			highestAcknowledged = sent.Sequence
		}
	}
	if hwm[2] < highestAcknowledged {
		runtime.state.Halted = true
		runtime.state.HaltReason = "signed peer incoming-data watermark proves peer rollback"
		return errors.New(runtime.state.HaltReason)
	}
	return nil
}

// v2CommittedTransferBody reads back a committed delivery and names where it
// came from. DUD's own copy is gone once a separate output holds the same
// bytes, so the committed output is the ordinary source here; it is checked
// against the digest the descriptor signed, because a file the operator edited
// afterwards is not the delivery this command claims to export.
func v2CommittedTransferBody(transfer v2InboundTransfer) ([]byte, string, error) {
	if transfer.PlaintextPayload != "" {
		body, err := os.ReadFile(transfer.PlaintextPayload)
		if err == nil {
			return body, transfer.PlaintextPayload, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, "", err
		}
	}
	if transfer.CommittedOutput == "" {
		return nil, "", fmt.Errorf("delivery %s retains no payload to export", transfer.DescriptorDigest)
	}
	body, err := os.ReadFile(transfer.CommittedOutput)
	if err != nil {
		return nil, "", fmt.Errorf("read committed output %s: %w", safeTerminalText(transfer.CommittedOutput), err)
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != transfer.OutputDigest {
		return nil, "", fmt.Errorf("committed output %s no longer matches delivery %s", safeTerminalText(transfer.CommittedOutput), transfer.DescriptorDigest)
	}
	return body, transfer.CommittedOutput, nil
}

func (runtime *v2PeerRuntime) exportCommittedTransfer(a *app, opts v2PeerReceiveOptions) error {
	transfer, exists := runtime.state.InboundTransfers[opts.id]
	if !exists || transfer.Phase != "output-committed" {
		return fmt.Errorf("no committed delivery with descriptor digest %s", opts.id)
	}
	body, source, err := v2CommittedTransferBody(transfer)
	if err != nil {
		return err
	}
	if opts.out == "" {
		if opts.json {
			return writeJSON(a.out, map[string]any{"peer": opts.alias, "descriptor_digest": opts.id, "output": source})
		}
		_, err = a.out.Write(body)
		return err
	}
	if _, err := os.Lstat(opts.out); err == nil {
		// This is the documented way to recover a delivery whose output was
		// skipped, so it has to be able to overwrite when asked; without that
		// the recovery path would refuse exactly where it is needed.
		if opts.onConflict != "overwrite" {
			return fmt.Errorf("refusing to overwrite existing output %s; pass --on-conflict overwrite to replace it", opts.out)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := atomicWriteV2File(opts.out, body, 0o600); err != nil {
		return err
	}
	if opts.json {
		return writeJSON(a.out, map[string]any{"peer": opts.alias, "descriptor_digest": opts.id, "output": opts.out})
	}
	fmt.Fprintf(a.out, "Exported committed delivery to %s.\n", opts.out)
	return nil
}

func (runtime *v2PeerRuntime) publishPeerRevocation(ctx context.Context, reason uint64) error {
	control := runtime.state.Chains["out:control"]
	now := uint64(time.Now().Unix())
	payloadCiphertext, err := encryptV2Payload(nil, runtime.recipient)
	if err != nil {
		return err
	}
	payloadDigest := sha256.Sum256(nil)
	cipherDigest := sha256.Sum256(payloadCiphertext)
	descriptorID, err := newV2DescriptorID()
	if err != nil {
		return err
	}
	policy := v2TransportPolicy{
		ExpiresAt:         now + v2MaximumTTLSeconds,
		Consume:           1,
		ClaimLeaseSeconds: 300,
		AckMode:           0,
	}
	descriptor := v2Descriptor{
		DescriptorID:      descriptorID,
		PayloadType:       6,
		RelationshipID:    runtime.relationshipID,
		Direction:         v2OutboundDirection(runtime.state.Role),
		Chain:             1,
		KeyEpoch:          0,
		Sequence:          control.SendSequence + 1,
		PreviousDigest:    mustDecodeHexV2(control.SendDigest, 32),
		SenderDeviceID:    runtime.localID,
		RecipientDeviceID: runtime.peerID,
		CanonicalOrigin:   runtime.origin,
		CreatedAt:         now,
		TransportPolicy:   policy,
		PayloadHash:       payloadDigest[:],
		ChunkHashes:       [][]byte{cipherDigest[:]},
		TypeMetadata: map[int]any{
			1: uint64(1),
			2: runtime.state.Chains["out:data"].SendSequence,
			3: control.SendSequence + 1,
			4: runtime.state.Chains["in:data"].ReceiveWatermark,
			5: runtime.state.Chains["in:control"].ReceiveWatermark,
			6: reason,
		},
	}
	descriptorCiphertext, err := encryptV2Envelope(
		descriptor,
		runtime.signingKey,
		runtime.recipient,
	)
	if err != nil {
		return err
	}
	signedMap, err := descriptorMap(descriptor, runtime.signingKey)
	if err != nil {
		return err
	}
	signedBytes, err := v2EncMode.Marshal(signedMap)
	if err != nil {
		return err
	}
	descriptorDigest := sha256.Sum256(signedBytes)
	secret, err := decodeV2Base64URL(
		runtime.state.OutboundRelationshipSecret,
		32,
	)
	if err != nil {
		return err
	}
	epoch := v2SlotEpoch(time.Now())
	slot, err := deriveV2Slot(secret, "control", epoch)
	if err != nil {
		return err
	}
	operationID, err := randomV2Bytes(16)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(descriptorDigest[:])
	runtime.state.PendingControlPublications = append(runtime.state.PendingControlPublications, v2PendingControlPublication{
		OperationID:    hex.EncodeToString(operationID),
		EncryptedEvent: v2Base64URL(descriptorCiphertext),
		ControlSlot:    hex.EncodeToString(slot),
		SlotEpoch:      epoch,
		CreatedAt:      now,
	})
	control.SendSequence = descriptor.Sequence
	control.SendDigest = key
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return err
	}
	return runtime.flushPendingControlPublications(ctx)
}

func (a *app) cmdSync(args []string) error {
	jsonOutput := false
	alias := ""
	for len(args) != 0 {
		switch args[0] {
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
			args = args[1:]
		case "--url", "--doh-url", "--ech-mode":
			return v2PeerNetworkOptionError(args[0])
		default:
			if strings.HasPrefix(args[0], "-") {
				return fatalError("Unknown sync option: " + args[0])
			}
			if alias != "" {
				return errors.New("dud sync accepts at most one peer")
			}
			alias, args = args[0], args[1:]
		}
	}
	cfg, _, err := loadV2Config()
	if err != nil {
		return err
	}
	aliases := []string{}
	if alias != "" {
		aliases = append(aliases, alias)
	} else {
		for name, peer := range cfg.Peers {
			if peer.Status == "active" {
				aliases = append(aliases, name)
			}
		}
	}
	sort.Strings(aliases)
	results := make([]map[string]any, 0, len(aliases))
	statuses := make([]*v2DeliveryStatus, 0, len(aliases))
	var failures []string
	for _, name := range aliases {
		result := map[string]any{"peer": name}
		var status *v2DeliveryStatus
		err := a.withV2Peer(name, 30*time.Second, func(runtime *v2PeerRuntime) error {
			drainErr := runtime.boundedControlDrain(context.Background())
			completionErr := runtime.flushPendingCompletions(context.Background())
			deliveryErr := runtime.flushPendingGranularDeliveries(context.Background())
			controlErr := runtime.flushPendingControlPublications(context.Background())
			if drainErr != nil {
				result["drain_error"] = drainErr.Error()
			}
			if completionErr != nil {
				result["completion_error"] = completionErr.Error()
			}
			if deliveryErr != nil {
				result["delivery_error"] = deliveryErr.Error()
			}
			if controlErr != nil {
				result["control_error"] = controlErr.Error()
			}
			resolved := v2DeliveryStatusOf(runtime.state)
			status = &resolved
			resolved.merge(result)
			if runtime.state.Halted {
				return errors.New(runtime.state.HaltReason)
			}
			if drainErr != nil || completionErr != nil || deliveryErr != nil || controlErr != nil {
				return errors.New("sync remains incomplete")
			}
			return nil
		})
		result["ok"] = err == nil
		if err != nil {
			result["error"] = err.Error()
			failures = append(failures, name+": "+err.Error())
		}
		results = append(results, result)
		statuses = append(statuses, status)
	}
	if jsonOutput {
		if err := writeJSON(a.out, results); err != nil {
			return err
		}
	} else {
		report := &textReport{}
		for index, result := range results {
			section := report.section("Peer " + fmt.Sprint(result["peer"]))
			if result["ok"] == true {
				section.add("result", "synchronized")
			} else {
				section.addf("result", "incomplete (%s)", result["error"])
			}
			if status := statuses[index]; status != nil {
				section.addRows(status.rows())
			}
		}
		if err := report.write(a.out); err != nil {
			return err
		}
	}
	if len(failures) != 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}
