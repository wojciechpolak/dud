// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	v2PairingStateVersion  = 4
	v2DeliveryStateVersion = 9
	v2ReplayHistoryLimit   = 4096
)

type v2PendingPairing struct {
	Version                    int              `json:"version"`
	Alias                      string           `json:"alias"`
	Role                       uint64           `json:"role"`
	PairingCode                string           `json:"pairing_code"`
	RendezvousLocator          string           `json:"rendezvous_locator"`
	CreationRequest            string           `json:"creation_request,omitempty"`
	InvitationID               string           `json:"invitation_id"`
	RelationshipID             string           `json:"relationship_id"`
	CanonicalOrigin            string           `json:"canonical_origin"`
	ExpiresAt                  uint64           `json:"expires_at"`
	InvitationMap              string           `json:"invitation_map"`
	AcceptanceMap              string           `json:"acceptance_map,omitempty"`
	KeyConfirmationMap         string           `json:"key_confirmation_map,omitempty"`
	StatusCapability           string           `json:"status_capability"`
	LocalPairingID             string           `json:"local_pairing_id"`
	PeerPairingID              string           `json:"peer_pairing_id,omitempty"`
	LocalNonce                 string           `json:"local_nonce"`
	PeerNonce                  string           `json:"peer_nonce,omitempty"`
	PeerAgeRecipient           string           `json:"peer_age_recipient,omitempty"`
	PeerSigningPublicKey       string           `json:"peer_signing_public_key,omitempty"`
	EncA                       string           `json:"enc_a,omitempty"`
	EncB                       string           `json:"enc_b,omitempty"`
	SecretA                    string           `json:"secret_a,omitempty"`
	SecretB                    string           `json:"secret_b,omitempty"`
	OutboundRelationshipSecret string           `json:"outbound_relationship_secret,omitempty"`
	InboundRelationshipSecret  string           `json:"inbound_relationship_secret,omitempty"`
	FullTranscriptHash         string           `json:"full_transcript_hash,omitempty"`
	CompletionMap              string           `json:"completion_map,omitempty"`
	CompletionSignature        string           `json:"completion_signature,omitempty"`
	Completed                  bool             `json:"completed"`
	ServerContract             v2ServerContract `json:"server_contract"`
}

type v2ReplayEntry struct {
	Sequence         uint64 `json:"sequence"`
	DescriptorDigest string `json:"descriptor_digest"`
	ExpiresAt        uint64 `json:"expires_at"`
	OutputDigest     string `json:"output_digest,omitempty"`
}

type v2ChainState struct {
	SendSequence     uint64                   `json:"send_sequence"`
	SendDigest       string                   `json:"send_digest"`
	ReceiveWatermark uint64                   `json:"receive_watermark"`
	ReceiveDigest    string                   `json:"receive_digest"`
	Replay           map[uint64]v2ReplayEntry `json:"replay"`
	Quarantined      bool                     `json:"quarantined"`
	QuarantineReason string                   `json:"quarantine_reason,omitempty"`
	// ResumeApproved records that the operator accepted the loss of the
	// sequences a gap skipped. It authorizes exactly one forward jump and is
	// cleared as soon as that jump is taken, so an approval cannot sit in the
	// state file silently excusing later gaps.
	ResumeApproved bool `json:"resume_approved,omitempty"`
}

type v2PendingControlPublication struct {
	OperationID    string `json:"operation_id"`
	EncryptedEvent string `json:"encrypted_event"`
	ControlSlot    string `json:"control_slot"`
	SlotEpoch      uint64 `json:"slot_epoch"`
	CreatedAt      uint64 `json:"created_at"`
	Attempts       uint64 `json:"attempts"`
	NextAttemptAt  uint64 `json:"next_attempt_at"`
}

type v2PendingGranularDelivery struct {
	OperationID         string `json:"operation_id"`
	EncryptedDescriptor string `json:"encrypted_descriptor"`
	PayloadCiphertext   string `json:"payload_ciphertext"`
	DataSlot            string `json:"data_slot"`
	SlotEpoch           uint64 `json:"slot_epoch"`
	RequestedPolicy     string `json:"requested_policy"`
	DescriptorDigest    string `json:"descriptor_digest"`
	Sequence            uint64 `json:"sequence"`
	CreatedAt           uint64 `json:"created_at"`
	Attempts            uint64 `json:"attempts"`
	NextAttemptAt       uint64 `json:"next_attempt_at"`
}

type v2PendingCompletion struct {
	DeliveryID       string `json:"delivery_id"`
	SourceSlot       string `json:"source_slot"`
	SourceSlotEpoch  uint64 `json:"source_slot_epoch"`
	TargetSlot       string `json:"target_slot"`
	TargetSlotEpoch  uint64 `json:"target_slot_epoch"`
	PolicyDigest     string `json:"policy_digest"`
	DescriptorDigest string `json:"descriptor_digest"`
	Result           uint64 `json:"result"`
	OperationID      string `json:"operation_id"`
	Acknowledgement  string `json:"acknowledgement"`
	CreatedAt        uint64 `json:"created_at"`
	Attempts         uint64 `json:"attempts"`
	NextAttemptAt    uint64 `json:"next_attempt_at"`
}

type v2SentDelivery struct {
	Sequence         uint64 `json:"sequence"`
	DescriptorDigest string `json:"descriptor_digest"`
	PayloadType      uint64 `json:"payload_type,omitempty"`
	TypeMetadata     string `json:"type_metadata,omitempty"`
	Acknowledged     bool   `json:"acknowledged"`
	AcknowledgedAt   uint64 `json:"acknowledged_at,omitempty"`
	OutputDigest     string `json:"output_digest,omitempty"`
	ResultMetadata   string `json:"result_metadata,omitempty"`
	// Rejected records a signed acknowledgement with result 1. It is distinct
	// from an unacknowledged delivery: the peer received this one, refused it
	// permanently, and will not change its mind on a retry.
	Rejected   bool   `json:"rejected,omitempty"`
	RejectedAt uint64 `json:"rejected_at,omitempty"`
	// FullCheckpointRequired records a validated git_retry hint on a rejected
	// incremental checkpoint. Other payloads and complete checkpoints ignore it.
	FullCheckpointRequired bool `json:"full_checkpoint_required,omitempty"`
}

type v2InboundTransfer struct {
	EntryID              string `json:"entry_id"`
	Slot                 string `json:"slot"`
	DescriptorDigest     string `json:"descriptor_digest"`
	Sequence             uint64 `json:"sequence"`
	Phase                string `json:"phase"`
	TemporaryOutput      string `json:"temporary_output,omitempty"`
	CommittedOutput      string `json:"committed_output,omitempty"`
	OutputDigest         string `json:"output_digest,omitempty"`
	PolicyDigest         string `json:"policy_digest"`
	DescriptorCiphertext string `json:"descriptor_ciphertext,omitempty"`
	PlaintextPayload     string `json:"plaintext_payload,omitempty"`
	RejectionReason      string `json:"rejection_reason,omitempty"`
	ExpiresAt            uint64 `json:"expires_at"`
}

type v2PeerDeliveryState struct {
	Version                    int                           `json:"version"`
	RelationshipID             string                        `json:"relationship_id"`
	Role                       uint64                        `json:"role"`
	OutboundRelationshipSecret string                        `json:"outbound_relationship_secret"`
	InboundRelationshipSecret  string                        `json:"inbound_relationship_secret"`
	Capabilities               map[string]string             `json:"capabilities"`
	ServerContract             v2ServerContract              `json:"server_contract"`
	CapabilitiesIssuedAt       uint64                        `json:"capabilities_issued_at"`
	CapabilitiesExpireAt       uint64                        `json:"capabilities_expire_at"`
	CapabilityReissues         uint64                        `json:"capability_reissues"`
	Chains                     map[string]*v2ChainState      `json:"chains"`
	PendingControlPublications []v2PendingControlPublication `json:"pending_control_publications"`
	PendingGranularDeliveries  []v2PendingGranularDelivery   `json:"pending_granular_deliveries"`
	PendingCompletions         []v2PendingCompletion         `json:"pending_completions"`
	InboundTransfers           map[string]v2InboundTransfer  `json:"inbound_transfers"`
	Sent                       map[string]v2SentDelivery     `json:"sent"`
	DataScanEpoch              uint64                        `json:"data_scan_epoch"`
	ControlScanEpoch           uint64                        `json:"control_scan_epoch"`
	PendingDataEpochs          []uint64                      `json:"pending_data_epochs"`
	PendingControlEventIDs     []string                      `json:"pending_control_event_ids"`
	LastSuccessfulDrain        uint64                        `json:"last_successful_drain"`
	UndrainedControl           bool                          `json:"undrained_control"`
	ConsecutiveDrainFailures   uint64                        `json:"consecutive_drain_failures"`
	Halted                     bool                          `json:"halted"`
	HaltReason                 string                        `json:"halt_reason,omitempty"`
	SignedAcknowledgements     map[string]string             `json:"signed_acknowledgements"`
	PeerFeatures               []uint64                      `json:"peer_features,omitempty"`
}

func pairingStatePath(paths v2Paths, alias string) string {
	return filepath.Join(paths.StateDir, "pairings", alias+".json")
}

func peerDeliveryStatePath(paths v2Paths, relationshipID string) string {
	return filepath.Join(paths.StateDir, "deliveries", relationshipID+".json")
}

func ensureV2PeerStateDirectories(paths v2Paths) error {
	for _, directory := range []string{
		filepath.Join(paths.StateDir, "pairings"),
		filepath.Join(paths.StateDir, "deliveries"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func writeV2PendingPairing(paths v2Paths, pending *v2PendingPairing) error {
	if pending.Version != v2PairingStateVersion {
		return fmt.Errorf("pending pairing state has an unsupported schema version; %s", v2LocalStateResetInstruction)
	}
	if err := ensureV2PeerStateDirectories(paths); err != nil {
		return err
	}
	body, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return atomicWriteV2File(pairingStatePath(paths, pending.Alias), body, 0o600)
}

func loadV2PendingPairing(paths v2Paths, alias string) (*v2PendingPairing, error) {
	path := pairingStatePath(paths, alias)
	if err := validatePrivateV2File(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("peer %q has no pending pairing", alias)
		}
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pending v2PendingPairing
	if err := json.Unmarshal(body, &pending); err != nil {
		return nil, fmt.Errorf("parse pending pairing state: %w", err)
	}
	if pending.Version != v2PairingStateVersion || pending.Alias != alias {
		return nil, fmt.Errorf("pending pairing state is invalid; %s", v2LocalStateResetInstruction)
	}
	return &pending, nil
}

func removeV2PendingPairing(paths v2Paths, alias string) error {
	err := os.Remove(pairingStatePath(paths, alias))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func emptyV2ChainState() *v2ChainState {
	return &v2ChainState{
		SendDigest:    fmt.Sprintf("%064x", 0),
		ReceiveDigest: fmt.Sprintf("%064x", 0),
		Replay:        map[uint64]v2ReplayEntry{},
	}
}

func newV2PeerDeliveryState(pending *v2PendingPairing, capabilities map[string]string) *v2PeerDeliveryState {
	now := uint64(time.Now().Unix())
	return &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             pending.RelationshipID,
		Role:                       pending.Role,
		OutboundRelationshipSecret: pending.OutboundRelationshipSecret,
		InboundRelationshipSecret:  pending.InboundRelationshipSecret,
		Capabilities:               capabilities,
		ServerContract:             pending.ServerContract,
		CapabilitiesIssuedAt:       now,
		CapabilitiesExpireAt:       now + v2MaximumTTLSeconds,
		Chains: map[string]*v2ChainState{
			"out:data":    emptyV2ChainState(),
			"out:control": emptyV2ChainState(),
			"in:data":     emptyV2ChainState(),
			"in:control":  emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{},
		PendingGranularDeliveries:  []v2PendingGranularDelivery{},
		PendingCompletions:         []v2PendingCompletion{},
		InboundTransfers:           map[string]v2InboundTransfer{},
		Sent:                       map[string]v2SentDelivery{},
		SignedAcknowledgements:     map[string]string{},
		DataScanEpoch:              v2SlotEpoch(time.Now()),
		ControlScanEpoch:           v2SlotEpoch(time.Now()),
		PendingDataEpochs:          []uint64{},
		PendingControlEventIDs:     []string{},
	}
}

func validateV2PeerDeliveryState(state *v2PeerDeliveryState, relationshipID string) error {
	if state.Version != v2DeliveryStateVersion || state.RelationshipID != relationshipID || (state.Role != 0 && state.Role != 1) {
		return fmt.Errorf("peer delivery state identity is invalid; %s", v2LocalStateResetInstruction)
	}
	if decoded, err := hex.DecodeString(relationshipID); err != nil || len(decoded) != 16 {
		return errors.New("peer delivery relationship ID is invalid")
	}
	for name, value := range map[string]string{
		"outbound relationship": state.OutboundRelationshipSecret,
		"inbound relationship":  state.InboundRelationshipSecret,
	} {
		if _, err := decodeV2Base64URL(value, 32); err != nil {
			return fmt.Errorf("%s secret is invalid", name)
		}
	}
	if state.Capabilities == nil || state.Chains == nil || state.Sent == nil || state.SignedAcknowledgements == nil {
		return errors.New("peer delivery state is incomplete")
	}
	if _, err := state.ServerContract.capabilities(); err != nil {
		return fmt.Errorf("peer delivery server contract is invalid; re-pair this peer to refresh its protocol contract: %w", err)
	}
	for name, value := range state.Capabilities {
		if _, err := decodeV2Base64URL(value, 32); err != nil {
			return fmt.Errorf("peer delivery capability %q is invalid", name)
		}
	}
	if state.PendingControlPublications == nil {
		state.PendingControlPublications = []v2PendingControlPublication{}
	}
	if state.PendingGranularDeliveries == nil {
		state.PendingGranularDeliveries = []v2PendingGranularDelivery{}
	}
	if state.PendingCompletions == nil {
		state.PendingCompletions = []v2PendingCompletion{}
	}
	for _, completion := range state.PendingCompletions {
		values := []struct {
			encoded string
			length  int
		}{
			{completion.DeliveryID, 16},
			{completion.SourceSlot, 16},
			{completion.TargetSlot, 16},
			{completion.PolicyDigest, 32},
			{completion.DescriptorDigest, 32},
			{completion.OperationID, 16},
		}
		for _, value := range values {
			decoded, err := hex.DecodeString(value.encoded)
			if err != nil || len(decoded) != value.length {
				return errors.New("pending completion is invalid")
			}
		}
		acknowledgement, err := decodeV2Base64URL(completion.Acknowledgement, -1)
		if err != nil || len(acknowledgement) == 0 || len(acknowledgement) > v2MaxDescriptorBytes || completion.SourceSlotEpoch == 0 || completion.TargetSlotEpoch == 0 || completion.Result > 1 {
			return errors.New("pending completion is invalid")
		}
	}
	for _, delivery := range state.PendingGranularDeliveries {
		operationID, operationErr := hex.DecodeString(delivery.OperationID)
		slot, slotErr := hex.DecodeString(delivery.DataSlot)
		descriptor, descriptorErr := decodeV2Base64URL(delivery.EncryptedDescriptor, -1)
		payload, payloadErr := decodeV2Base64URL(delivery.PayloadCiphertext, -1)
		policy, policyErr := decodeV2Base64URL(delivery.RequestedPolicy, -1)
		digest, digestErr := hex.DecodeString(delivery.DescriptorDigest)
		if operationErr != nil || len(operationID) != 16 || slotErr != nil || len(slot) != 16 || descriptorErr != nil || len(descriptor) == 0 || len(descriptor) > v2MaxDescriptorBytes || payloadErr != nil || len(payload) > v2GranularMaxPayloadBytes || policyErr != nil || len(policy) == 0 || digestErr != nil || len(digest) != 32 || delivery.SlotEpoch == 0 || delivery.Sequence == 0 {
			return errors.New("pending granular delivery is invalid")
		}
	}
	for _, publication := range state.PendingControlPublications {
		operationID, operationErr := hex.DecodeString(publication.OperationID)
		slot, slotErr := hex.DecodeString(publication.ControlSlot)
		if operationErr != nil || len(operationID) != 16 || slotErr != nil || len(slot) != 16 || publication.SlotEpoch == 0 {
			return errors.New("pending control publication is invalid")
		}
		if event, err := decodeV2Base64URL(publication.EncryptedEvent, -1); err != nil || len(event) == 0 || len(event) > v2MaxDescriptorBytes {
			return errors.New("pending control publication envelope is invalid")
		}
	}
	if state.PendingDataEpochs == nil || state.PendingControlEventIDs == nil {
		return errors.New("peer delivery scan state is incomplete")
	}
	for _, id := range state.PendingControlEventIDs {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 16 {
			return errors.New("peer delivery pending control event ID is invalid")
		}
	}
	if state.InboundTransfers == nil {
		state.InboundTransfers = map[string]v2InboundTransfer{}
	}
	for _, name := range []string{"out:data", "out:control", "in:data", "in:control"} {
		chain := state.Chains[name]
		if chain == nil {
			return fmt.Errorf("peer delivery state is missing chain %q", name)
		}
		if chain.Replay == nil {
			chain.Replay = map[uint64]v2ReplayEntry{}
		}
		for label, digest := range map[string]string{
			"send":    chain.SendDigest,
			"receive": chain.ReceiveDigest,
		} {
			decoded, err := hex.DecodeString(digest)
			if err != nil || len(decoded) != 32 {
				return fmt.Errorf("peer delivery %s %s digest is invalid", name, label)
			}
		}
	}
	return nil
}

func writeV2PeerDeliveryState(paths v2Paths, state *v2PeerDeliveryState) error {
	if err := validateV2PeerDeliveryState(state, state.RelationshipID); err != nil {
		return err
	}
	if err := ensureV2PeerStateDirectories(paths); err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return atomicWriteV2File(peerDeliveryStatePath(paths, state.RelationshipID), body, 0o600)
}

func loadV2PeerDeliveryState(paths v2Paths, relationshipID string) (*v2PeerDeliveryState, error) {
	path := peerDeliveryStatePath(paths, relationshipID)
	if err := validatePrivateV2File(path); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state v2PeerDeliveryState
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, fmt.Errorf("parse peer delivery state: %w", err)
	}
	if err := validateV2PeerDeliveryState(&state, relationshipID); err != nil {
		return nil, err
	}
	return &state, nil
}

func pruneV2ReplayHistory(state *v2PeerDeliveryState, now uint64) {
	for _, chain := range state.Chains {
		for sequence, entry := range chain.Replay {
			if entry.ExpiresAt <= now {
				delete(chain.Replay, sequence)
			}
		}
		if len(chain.Replay) <= v2ReplayHistoryLimit {
			continue
		}
		cutoff := chain.ReceiveWatermark - min(chain.ReceiveWatermark, uint64(v2ReplayHistoryLimit))
		for sequence := range chain.Replay {
			if sequence <= cutoff {
				delete(chain.Replay, sequence)
			}
		}
	}
}

// pruneV2ExpiredInboundTransfers removes the private durable copy of payloads
// whose signed transport lifetime has ended. CommittedOutput remains
// not touched: it may be an operator-selected destination rather than DUD's
// own recovery copy.
//
// A payload that cannot be removed is reported rather than returned as a
// failure: pruning is upkeep that every peer operation performs, so a single
// undeletable file must not make the peer unusable. The remaining expired
// transfers are still pruned, and the offending record survives so the next
// operation retries it instead of losing track of plaintext left on disk.
func pruneV2ExpiredInboundTransfers(state *v2PeerDeliveryState, now uint64) (bool, []error) {
	changed := false
	var problems []error
	for digest, transfer := range state.InboundTransfers {
		if transfer.ExpiresAt == 0 || transfer.ExpiresAt > now {
			continue
		}
		paths := map[string]bool{}
		retained := false
		for _, path := range []string{transfer.PlaintextPayload, transfer.TemporaryOutput} {
			if path == "" || paths[path] {
				continue
			}
			paths[path] = true
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				problems = append(problems, fmt.Errorf("remove expired peer delivery payload %s: %w", digest, err))
				retained = true
			}
		}
		if retained {
			continue
		}
		delete(state.InboundTransfers, digest)
		changed = true
	}
	return changed, problems
}

// discardRedundantV2DurableCopy removes DUD's own copy of a payload as soon as
// a separate committed output holds the same bytes, rather than leaving it for
// the expiry pruner. Nothing reads that copy again except 'receive --id', which
// falls back to the committed output, so retaining it past the commit would
// only mean a second plaintext of every ordinary delivery sitting under the
// world directory for the sender's chosen lifetime.
//
// The copy is kept where it is still the only one: an output the operator
// skipped, a message that went to stdout, and an extracted collection, whose
// committed output is the destination directory rather than the archive these
// bytes are. Verifying the output against the signed digest decides all three
// without naming a payload type. A directory or a mismatch retains the copy.
func discardRedundantV2DurableCopy(transfer *v2InboundTransfer, durablePath, committedOutput string, payloadDigest []byte) (bool, error) {
	if durablePath == "" || committedOutput == "" || committedOutput == durablePath {
		return false, nil
	}
	if !v2ExistingOutputMatches(committedOutput, payloadDigest) {
		return false, nil
	}
	if err := os.Remove(durablePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove redundant peer delivery payload %s: %w", transfer.DescriptorDigest, err)
	}
	if transfer.PlaintextPayload == durablePath {
		transfer.PlaintextPayload = ""
	}
	if transfer.TemporaryOutput == durablePath {
		transfer.TemporaryOutput = ""
	}
	return true, nil
}

func v2BackoffDuration(failures uint64) time.Duration {
	if failures == 0 {
		return 0
	}
	seconds := uint64(1) << min(failures-1, uint64(8))
	if seconds > 300 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}

func v2BackoffWithJitter(failures uint64) time.Duration {
	base := v2BackoffDuration(failures)
	if base <= 0 {
		return 0
	}
	random, err := randomV2Bytes(2)
	if err != nil {
		return base
	}
	fraction := uint64(random[0])<<8 | uint64(random[1])
	jitter := time.Duration(fraction) * (base / 4) / 65535
	if base+jitter > 5*time.Minute {
		return 5 * time.Minute
	}
	return base + jitter
}
