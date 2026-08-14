// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// v2InboxPreview describes the delivery at the head of a peer's queue without
// committing it. Only the head is visible: the server answers an inbox query
// with the oldest pending delivery and nothing else, so there is no listing to
// report and this deliberately does not pretend otherwise.
type v2InboxPreview struct {
	Sequence         uint64 `json:"sequence"`
	Expected         uint64 `json:"expected_sequence"`
	DescriptorDigest string `json:"descriptor_digest"`
	PayloadType      uint64 `json:"payload_type"`
	Kind             string `json:"kind"`
	DisplayName      string `json:"display_name,omitempty"`
	PlaintextSize    uint64 `json:"plaintext_size"`
}

func v2PayloadKind(payloadType uint64) string {
	switch payloadType {
	case 1:
		return "message"
	case 2:
		return "file"
	case 3:
		return "collection"
	case 4:
		return "Git checkpoint"
	}
	return fmt.Sprintf("payload type %d", payloadType)
}

func (a *app) cmdInbox(args []string) error {
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
				return fatalError("Unknown inbox option: " + args[0])
			}
			if alias != "" {
				return errors.New("dud inbox accepts at most one peer")
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
	var failures []string
	for _, name := range aliases {
		result := map[string]any{"peer": name}
		err := a.withV2Peer(name, 60*time.Second, func(runtime *v2PeerRuntime) error {
			preview, err := runtime.previewInbox(context.Background())
			if err != nil {
				return err
			}
			if preview != nil {
				result["next"] = preview
			} else {
				result["next"] = nil
			}
			v2DeliveryStatusOf(runtime.state).merge(result)
			return nil
		})
		result["ok"] = err == nil
		if err != nil {
			result["error"] = err.Error()
			failures = append(failures, name+": "+err.Error())
		}
		results = append(results, result)
	}
	if jsonOutput {
		if err := writeJSON(a.out, results); err != nil {
			return err
		}
	} else if err := a.renderV2InboxReport(results); err != nil {
		return err
	}
	if len(failures) != 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (a *app) renderV2InboxReport(results []map[string]any) error {
	report := &textReport{}
	for _, result := range results {
		section := report.section("Inbox " + fmt.Sprint(result["peer"]))
		if result["ok"] != true {
			section.addf("result", "unavailable (%s)", result["error"])
			continue
		}
		preview, _ := result["next"].(*v2InboxPreview)
		if preview == nil {
			section.add("next delivery", "none")
		} else {
			section.addf("next delivery", "sequence %d", preview.Sequence)
			section.add("kind", preview.Kind)
			if preview.DisplayName != "" {
				section.add("name", safeTerminalText(preview.DisplayName))
			}
			section.addf("size", "%d bytes", preview.PlaintextSize)
			if preview.Sequence != preview.Expected {
				section.addf("expected", "sequence %d", preview.Expected)
			}
		}
		section.add("more waiting", v2YesNo(result["inbound_waiting"] == true))
		section.note(
			"Only the oldest delivery is visible; the rest appear as receive " +
				"drains them. Reading it here downloads its payload, which " +
				"receive fetches again, and commits nothing.",
		)
	}
	return report.write(a.out)
}

// previewInbox reads the head of the inbox and reports it without committing.
// Inbox reads do not consume, so nothing here retires a delivery, advances a
// watermark, or queues an acknowledgement. Inline control events are the one
// exception: they ride on the same response whether or not this command wants
// them, so dropping them on the floor would lose acknowledgements the peer
// already sent.
func (runtime *v2PeerRuntime) previewInbox(ctx context.Context) (*v2InboxPreview, error) {
	now := time.Now()
	dataProofs, err := runtime.granularDataQueryProofs(now)
	if err != nil {
		return nil, err
	}
	controlProofs, err := runtime.granularControlQueryProofs(now)
	if err != nil {
		return nil, err
	}
	processed, err := decodeV2ControlEventIDs(runtime.state.PendingControlEventIDs)
	if err != nil {
		return nil, err
	}
	response, err := queryV2GranularInbox(ctx, runtime.transport, runtime.origin, dataProofs, controlProofs, processed)
	if err != nil {
		return nil, err
	}
	rawControls, controlsOK := response.Header[2].([]any)
	if !controlsOK {
		return nil, errors.New("granular inbox control events are invalid")
	}
	if err := runtime.applyV2GranularControlResponse(rawControls); err != nil {
		return nil, err
	}
	if runtime.state.Halted {
		return nil, fmt.Errorf("peer relationship is halted: %s", runtime.state.HaltReason)
	}
	pendingEpochs, err := validateV2GranularDataSlotResults(response.Header, dataProofs)
	if err != nil {
		return nil, err
	}
	delivery, err := decodeV2GranularInboxDelivery(response)
	if err != nil {
		return nil, err
	}
	runtime.state.DataScanEpoch = v2SlotEpoch(now)
	runtime.state.PendingDataEpochs = pendingEpochs
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return nil, err
	}
	if delivery == nil {
		return nil, nil
	}
	expectation, err := runtime.descriptorExpectation()
	if err != nil {
		return nil, err
	}
	envelope, err := decryptAndValidateV2Envelope(delivery.EncryptedDescriptor, runtime.identity, expectation)
	if err != nil {
		return nil, err
	}
	chainID, err := descriptorUint(envelope.Descriptor, kChain, "chain")
	if err != nil || chainID != 0 {
		return nil, errors.New("inbox contains a non-data descriptor")
	}
	sequence, err := descriptorUint(envelope.Descriptor, kSequence, "sequence")
	if err != nil {
		return nil, err
	}
	payloadType, err := descriptorUint(envelope.Descriptor, kPayloadType, "payload type")
	if err != nil {
		return nil, err
	}
	displayName, _ := envelope.Descriptor[kDisplayName].(string)
	plaintextSize, _ := asV2Uint(envelope.Descriptor[kPlaintextSize])
	return &v2InboxPreview{
		Sequence:         sequence,
		Expected:         runtime.state.Chains["in:data"].ReceiveWatermark + 1,
		DescriptorDigest: hex.EncodeToString(envelope.DescriptorDigest[:]),
		PayloadType:      payloadType,
		Kind:             v2PayloadKind(payloadType),
		DisplayName:      displayName,
		PlaintextSize:    plaintextSize,
	}, nil
}
