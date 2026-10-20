// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// v2GitTransferReport separates this operation's result from relationship-wide
// incoming refusals and repository-scoped outgoing refusals.
type v2GitTransferReport struct {
	summary            []string
	status             v2DeliveryStatus
	quarantined        []map[string]any
	rejected           []map[string]any
	refused            []map[string]any
	rejectedDigest     string
	confirmationQueued bool
	inboundWaiting     bool
	confirmationError  error
	checkpoint         []textRow
	peerSteps          []cliNextStep
}

func newV2GitTransferReport(runtime *v2PeerRuntime, state *v2GitPeerState) v2GitTransferReport {
	result := v2GitTransferReport{
		status:            v2DeliveryStatusOf(runtime.state, runtime.alias),
		rejected:          rejectedV2GitDeliveries(runtime.state),
		confirmationError: runtime.gitConfirmationErr,
	}
	if state != nil {
		result.quarantined = quarantinedV2GitDeliveries(state)
		result.refused = refusedV2GitCheckpoints(state)
	}
	result.inboundWaiting = result.status.InboundWaiting
	return result
}

// The scan's occupied epoch includes the delivery this fetch committed. It
// proves neither that more checkpoints exist there nor that the slot is empty.
// Other occupied epochs still identify incoming work independent of this fetch.
func v2GitOtherInboxEpochsWaiting(state *v2PeerDeliveryState, consumedEpoch uint64) bool {
	for _, epoch := range state.PendingDataEpochs {
		if epoch != consumedEpoch {
			return true
		}
	}
	return false
}

func loadV2GitReportState(runtime *v2PeerRuntime, repository *v2GitRepository) (*v2GitPeerState, error) {
	repositoryID, err := repository.loadRepositoryID()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	state, err := repository.loadPeerState(repositoryID, runtime.peer.PeerPseudonymousID)
	if err != nil {
		return nil, err
	}
	if err := reconcileV2GitAcknowledgements(runtime, repository, state); err != nil {
		return nil, err
	}
	return state, nil
}

func v2GitConfirmationQueued(state *v2PeerDeliveryState, digest string) bool {
	for _, completion := range state.PendingCompletions {
		if completion.DescriptorDigest == digest {
			return true
		}
	}
	return false
}

func v2GitCheckpointRows(mode v2GitCheckpointMode, sequence, baseSequence uint64, repositoryID, digest string, refs map[string]string) []textRow {
	rows := []textRow{
		{Label: "checkpoint mode", Value: string(mode)},
		{Label: "data sequence", Value: strconv.FormatUint(sequence, 10)},
		{Label: "repository ID", Value: repositoryID},
		{Label: "descriptor digest", Value: digest},
	}
	if baseSequence != 0 {
		rows = append(rows, textRow{Label: "acknowledged base sequence", Value: strconv.FormatUint(baseSequence, 10)})
	}
	for _, ref := range sortedKeys(refs) {
		rows = append(rows, textRow{Label: safeTerminalText(ref), Value: safeTerminalText(refs[ref])})
	}
	return rows
}

func (result v2GitTransferReport) report(verbose bool) *textReport {
	report := &textReport{}
	section := report.section("")
	for _, line := range result.summary {
		section.add(line, "")
	}
	attention := result.attention()
	if len(attention) != 0 {
		if len(result.summary) != 0 {
			section.add("", "")
		}
		for _, line := range attention {
			section.add(line, "")
		}
	}
	if !verbose {
		return report
	}
	if len(result.checkpoint) != 0 || result.confirmationError != nil {
		checkpoint := report.section("Checkpoint")
		checkpoint.addRows(result.checkpoint)
		if result.confirmationError != nil {
			checkpoint.add("confirmation publication error", safeTerminalText(result.confirmationError.Error()))
		}
	}
	status := report.section("Status")
	status.addRows(result.status.rows())
	for _, group := range []struct {
		label string
		items []map[string]any
		field string
	}{
		{"incoming Git checkpoints needing review", result.quarantined, "phase"},
		{"refused incoming checkpoints", result.rejected, "reason"},
		{"outgoing checkpoints refused by the peer", result.refused, "sequence"},
	} {
		if len(group.items) == 0 {
			status.add(group.label, "none")
			continue
		}
		entries := make([]string, 0, len(group.items))
		for _, item := range group.items {
			entries = append(entries, safeTerminalText(fmt.Sprintf("%v (%v)", item["descriptor_digest"], item[group.field])))
		}
		status.addList(group.label, strconv.Itoa(len(entries)), entries)
	}
	return report
}

func (result v2GitTransferReport) attention() []string {
	status := result.status
	alias := safeTerminalText(status.Alias)
	lines := []string{}
	rejected := 0
	for _, item := range result.rejected {
		if result.rejectedDigest == "" || item["descriptor_digest"] != result.rejectedDigest {
			rejected++
		}
	}
	if rejected != 0 {
		lines = append(lines, fmt.Sprintf("Warning: This device rejected %s from %s.", v2GitCheckpointCount(rejected, "incoming"), alias))
	}
	if len(result.refused) != 0 {
		lines = append(lines, fmt.Sprintf("Warning: %s rejected %s from this device.", alias, v2GitCheckpointCount(len(result.refused), "outgoing")))
	}
	if len(result.quarantined) != 0 {
		verb := "need"
		if len(result.quarantined) == 1 {
			verb = "needs"
		}
		lines = append(lines, fmt.Sprintf("Warning: %s from %s %s review.", v2GitCheckpointCount(len(result.quarantined), "incoming"), alias, verb))
	}
	if rejected != 0 || len(result.refused) != 0 || len(result.quarantined) != 0 || result.rejectedDigest != "" {
		lines = append(lines, "Details: "+safeTerminalText(v2ProfiledCommand("git status "+status.Alias)))
	}
	resetting := status.RelationshipReset != nil && status.RelationshipReset.Phase != "active" && status.RelationshipReset.Phase != "cancelled"
	guarded := resetting || status.Halted || len(status.QuarantinedChains) != 0
	if guarded {
		switch {
		case resetting:
			lines = append(lines, "Warning: The relationship with "+alias+" requires reset recovery.")
		case status.Halted:
			lines = append(lines, "Warning: The relationship with "+alias+" is halted.")
		default:
			lines = append(lines, "Warning: Transfers with "+alias+" require chain recovery.")
		}
		for _, step := range status.nextSteps() {
			if step.Device == "peer" {
				lines = append(lines, step.text())
				continue
			}
			label := "Resume"
			if step.Command == v2ProfiledCommand("peer show "+status.Alias) {
				label = "Details"
			}
			lines = append(lines, safeTerminalText(step.Action), label+": "+safeTerminalText(step.Command))
		}
		return lines
	}
	return append(lines, result.queueAttention()...)
}

func (result v2GitTransferReport) queueAttention() []string {
	status := result.status
	alias := safeTerminalText(status.Alias)
	lines := []string{}
	if status.PendingDeliveries != 0 || status.PendingChunkTransfers != 0 {
		lines = append(lines, "Warning: Local transfers to "+alias+" are waiting to be sent.")
	}
	if status.PendingCompletions != 0 && !result.confirmationQueued {
		lines = append(lines, "Warning: Confirmations for incoming transfers from "+alias+" are waiting to be sent.")
	}
	if status.PendingControlPublications != 0 || status.UndrainedControl {
		lines = append(lines, "Warning: Peer updates with "+alias+" need synchronization.")
	}
	if result.confirmationQueued || status.PendingDeliveries != 0 || status.PendingChunkTransfers != 0 || status.PendingCompletions != 0 || status.PendingControlPublications != 0 || status.UndrainedControl {
		lines = append(lines, "Resume: "+safeTerminalText(v2ProfiledCommand("sync "+status.Alias)))
	}
	if result.inboundWaiting {
		lines = append(lines, "Incoming data from "+alias+" was waiting at the last inbox check.")
	}
	if status.InboundChunkTransfers != 0 {
		lines = append(lines, "Warning: Incoming transfers from "+alias+" have unfinished downloads.")
	}
	if result.inboundWaiting || status.InboundChunkTransfers != 0 {
		lines = append(lines, "Check: "+safeTerminalText(v2ProfiledCommand("inbox "+status.Alias)))
	}
	for _, step := range result.peerSteps {
		lines = append(lines, step.text())
	}
	return lines
}

func v2GitCheckpointCount(count int, direction string) string {
	noun := "checkpoints"
	if count == 1 {
		noun = "checkpoint"
	}
	return fmt.Sprintf("%d %s Git %s", count, direction, noun)
}
