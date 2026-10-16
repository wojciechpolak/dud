// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// v2QuarantinedChain names one halted delivery chain and why it stopped.
type v2QuarantinedChain struct {
	Chain  string `json:"chain"`
	Reason string `json:"reason"`
}

type v2ResumableTransfer struct {
	Direction        string `json:"direction"`
	DescriptorDigest string `json:"descriptor_digest"`
	RemainingBytes   uint64 `json:"remaining_bytes"`
}

// v2DeliveryStatus is the single summary of durable local relationship state
// that every peer-facing command reports. Queued work, undrained control
// events, quarantined chains, and a halted relationship are operator-visible
// facts, so text and JSON output render them from this one value rather than
// from per-command ad-hoc maps.
type v2DeliveryStatus struct {
	Alias                      string
	Generation                 uint64
	RelationshipReset          *v2RelationshipReset
	PendingDeliveries          int
	PendingChunkTransfers      int
	PendingChunkBytes          uint64
	InboundChunkTransfers      int
	InboundChunkBytes          uint64
	ResumableTransfers         []v2ResumableTransfer
	PendingCompletions         int
	PendingControlPublications int
	UnacknowledgedDeliveries   int
	// InboundWaiting reports whether the last inbox query left deliveries
	// behind. Only a command that queries the inbox refreshes it, so after a
	// send it still describes the previous check rather than the queue now.
	InboundWaiting      bool
	UndrainedControl    bool
	QuarantinedChains   []v2QuarantinedChain
	Halted              bool
	HaltReason          string
	HaltEvidence        *v2HaltEvidence
	LastSuccessfulDrain uint64
}

func v2DeliveryStatusOf(state *v2PeerDeliveryState, aliases ...string) v2DeliveryStatus {
	pendingChunkBytes := uint64(0)
	resumableTransfers := make([]v2ResumableTransfer, 0, len(state.PendingChunkDeliveries)+len(state.InboundTransfers))
	for _, transfer := range state.PendingChunkDeliveries {
		remaining := uint64(0)
		for _, part := range transfer.Parts {
			if !part.Uploaded {
				pendingChunkBytes += part.CiphertextLength
				remaining += part.CiphertextLength
			}
		}
		resumableTransfers = append(resumableTransfers, v2ResumableTransfer{
			Direction: "upload", DescriptorDigest: transfer.DescriptorDigest, RemainingBytes: remaining,
		})
	}
	inboundChunkTransfers := 0
	inboundChunkBytes := uint64(0)
	for _, transfer := range state.InboundTransfers {
		if len(transfer.Chunks) == 0 {
			continue
		}
		inboundChunkTransfers++
		remaining := uint64(0)
		for _, part := range transfer.Chunks {
			if !part.Downloaded {
				inboundChunkBytes += part.CiphertextLength
				remaining += part.CiphertextLength
			}
		}
		resumableTransfers = append(resumableTransfers, v2ResumableTransfer{
			Direction: "download", DescriptorDigest: transfer.DescriptorDigest, RemainingBytes: remaining,
		})
	}
	sort.Slice(resumableTransfers, func(left, right int) bool {
		if resumableTransfers[left].Direction != resumableTransfers[right].Direction {
			return resumableTransfers[left].Direction < resumableTransfers[right].Direction
		}
		return resumableTransfers[left].DescriptorDigest < resumableTransfers[right].DescriptorDigest
	})
	status := v2DeliveryStatus{
		Generation:                 state.Generation,
		RelationshipReset:          state.Reset,
		PendingDeliveries:          len(state.PendingGranularDeliveries) + len(state.PendingChunkDeliveries),
		PendingChunkTransfers:      len(state.PendingChunkDeliveries),
		PendingChunkBytes:          pendingChunkBytes,
		InboundChunkTransfers:      inboundChunkTransfers,
		InboundChunkBytes:          inboundChunkBytes,
		ResumableTransfers:         resumableTransfers,
		PendingCompletions:         len(state.PendingCompletions),
		PendingControlPublications: len(state.PendingControlPublications),
		UnacknowledgedDeliveries:   unacknowledgedV2Deliveries(state),
		InboundWaiting:             len(state.PendingDataEpochs) != 0,
		UndrainedControl:           state.UndrainedControl,
		QuarantinedChains:          []v2QuarantinedChain{},
		Halted:                     state.Halted,
		HaltReason:                 state.HaltReason,
		HaltEvidence:               state.HaltEvidence,
		LastSuccessfulDrain:        state.LastSuccessfulDrain,
	}
	for name, chain := range state.Chains {
		if chain != nil && chain.Quarantined {
			status.QuarantinedChains = append(status.QuarantinedChains, v2QuarantinedChain{
				Chain:  name,
				Reason: chain.QuarantineReason,
			})
		}
	}
	sort.Slice(status.QuarantinedChains, func(left, right int) bool {
		return status.QuarantinedChains[left].Chain < status.QuarantinedChains[right].Chain
	})
	if len(aliases) != 0 {
		status.Alias = aliases[0]
	}
	return status
}

// unacknowledgedV2Deliveries counts committed outbound deliveries whose signed
// acknowledgement has not been drained yet. The queue counters only describe
// work this device still owes the server, so without this count a delivery the
// peer never fetched is indistinguishable from one it fetched and confirmed.
func unacknowledgedV2Deliveries(state *v2PeerDeliveryState) int {
	count := 0
	for _, sent := range state.Sent {
		if !sent.Acknowledged {
			count++
		}
	}
	return count
}

// fields renders the JSON keys shared by every command that reports status.
func (status v2DeliveryStatus) fields() map[string]any {
	fields := map[string]any{
		"generation":                   status.Generation,
		"pending_deliveries":           status.PendingDeliveries,
		"pending_chunk_transfers":      status.PendingChunkTransfers,
		"pending_chunk_bytes":          status.PendingChunkBytes,
		"inbound_chunk_transfers":      status.InboundChunkTransfers,
		"inbound_chunk_bytes":          status.InboundChunkBytes,
		"resumable_transfers":          status.ResumableTransfers,
		"pending_completions":          status.PendingCompletions,
		"pending_control_publications": status.PendingControlPublications,
		"unacknowledged_deliveries":    status.UnacknowledgedDeliveries,
		"inbound_waiting":              status.InboundWaiting,
		"undrained_control":            status.UndrainedControl,
		"quarantined_chains":           status.QuarantinedChains,
		"halted":                       status.Halted,
		"halt_reason":                  status.HaltReason,
		"last_successful_drain":        status.LastSuccessfulDrain,
	}
	if status.Alias != "" {
		fields["next_steps"] = status.nextSteps()
	}
	if status.RelationshipReset != nil {
		fields["relationship_reset"] = status.RelationshipReset
		fields["relationship_reset_next_step"] = v2ResetStatusGuidance(status.RelationshipReset)
		fields["relationship_reset_can_cancel"] = v2ResetCanCancel(status.RelationshipReset)
		if status.RelationshipReset.Phase != "active" && status.RelationshipReset.Phase != "cancelled" {
			fields["relationship_reset_recovery_command"] = v2ResetRecoveryCommand(status.RelationshipReset, status.Alias)
			if v2ResetCanCancel(status.RelationshipReset) {
				fields["relationship_reset_cancel_command"] = v2ResetRecoveryCommand(status.RelationshipReset, status.Alias) + " --cancel"
			}
		}
	}
	if status.HaltEvidence != nil {
		fields["halt_evidence"] = status.HaltEvidence
	}
	return fields
}

func (status v2DeliveryStatus) merge(target map[string]any) map[string]any {
	for key, value := range status.fields() {
		target[key] = value
	}
	return target
}

// needsAttention identifies saved work and recovery guards that take priority
// over waiting for a normal acknowledgement. Unacknowledged deliveries alone
// do not indicate a stalled relationship.
func (status v2DeliveryStatus) needsAttention() bool {
	return status.PendingDeliveries != 0 ||
		status.InboundChunkTransfers != 0 ||
		status.PendingCompletions != 0 ||
		status.PendingControlPublications != 0 ||
		status.UndrainedControl ||
		len(status.QuarantinedChains) != 0 ||
		status.Halted ||
		(status.RelationshipReset != nil && status.RelationshipReset.Phase != "active" && status.RelationshipReset.Phase != "cancelled")
}

// rows renders every counter and recovery detail for explicit diagnostics and
// verbose transfer output. Zero counters keep these reports comparable.
func (status v2DeliveryStatus) rows() []textRow {
	uploads := textRow{Label: "resumable uploads", Value: strconv.Itoa(status.PendingChunkTransfers)}
	downloads := textRow{Label: "resumable downloads", Value: strconv.Itoa(status.InboundChunkTransfers)}
	for _, transfer := range status.ResumableTransfers {
		item := fmt.Sprintf("%s (%d bytes remaining)", transfer.DescriptorDigest, transfer.RemainingBytes)
		if transfer.Direction == "upload" {
			uploads.Items = append(uploads.Items, item)
		} else {
			downloads.Items = append(downloads.Items, item)
		}
	}
	quarantined := textRow{Label: "quarantined chains", Value: "none"}
	if len(status.QuarantinedChains) != 0 {
		items := make([]string, 0, len(status.QuarantinedChains))
		for _, chain := range status.QuarantinedChains {
			items = append(items, fmt.Sprintf("%s (%s)", chain.Chain, chain.Reason))
		}
		quarantined.Value = strconv.Itoa(len(items))
		quarantined.Items = items
	}
	halted := "no"
	if status.Halted {
		halted = "yes"
		if status.HaltReason != "" {
			halted = "yes (" + status.HaltReason + ")"
		}
	}
	rows := []textRow{
		{Label: "queued deliveries", Value: strconv.Itoa(status.PendingDeliveries)},
		uploads,
		{Label: "resumable upload bytes", Value: strconv.FormatUint(status.PendingChunkBytes, 10)},
		downloads,
		{Label: "resumable download bytes", Value: strconv.FormatUint(status.InboundChunkBytes, 10)},
		{Label: "queued completions", Value: strconv.Itoa(status.PendingCompletions)},
		{Label: "queued control events", Value: strconv.Itoa(status.PendingControlPublications)},
		{Label: "unacknowledged deliveries", Value: strconv.Itoa(status.UnacknowledgedDeliveries)},
		{Label: "inbound waiting", Value: v2YesNo(status.InboundWaiting)},
		{Label: "undrained control", Value: v2YesNo(status.UndrainedControl)},
		quarantined,
		{Label: "halted", Value: halted},
		{Label: "active generation", Value: strconv.FormatUint(status.Generation, 10)},
	}
	if reset := status.RelationshipReset; reset != nil {
		rows = append(rows,
			textRow{Label: "peer relationship reset", Value: reset.Phase},
			textRow{Label: "reset proposal ID", Value: reset.ResetID},
			textRow{Label: "reset local consent", Value: v2YesNo(reset.LocalConsent)},
			textRow{Label: "reset peer consent", Value: v2YesNo(reset.PeerConsent)},
			textRow{Label: "reset server activation", Value: v2YesNo(reset.ServerActivated)},
			textRow{Label: "reset local abandoned", Value: formatV2ResetDisposition(reset.LocalDisposition)},
			textRow{Label: "reset peer abandoned", Value: formatV2ResetDisposition(reset.PeerDisposition)},
			textRow{Label: "reset next step", Value: v2ResetStatusGuidance(reset)},
		)
		if reset.Phase != "active" && reset.Phase != "cancelled" {
			rows = append(rows, textRow{Label: "reset recovery command", Value: v2ResetRecoveryCommand(reset, status.Alias)})
			if v2ResetCanCancel(reset) {
				rows = append(rows, textRow{Label: "cancel before activation", Value: v2ResetRecoveryCommand(reset, status.Alias) + " --cancel"})
			}
		}
	}
	if evidence := status.HaltEvidence; evidence != nil {
		rows = append(rows,
			textRow{Label: "rollback field", Value: evidence.Field},
			textRow{Label: "signed peer value", Value: strconv.FormatUint(evidence.PeerValue, 10)},
			textRow{Label: "corresponding local value", Value: strconv.FormatUint(evidence.LocalValue, 10)},
			textRow{Label: "control descriptor", Value: fmt.Sprintf("sequence %d, digest %s", evidence.DescriptorSequence, evidence.DescriptorDigest)},
			textRow{Label: "relationship ID", Value: evidence.RelationshipID},
		)
	}
	return append(rows, cliStepRows(status.nextSteps())...)
}

func formatV2ResetDisposition(value v2ResetDisposition) string {
	return fmt.Sprintf(
		"queued %d, completions %d, control %d, unacknowledged %d, inbound %d, quarantined chains %d, resumable %d, refused Git checkpoints %d",
		value.QueuedDeliveries,
		value.QueuedCompletions,
		value.QueuedControlEvents,
		value.Unacknowledged,
		value.InboundTransfers,
		value.QuarantinedChains,
		value.ResumableTransfers,
		value.RefusedGitCheckpoints,
	)
}

// renderInto attaches the counters as a titled block under the given section.
func (status v2DeliveryStatus) renderInto(parent *textSection, title string) {
	parent.child(title).addRows(status.rows())
}

// report renders the counters as a standalone block, for the commands whose
// whole output is a status report.
func (status v2DeliveryStatus) report(title string) *textReport {
	out := &textReport{}
	out.section(title).addRows(status.rows())
	return out
}

// transferReport keeps routine results compact while verbose output includes
// every counter and the evidence needed to diagnose a relationship.
func (status v2DeliveryStatus) transferReport(verbose bool, title string, nextReported ...bool) *textReport {
	if verbose {
		return status.report(title)
	}
	return status.compactReport(0, 0, nextReported...)
}

// compactReport uses at most three lines. Lists and untrusted reason strings
// belong in explicit diagnostics, so neither can grow a transfer's footer.
func (status v2DeliveryStatus) compactReport(quarantinedGit, rejectedGit int, nextReported ...bool) *textReport {
	parts := []string{
		fmt.Sprintf("queued deliveries %d", status.PendingDeliveries),
		fmt.Sprintf("unacknowledged deliveries %d", status.UnacknowledgedDeliveries),
	}
	for _, item := range []struct {
		label string
		count int
	}{
		{"resumable uploads", status.PendingChunkTransfers},
		{"resumable downloads", status.InboundChunkTransfers},
		{"queued completions", status.PendingCompletions},
		{"queued control events", status.PendingControlPublications},
	} {
		if item.count != 0 {
			parts = append(parts, fmt.Sprintf("%s %d", item.label, item.count))
		}
	}
	if status.InboundWaiting {
		parts = append(parts, "inbound waiting at last check")
	}
	if status.UndrainedControl {
		parts = append(parts, "undrained control")
	}
	warnings := []string{}
	if status.Halted {
		warnings = append(warnings, "relationship halted")
	}
	if reset := status.RelationshipReset; reset != nil && reset.Phase != "active" && reset.Phase != "cancelled" {
		warnings = append(warnings, "relationship reset "+safeTerminalText(reset.Phase))
	}
	if len(status.QuarantinedChains) != 0 {
		warnings = append(warnings, fmt.Sprintf("quarantined chains %d", len(status.QuarantinedChains)))
	}
	if quarantinedGit != 0 {
		warnings = append(warnings, fmt.Sprintf("quarantined Git deliveries %d", quarantinedGit))
	}
	if rejectedGit != 0 {
		warnings = append(warnings, fmt.Sprintf("refused Git deliveries %d", rejectedGit))
	}
	report := &textReport{}
	section := report.section("")
	section.add("Status: "+strings.Join(parts, "; ")+".", "")
	if len(warnings) != 0 {
		section.add("Warning: "+strings.Join(warnings, "; ")+".", "")
	}
	if status.Alias != "" {
		command := ""
		label := "Next (local): "
		resetting := status.RelationshipReset != nil && status.RelationshipReset.Phase != "active" && status.RelationshipReset.Phase != "cancelled"
		if resetting {
			command = v2ProfiledCommand("peer reset " + status.Alias)
		} else if (quarantinedGit != 0 || rejectedGit != 0) && !status.Halted && len(status.QuarantinedChains) == 0 {
			command = v2ProfiledCommand("git status " + status.Alias)
		} else {
			for _, step := range status.nextSteps() {
				if step.Device == "local" {
					command = step.Command
					break
				}
			}
			if !status.needsAttention() && !status.InboundWaiting && status.UnacknowledgedDeliveries != 0 {
				label = "After receipt: "
			}
		}
		if command != "" && !(len(nextReported) != 0 && nextReported[0] && !status.needsAttention()) {
			section.add(label+safeTerminalText(command), "")
		}
	}
	return report
}

func v2YesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

// nextSteps prioritizes recovery guards over ordinary queue work. Synchronizing
// a halted or resetting relationship cannot advance it, and must not be shown
// as a way around that guard.
func (status v2DeliveryStatus) nextSteps() []cliNextStep {
	alias := status.Alias
	if alias == "" {
		return nil
	}
	if reset := status.RelationshipReset; reset != nil && reset.Phase != "active" && reset.Phase != "cancelled" {
		return v2ResetNextSteps(alias, reset)
	}
	if status.Halted {
		return []cliNextStep{localCLIStep("Check peer state and verify both devices.", "peer show "+alias), localCLIStep("If both devices are trusted, preview reset losses.", "peer reset "+alias)}
	}
	if len(status.QuarantinedChains) != 0 {
		return []cliNextStep{localCLIStep("Skipping loses deliveries; ask the sender to resend them.", "peer resume "+alias)}
	}
	steps := []cliNextStep{}
	if status.PendingDeliveries != 0 || status.PendingCompletions != 0 || status.PendingControlPublications != 0 || status.UndrainedControl {
		steps = append(steps, localCLIStep("Resume after any retry delay; do not repeat send or Git push.", "sync "+alias))
	}
	if status.InboundWaiting || status.InboundChunkTransfers != 0 {
		steps = append(steps, localCLIStep("Check whether receive or git fetch is needed.", "inbox "+alias))
	}
	if status.UnacknowledgedDeliveries != 0 {
		steps = append(steps, peerCLIStep("Receive files/messages; use git fetch for checkpoints.", "receive PEER"), localCLIStep("After peer receipt, collect the acknowledgement.", "sync "+alias))
	}
	return steps
}
