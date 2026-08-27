// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"fmt"
	"sort"
	"strconv"
)

// v2QuarantinedChain names one halted delivery chain and why it stopped.
type v2QuarantinedChain struct {
	Chain  string `json:"chain"`
	Reason string `json:"reason"`
}

// v2DeliveryStatus is the single summary of durable local relationship state
// that every peer-facing command reports. Queued work, undrained control
// events, quarantined chains, and a halted relationship are operator-visible
// facts, so text and JSON output render them from this one value rather than
// from per-command ad-hoc maps.
type v2DeliveryStatus struct {
	PendingDeliveries          int
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
	LastSuccessfulDrain uint64
}

func v2DeliveryStatusOf(state *v2PeerDeliveryState) v2DeliveryStatus {
	status := v2DeliveryStatus{
		PendingDeliveries:          len(state.PendingGranularDeliveries),
		PendingCompletions:         len(state.PendingCompletions),
		PendingControlPublications: len(state.PendingControlPublications),
		UnacknowledgedDeliveries:   unacknowledgedV2Deliveries(state),
		InboundWaiting:             len(state.PendingDataEpochs) != 0,
		UndrainedControl:           state.UndrainedControl,
		QuarantinedChains:          []v2QuarantinedChain{},
		Halted:                     state.Halted,
		HaltReason:                 state.HaltReason,
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
	return map[string]any{
		"pending_deliveries":           status.PendingDeliveries,
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
}

func (status v2DeliveryStatus) merge(target map[string]any) map[string]any {
	for key, value := range status.fields() {
		target[key] = value
	}
	return target
}

// needsAttention reports whether anything is queued, undrained, quarantined,
// or halted, which is what decides whether an action command volunteers its
// status block. Unacknowledged deliveries are excluded. Every successful send
// remains unacknowledged until the peer receives it, so counting them would
// raise the block during ordinary progress.
func (status v2DeliveryStatus) needsAttention() bool {
	return status.PendingDeliveries != 0 ||
		status.PendingCompletions != 0 ||
		status.PendingControlPublications != 0 ||
		status.UndrainedControl ||
		len(status.QuarantinedChains) != 0 ||
		status.Halted
}

// rows renders the counters that send, receive, sync, doctor, peer show, and
// the Git commands all report. Whenever the block is printed at all, every
// counter is present, including the zeros: a healthy relationship and a stalled
// one have the same shape, so an operator reads the same rows in the same order
// in either case, and a missing row means a command forgot to report rather
// than a queue being empty. Whether an action command prints the block in the
// first place is a separate decision, made by reportWhen.
func (status v2DeliveryStatus) rows() []textRow {
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
	return []textRow{
		{Label: "queued deliveries", Value: strconv.Itoa(status.PendingDeliveries)},
		{Label: "queued completions", Value: strconv.Itoa(status.PendingCompletions)},
		{Label: "queued control events", Value: strconv.Itoa(status.PendingControlPublications)},
		{Label: "unacknowledged deliveries", Value: strconv.Itoa(status.UnacknowledgedDeliveries)},
		{Label: "inbound waiting", Value: v2YesNo(status.InboundWaiting)},
		{Label: "undrained control", Value: v2YesNo(status.UndrainedControl)},
		quarantined,
		{Label: "halted", Value: halted},
	}
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

// reportWhen renders the counters for a command whose result is one line and
// whose status block is a footer. An operator running a send or a receive asked
// to move data, not to read eight counters, so the block appears only when it
// was asked for or when something is actually wrong. A stalled relationship
// still announces itself without the flag, because silence there would be a
// report that everything is fine.
func (status v2DeliveryStatus) reportWhen(verbose bool, title string) *textReport {
	if !verbose && !status.needsAttention() {
		return &textReport{}
	}
	return status.report(title)
}

func v2YesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
