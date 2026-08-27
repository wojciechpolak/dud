// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"fmt"
	"strconv"
)

// v2ReceivedItem records what one drained delivery did. A receive commits every
// delivery it can reach in one run, so the outcome of each one has to survive
// until the whole run is reported rather than being printed as it happens.
type v2ReceivedItem struct {
	Sequence         uint64 `json:"sequence"`
	DescriptorDigest string `json:"descriptor_digest"`
	PayloadType      uint64 `json:"payload_type"`
	DisplayName      string `json:"display_name,omitempty"`
	PlaintextSize    uint64 `json:"plaintext_size"`
	Output           string `json:"output"`
	Outcome          string `json:"outcome"`
	Conflict         string `json:"conflict,omitempty"`
	// Set when a copy DUD manages itself outlives the run. That copy is removed
	// as soon as a separate output holds the same bytes, so what remains is
	// either Output, a message or an output the operator skipped, or the archive
	// that an extracted collection came from, which RetainedPayload names.
	// Either way it is pruned once the delivery's signed transport lifetime
	// ends, and a reader is holding a path with a deadline rather than a
	// permanent one. It is the only announcement that plaintext DUD chose the
	// location of is still on disk, so it is set wherever that is true.
	OutputExpiresAt uint64 `json:"output_expires_at,omitempty"`
	// Set only when the retained copy is not Output itself.
	RetainedPayload string `json:"retained_payload,omitempty"`
}

// v2ReceiveStop ends a drain without failing it: the queue head needs a
// different command or an operator decision, and everything before it is
// already committed and acknowledged. The run reports what it did and exits
// zero, because refusing to report committed work would be worse than stopping.
type v2ReceiveStop struct {
	Reason   string // "git_checkpoint" | "conflict" | "replay"
	Sequence uint64
	Detail   string // the conflicting path, for a conflict
	Next     string // the command that unblocks the queue, when one exists
}

// Error keeps the wording each stop had when it was an outright failure, which
// is still how a run that committed nothing reports it. A conflict names a path
// the peer chose the last component of, so it is escaped here: this string is
// written straight to the terminal.
func (stop *v2ReceiveStop) Error() string {
	switch stop.Reason {
	case "git_checkpoint":
		return fmt.Sprintf("next delivery is a Git checkpoint; receive it with %s", stop.Next)
	case "conflict":
		return fmt.Sprintf("refusing to overwrite existing output %s", safeTerminalText(stop.Detail))
	}
	return stop.describe()
}

// describe renders the stop as the operator-facing reason line. It stays
// unescaped because JSON output encodes it verbatim; the text report escapes it
// where it renders.
func (stop *v2ReceiveStop) describe() string {
	switch stop.Reason {
	case "git_checkpoint":
		return fmt.Sprintf("Git checkpoint at sequence %d", stop.Sequence)
	case "conflict":
		return fmt.Sprintf("sequence %d would overwrite %s", stop.Sequence, stop.Detail)
	case "replay":
		return "the oldest delivery was already applied and awaits server retirement"
	}
	return stop.Reason
}

// receiveContainsMessage reports whether any drained item wrote its payload to
// stdout. When one did, the payload owns stdout and the report goes to stderr,
// so that piping a receive still yields only the messages.
func receiveContainsMessage(drained []v2ReceivedItem) bool {
	for _, item := range drained {
		if item.Outcome == "message" {
			return true
		}
	}
	return false
}

// v2ReceiveReportsStatus decides whether a receive prints its status block.
// It adds inbound work to the shared rule, because receive is the command that
// just refreshed that flag: a bounded or stopped drain leaves deliveries in the
// inbox, and an operator who is told only what arrived would read a partial
// drain as a complete one. After a send the same flag describes the previous
// inbox check, which is why the shared rule leaves it out.
func v2ReceiveReportsStatus(opts v2PeerReceiveOptions, status v2DeliveryStatus) bool {
	return opts.verbose || status.needsAttention() || status.InboundWaiting
}

func (a *app) renderV2ReceiveReport(opts v2PeerReceiveOptions, drained []v2ReceivedItem, stop *v2ReceiveStop, status v2DeliveryStatus) error {
	if opts.json {
		return writeJSON(a.out, v2ReceiveJSON(opts.alias, drained, stop, status))
	}
	out := a.out
	if receiveContainsMessage(drained) {
		out = a.errOut
	}
	// A run that drained nothing, or drained exactly one delivery cleanly, keeps
	// the single-delivery wording it has always had. The sectioned form below
	// only earns its extra lines once there is more than one outcome to report.
	if stop == nil && len(drained) == 0 {
		fmt.Fprintf(out, "No pending delivery from %s.\n", opts.alias)
		return status.reportWhen(v2ReceiveReportsStatus(opts, status), "Status").write(out)
	}
	// A retained archive is a second thing to report about the same delivery, so
	// it takes the sectioned form below rather than the one-line one: the whole
	// point of naming it is that it is not the path the operator asked for.
	if stop == nil && len(drained) == 1 && drained[0].RetainedPayload == "" {
		item := drained[0]
		if item.Outcome == "received" {
			fmt.Fprintf(out, "Received data sequence %d from %s at %s.\n", item.Sequence, opts.alias, safeTerminalText(item.Output))
			return status.reportWhen(v2ReceiveReportsStatus(opts, status), "Status").write(out)
		}
		if item.Outcome == "message" {
			return status.reportWhen(v2ReceiveReportsStatus(opts, status), "Status").write(out)
		}
	}
	report := &textReport{}
	report.section("").add(v2ReceiveHeadline(opts.alias, drained, stop), "")
	if len(drained) != 0 {
		received := report.section("Received")
		for _, item := range drained {
			received.addRows([]textRow{v2ReceivedItemRow(opts.alias, item)})
		}
	}
	if stop != nil {
		stopped := report.section("Stopped")
		stopped.add("reason", safeTerminalText(stop.describe()))
		if stop.Next != "" {
			stopped.add("next", stop.Next)
		}
	}
	// A section left empty is skipped when the report is written, so the same
	// visibility rule reportWhen applies to the single-delivery forms holds here
	// by declaring the section and filling it only when it earns its lines.
	if v2ReceiveReportsStatus(opts, status) {
		report.section("Status").addRows(status.rows())
	}
	return report.write(out)
}

// v2ReceiveHeadline opens the report with the one line an operator reads first:
// how much arrived, and whether the queue is now empty or merely blocked.
func v2ReceiveHeadline(alias string, drained []v2ReceivedItem, stop *v2ReceiveStop) string {
	count := "no deliveries"
	switch len(drained) {
	case 0:
	case 1:
		count = "1 delivery"
	default:
		count = fmt.Sprintf("%d deliveries", len(drained))
	}
	if stop == nil {
		return fmt.Sprintf("Received %s from %s.", count, alias)
	}
	if stop.Sequence == 0 {
		return fmt.Sprintf("Received %s from %s; stopped.", count, alias)
	}
	return fmt.Sprintf("Received %s from %s; stopped at sequence %d.", count, alias, stop.Sequence)
}

func v2ReceivedItemRow(alias string, item v2ReceivedItem) textRow {
	label := strconv.FormatUint(item.Sequence, 10)
	if item.DisplayName != "" {
		label += " " + safeTerminalText(item.DisplayName)
	}
	switch item.Outcome {
	case "message":
		return textRow{Label: label, Value: "message written to stdout"}
	case "skipped":
		return textRow{
			Label: label,
			Value: fmt.Sprintf("skipped: %s already exists", safeTerminalText(item.Conflict)),
			Items: []string{fmt.Sprintf(
				"recover with: dud receive %s --id %s --out PATH",
				alias, item.DescriptorDigest,
			)},
		}
	}
	row := textRow{Label: label, Value: safeTerminalText(item.Output)}
	if item.RetainedPayload != "" {
		row.Items = append(row.Items, "archive retained at "+safeTerminalText(item.RetainedPayload))
	}
	return row
}

// v2ReceiveJSON mirrors the text report field for field. The single-delivery
// keys are echoed at the top level when exactly one delivery arrived, so a
// caller written against the one-at-a-time receive keeps working.
func v2ReceiveJSON(alias string, drained []v2ReceivedItem, stop *v2ReceiveStop, status v2DeliveryStatus) map[string]any {
	if drained == nil {
		drained = []v2ReceivedItem{}
	}
	payload := map[string]any{
		"peer":            alias,
		"received":        len(drained) != 0,
		"count":           len(drained),
		"deliveries":      drained,
		"acknowledgement": status.PendingCompletions == 0,
	}
	if len(drained) == 1 {
		payload["sequence"] = drained[0].Sequence
		payload["descriptor_digest"] = drained[0].DescriptorDigest
		payload["output"] = drained[0].Output
	}
	if stop != nil {
		stopped := map[string]any{"reason": stop.Reason, "detail": stop.describe()}
		if stop.Sequence != 0 {
			stopped["sequence"] = stop.Sequence
		}
		if stop.Next != "" {
			stopped["next"] = stop.Next
		}
		payload["stopped"] = stopped
	}
	return status.merge(payload)
}
