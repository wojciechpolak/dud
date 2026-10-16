// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// cliNextStep identifies the actor as well as the command. A peer's local
// alias and profile are not transmitted during pairing, so remote commands
// explicitly require substitution rather than borrowing this device's names.
type cliNextStep struct {
	Device            string `json:"device"`
	Action            string `json:"action"`
	Command           string `json:"command"`
	PeerAliasRequired bool   `json:"peer_alias_required,omitempty"`
	ProfileRequired   bool   `json:"profile_required,omitempty"`
	label             string
}

// cliShellArg quotes values outside the portable alias grammar before a
// diagnostic turns them into a command a user may paste into a shell.
func cliShellArg(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\r\n'\"`$;&|()<>*?[]{}!\\") {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func localCLIStep(action, command string) cliNextStep {
	return cliNextStep{Device: "local", Action: action, Command: v2ProfiledCommand(command)}
}

func peerCLIStep(action, command string) cliNextStep {
	return cliNextStep{Device: "peer", Action: action, Command: "dud " + command, PeerAliasRequired: true, ProfileRequired: true}
}

func (step cliNextStep) text() string {
	if step.label != "" {
		return step.label + ": " + safeTerminalText(step.Command)
	}
	device := "Here"
	if step.Device == "peer" {
		device = "Other device"
	}
	command := device + ": " + safeTerminalText(step.Command)
	if step.Action == "" {
		return command
	}
	return safeTerminalText(step.Action) + "\n" + command
}

func cliStepRows(steps []cliNextStep) []textRow {
	rows := make([]textRow, 0, 2*len(steps))
	for _, step := range steps {
		for _, line := range strings.Split(step.text(), "\n") {
			rows = append(rows, textRow{Value: line, plain: true})
		}
	}
	return rows
}

type cliGuidanceError struct {
	cause error
	steps []cliNextStep
}

func (err *cliGuidanceError) Error() string {
	parts := []string{err.cause.Error()}
	for _, step := range err.steps {
		parts = append(parts, step.text())
	}
	return strings.Join(parts, "\n")
}
func (err *cliGuidanceError) Unwrap() error { return err.cause }
func withCLISteps(err error, steps ...cliNextStep) error {
	if err == nil {
		return nil
	}
	return &cliGuidanceError{cause: err, steps: steps}
}

func unknownV2Peer(alias string) error {
	return withCLISteps(fmt.Errorf("unknown peer %q", alias), localCLIStep("List peers in this profile.", "peer list"))
}

func v2HaltedPeerHint(reason, alias string) error {
	return withCLISteps(fmt.Errorf("peer relationship is halted: %s", reason),
		localCLIStep("Check peer state and verify both devices.", "peer show "+alias),
		localCLIStep("If both devices are trusted, preview reset losses.", "peer reset "+alias))
}

// scheduledV2RetryError keeps a durable backoff distinct from a failed new
// attempt, so the caller can name a safe queue-resume command and a real date.
type scheduledV2RetryError struct {
	kind string
	at   uint64
}

func (err *scheduledV2RetryError) Error() string {
	return fmt.Sprintf("next %s retry is scheduled at %s", err.kind, time.Unix(int64(err.at), 0).UTC().Format(time.RFC3339))
}

type v2StoredContractError struct{ cause error }

func (err *v2StoredContractError) Error() string {
	return "stored peer server contract is invalid: " + err.cause.Error()
}
func (err *v2StoredContractError) Unwrap() error { return err.cause }

func v2PeerOperationHint(err error, alias string) error {
	if err == nil {
		return nil
	}
	var guided *cliGuidanceError
	if errors.As(err, &guided) {
		return err
	}
	if validateV2PeerAlias(alias) != nil {
		return err
	}
	var contract *v2StoredContractError
	if errors.As(err, &contract) {
		return v2PeerStateFailureHint(err, alias)
	}
	var stop *v2ReceiveStop
	if errors.As(err, &stop) && stop.Next != "" {
		return withCLISteps(err)
	}
	var retry *scheduledV2RetryError
	if errors.As(err, &retry) {
		return withCLISteps(err, localCLIStep("Wait until the retry time; do not repeat send or Git push.", "sync "+alias))
	}
	var protocol *v2ProtocolError
	if errors.As(err, &protocol) && protocol.Status == 429 {
		return withCLISteps(err, localCLIStep("Wait for the limit to clear; do not repeat send or Git push.", "sync "+alias))
	}
	if isRetryableV2ConnectionError(err) {
		return withCLISteps(err, localCLIStep("Check connectivity before resuming queued work with sync.", "doctor"))
	}
	return withCLISteps(err, localCLIStep("Inspect this peer before retrying.", "peer show "+alias))
}

func v2PairingResumeCommand(pending *v2PendingPairing) string {
	action := "accept"
	if pending.Role == 0 {
		action = "invite"
	}
	return "peer " + action + " " + pending.Alias
}

func v2PairingNextSteps(pending *v2PendingPairing) []cliNextStep {
	steps := []cliNextStep{}
	if pending.Role == 0 {
		steps = append(steps, peerCLIStep("Enter the pairing code shared through a trusted channel.", "peer accept PEER"))
	} else {
		steps = append(steps, peerCLIStep("Keep the invitation running.", "peer invite PEER"))
	}
	return append(steps, v2PairingRecoverySteps(pending)...)
}

func v2PairingRecoverySteps(pending *v2PendingPairing) []cliNextStep {
	resume := localCLIStep("Resume pairing.", v2PairingResumeCommand(pending))
	resume.label = "Resume"
	cancel := localCLIStep("Cancel pairing.", "peer remove "+pending.Alias+" --yes")
	cancel.label = "Cancel"
	return []cliNextStep{resume, cancel}
}

type v2PairingTerminalError struct{ phase uint64 }

func (err *v2PairingTerminalError) Error() string {
	if err.phase == 4 {
		return "pairing was cancelled"
	}
	return "pairing invitation expired"
}

func v2PairingFailureHint(err error, pending *v2PendingPairing) error {
	var terminal *v2PairingTerminalError
	if errors.As(err, &terminal) || pending.ExpiresAt <= uint64(time.Now().Unix()) {
		if pending.Role == 0 {
			return withCLISteps(err, localCLIStep("Share a new pairing code.", "peer invite "+pending.Alias))
		}
		return withCLISteps(err, peerCLIStep("Share a new code through a trusted channel.", "peer invite PEER"), localCLIStep("Enter the new pairing code.", "peer accept "+pending.Alias))
	}
	return withCLISteps(fmt.Errorf("pairing interrupted: %w", err), v2PairingRecoverySteps(pending)...)
}

func v2QueuedPublicationHint(err error, alias string) error {
	command := "sync"
	if alias != "" {
		command += " " + alias
	}
	return withCLISteps(fmt.Errorf("delivery saved locally: %w", err), localCLIStep("Resume after any retry delay; do not repeat send or Git push.", command))
}

func v2PeerProfileNextSteps(paths v2Paths, alias string, peer v2PeerProfile) []cliNextStep {
	if peer.Status == "active" {
		return nil
	}
	if pending, err := loadV2PendingPairing(paths, alias); err == nil {
		return v2PairingNextSteps(pending)
	}
	if peer.Status == "revoked" {
		return []cliNextStep{localCLIStep("Pair again using an unused alias on each device.", "peer invite PEER")}
	}
	return []cliNextStep{localCLIStep("Share the code through a trusted channel.", "peer invite "+alias)}
}

func v2ReceiveOutputRecoveryCommand(opts v2PeerReceiveOptions, payloadType uint64) string {
	command := "receive " + opts.alias
	if opts.id != "" {
		return command + " --id " + opts.id + " --out PATH"
	}
	if payloadType == 3 {
		if !opts.noExtract {
			return command + " --out-dir PATH"
		}
		command += " --no-extract"
	}
	return command + " --out PATH"
}

func v2NetworkDiagnosticStep(settings v2NetworkSettings) cliNextStep {
	baseURL, dohURL, echMode := settings.values()
	command := "capabilities --url " + cliShellArg(baseURL) + " --doh-url " + cliShellArg(dohURL) + " --ech-mode " + cliShellArg(echMode) + " --json"
	return localCLIStep("Check connectivity; ask the operator if the probe still fails.", command)
}

func v2PeerStateFailureHint(err error, alias string) error {
	return withCLISteps(err, localCLIStep("Use a client compatible with the saved state.", "--version"), localCLIStep("Preview erasure of this pairing and its pending work.", "erase peer "+alias+" --dry-run"))
}

func cliUsageHint(err error) error {
	var guided *cliGuidanceError
	if err == nil || errors.As(err, &guided) {
		return err
	}
	return withCLISteps(err, localCLIStep("Check command syntax.", "help"))
}
