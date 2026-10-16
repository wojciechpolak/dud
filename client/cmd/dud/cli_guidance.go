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
	return cliNextStep{Device: "peer", Action: action + " Replace PROFILE_ON_OTHER_DEVICE and NAME_FOR_THIS_DEVICE with that device's paired profile and local alias; list aliases there with 'DUD_PROFILE=PROFILE_ON_OTHER_DEVICE dud peer list'.", Command: "DUD_PROFILE=PROFILE_ON_OTHER_DEVICE dud " + command, PeerAliasRequired: true, ProfileRequired: true}
}

func (step cliNextStep) text() string {
	device := "On this device"
	if step.Device == "peer" {
		device = "On the other device"
	}
	return fmt.Sprintf("%s: %s Run '%s'.", device, step.Action, step.Command)
}

func cliStepRows(steps []cliNextStep) []textRow {
	rows := make([]textRow, 0, len(steps))
	for _, step := range steps {
		rows = append(rows, textRow{Label: "next (" + step.Device + ")", Value: step.Action, Items: []string{step.Command}})
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
	return strings.Join(parts, "; ")
}
func (err *cliGuidanceError) Unwrap() error { return err.cause }
func withCLISteps(err error, steps ...cliNextStep) error {
	if err == nil {
		return nil
	}
	return &cliGuidanceError{cause: err, steps: steps}
}

func unknownV2Peer(alias string) error {
	return withCLISteps(fmt.Errorf("unknown peer %q", alias), localCLIStep("Check the aliases in this profile; select the profile containing the paired device.", "peer list"))
}

func v2HaltedPeerHint(reason, alias string) error {
	return withCLISteps(fmt.Errorf("peer relationship is halted: %s", reason),
		localCLIStep("Inspect the halt evidence. Verify the other device and its state before approving any reset or abandoning work.", "peer show "+alias),
		localCLIStep("If both devices are trusted, preview a reset and its abandoned work; the preview prints confirmation and cancellation commands.", "peer reset "+alias))
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
		return withCLISteps(err, localCLIStep("After the scheduled time, resume the saved queue. Do not repeat send or Git push: that creates another delivery.", "sync "+alias))
	}
	var protocol *v2ProtocolError
	if errors.As(err, &protocol) && protocol.Status == 429 {
		return withCLISteps(err, localCLIStep("Wait for the server's rate or quota limit to clear, then resume saved work; do not repeat send or Git push.", "sync "+alias))
	}
	if isRetryableV2ConnectionError(err) {
		return withCLISteps(err, localCLIStep("Check connectivity and the pinned server settings; restore connectivity before resuming saved work with '"+v2ProfiledCommand("sync "+alias)+"'.", "doctor --json"))
	}
	return withCLISteps(err, localCLIStep("Inspect this relationship and its pending work before retrying an operation.", "peer show "+alias))
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
		steps = append(steps, peerCLIStep("Accept the displayed pairing code through a trusted channel; enter it at the prompt. For a new pairing, choose the profile and alias to create on that device.", "peer accept NAME_FOR_THIS_DEVICE"))
	} else {
		steps = append(steps, peerCLIStep("Keep the invitation command running, or resume it to finish mutual authentication.", "peer invite NAME_FOR_THIS_DEVICE"))
	}
	return append(steps, localCLIStep("Keep this command running. If interrupted before expiry, resume the same pairing.", v2PairingResumeCommand(pending)), localCLIStep("To cancel this pending pairing instead, remove its local entry and cancel the rendezvous.", "peer remove "+pending.Alias+" --yes"))
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
			return withCLISteps(err, localCLIStep("Issue an invitation and share its new code with the other device.", "peer invite "+pending.Alias))
		}
		return withCLISteps(err, peerCLIStep("Issue an invitation and share its new code through a trusted channel.", "peer invite NAME_FOR_THIS_DEVICE"), localCLIStep("Accept the new code at the prompt.", "peer accept "+pending.Alias))
	}
	return withCLISteps(err, v2PairingNextSteps(pending)...)
}

func v2QueuedPublicationHint(err error, alias string) error {
	command := "sync"
	if alias != "" {
		command += " " + alias
	}
	return withCLISteps(fmt.Errorf("delivery committed locally and will retry publication: %w", err), localCLIStep("Resume the saved delivery here; do not repeat send or Git push because that creates another delivery. Respect any scheduled retry time.", command))
}

func v2PeerProfileNextSteps(paths v2Paths, alias string, peer v2PeerProfile) []cliNextStep {
	if peer.Status == "active" {
		return nil
	}
	if pending, err := loadV2PendingPairing(paths, alias); err == nil {
		return v2PairingNextSteps(pending)
	}
	if peer.Status == "revoked" {
		return []cliNextStep{localCLIStep("This relationship is revoked. To establish another one, choose an unused alias on both devices; replace NEW_PEER_ALIAS here and share the displayed pairing code.", "peer invite NEW_PEER_ALIAS")}
	}
	return []cliNextStep{localCLIStep("Start pairing here and share the displayed code through a trusted channel.", "peer invite "+alias)}
}

func v2ReceiveOutputRecoveryCommand(opts v2PeerReceiveOptions, payloadType uint64) string {
	command := "receive " + opts.alias
	if opts.id != "" {
		return command + " --id " + opts.id + " --out PATH_TO_NEW_OUTPUT"
	}
	if payloadType == 3 {
		if !opts.noExtract {
			return command + " --out-dir PATH_TO_NEW_DIRECTORY"
		}
		command += " --no-extract"
	}
	return command + " --out PATH_TO_NEW_OUTPUT"
}

func v2NetworkDiagnosticStep(settings v2NetworkSettings) cliNextStep {
	baseURL, dohURL, echMode := settings.values()
	command := "capabilities --url " + cliShellArg(baseURL) + " --doh-url " + cliShellArg(dohURL) + " --ech-mode " + cliShellArg(echMode) + " --json"
	return localCLIStep("Resolve the reported network or TLS error on this device and repeat this probe with the displayed settings. If the endpoint still refuses it, ask the server operator to inspect the server and proxy logs.", command)
}

func v2PeerStateFailureHint(err error, alias string) error {
	return withCLISteps(err, localCLIStep("Check the installed version and use one compatible with the saved state; retain the files if you intend to restore a backup.", "--version"), localCLIStep("If you choose to discard this pairing and its pending work, inspect the affected local files before confirming erasure. This preview does not remove them.", "erase peer "+alias+" --dry-run"))
}

func cliUsageHint(err error) error {
	var guided *cliGuidanceError
	if err == nil || errors.As(err, &guided) {
		return err
	}
	return withCLISteps(err, localCLIStep("Correct the reported arguments; consult the supported command forms and options.", "help"))
}
