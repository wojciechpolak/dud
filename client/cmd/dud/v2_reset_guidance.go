// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "strings"

type v2ResetNextStep = cliNextStep

func v2ResetCanCancel(reset *v2RelationshipReset) bool {
	return !reset.ServerActivated && reset.Phase != "active" && reset.Phase != "cancelled"
}

func v2ResetStatusGuidance(reset *v2RelationshipReset) string {
	switch {
	case reset.Phase == "active":
		return "Reset complete here."
	case reset.Phase == "cancelled":
		return "Reset cancelled; pairing retained."
	case reset.ServerActivated:
		return "Server activated; finish here. Cancellation is unavailable."
	case reset.LocalConsent && reset.PeerConsent:
		return "Both devices agreed; finish activation here."
	case !reset.LocalConsent:
		return "Review reset losses before confirming."
	default:
		return "Waiting for the other device."
	}
}

func v2ResetNextSteps(alias string, reset *v2RelationshipReset) []v2ResetNextStep {
	resume := v2ProfiledCommand("peer reset " + alias + " --yes")
	sync := v2ProfiledCommand("sync " + alias)
	peer := peerCLIStep("", "peer reset PEER --yes")

	switch {
	case reset.Phase == "active":
		peer.Action = "If still waiting there, finish activation."
		return []v2ResetNextStep{peer, {Device: "local", Action: "Once both devices are active, sync.", Command: sync}}
	case reset.Phase == "cancelled":
		peer.Action = "If still pending there, retrieve cancellation."
		return []v2ResetNextStep{{Device: "local", Action: "Inspect the retained pairing.", Command: v2ProfiledCommand("peer show " + alias)}, peer}
	case reset.ServerActivated || reset.LocalConsent && reset.PeerConsent:
		return []v2ResetNextStep{{Device: "local", Action: "Finish activation here.", Command: resume}}
	case !reset.LocalConsent:
		return []v2ResetNextStep{{Device: "local", Action: "Confirm only if you accept the listed losses.", Command: resume}}
	default:
		peer.Action = "If not active there, confirm the reset."
		return []v2ResetNextStep{peer, {Device: "local", Action: "After activation there, finish here.", Command: resume}}
	}
}

func v2ResetRecoveryCommand(reset *v2RelationshipReset, aliases ...string) string {
	if len(aliases) != 0 && aliases[0] != "" {
		return v2ProfiledCommand("peer reset " + aliases[0] + " --yes")
	}
	if strings.HasPrefix(reset.RecoveryCommand, "DUD_PROFILE=") {
		if _, command, ok := strings.Cut(reset.RecoveryCommand, " dud "); ok {
			return v2ProfiledCommand(command)
		}
	}
	if command, ok := strings.CutPrefix(reset.RecoveryCommand, "dud "); ok {
		return v2ProfiledCommand(command)
	}
	return reset.RecoveryCommand
}
