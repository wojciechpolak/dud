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
		return "Complete on this device. If the other device still shows waiting, finish activation there; then sync. Starting another reset requires --new."
	case reset.Phase == "cancelled":
		return "Cancelled. The existing relationship is retained. Starting another reset requires --new."
	case reset.ServerActivated:
		return "Activated on the server. Finish activation here with the recovery command. Cancellation is unavailable."
	case reset.LocalConsent && reset.PeerConsent:
		return "Both consents are recorded. Use the recovery command here to retrieve the outcome and finish activation."
	case !reset.LocalConsent:
		return "The peer proposed a reset. Review the abandoned work and confirm here with the recovery command."
	default:
		return "Confirm on the other device with 'DUD_PROFILE=PROFILE_ON_OTHER_DEVICE dud peer reset NAME_FOR_THIS_DEVICE --yes' if this reset is not active there; use its profile and local alias from 'DUD_PROFILE=PROFILE_ON_OTHER_DEVICE dud peer list'. If it is active there, resume here."
	}
}

func v2ResetNextSteps(alias string, reset *v2RelationshipReset) []v2ResetNextStep {
	resume := v2ProfiledCommand("peer reset " + alias + " --yes")
	sync := v2ProfiledCommand("sync " + alias)
	peer := peerCLIStep("Use the other device's paired profile and its local alias for this device.", "peer reset NAME_FOR_THIS_DEVICE --yes")

	switch {
	case reset.Phase == "active":
		peer.Action = "If the other device still shows waiting or activating, finish activation there. " + peer.Action
		return []v2ResetNextStep{peer, {Device: "local", Action: "When both devices show active, synchronize here. This reset is complete on this device.", Command: sync}}
	case reset.Phase == "cancelled":
		peer.Action = "If the other device still shows a pending reset, retrieve the cancellation there. " + peer.Action
		return []v2ResetNextStep{{Device: "local", Action: "Inspect the retained relationship and pending work.", Command: v2ProfiledCommand("peer show " + alias)}, peer}
	case reset.ServerActivated || reset.LocalConsent && reset.PeerConsent:
		return []v2ResetNextStep{{Device: "local", Action: "Retrieve the reset outcome and finish activation here.", Command: resume}}
	case !reset.LocalConsent:
		return []v2ResetNextStep{{Device: "local", Action: "Review the abandoned work, then confirm this peer's reset here.", Command: resume}}
	default:
		peer.Action = "Confirm this reset on the other device only if it is not already active there. " + peer.Action
		return []v2ResetNextStep{peer, {Device: "local", Action: "After the other device reports activation, return here and finish the same reset.", Command: resume}}
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
