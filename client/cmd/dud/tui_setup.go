// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

func isTUISetupAction(action string) bool {
	return action == "initialize" || action == "invite" || action == "accept"
}

func newTUISetupForm(action string) *tuiForm {
	form := &tuiForm{action: action}
	switch action {
	case "initialize":
		form.addInput("device", "Name of this device", "")
		form.addInput("url", "Peer server URL (use the same server on both devices)", "")
		form.addInput("doh", "DNS-over-HTTPS resolver", "")
		form.addInput("ech", "ECH mode (hard or off)", "hard")
	case "invite":
		form.addInput("alias", "Local alias for the device you are inviting", "")
		form.addInput("expires", "Invitation lifetime", "15m")
		form.addInput("enrollment", "Enrollment secret (blank: use DUD_PEER_SECRET)", "")
		form.fields[2].input.EchoMode = textinput.EchoPassword
	case "accept":
		form.addInput("alias", "Local alias for the device that invited you", "")
		form.addInput("code", "Pairing code (blank: resume a pending acceptance)", "")
	}
	form.setTheme(defaultTUITheme())
	return form
}

func (form *tuiForm) setupArguments() ([]string, error) {
	if form.action == "initialize" {
		if err := validateV2DeviceName(form.value("device")); err != nil {
			return nil, err
		}
		if _, err := canonicalV2Origin(form.value("url")); err != nil {
			return nil, err
		}
		if _, err := canonicalV2DOHURL(form.value("doh")); err != nil {
			return nil, err
		}
		if form.value("ech") != "hard" && form.value("ech") != "off" {
			return nil, errors.New("ECH mode must be hard or off.")
		}
		return []string{"init", "--device", form.value("device"), "--url", form.value("url"), "--doh-url", form.value("doh"), "--ech-mode", form.value("ech")}, nil
	}
	alias := form.value("alias")
	if err := validateV2PeerAlias(alias); err != nil {
		return nil, err
	}
	if form.action == "invite" {
		args := []string{"peer", "invite", alias, "--expires", form.value("expires")}
		_, err := parseV2PeerInviteOptions(args[2:])
		return args, err
	}
	if code := form.value("code"); code != "" {
		if _, err := parseV2PairingCode(code); err != nil {
			return nil, err
		}
	}
	return []string{"peer", "accept", alias}, nil
}

func (form *tuiForm) setupInput() tuiSetupInput {
	return tuiSetupInput{pairingCode: form.value("code"), enrollmentSecret: form.value("enrollment")}
}

func (form *tuiForm) clearSetupSecrets() {
	for index := range form.fields {
		if form.fields[index].key == "code" || form.fields[index].key == "enrollment" {
			form.fields[index].input.SetValue("")
		}
	}
}

func (form *tuiForm) submitLabel() string {
	switch form.action {
	case "initialize":
		return "Initialize device"
	case "invite":
		return "Create invitation"
	case "accept":
		return "Accept invitation"
	case "git-push":
		return "Push checkpoint"
	case "git-fetch":
		return "Fetch checkpoint"
	case "transport-test":
		return "Test transport"
	case "flush":
		return "Flush expired dead drops"
	case "keygen":
		return "Generate identity"
	case "keygen-convert":
		return "Derive recipients"
	case "peer-rename":
		return "Rename peer"
	case "peer-remove":
		return "Remove peer"
	case "peer-revoke":
		return "Revoke peer"
	default:
		if strings.HasPrefix(form.action, "erase-") {
			return "Inspect or erase state"
		}
		return "Run transfer"
	}
}

func (model *tuiModel) setupActions() []list.Item {
	return []list.Item{
		tuiItem{id: "initialize", title: "initialize device", description: "Choose a device name and peer server"},
		tuiItem{id: "config-show", title: "show configuration", description: "Inspect this device and its peer server"},
		tuiItem{id: "config-validate", title: "validate configuration", description: "Check the private device files"},
		tuiItem{id: "migrate", title: "migrate configuration", description: "Check configuration schema compatibility"},
		tuiItem{id: "erase-menu", title: "erase local state", description: "Preview state removal before confirming"},
	}
}

func (model *tuiModel) prepareSetupForm() {
	if model.form.action == "initialize" {
		for index := range model.form.fields {
			field := &model.form.fields[index]
			switch field.key {
			case "url":
				field.input.SetValue(model.app.cfg.PeerBaseURL)
			case "doh":
				field.input.SetValue(model.app.cfg.DOHURL)
			case "ech":
				field.input.SetValue(model.app.cfg.ECHMode)
			}
		}
	} else if model.target.pairingAction != "" {
		model.form.fields[0].input.SetValue(model.target.id)
	}
}

func (model *tuiModel) pairingCodeView() string {
	display := model.pairing
	expires := time.Unix(int64(display.ExpiresAt), 0).Local().Format("15:04:05 MST")
	return fmt.Sprintf("Pairing code:\n%s\nExpires: %s\nPeer: %s\nServer: %s\nOn the other device: peers → accept invitation.\nKeep this invitation open while the other device accepts.", safeTerminalText(display.Code), expires, safeTerminalText(display.Alias), safeTerminalText(display.Origin))
}

func (model *tuiModel) setupResultBack() tea.Cmd {
	if model.returnToTargets {
		if model.homeAction == "peers" {
			model.peersOnly = true
			return loadTUITargets
		}
		return model.showHome()
	}
	return model.goBack()
}
