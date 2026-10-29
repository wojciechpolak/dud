// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"fmt"

	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
)

type tuiNavigation struct {
	screen                               tuiScreen
	menu                                 list.Model
	target                               tuiItem
	homeAction, targetAction, notice     string
	peersOnly, includeInactive, allowAll bool
}

func (model *tuiModel) pushNavigation() {
	model.history = append(model.history, tuiNavigation{model.screen, model.menu, model.target, model.homeAction, model.targetAction, model.notice, model.peersOnly, model.includeInactive, model.allowAll})
}

func (model *tuiModel) goBack() tea.Cmd {
	model.qr, model.qrOnly = nil, false
	if len(model.history) == 0 {
		return model.showHome()
	}
	previous := model.history[len(model.history)-1]
	model.history = model.history[:len(model.history)-1]
	model.screen, model.menu, model.target = previous.screen, previous.menu, previous.target
	model.homeAction, model.targetAction, model.notice = previous.homeAction, previous.targetAction, previous.notice
	model.peersOnly, model.includeInactive, model.allowAll = previous.peersOnly, previous.includeInactive, previous.allowAll
	model.form = nil
	model.setTheme(model.theme)
	model.resize()
	if model.screen == tuiTargets {
		return loadTUITargets
	}
	return nil
}

func (model *tuiModel) showHome() tea.Cmd {
	model.qr, model.qrOnly = nil, false
	model.screen, model.form = tuiHome, nil
	model.target = tuiItem{}
	model.homeAction, model.targetAction, model.notice = "", "", ""
	model.peersOnly, model.includeInactive, model.allowAll = false, false, false
	model.history = nil
	model.setTheme(model.theme)
	descriptions := map[string]string{
		"send":    "Send to a peer or create a dead drop",
		"receive": "Receive from a peer or a dead drop",
		"git":     "Push, fetch and inspect Git checkpoints",
		"peers":   "Pair and manage devices",
		"status":  "Inspect deliveries and connectivity",
		"setup":   "Initialize this device and manage local state",
		"tools":   "Test transport, manage keys and clean expired dead drops",
	}
	items := make([]list.Item, 0, len(interactiveRootVerbs))
	for index, verb := range interactiveRootVerbs {
		items = append(items, tuiItem{id: verb, title: fmt.Sprintf("%d) %s", index+1, verb), description: descriptions[verb]})
	}
	model.menu.ResetSelected()
	model.resize()
	return model.menu.SetItems(items)
}

func (model *tuiModel) showMenu(title string, items []list.Item) tea.Cmd {
	model.screen, model.form = tuiActions, nil
	model.target = tuiItem{title: title}
	model.notice = ""
	model.setTheme(model.theme)
	model.menu.ResetSelected()
	model.resize()
	return model.menu.SetItems(items)
}

func (model *tuiModel) selectHome() tea.Cmd {
	item, ok := model.menu.SelectedItem().(tuiItem)
	if !ok {
		return nil
	}
	model.pushNavigation()
	model.homeAction = item.id
	switch item.id {
	case "send", "receive":
		return model.chooseTarget(item.id, false, false, false)
	case "git":
		return model.showMenu("Git", []list.Item{
			tuiItem{id: "git-push", title: "push", description: "Publish a Git checkpoint"},
			tuiItem{id: "git-fetch", title: "fetch", description: "Import a checkpoint without merging local branches"},
			tuiItem{id: "git-status", title: "status", description: "Inspect repository synchronization"},
		})
	case "peers":
		return model.showPeersMenu()
	case "status":
		return model.showMenu("Status", []list.Item{
			tuiItem{id: "peer-list", title: "peer list", description: "List paired devices"},
			tuiItem{id: "peer-detail", title: "peer detail", description: "Inspect a device and its delivery counters"},
			tuiItem{id: "sync-target", title: "synchronize peers", description: "Publish queued work and collect acknowledgements"},
			tuiItem{id: "inbox-target", title: "what is waiting to be received", description: "Inspect the oldest delivery without committing it"},
			tuiItem{id: "git-status", title: "git synchronization state", description: "Inspect repository synchronization"},
			tuiItem{id: "doctor", title: "transport doctor", description: "Check peer transport and local state"},
			tuiItem{id: "capabilities", title: "server capabilities", description: "Inspect the peer server contract"},
		})
	case "setup":
		return model.showMenu("Setup", model.setupActions())
	case "tools":
		return model.showMenu("Tools", []list.Item{
			tuiItem{id: "transport-test", title: "transport test", description: "Check the dead drop server"},
			tuiItem{id: "keygen-menu", title: "keygen", description: "Generate an identity or derive recipients"},
			tuiItem{id: "flush", title: "flush expired dead drop files", description: "Clean expired files on the dead drop server"},
		})
	}
	return nil
}

func (model *tuiModel) showPeersMenu() tea.Cmd {
	return model.showMenu("Peers", []list.Item{
		tuiItem{id: "invite", title: "create invitation", description: "Create or resume an invitation"},
		tuiItem{id: "accept", title: "accept invitation", description: "Enter a code or resume acceptance"},
		tuiItem{id: "peer-list", title: "list", description: "List paired devices"},
		tuiItem{id: "peer-detail", title: "show", description: "Inspect status and resume pending pairing"},
		tuiItem{id: "peer-rename", title: "rename", description: "Change a local peer alias"},
		tuiItem{id: "peer-remove", title: "remove", description: "Remove the peer and its pending local state"},
		tuiItem{id: "peer-revoke", title: "revoke", description: "Disable the peer's server capabilities"},
	})
}

func (model *tuiModel) chooseTarget(action string, peersOnly, includeInactive, allowAll bool) tea.Cmd {
	model.targetAction = action
	model.peersOnly, model.includeInactive, model.allowAll = peersOnly, includeInactive, allowAll
	return loadTUITargets
}

func (model *tuiModel) selectTarget() tea.Cmd {
	item, ok := model.menu.SelectedItem().(tuiItem)
	if !ok {
		return nil
	}
	model.pushNavigation()
	model.target = item
	switch model.targetAction {
	case "receive", "git-push", "git-fetch", "peer-rename", "peer-remove", "peer-revoke", "erase-peer":
		return model.openForm(model.targetAction)
	case "peer-detail":
		if item.pairingAction != "" {
			return model.showActions()
		}
		return model.start([]string{"peer", "show", item.id})
	case "sync-target", "inbox-target", "git-status":
		args := []string{"sync"}
		if model.targetAction == "inbox-target" {
			args = []string{"inbox"}
		}
		if model.targetAction == "git-status" {
			args = []string{"git", "status"}
		}
		if !item.allPeers {
			args = append(args, item.id)
		}
		return model.start(args)
	}
	return model.showActions()
}

func (model *tuiModel) openForm(action string) tea.Cmd {
	model.form = newTUIForm(action, model.target.deadDrop)
	if isTUISetupAction(action) {
		model.prepareSetupForm()
	}
	model.prepareUtilityForm()
	model.form.setTheme(model.theme)
	model.screen = tuiEditing
	model.resize()
	return model.form.focusInput()
}

func (model *tuiModel) selectMenuAction(id string) tea.Cmd {
	switch id {
	case "git-push", "git-fetch":
		return model.chooseTarget(id, false, false, false)
	case "git-status", "sync-target", "inbox-target":
		return model.chooseTarget(id, true, false, true)
	case "peer-detail", "peer-rename", "peer-remove", "peer-revoke":
		return model.chooseTarget(id, true, true, false)
	case "erase-peer":
		return model.chooseTarget(id, true, true, false)
	case "peer-list":
		return model.start([]string{"peer", "list"})
	case "config-show":
		return model.start([]string{"config", "show"})
	case "config-validate":
		return model.start([]string{"config", "validate"})
	case "doctor", "capabilities", "migrate":
		return model.start([]string{id})
	case "keygen-menu":
		return model.showMenu("Keygen", []list.Item{
			tuiItem{id: "keygen", title: "generate a new identity", description: "Write a private identity to a file"},
			tuiItem{id: "keygen-convert", title: "convert an identity to recipients", description: "Derive public recipients from a private identity file"},
		})
	case "erase-menu":
		return model.showMenu("Erase local state", []list.Item{
			tuiItem{id: "erase-pairings", title: "pending pairings", description: "Inspect or erase pending local pairing state"},
			tuiItem{id: "erase-peer", title: "one peer", description: "Inspect or erase one peer's local state"},
			tuiItem{id: "erase-repo", title: "repository state", description: "Inspect or erase DUD state in this repository"},
			tuiItem{id: "erase-all", title: "all local DUD state", description: "Inspect or erase all device identities and peer state"},
		})
	}
	return model.openForm(id)
}

func (model *tuiModel) homeKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return model, tea.Quit
	case "enter":
		return model, model.selectHome()
	}
	if msg.Mod == 0 && msg.Code >= '1' && msg.Code <= '7' {
		model.menu.Select(int(msg.Code - '1'))
		return model, model.selectHome()
	}
	return model.updateComponent(msg)
}
