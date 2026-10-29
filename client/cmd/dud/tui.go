// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type tuiScreen int

const (
	tuiHome tuiScreen = iota
	tuiTargets
	tuiActions
	tuiEditing
	tuiFiles
	tuiRunning
	tuiConfirming
	tuiResult
)

type tuiItem struct {
	id, title, description, details string
	deadDrop                        bool
	active                          bool
	pairingAction                   string
	allPeers                        bool
}

func (item tuiItem) Title() string       { return item.title }
func (item tuiItem) Description() string { return item.description }
func (item tuiItem) FilterValue() string { return item.title }

type tuiTargetsMsg struct {
	items  []list.Item
	notice string
}
type tuiTickMsg struct{ operation *tuiOperation }
type tuiTerminalFinishedMsg struct{}

type tuiModel struct {
	app                                  *app
	screen                               tuiScreen
	width, height                        int
	menu                                 list.Model
	target                               tuiItem
	notice                               string
	form                                 *tuiForm
	picker                               filepicker.Model
	view                                 viewport.Model
	bar                                  progress.Model
	operation                            *tuiOperation
	busy, cancelling, quitAfterOperation bool
	confirmation                         *tuiConfirmMsg
	status                               string
	resultErr                            error
	snapshot                             v2ProgressSnapshot
	theme                                tuiTheme
	pairing                              *v2PairingCodeDisplay
	qr                                   *tuiQRCode
	qrOnly                               bool
	returnToTargets                      bool
	homeAction                           string
	peersOnly                            bool
	includeInactive, allowAll            bool
	targetAction                         string
	history                              []tuiNavigation
}

func (a *app) cmdTUI(args []string) error {
	if len(args) != 0 {
		return fatalError("dud --tui accepts no arguments; use dud --tui --help")
	}
	input, ok := a.in.(*os.File)
	if !ok || input == nil || !isTerminal(input.Fd()) || !v2ProgressWriterIsTerminal(a.out) {
		return errors.New("dud --tui requires terminal stdin and stdout; use CLI commands for redirected input or output")
	}
	ctx, stop := signal.NotifyContext(a.commandContext(), processCleanupSignals()...)
	defer stop()
	parent := *a
	parent.commandCtx = ctx
	model := newTUIModel(&parent)
	defer func() {
		if model.operation != nil {
			model.operation.cancel()
			<-model.operation.done
		}
	}()
	_, err := tea.NewProgram(model, tea.WithInput(a.in), tea.WithOutput(a.out), tea.WithContext(ctx), tea.WithoutSignalHandler()).Run()
	return err
}

func newTUIModel(a *app) *tuiModel {
	menu := list.New(nil, defaultTUITheme().delegate(), 72, 16)
	menu.SetShowTitle(false)
	menu.SetShowStatusBar(false)
	menu.SetShowHelp(false)
	menu.SetFilteringEnabled(false)
	menu.DisableQuitKeybindings()
	model := &tuiModel{app: a, width: 80, height: 24, menu: menu,
		view: viewport.New(viewport.WithWidth(76), viewport.WithHeight(14)),
		bar:  progress.New(progress.WithColors(lipgloss.NoColor{})), notice: "Loading peers…"}
	model.setTheme(defaultTUITheme())
	model.showHome()
	return model
}

func (model *tuiModel) Init() tea.Cmd { return tea.RequestBackgroundColor }

func loadTUITargets() tea.Msg {
	items := []list.Item{}
	cfg, paths, err := loadV2Config()
	notice := ""
	if err != nil {
		reason, _, _ := strings.Cut(err.Error(), "\n")
		notice = "Peer setup: " + tuiSafeLines(reason) + "\nChoose setup on the main menu to initialize this device."
	} else {
		aliases := make([]string, 0, len(cfg.Peers))
		for alias := range cfg.Peers {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		for _, alias := range aliases {
			peer := cfg.Peers[alias]
			item := tuiItem{id: alias, title: safeTerminalText(alias), description: "peer · " + safeTerminalText(peer.Status), active: peer.Status == "active",
				details: fmt.Sprintf("Peer: %s\nState: %s\nOrigin: %s\nECH: %s", safeTerminalText(alias), safeTerminalText(peer.Status), safeTerminalText(peer.BaseURL), safeTerminalText(peer.ECHMode))}
			if peer.Status == "pending" {
				if pending, pendingErr := loadV2PendingPairing(paths, alias); pendingErr == nil {
					item.pairingAction = "invite"
					if pending.Role == 1 {
						item.pairingAction = "accept"
					}
				}
			}
			items = append(items, item)
		}
		if len(aliases) == 0 {
			notice = "No paired peers. Choose peers on the main menu to invite or accept."
		}
	}
	items = append(items, tuiItem{id: "dead-drop", title: "Dead drop", description: "Share by opaque ID", deadDrop: true, active: true,
		details: "Dead drop\nSend encrypted content and share its ID.\nReceive using an ID and passphrase or age identity.\nDelete after read is opt-in."})
	return tuiTargetsMsg{items, notice}
}

func tuiTick(operation *tuiOperation) tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return tuiTickMsg{operation} })
}

func (model *tuiModel) resize() {
	model.menu.SetSize(max(1, model.width-4), max(1, model.height-7))
	if model.screen == tuiTargets && model.notice != "" {
		model.menu.SetHeight(max(1, model.height-8-lipgloss.Height(model.targetNotice())))
	}
	if model.screen == tuiTargets && model.width >= 90 {
		model.menu.SetWidth(32)
	}
	model.view.SetWidth(max(1, model.width-4))
	model.view.SetHeight(max(1, model.height-10))
	if model.qr != nil && (model.screen == tuiRunning || model.screen == tuiResult) {
		if model.qrBesideDetails() {
			model.view.SetWidth(model.width - 4 - model.qr.width - 2)
		} else if model.qr.width > 0 && model.width-4 >= model.qr.width && model.height >= model.qr.height+14 {
			model.view.SetHeight(model.height - 11 - model.qr.height)
		} else {
			model.view.SetHeight(max(1, model.height-12))
		}
	}
	model.bar.SetWidth(max(1, model.width-6))
	model.picker.SetHeight(max(1, model.height-9))
	if model.form != nil {
		model.form.resize(max(1, model.width-4))
	}
}

func (model *tuiModel) targetNotice() string {
	return lipgloss.NewStyle().Width(max(1, model.width-4)).MaxHeight(max(1, model.height-11)).Render(model.notice)
}

func (model *tuiModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.BackgroundColorMsg:
		model.setTheme(backgroundTUITheme(msg.IsDark()))
		return model, nil
	case tea.WindowSizeMsg:
		model.width, model.height = msg.Width, msg.Height
		model.resize()
		return model, nil
	case tuiTargetsMsg:
		model.screen, model.notice = tuiTargets, msg.notice
		model.setTheme(model.theme)
		items := []list.Item{}
		for _, value := range msg.items {
			item := value.(tuiItem)
			if item.deadDrop && model.peersOnly {
				continue
			}
			if !item.deadDrop && !item.active && !model.includeInactive {
				continue
			}
			items = append(items, item)
		}
		if model.allowAll {
			items = append(items, tuiItem{title: "All peers", description: "Select all active peers", allPeers: true})
		}
		model.menu.ResetSelected()
		model.resize()
		return model, model.menu.SetItems(items)
	case tuiTickMsg:
		if model.busy && msg.operation == model.operation {
			model.refreshOutput()
			return model, tuiTick(model.operation)
		}
		return model, nil
	case tuiDoneMsg:
		model.busy, model.confirmation = false, nil
		if model.pairing != nil {
			model.qr = nil
			model.qrOnly = false
		}
		model.pairing = nil
		cancelled := model.operation.ctx.Err() != nil
		model.operation.cancel()
		model.screen, model.resultErr = tuiResult, msg.err
		model.resize()
		model.status = "Completed"
		if msg.err != nil {
			model.status = "Failed"
			if model.cancelling || cancelled {
				model.status = "Cancelled"
			}
		}
		model.refreshOutput()
		model.view.GotoTop()
		if model.quitAfterOperation {
			return model, tea.Quit
		}
		return model, nil
	case tuiPairingCodeMsg:
		if !model.cancelling {
			model.pairing = &msg.display
			model.qr = &msg.qr
			model.resize()
		}
		return model, model.operation.nextEvent
	case tuiQRCodeMsg:
		if !model.cancelling {
			model.qr = &msg.qr
			model.resize()
			model.refreshOutput()
		}
		return model, model.operation.nextEvent
	case tuiConfirmMsg:
		if model.cancelling {
			msg.answer <- false
			return model, model.operation.nextEvent
		}
		model.screen, model.confirmation = tuiConfirming, &msg
		model.view.SetContent(msg.preview)
		model.view.GotoTop()
		return model, model.operation.nextEvent
	case *tuiTerminalMsg:
		if model.cancelling {
			msg.answer <- model.operation.ctx.Err()
			return model, model.operation.nextEvent
		}
		command := tuiTerminalCommand{msg, model.operation.output}
		return model, tea.Batch(model.operation.nextEvent, tea.Exec(command, func(err error) tea.Msg { msg.answer <- err; return tuiTerminalFinishedMsg{} }))
	case tea.KeyPressMsg:
		return model.handleKey(msg)
	}
	return model.updateComponent(message)
}

func (model *tuiModel) refreshOutput() {
	content, snapshot := model.operation.output.snapshot()
	model.snapshot = snapshot
	if model.screen == tuiConfirming {
		return
	}
	if model.resultErr != nil {
		content += "\n" + tuiSafeLines(model.resultErr.Error())
	}
	atBottom := model.view.AtBottom()
	model.view.SetContent(content)
	if atBottom && model.busy {
		model.view.GotoBottom()
	}
}

func (model *tuiModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	pressed := msg.String()
	if pressed == "ctrl+c" {
		if model.busy {
			model.quitAfterOperation = true
			model.cancelOperation()
			return model, nil
		}
		return model, tea.Quit
	}
	if model.width < 48 || model.height < 16 {
		if pressed == "q" && !model.busy {
			return model, tea.Quit
		}
		if pressed == "esc" && model.busy {
			model.cancelOperation()
		}
		return model, nil
	}
	switch model.screen {
	case tuiHome:
		return model.homeKey(msg)
	case tuiTargets:
		switch pressed {
		case "q":
			return model, tea.Quit
		case "r":
			return model, loadTUITargets
		case "esc", "left":
			return model, model.goBack()
		case "enter":
			return model, model.selectTarget()
		}
	case tuiActions:
		switch pressed {
		case "esc", "left":
			return model, model.goBack()
		case "q":
			return model, tea.Quit
		case "enter":
			return model, model.selectAction()
		}
	case tuiEditing:
		return model.editKey(msg)
	case tuiFiles:
		if pressed == "esc" {
			model.screen = tuiEditing
			return model, model.form.focusInput()
		}
	case tuiRunning, tuiConfirming, tuiResult:
		return model.operationKey(msg)
	}
	return model.updateComponent(msg)
}

func (model *tuiModel) operationKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	pressed := msg.String()
	if pressed == "v" && model.qr != nil && model.qr.width > 0 && model.screen != tuiConfirming {
		model.qrOnly = !model.qrOnly
		return model, nil
	}
	switch model.screen {
	case tuiRunning:
		if pressed == "esc" {
			model.cancelOperation()
			return model, nil
		}
	case tuiConfirming:
		switch pressed {
		case "y", "n", "esc":
			model.confirmation.answer <- pressed == "y"
			model.confirmation = nil
			model.screen = tuiRunning
			model.refreshOutput()
			return model, nil
		}
	case tuiResult:
		switch pressed {
		case "esc", "left", "enter":
			return model, model.setupResultBack()
		case "q":
			return model, tea.Quit
		}
	}
	return model.updateComponent(msg)
}

func (model *tuiModel) cancelOperation() {
	model.cancelling = true
	model.status = "Cancelling; waiting for the operation to finish"
	model.screen, model.confirmation = tuiRunning, nil
	model.pairing = nil
	model.qr = nil
	model.qrOnly = false
	model.operation.cancel()
}

func (model *tuiModel) showActions() tea.Cmd {
	model.screen, model.form = tuiActions, nil
	model.setTheme(model.theme)
	items := []list.Item{}
	if model.target.pairingAction != "" {
		items = append(items, tuiItem{id: model.target.pairingAction, title: "Resume pairing", description: "Continue this peer's invitation or acceptance"})
	}
	if model.target.active && model.homeAction != "peers" {
		items = append(items,
			tuiItem{id: "message", title: "Send message", description: "Type or paste text"},
			tuiItem{id: "files", title: "Send files", description: "Choose files or directories"})
		if model.homeAction != "send" {
			items = append(items, tuiItem{id: "receive", title: "Receive", description: "Save incoming content"})
		}
		if !model.target.deadDrop && model.homeAction != "send" {
			items = append(items, tuiItem{id: "sync", title: "Sync", description: "Publish queued work and collect acknowledgements"})
		}
	}
	if !model.target.deadDrop && model.homeAction != "send" {
		items = append(items, tuiItem{id: "status", title: "Status", description: "Inspect peer state and delivery counters"})
	}
	model.menu.ResetSelected()
	model.resize()
	return model.menu.SetItems(items)
}

func (model *tuiModel) selectAction() tea.Cmd {
	item, ok := model.menu.SelectedItem().(tuiItem)
	if !ok {
		return nil
	}
	model.pushNavigation()
	switch item.id {
	case "peers-list":
		model.peersOnly = true
		return loadTUITargets
	case "config-show":
		return model.start([]string{"config", "show"})
	case "config-validate":
		return model.start([]string{"config", "validate"})
	case "sync":
		return model.start([]string{"sync", model.target.id})
	case "status":
		return model.start([]string{"peer", "show", model.target.id})
	}
	return model.selectMenuAction(item.id)
}

func (model *tuiModel) start(args []string) tea.Cmd {
	input := tuiSetupInput{}
	model.returnToTargets = false
	if model.form != nil && isTUISetupAction(model.form.action) {
		input = model.form.setupInput()
		model.form.clearSetupSecrets()
		model.returnToTargets = true
	}
	model.operation = startTUIOperationWithInput(model.app, args, input)
	model.busy, model.cancelling, model.quitAfterOperation = true, false, false
	model.resultErr, model.confirmation = nil, nil
	model.pairing = nil
	model.qr = nil
	model.qrOnly = false
	model.resize()
	model.snapshot = v2ProgressSnapshot{}
	model.screen, model.status = tuiRunning, "Working"
	model.view.SetContent("")
	model.view.GotoTop()
	return tea.Batch(model.operation.nextEvent, tuiTick(model.operation))
}

func (model *tuiModel) editKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	form := model.form
	switch msg.String() {
	case "esc":
		return model, model.goBack()
	case "tab", "shift+tab":
		direction := 1
		if msg.String() == "shift+tab" {
			direction = -1
		}
		form.focus = (form.focus + direction + form.count() + 1) % (form.count() + 1)
		return model, form.focusInput()
	case "ctrl+s":
		return model, model.submitForm()
	case "enter":
		if form.focus == form.count() {
			return model, model.submitForm()
		}
	case "space":
		if field := form.activeField(); field != nil && field.toggle {
			field.checked = !field.checked
			return model, nil
		}
	case "ctrl+o":
		if field := form.activeField(); field != nil && field.key == "path" {
			model.picker = filepicker.New()
			model.picker.CurrentDirectory, _ = os.Getwd()
			model.picker.DirAllowed = true
			model.screen = tuiFiles
			model.resize()
			return model, model.picker.Init()
		}
	case "ctrl+n":
		if field := form.activeField(); field != nil && field.key == "path" {
			form.err = ""
			if err := form.addPath(field.input.Value()); err != nil {
				form.err = tuiSafeLines(err.Error())
			}
			return model, nil
		}
	case "ctrl+d":
		if field := form.activeField(); field != nil && field.key == "path" && len(form.paths) != 0 {
			form.paths = form.paths[:len(form.paths)-1]
			return model, nil
		}
	}
	return model.updateComponent(msg)
}

func (model *tuiModel) submitForm() tea.Cmd {
	args, err := model.form.arguments(model.target, model.app.cfg)
	if err != nil {
		model.form.err = tuiSafeLines(err.Error())
		return nil
	}
	return model.start(args)
}

func (model *tuiModel) updateComponent(message tea.Msg) (tea.Model, tea.Cmd) {
	var command tea.Cmd
	switch model.screen {
	case tuiHome, tuiTargets, tuiActions:
		model.menu, command = model.menu.Update(message)
	case tuiEditing:
		if model.form.hasMessage && model.form.focus == 0 {
			model.form.message, command = model.form.message.Update(message)
		} else if field := model.form.activeField(); field != nil && !field.toggle {
			field.input, command = field.input.Update(message)
		}
	case tuiFiles:
		return model.updatePicker(message)
	case tuiRunning, tuiConfirming, tuiResult:
		model.view, command = model.view.Update(message)
	}
	return model, command
}

func (model *tuiModel) updatePicker(message tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := message.(tea.KeyPressMsg); ok {
		path := model.picker.HighlightedPath()
		info, err := os.Lstat(path)
		selectPath := msg.String() == "space" || msg.String() == "enter" && err == nil && !info.IsDir()
		if selectPath {
			model.form.err = ""
			if err := model.form.addPath(path); err != nil {
				model.form.err = tuiSafeLines(err.Error())
			}
			model.screen = tuiEditing
			return model, model.form.focusInput()
		}
	}
	var command tea.Cmd
	model.picker, command = model.picker.Update(message)
	return model, command
}

func (model *tuiModel) View() tea.View {
	header := model.theme.accentStyle().Render("dud") + " — Discreet Upload/Download"
	if model.screen == tuiTargets {
		header = model.theme.accentStyle().Render("dud") + " / " + model.homeAction + " / choose target"
	}
	if model.screen != tuiTargets && model.screen != tuiHome {
		header = model.theme.accentStyle().Render("dud") + " / " + model.homeAction + " / " + model.target.title
	}
	body, footer := model.body()
	if model.width < 48 || model.height < 16 {
		body, footer = "Need 48 × 16.", "Ctrl+C quit"
		if model.busy {
			footer = "Esc cancel"
		}
	}
	header = ansi.Truncate(header, max(1, model.width-4), "…")
	separator := "\n\n"
	if model.qrOnly {
		separator = "\n"
	}
	content := header + separator + body
	frame := lipgloss.NewStyle().Width(max(1, model.width-4)).MaxWidth(max(1, model.width-4)).MaxHeight(max(1, model.height-4)).Render(content)
	footer = ansi.Truncate(footer, max(1, model.width-4), "…")
	v := tea.NewView(lipgloss.NewStyle().Padding(1, 2).Render(frame + "\n" + footer))
	v.AltScreen = true
	return v
}

func (model *tuiModel) body() (string, string) {
	switch model.screen {
	case tuiHome:
		return model.menu.View(), "↑/↓ choose · Enter or 1–7 open · q quit"
	case tuiTargets:
		body := model.menu.View()
		if item, ok := model.menu.SelectedItem().(tuiItem); ok && model.width >= 90 {
			details := lipgloss.NewStyle().Width(model.width - 40).PaddingLeft(2).Render(item.details)
			body = lipgloss.JoinHorizontal(lipgloss.Top, body, details)
		}
		if model.notice != "" {
			body += "\n" + model.targetNotice()
		}
		if len(model.menu.Items()) < 2 {
			return body, "Enter continue · Esc/← back · r refresh · q quit"
		}
		return body, "↑/↓ choose · Enter open · Esc/← back · r refresh"
	case tuiActions:
		return model.menu.View(), "↑/↓ choose · Enter open · Esc/← back · q quit"
	case tuiEditing:
		body := model.form.View(max(1, model.width-4), max(1, model.height-8))
		if model.form.err != "" {
			body += "\n" + ansi.Truncate(strings.ReplaceAll(model.form.err, "\n", " "), max(1, model.width-4), "…")
		}
		footer := "Tab next · Space toggle · Ctrl+S run · Esc back"
		if isTUISetupAction(model.form.action) {
			footer = "Tab next · Ctrl+S " + model.form.submitLabel() + " · Esc back"
		}
		return body, footer
	case tuiFiles:
		return safeTerminalText(model.picker.CurrentDirectory) + "\n\n" + tuiSafeLines(ansi.Strip(model.picker.View())), "↑/↓ choose · Enter open/file · Space select · Esc back"
	case tuiConfirming:
		return model.view.View() + "\n\nExtract this collection? [y/N]", "y approve · n/Esc decline · ↑/↓ scroll"
	case tuiRunning, tuiResult:
		status := model.status
		if model.pairing != nil && model.busy {
			return model.withQRCode(model.pairingCodeView()), model.qrFooter("Esc stop waiting · Ctrl+C stop and quit")
		}
		if model.busy && model.snapshot.Phase != "" && !model.cancelling {
			status += " / " + safeTerminalText(model.snapshot.Phase)
			if model.snapshot.Total > 0 {
				status += "\n" + model.bar.ViewAs(float64(model.snapshot.Current)/float64(model.snapshot.Total))
				status += "\n" + formatV2ProgressTransfer(model.snapshot.Current, model.snapshot.Total)
			}
		}
		footer := "↑/↓ scroll · Enter/Esc/← back · q quit"
		if model.busy {
			footer = "↑/↓ scroll · Esc cancel · Ctrl+C cancel and quit"
		}
		return model.withQRCode(status + "\n\n" + model.view.View()), model.qrFooter(footer)
	}
	return "", ""
}
