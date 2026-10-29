// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestTUIHomeMatchesInteractiveVerbsAndKeepsEveryEntryVisible(t *testing.T) {
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	var verbs []string
	for _, item := range model.menu.Items() {
		verbs = append(verbs, item.(tuiItem).id)
	}
	if !reflect.DeepEqual(verbs, interactiveRootVerbs) {
		t.Fatalf("root verbs=%q", verbs)
	}
	view := ansi.Strip(model.View().Content)
	for _, verb := range interactiveRootVerbs {
		if !strings.Contains(view, verb) {
			t.Fatalf("root hides %s: %q", verb, view)
		}
	}
	model.Update(tuiTestKey('6'))
	if model.homeAction != "setup" {
		t.Fatal("number shortcut did not open setup")
	}
	model.Update(tuiTestKey(tea.KeyEscape))
	if model.screen != tuiHome {
		t.Fatal("setup did not return to the root menu")
	}
}

func TestTUIInitializesADeviceAndRefreshesTheSetupFlow(t *testing.T) {
	setTestV2Homes(t)
	parent := newApp(strings.NewReader(""), io.Discard, io.Discard)
	parent.cfg.PeerBaseURL = "https://peer.example.test"
	parent.cfg.DropBaseURL = "https://drop.example.test"
	parent.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return nil, errors.New("initialization must be local") }
	model := newTUIModel(parent)
	model.Update(tuiTestKey('6'))
	model.Update(tuiTestKey(tea.KeyEnter))
	if model.form == nil || model.form.action != "initialize" {
		t.Fatal("setup did not open the device form")
	}
	setTUITestValue(model.form, "device", "tui-desktop")
	model.submitForm()
	operation := model.operation
	t.Cleanup(func() { finishTUITestOperation(t, operation) })
	model.Update(awaitTUITestEvent(t, operation))
	if model.resultErr != nil {
		t.Fatal(model.resultErr)
	}
	cfg, paths, err := loadV2Config()
	if err != nil || cfg.Device != "tui-desktop" || cfg.BaseURL != parent.cfg.PeerBaseURL || cfg.ECHMode != "hard" {
		t.Fatalf("device=%+v,err=%v", cfg, err)
	}
	if info, err := os.Stat(paths.Seed); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("seed permissions: %v", err)
	}
	seed, err := os.ReadFile(paths.Seed)
	if err != nil {
		t.Fatal(err)
	}
	model.Update(tuiTestKey(tea.KeyEnter))
	if model.screen != tuiHome {
		t.Fatal("initialization did not return to the main menu")
	}
	repeated := startTUIOperation(parent, []string{"init", "--device", "replacement"})
	result := awaitTUITestEvent(t, repeated).(tuiDoneMsg)
	finishTUITestOperation(t, repeated)
	if result.err == nil {
		t.Fatal("initialization replaced an existing device")
	}
	after, _ := os.ReadFile(paths.Seed)
	if !bytes.Equal(seed, after) {
		t.Fatal("reinitialization replaced the identity")
	}
}

type tuiHoldingPairingTransport struct {
	base   inviteTestTransport
	polled chan struct{}
}

func (transport *tuiHoldingPairingTransport) Do(ctx context.Context, request v2Request) (*v2Response, error) {
	if strings.HasSuffix(request.Path, "/status") {
		select {
		case transport.polled <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return transport.base.Do(ctx, request)
}

func TestTUIInvitationDisplaysItsCodeWithoutLoggingItAndResumesAfterCancellation(t *testing.T) {
	setTestV2Homes(t)
	_, paths, err := initializeV2Config("desktop", v2DefaultBaseURL, v2DefaultDOHURL, "hard")
	if err != nil {
		t.Fatal(err)
	}
	transport := &tuiHoldingPairingTransport{polled: make(chan struct{}, 1)}
	parent := newApp(strings.NewReader(""), io.Discard, io.Discard)
	parent.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
	qrInput := installTUITestQREncoder(t, parent)
	firstCode := ""
	for attempt := 0; attempt < 2; attempt++ {
		operation := startTUIOperationWithInput(parent, []string{"peer", "invite", "laptop"}, tuiSetupInput{enrollmentSecret: "a-private-enrollment-credential-for-tui"})
		event, ok := awaitTUITestEvent(t, operation).(tuiPairingCodeMsg)
		if !ok {
			finishTUITestOperation(t, operation)
			t.Fatal("invitation did not display its code")
		}
		if _, err := parseV2PairingCode(event.display.Code); err != nil {
			t.Fatal(err)
		}
		if event.qr.text+"\n" != tuiQRTestText {
			t.Fatal("invitation did not display its QR")
		}
		assertTUIQRPayload(t, qrInput, event.display.Code)
		if attempt == 0 {
			firstCode = event.display.Code
		} else if event.display.Code != firstCode {
			t.Fatal("resuming an invitation changed its code")
		}
		select {
		case <-transport.polled:
		case <-time.After(time.Second):
			t.Fatal("invitation did not poll")
		}
		operation.cancel()
		result := awaitTUITestEvent(t, operation).(tuiDoneMsg)
		finishTUITestOperation(t, operation)
		if !errors.Is(result.err, context.Canceled) {
			t.Fatal(result.err)
		}
		output, _ := operation.output.snapshot()
		if strings.Contains(output, firstCode) || strings.Contains(output, "a-private-enrollment") {
			t.Fatal("pairing credentials reached command output")
		}
		pending, err := loadV2PendingPairing(paths, "laptop")
		if err != nil || pending.PairingCode != firstCode {
			t.Fatalf("pending invitation=%+v,err=%v", pending, err)
		}
	}
	model := newTUIModel(parent)
	model.pairing = &v2PairingCodeDisplay{Alias: "laptop", Code: firstCode, Origin: v2DefaultBaseURL, ExpiresAt: uint64(time.Now().Add(time.Minute).Unix())}
	model.screen, model.busy = tuiRunning, true
	model.Update(tea.WindowSizeMsg{Width: 48, Height: 16})
	if !strings.Contains(ansi.Strip(model.View().Content), firstCode) {
		t.Fatal("small terminal truncates the pairing code")
	}
}

func TestTUIAcceptsAndResumesAnInvitationWithoutTTYOrCodeArguments(t *testing.T) {
	flow := startV2PairingFlow(t)
	flow.inviteeHome(t)
	_, paths, err := initializeV2Config("laptop", v2DefaultBaseURL, v2DefaultDOHURL, "hard")
	if err != nil {
		t.Fatal(err)
	}
	transport := &pairingFlowTransport{locator: flow.inviterPending.RendezvousLocator, nonce: flow.createMap[3].([]byte), ciphertext: flow.createMap[4].([]byte), expiresAt: flow.createMap[5].(uint64), stopStatus: true}
	parent := newApp(unreadableHelpInput{t}, io.Discard, io.Discard)
	parent.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
	previous := openV2TTY
	openV2TTY = func() (*v2Terminal, error) { return nil, errors.New("TUI acceptance attempted to open a TTY") }
	t.Cleanup(func() { openV2TTY = previous })
	for _, code := range []string{flow.code, ""} {
		form := newTUIForm("accept", false)
		setTUITestValue(form, "alias", "desktop")
		setTUITestValue(form, "code", code)
		args, err := form.setupArguments()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(args, " "), flow.code) {
			t.Fatal("code reached command arguments")
		}
		operation := startTUIOperationWithInput(parent, args, form.setupInput())
		result := awaitTUITestEvent(t, operation).(tuiDoneMsg)
		finishTUITestOperation(t, operation)
		if result.err == nil || !strings.Contains(result.err.Error(), "stop after acceptance") {
			t.Fatalf("acceptance result=%v", result.err)
		}
		output, _ := operation.output.snapshot()
		if strings.Contains(output, flow.code) {
			t.Fatal("code reached output")
		}
		pending, err := loadV2PendingPairing(paths, "desktop")
		if err != nil || pending.Role != 1 {
			t.Fatalf("pending acceptance=%+v,err=%v", pending, err)
		}
	}
	model := newTUIModel(parent)
	model.homeAction = "peers"
	model.peersOnly = true
	model.includeInactive = true
	model.targetAction = "peer-detail"
	model.Update(loadTUITargets())
	if model.menu.SelectedItem().(tuiItem).pairingAction != "accept" {
		t.Fatal("pending acceptance has no resume action")
	}
	model.selectTarget()
	model.selectAction()
	if model.form.action != "accept" || model.form.value("alias") != "desktop" {
		t.Fatal("resume action lost the alias")
	}
}

func runTUITestOperation(t *testing.T, parent *app, args []string) *tuiOperation {
	t.Helper()
	operation := startTUIOperation(parent, args)
	for {
		switch event := awaitTUITestEvent(t, operation).(type) {
		case *tuiTerminalMsg:
			event.answer <- (tuiTerminalCommand{request: event, output: operation.output}).Run()
		case tuiQRCodeMsg:
		case tuiDoneMsg:
			finishTUITestOperation(t, operation)
			if event.err != nil {
				output, _ := operation.output.snapshot()
				t.Fatalf("%q: %v\n%s", args, event.err, output)
			}
			return operation
		default:
			operation.cancel()
			finishTUITestOperation(t, operation)
			t.Fatal("unexpected operation event")
		}
	}
}

func TestTUIGitDeadDropPushAndFetchRoundTripARepository(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	initializeGitTestRepository(t, source)
	initializeGitTestRepository(t, destination)
	head := commitGitTestFile(t, source, "message.txt", "Git through a dead drop\n", "checkpoint")
	parent, transport, _, _ := newDropTestApp(t, "")
	qrInput := installTUITestQREncoder(t, parent)
	transport.respond = uploadJSONResponder("git-checkpoint")
	push := newTUIForm("git-push", true)
	args, err := push.arguments(tuiItem{deadDrop: true}, parent.cfg)
	if err != nil {
		t.Fatal(err)
	}
	withGitTestDirectory(t, source, func() { runTUITestOperation(t, parent, args) })
	assertTUIQRPayload(t, qrInput, "git-checkpoint")
	bundle := transport.only(t).Body
	if !bytes.HasPrefix(bundle, []byte("# v2 git bundle")) {
		t.Fatal("Git push did not publish a bundle")
	}
	transport.requests = nil
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: bundle}, nil
	}
	fetch := newTUIForm("git-fetch", true)
	setTUITestValue(fetch, "id", "git-checkpoint")
	args, err = fetch.arguments(tuiItem{deadDrop: true}, parent.cfg)
	if err != nil {
		t.Fatal(err)
	}
	withGitTestDirectory(t, destination, func() { runTUITestOperation(t, parent, args) })
	if got := runGitTestCommand(t, destination, "rev-parse", "refs/remotes/dud/main"); got != head {
		t.Fatalf("fetched checkpoint=%s,want=%s", got, head)
	}
}

func TestTUIUtilityFormsRequireExplicitDestructiveConsent(t *testing.T) {
	for _, action := range []string{"peer-remove", "peer-revoke", "erase-peer", "erase-all"} {
		form := newTUIForm(action, false)
		target := tuiItem{id: "laptop"}
		if strings.HasPrefix(action, "erase-") {
			args, err := form.arguments(target, config{})
			if err != nil || args[len(args)-1] != "--dry-run" {
				t.Fatalf("%s default=%q,%v", action, args, err)
			}
			form.fields[0].checked = false
		}
		if _, err := form.arguments(target, config{}); err == nil {
			t.Fatalf("%s ran without consent", action)
		}
	}
	form := newTUIForm("keygen", false)
	if _, err := form.arguments(tuiItem{}, config{}); err == nil {
		t.Fatal("keygen allowed a private identity on screen")
	}
	invite := newTUIForm("invite", false)
	if invite.fields[2].input.EchoMode != textinput.EchoPassword {
		t.Fatal("enrollment credential is visible")
	}
}

func TestTUIGitFormsSelectTheTransferModeAndKeepPeerFetchConsentExplicit(t *testing.T) {
	cfg := config{DropBaseURL: "https://default.example.test", DOHURL: v2DefaultDOHURL, SecretToken: "secret"}
	drop := tuiItem{deadDrop: true}
	push := newTUIForm("git-push", true)
	setTUITestValue(push, "url", "https://git.example.test")
	args, err := push.arguments(drop, cfg)
	if err != nil {
		t.Fatal(err)
	}
	upload, err := parseUploadOptions(args[2:], cfg.DropBaseURL, cfg.DOHURL)
	if err != nil || upload.baseURL != "https://git.example.test" || !upload.passphraseRequested {
		t.Fatalf("dead drop Git options=%+v,err=%v", upload, err)
	}
	fetch := newTUIForm("git-fetch", false)
	args, err = fetch.arguments(tuiItem{id: "laptop"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	options, err := parseV2GitFetchOptions(args[2:])
	if err != nil || options.Associate || options.AllowRewrite {
		t.Fatalf("peer fetch consent=%+v,err=%v", options, err)
	}
	for index := range fetch.fields {
		fetch.fields[index].checked = true
	}
	args, err = fetch.arguments(tuiItem{id: "laptop"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	options, err = parseV2GitFetchOptions(args[2:])
	if err != nil || !options.Associate || !options.AllowRewrite {
		t.Fatalf("peer fetch consent=%+v,err=%v", options, err)
	}
}

func TestTUILeftArrowAndEscapeGoBackThroughMenusAndResults(t *testing.T) {
	setTestV2Homes(t)
	for _, back := range []rune{tea.KeyLeft, tea.KeyEscape} {
		model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
		model.Update(tuiTestKey('3'))
		_, loadTargets := model.Update(tuiTestKey(tea.KeyEnter))
		model.Update(loadTargets())
		if model.screen != tuiTargets {
			t.Fatal("Git push did not open the target picker")
		}
		model.Update(tuiTestKey(back))
		if model.screen != tuiActions || model.menu.SelectedItem().(tuiItem).id != "git-push" {
			t.Fatal("back did not restore the Git submenu")
		}
		model.pushNavigation()
		model.screen = tuiResult
		model.Update(tuiTestKey(back))
		if model.screen != tuiActions {
			t.Fatal("back did not leave the result screen")
		}
		model.Update(tuiTestKey(back))
		if model.screen != tuiHome {
			t.Fatal("back did not restore the main menu")
		}
	}
}

func TestTUILeftArrowEditsTextWithoutLeavingTheForm(t *testing.T) {
	for _, action := range []string{"initialize", "message"} {
		model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
		model.form = newTUIForm(action, false)
		model.screen = tuiEditing
		if action == "message" {
			model.form.message.SetValue("abc")
		} else {
			model.form.fields[0].input.SetValue("abc")
		}
		model.form.focusInput()
		model.Update(tuiTestKey(tea.KeyLeft))
		model.Update(tuiTestKey('X'))
		value := ""
		if action == "message" {
			value = model.form.message.Value()
		} else {
			value = model.form.fields[0].input.Value()
		}
		if model.screen != tuiEditing || value != "abXc" {
			t.Fatalf("%s: left arrow left the form or failed to edit: %q", action, value)
		}
	}
}
