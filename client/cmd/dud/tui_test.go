// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func tuiTestKey(code rune, modifiers ...tea.KeyMod) tea.KeyPressMsg {
	key := tea.Key{Code: code}
	for _, modifier := range modifiers {
		key.Mod |= modifier
	}
	if code >= ' ' && code <= '~' && key.Mod == 0 {
		key.Text = string(code)
	}
	return tea.KeyPressMsg(key)
}

func setTUITestValue(form *tuiForm, name, value string) {
	for index := range form.fields {
		if form.fields[index].key == name {
			form.fields[index].input.SetValue(value)
		}
	}
}

func awaitTUITestEvent(t *testing.T, operation *tuiOperation) tea.Msg {
	t.Helper()
	select {
	case event := <-operation.events:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not produce an event")
		return nil
	}
}

func finishTUITestOperation(t *testing.T, operation *tuiOperation) {
	t.Helper()
	operation.cancel()
	select {
	case <-operation.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not release its resources")
	}
}

func TestTUIRequiresTerminalAndRejectsExtraArguments(t *testing.T) {
	for _, args := range [][]string{{"--tui"}, {"--tui", "send"}} {
		var output, diagnostic bytes.Buffer
		a := newApp(unreadableHelpInput{t}, &output, &diagnostic)
		if code := a.main(args); code == 0 || output.Len() != 0 {
			t.Fatalf("%v: code=%d, output=%q", args, code, output.String())
		}
		if !strings.Contains(diagnostic.String(), "dud --tui") {
			t.Fatal(diagnostic.String())
		}
	}
}

func TestTUITargetsKeepDeadDropAvailableWithoutPeerConfiguration(t *testing.T) {
	setTestV2Homes(t)
	paths, err := resolveV2Paths()
	if err != nil {
		t.Fatal(err)
	}
	result := loadTUITargets().(tuiTargetsMsg)
	if len(result.items) != 1 || !result.items[0].(tuiItem).deadDrop || result.notice == "" {
		t.Fatalf("targets=%+v", result)
	}
	if _, err := os.Stat(paths.Root); !os.IsNotExist(err) {
		t.Fatalf("opening targets created peer state: %v", err)
	}
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.Update(result)
	for _, size := range [][2]int{{48, 16}, {80, 24}, {100, 24}} {
		model.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		view := ansi.Strip(model.View().Content)
		if !strings.Contains(view, "Choose setup") || !strings.Contains(view, "Enter continue") || strings.Contains(view, "↑/↓ choose") {
			t.Fatalf("size=%v: single target obscures setup or navigation: %q", size, view)
		}
	}
	model.Update(tuiTestKey(tea.KeyEnter))
	model.Update(tuiTestKey(tea.KeyDown))
	if model.menu.SelectedItem().(tuiItem).id != "files" {
		t.Fatal("down did not select Send files after opening dead drop actions")
	}
	model.Update(tuiTestKey(tea.KeyUp))
	if model.menu.SelectedItem().(tuiItem).id != "message" {
		t.Fatal("up did not return to Send message")
	}
}

func TestTUIArrowsNavigateTargetsAndOpenTheSelectedAction(t *testing.T) {
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.Update(tuiTargetsMsg{items: []list.Item{
		tuiItem{id: "laptop", title: "laptop", active: true},
		tuiItem{id: "desktop", title: "desktop", active: true},
		tuiItem{title: "Dead drop", deadDrop: true, active: true},
	}})
	model.Update(tuiTestKey(tea.KeyDown))
	if model.menu.SelectedItem().(tuiItem).id != "desktop" {
		t.Fatal("down did not select the next peer")
	}
	model.Update(tuiTestKey(tea.KeyUp))
	if model.menu.SelectedItem().(tuiItem).id != "laptop" {
		t.Fatal("up did not select the previous peer")
	}
	model.Update(tuiTestKey(tea.KeyEnter))
	model.Update(tuiTestKey(tea.KeyDown))
	model.Update(tuiTestKey(tea.KeyDown))
	model.Update(tuiTestKey(tea.KeyEnter))
	if model.screen != tuiEditing || model.target.id != "laptop" || model.form.action != "receive" {
		t.Fatal("arrows and Enter did not open the selected peer receive form")
	}
}

func TestTUIPeerAliasDoesNotSelectDeadDropByName(t *testing.T) {
	newPairedV2TestPeer(t, "dead-drop")
	result := loadTUITargets().(tuiTargetsMsg)
	if len(result.items) != 2 {
		t.Fatal(result.items)
	}
	peer, drop := result.items[0].(tuiItem), result.items[1].(tuiItem)
	if peer.deadDrop || !drop.deadDrop || peer.id != drop.id {
		t.Fatalf("peer=%+v, dead drop=%+v", peer, drop)
	}
	form := newTUIForm("message", false)
	form.message.SetValue("--help\nsecond line")
	args, err := form.arguments(peer, config{})
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseV2PeerSendOptions(args[1:])
	if err != nil || opts.alias != "dead-drop" || opts.message != "--help\nsecond line" || opts.deleteAfterRead {
		t.Fatalf("options=%+v, err=%v", opts, err)
	}
}

func TestTUIFileFormsPreservePathsWithSpacesAndDefaultPolicies(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first file"), filepath.Join(dir, "second file")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	form := newTUIForm("files", false)
	if err := form.addPath(first); err != nil {
		t.Fatal(err)
	}
	setTUITestValue(form, "path", second)
	args, err := form.arguments(tuiItem{id: "laptop"}, config{})
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseV2PeerSendOptions(args[1:])
	if err != nil || !reflect.DeepEqual(opts.files, []string{first, second}) || opts.ttl != 168*time.Hour || opts.deleteAfterRead {
		t.Fatalf("options=%+v, err=%v", opts, err)
	}
	form = newTUIForm("message", true)
	form.message.SetValue("hello")
	args, err = form.arguments(tuiItem{deadDrop: true}, config{SecretToken: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	dropOpts, err := parseUploadOptions(args[1:], v2DefaultBaseURL, v2DefaultDOHURL)
	if err != nil || dropOpts.ttl != "24h" || dropOpts.deleteAfterRead || !dropOpts.passphraseRequested {
		t.Fatalf("dead drop options=%+v, err=%v", dropOpts, err)
	}
}

func TestTUIReceiveFormRetainsCollectionConfirmationAndConflictPolicy(t *testing.T) {
	form := newTUIForm("receive", false)
	setTUITestValue(form, "outdir", t.TempDir())
	args, err := form.arguments(tuiItem{id: "laptop"}, config{})
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseV2PeerReceiveOptions(args[1:])
	if err != nil || !opts.interactive || opts.onConflict != "skip" || opts.wait != 0 || opts.max != 0 {
		t.Fatalf("options=%+v, err=%v", opts, err)
	}
	setTUITestValue(form, "wait", "bad")
	if _, err := form.arguments(tuiItem{id: "laptop"}, config{}); err == nil {
		t.Fatal("invalid wait was accepted")
	}
}

func TestTUIFormsKeepTextAndCheckboxKeysSeparateFromNavigation(t *testing.T) {
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.target = tuiItem{id: "laptop", title: "laptop", active: true}
	model.form, model.screen = newTUIForm("message", false), tuiEditing
	model.form.focusInput()
	model.Update(tuiTestKey('q'))
	model.Update(tuiTestKey(tea.KeyEnter))
	model.Update(tuiTestKey('y'))
	if model.form.message.Value() != "q\ny" || model.screen != tuiEditing {
		t.Fatalf("message=%q, screen=%d", model.form.message.Value(), model.screen)
	}
	model.Update(tuiTestKey(tea.KeyTab))
	model.Update(tuiTestKey(tea.KeyTab))
	model.Update(tuiTestKey(' '))
	if !model.form.checked("delete") {
		t.Fatal("space did not toggle the focused checkbox")
	}
	model.Update(tuiTestKey(tea.KeyEscape))
	if model.screen != tuiHome {
		t.Fatalf("screen=%d", model.screen)
	}
}

func TestTUIFileBrowserSelectsDirectoriesWithoutChangingThePath(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "chosen directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.form, model.screen = newTUIForm("files", false), tuiFiles
	model.picker = filepicker.New()
	model.picker.CurrentDirectory = filepath.Dir(directory)
	model.Update(model.picker.Init()())
	model.Update(tuiTestKey(' '))
	if model.screen != tuiEditing || !reflect.DeepEqual(model.form.paths, []string{directory}) {
		t.Fatalf("paths=%q, screen=%d", model.form.paths, model.screen)
	}
}

func TestTUIOutputIsBoundedAndEscapesTerminalControls(t *testing.T) {
	output := &tuiOutput{}
	if _, err := output.Write([]byte(strings.Repeat("x", tuiOutputLimit+1))); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("\nmessage\x1b]52;c;secret\a\r\u202e\nnext")); err != nil {
		t.Fatal(err)
	}
	text, _ := output.snapshot()
	if len(output.text) > tuiOutputLimit || !strings.Contains(text, "[Earlier output omitted]") || strings.ContainsAny(text, "\x1b\a\r\u202e") || !strings.Contains(text, "\nnext") {
		t.Fatalf("unsafe or unbounded output: %q", text[len(text)-100:])
	}
}

func TestTUIProgressUsesStructuredEventsWithoutWritingTerminalOutput(t *testing.T) {
	var terminal bytes.Buffer
	output := &tuiOutput{}
	a := newApp(strings.NewReader(""), io.Discard, &terminal)
	a.observeProgress = output.observe
	reporter := a.newV2ProgressReporter("laptop", false, v2ProgressFlags{})
	reporter.Phase("upload", 100)
	reporter.Set(40, 100)
	_, snapshot := output.snapshot()
	if snapshot.Phase != "upload" || snapshot.Current != 40 || snapshot.Total != 100 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	reporter.Complete()
	if terminal.Len() != 0 {
		t.Fatalf("terminal output=%q", terminal.String())
	}
	_, snapshot = output.snapshot()
	if snapshot.Phase != "complete" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestTUIDeadDropSharesCommandExecutionAndSuspendsForAge(t *testing.T) {
	a, transport, stdout, stderr := newDropTestApp(t, "")
	qrInput := installTUITestQREncoder(t, a)
	transport.respond = uploadJSONResponder("shared-id")
	operation := startTUIOperation(a, []string{"upload", "-m", "hello from TUI", "--passphrase"})
	t.Cleanup(func() { finishTUITestOperation(t, operation) })
	request, ok := awaitTUITestEvent(t, operation).(*tuiTerminalMsg)
	if !ok {
		t.Fatal("age did not request ownership of the terminal")
	}
	if len(transport.requests) != 0 {
		t.Fatal("upload preceded encryption")
	}
	request.answer <- request.command.Run()
	qr, ok := awaitTUITestEvent(t, operation).(tuiQRCodeMsg)
	if !ok || qr.qr.text+"\n" != tuiQRTestText {
		t.Fatal("upload did not display its QR")
	}
	assertTUIQRPayload(t, qrInput, "shared-id")
	result, ok := awaitTUITestEvent(t, operation).(tuiDoneMsg)
	if !ok || result.err != nil {
		t.Fatalf("result=%+v", result)
	}
	finishTUITestOperation(t, operation)
	if got := string(transport.only(t).Body); got != "hello from TUI" {
		t.Fatalf("uploaded fixture=%q", got)
	}
	text, snapshot := operation.output.snapshot()
	if !strings.Contains(text, "shared-id") || snapshot.Phase != "upload" {
		t.Fatalf("result=%q, progress=%+v", text, snapshot)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("worker wrote to the UI's terminal")
	}
}

func TestTUICancelsWhileAwaitingConfirmationOrTerminalOwnership(t *testing.T) {
	for _, mode := range []string{"confirmation", "terminal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			operation := &tuiOperation{ctx: ctx, cancel: cancel, events: make(chan tea.Msg, 2)}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if mode == "confirmation" {
					if operation.confirmCollection([]v2CollectionEntry{{name: "unsafe\x1b[2J"}}) {
						t.Error("cancellation approved extraction")
					}
				} else {
					if err := operation.terminalCommand(nil); !errors.Is(err, context.Canceled) {
						t.Errorf("terminal error=%v", err)
					}
				}
			}()
			event := awaitTUITestEvent(t, operation)
			if request, ok := event.(tuiConfirmMsg); ok && strings.ContainsRune(request.preview, '\x1b') {
				t.Fatal("unsafe preview")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cancellation left a prompt blocked")
			}
		})
	}
}

func TestTUICancellationWaitsForRunningAgeBeforeCommandCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	operation := &tuiOperation{ctx: ctx, cancel: cancel, events: make(chan tea.Msg, 2)}
	done := make(chan error, 1)
	go func() { done <- operation.terminalCommand(nil) }()
	request := awaitTUITestEvent(t, operation).(*tuiTerminalMsg)
	request.state.Store(tuiTerminalRunning)
	cancel()
	select {
	case <-done:
		t.Fatal("worker returned before age exited")
	case <-time.After(25 * time.Millisecond):
	}
	request.answer <- context.Canceled
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not finish after age exited")
	}
	pending := &tuiTerminalMsg{}
	pending.state.Store(tuiTerminalCancelled)
	if err := (tuiTerminalCommand{request: pending}).Run(); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled terminal request started a process")
	}
}

func TestTUIFailedOperationStaysVisibleAndReturnsToMenu(t *testing.T) {
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.target = tuiItem{id: "laptop", title: "laptop", active: true}
	model.start([]string{"unknown"})
	defer finishTUITestOperation(t, model.operation)
	model.Update(awaitTUITestEvent(t, model.operation))
	if model.busy || model.screen != tuiResult || model.status != "Failed" || !strings.Contains(model.View().Content, "Unknown command") {
		t.Fatalf("result screen=%q", model.View().Content)
	}
	model.Update(tuiTestKey(tea.KeyEnter))
	if model.screen != tuiHome {
		t.Fatal("result did not return to actions")
	}
}

type tuiBlockingTransport struct{ entered chan struct{} }

func (transport *tuiBlockingTransport) Do(ctx context.Context, _ v2Request) (*v2Response, error) {
	select {
	case transport.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestTUICancelsNetworkWorkAndReleasesThePeerLock(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	transport := &tuiBlockingTransport{entered: make(chan struct{}, 1)}
	a := newDrainingV2TestApp(t, transport, &bytes.Buffer{}, &bytes.Buffer{})
	operation := startTUIOperation(a, []string{"receive", "laptop", "--wait", "1h"})
	t.Cleanup(func() { finishTUITestOperation(t, operation) })
	select {
	case <-transport.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("receive did not reach transport")
	}
	operation.cancel()
	result, ok := awaitTUITestEvent(t, operation).(tuiDoneMsg)
	if !ok || !errors.Is(result.err, context.Canceled) {
		t.Fatalf("result=%+v", result)
	}
	finishTUITestOperation(t, operation)
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		t.Fatalf("cancelled receive retained its lock: %v", err)
	}
	unlock()
	stored, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil || stored.Chains["in:data"].ReceiveWatermark != 0 {
		t.Fatalf("cancelled receive advanced state: %v", err)
	}
}

func TestTUICollectionDeclinePreservesDeliveryForRetry(t *testing.T) {
	for _, approve := range []bool{false, true} {
		t.Run(map[bool]string{false: "decline", true: "approve"}[approve], func(t *testing.T) {
			paths, state := newPairedV2TestPeer(t, "laptop")
			if err := writeV2PeerDeliveryState(paths, state); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(t.TempDir(), "hello.txt")
			if err := os.WriteFile(source, []byte("hello\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			archive, _, err := createV2CollectionArchive([]string{source})
			if err != nil {
				t.Fatal(err)
			}
			crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
			delivery := buildInboundV2Delivery(t, crypto, 1, strings.Repeat("00", 32), 3, "collection.tar", archive)
			transport := &drainingInboxTransport{queue: []stubbedV2Delivery{delivery}}
			a := newDrainingV2TestApp(t, transport, &bytes.Buffer{}, &bytes.Buffer{})
			destination := filepath.Join(t.TempDir(), "received")
			operation := startTUIOperation(a, []string{"receive", "laptop", "--interactive", "--out-dir", destination})
			t.Cleanup(func() { finishTUITestOperation(t, operation) })
			request, ok := awaitTUITestEvent(t, operation).(tuiConfirmMsg)
			if !ok || !strings.Contains(request.preview, "hello.txt") {
				t.Fatalf("confirmation=%+v", request)
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatalf("extraction preceded confirmation: %v", err)
			}
			request.answer <- approve
			result, ok := awaitTUITestEvent(t, operation).(tuiDoneMsg)
			if !ok || (result.err == nil) != approve {
				t.Fatalf("approve=%v, result=%+v", approve, result)
			}
			finishTUITestOperation(t, operation)
			stored, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
			if err != nil {
				t.Fatal(err)
			}
			wantWatermark := uint64(0)
			if approve {
				wantWatermark = 1
			}
			if stored.Chains["in:data"].ReceiveWatermark != wantWatermark {
				t.Fatal("confirmation did not control delivery commit")
			}
			if approve {
				data, err := os.ReadFile(filepath.Join(destination, "hello.txt"))
				if err != nil || string(data) != "hello\n" {
					t.Fatalf("output=%q, err=%v", data, err)
				}
			}
		})
	}
}

func TestTUILayoutKeepsFooterVisibleAcrossTerminalSizes(t *testing.T) {
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.target = tuiItem{id: "laptop", title: "laptop", active: true}
	for _, size := range [][2]int{{48, 16}, {80, 24}, {120, 35}, {20, 8}} {
		model.form, model.screen = newTUIForm("message", true), tuiEditing
		model.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		if model.form.message.Width() < size[0]-12 || model.form.message.Width() > size[0]-4 || model.form.fields[0].input.Width() != size[0]-6 {
			t.Fatal("resize did not update the message editor")
		}
		model.form.focus = model.form.count()
		text := ansi.Strip(model.View().Content)
		if !strings.Contains(text, "Esc") && !strings.Contains(text, "Ctrl+C") {
			t.Fatalf("size=%v has no navigation: %q", size, text)
		}
		if size[0] >= 48 && !strings.Contains(text, "Run transfer") {
			t.Fatalf("size=%v hides focused control: %q", size, text)
		}
		for _, line := range strings.Split(text, "\n") {
			if ansi.StringWidth(line) > size[0] {
				t.Fatalf("size=%v overflows: %q", size, line)
			}
		}
	}
}
