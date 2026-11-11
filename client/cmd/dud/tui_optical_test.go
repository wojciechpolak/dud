// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func TestTUIOpticalTargetBelongsToSendAndCapsuleDecryptionBelongsToTools(t *testing.T) {
	setTestV2Homes(t)
	for _, action := range []string{"send", "receive", "git-push", "git-fetch", "sync-target"} {
		model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
		model.homeAction, model.targetAction = action, action
		model.Update(loadTUITargets())
		optical := -1
		for index, value := range model.menu.Items() {
			if value.(tuiItem).optical {
				optical = index
			}
		}
		if (optical >= 0) != (action == "send") {
			t.Fatalf("optical target in %s: %d", action, optical)
		}
		if optical >= 0 {
			model.menu.Select(optical)
			model.selectTarget()
			model.selectAction()
			if model.form.action != "optical-message" || !model.form.hasMessage {
				t.Fatal("optical target did not open the optical message form")
			}
		}
	}
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.menu.Select(6)
	model.selectHome()
	if model.menu.SelectedItem().(tuiItem).title != "decrypt optical capsule" {
		t.Fatal("tools does not identify local capsule decryption")
	}
	model.selectAction()
	if model.form.action != "optical-recover" || model.form.submitLabel() != "Decrypt capsule" {
		t.Fatal("decryption tool opened a transfer receive form")
	}
}

func TestTUIOpticalFormsValidateLocalOptionsAndCycleRendererAndProfile(t *testing.T) {
	form := newTUIForm("optical-files", false)
	first, second := filepath.Join(t.TempDir(), "first file"), filepath.Join(t.TempDir(), "second file")
	form.paths = []string{first}
	setTUITestValue(form, "path", second)
	args, err := form.arguments(tuiItem{optical: true}, config{DropBaseURL: "invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "optical" || args[1] != "send" {
		t.Fatal(args)
	}
	opts, err := parseUploadOptions(append([]string{"--optical"}, args[2:]...), "", "")
	if err != nil || !reflect.DeepEqual(opts.files, []string{first, second}) || opts.opticalProfile != "balanced" || !opts.passphraseRequested {
		t.Fatalf("options=%+v, err=%v", opts, err)
	}
	for _, flag := range []string{"--ttl", "--delete-after-read", "--url", "--doh-url", "--id"} {
		if opts.explicitFlags[flag] {
			t.Fatalf("optical form generated %s", flag)
		}
	}
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.form, model.screen = form, tuiEditing
	for index, field := range form.fields {
		if field.key == "renderer" {
			form.focus = index
		}
	}
	initial := form.value("renderer")
	model.Update(tuiTestKey(tea.KeyRight))
	if form.value("renderer") == initial {
		t.Fatal("right arrow did not change the renderer")
	}
	model.Update(tuiTestKey(tea.KeyLeft))
	if form.value("renderer") != initial {
		t.Fatal("left arrow did not restore the renderer")
	}
	model.Update(tuiTestKey('x'))
	if form.value("renderer") != initial {
		t.Fatal("choice accepted arbitrary text")
	}
	form.focus++
	model.Update(tuiTestKey(' '))
	if form.value("profile") != "high-rate" {
		t.Fatal("Space did not choose the next profile")
	}
	model.Update(tea.WindowSizeMsg{Width: 48, Height: 16})
	if !strings.Contains(ansi.Strip(model.View().Content), "Esc") {
		t.Fatal("optical form hides navigation at the minimum terminal size")
	}
}

func TestTUIOpticalRendererChoicesMatchBuildCapabilities(t *testing.T) {
	for _, action := range []string{"optical-message", "optical-files"} {
		form := newTUIOpticalForm(action)
		for _, field := range form.fields {
			if field.key != "renderer" {
				continue
			}
			if !slices.Contains(field.choices, "terminal") || slices.Contains(field.choices, "kitty") != opticalKittySupported || slices.Contains(field.choices, "window") != display.NativeWindow {
				t.Fatalf("%s offers renderers incompatible with the build: %v", action, field.choices)
			}
			wantDefault := "terminal"
			if opticalKittySupported {
				wantDefault = "kitty"
			}
			if field.input.Value() != wantDefault {
				t.Fatalf("default renderer = %s, want %s", field.input.Value(), wantDefault)
			}
		}
	}
}

func TestTUIOpticalDecryptionUsesTheExplicitCLICommand(t *testing.T) {
	form := newTUIForm("optical-recover", false)
	setTUITestValue(form, "path", "capsule with spaces.age")
	setTUITestValue(form, "out", "recovered file")
	setTUITestValue(form, "identity", "private identity.txt")
	args, err := form.arguments(tuiItem{}, config{})
	if err != nil || !reflect.DeepEqual(args, []string{"optical", "decrypt", "--file", "capsule with spaces.age", "--out", "recovered file", "--identity", "private identity.txt"}) {
		t.Fatalf("decryption args=%q, err=%v", args, err)
	}
	for index := range form.fields {
		if form.fields[index].key == "extract" {
			form.fields[index].checked = true
		}
	}
	args, err = form.arguments(tuiItem{}, config{})
	if err != nil || !strings.Contains(strings.Join(args, " "), "--extract --out-dir recovered file") {
		t.Fatal(args, err)
	}
}

func TestTUIOpticalTerminalUsesOneCellPerModuleForBothProfiles(t *testing.T) {
	for _, action := range []string{"optical-message", "optical-files"} {
		for _, profile := range []string{"balanced", "high-rate"} {
			for _, renderer := range []string{"terminal", "kitty", "window"} {
				t.Run(action+"/"+profile+"/"+renderer, func(t *testing.T) {
					form := newTUIOpticalForm(action)
					if form.hasMessage {
						form.message.SetValue("message")
					} else {
						setTUITestValue(form, "path", "file")
					}
					setTUITestValue(form, "renderer", renderer)
					setTUITestValue(form, "profile", profile)
					args, err := form.opticalArguments()
					if err != nil {
						t.Fatal(err)
					}
					opts, err := parseUploadOptions(args[2:], "", "")
					if err != nil {
						t.Fatal(err)
					}
					if renderer != "terminal" {
						if opts.opticalScale != 2 {
							t.Fatalf("pixel renderer scale = %d, want 2", opts.opticalScale)
						}
						return
					}
					columns, rows := 290, 146
					if profile == "high-rate" {
						columns, rows = 370, 186
					}
					session, err := display.OpenTerminal(io.Discard, opticalDisplayOptions(opts), func() (int, int, error) { return columns, rows, nil }, nil)
					if err != nil {
						t.Fatalf("terminal profile does not fit %dx%d cells: %v", columns, rows, err)
					}
					if err := session.Close(); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestTUIOpticalOperationAcquiresTerminalBeforePreflightAndCapturesOnlyReport(t *testing.T) {
	parent, renderer, output, diagnostics := newOpticalTestApp(t, "")
	form := newTUIForm("optical-message", false)
	form.message.SetValue("private message in memory")
	args, err := form.arguments(tuiItem{optical: true}, parent.cfg)
	if err != nil {
		t.Fatal(err)
	}
	operation := startTUIOperation(parent, args)
	defer finishTUITestOperation(t, operation)
	request := awaitTUITestEvent(t, operation).(*tuiTerminalMsg)
	if request.run == nil || request.command != nil || renderer.called {
		t.Fatal("optical preflight preceded terminal ownership or created a subprocess")
	}
	command := &tuiTerminalCommand{request: request, output: operation.output}
	command.SetStdin(strings.NewReader(""))
	command.SetStdout(io.Discard)
	command.SetStderr(io.Discard)
	request.answer <- command.Run()
	result := awaitTUITestEvent(t, operation).(tuiDoneMsg)
	if result.err != nil || !renderer.called || !renderer.closed {
		t.Fatal("optical command or cleanup failed", result.err)
	}
	_, payload, err := capsule.Decode(renderer.ciphertext)
	if err != nil || string(payload) != "private message in memory" {
		t.Fatal("optical input changed", err)
	}
	text, _ := operation.output.snapshot()
	if !strings.Contains(text, "display ended") || strings.Contains(text, "private message") || output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatal("optical data reached UI-owned output", text)
	}
}

type tuiWaitingOpticalRenderer struct {
	entered chan struct{}
	closed  bool
	once    sync.Once
}

func (renderer *tuiWaitingOpticalRenderer) Display(ctx context.Context, _ string) error {
	renderer.once.Do(func() { close(renderer.entered) })
	<-ctx.Done()
	return ctx.Err()
}
func (renderer *tuiWaitingOpticalRenderer) Close() error { renderer.closed = true; return nil }

func TestTUIOpticalCancellationWaitsForDisplayAndCommandCleanup(t *testing.T) {
	parent, _, _, _ := newOpticalTestApp(t, "")
	renderer := &tuiWaitingOpticalRenderer{entered: make(chan struct{})}
	parent.newOpticalRenderer = func(context.Context, display.Options) (display.Renderer, error) { return renderer, nil }
	operation := startTUIOperation(parent, []string{"optical", "send", "-m", "message", "--passphrase"})
	defer finishTUITestOperation(t, operation)
	request := awaitTUITestEvent(t, operation).(*tuiTerminalMsg)
	command := &tuiTerminalCommand{request: request, output: operation.output}
	command.SetStdin(strings.NewReader(""))
	command.SetStdout(io.Discard)
	command.SetStderr(io.Discard)
	go func() { request.answer <- command.Run() }()
	select {
	case <-renderer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("display did not start")
	}
	operation.cancel()
	result := awaitTUITestEvent(t, operation).(tuiDoneMsg)
	if result.err == nil || !renderer.closed {
		t.Fatal("cancellation lost display cleanup", result.err)
	}
	assertOpticalCleanup(t)
}

func TestOpticalReceiveFlagsAreRejectedAndDecryptIsNotAReceiver(t *testing.T) {
	for _, command := range []string{"download", "receive"} {
		var output, diagnostic bytes.Buffer
		parent := newApp(opticalUnreadableInput{t}, &output, &diagnostic)
		if code := parent.main([]string{command, "--optical", "--file", "capsule", "--out", "output"}); code == 0 || !strings.Contains(diagnostic.String(), "Unknown download option") {
			t.Fatalf("%s accepted optical reception: %s", command, diagnostic.String())
		}
	}
	var output bytes.Buffer
	parent := newApp(opticalUnreadableInput{t}, &output, io.Discard)
	if err := parent.run([]string{"optical", "receive"}); err == nil || !strings.Contains(err.Error(), "Unknown optical command") {
		t.Fatal("optical receive accepted", err)
	}
	if err := parent.run([]string{"optical", "decrypt", "--optical", "--json"}); err == nil {
		t.Fatal("mode flag accepted by optical decrypt")
	}
	if errors.Is(parent.commandContext().Err(), context.Canceled) {
		t.Fatal("usage validation cancelled parent context")
	}
}
