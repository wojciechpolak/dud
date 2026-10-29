// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"image/color"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// A UTF8i QR for the payload "test", including its four-module quiet zone.
const tuiQRTestText = "                             \n                             \n    █▀▀▀▀▀█   ▀ █ █▀▀▀▀▀█    \n    █ ███ █ ▀ ▀ ▄ █ ███ █    \n    █ ▀▀▀ █  █▄█▀ █ ▀▀▀ █    \n    ▀▀▀▀▀▀▀ █ █ ▀ ▀▀▀▀▀▀▀    \n    ▀█▀▄█▀▀▀▀ █▄▀█▀▄  ▀▄▄    \n    ▄ █ ▄▄▀▄▄▄ █▄█▀█▄▀▀█▀    \n     ▀ ▀  ▀ █▄▄▀ ▀█▀ █ ▀█    \n    █▀▀▀▀▀█ █▄▀ ▀ ▄ ▀▀ █▀    \n    █ ███ █ ▀▀▄▄▀▄▀▄▀▀ █▀    \n    █ ▀▀▀ █ █▀▄█▄█▀█▄▄▀▄▀    \n    ▀▀▀▀▀▀▀ ▀▀ ▀ ▀▀▀  ▀▀▀    \n                             \n                             \n"

func installTUITestQREncoder(t *testing.T, a *app) string {
	t.Helper()
	directory := t.TempDir()
	input := filepath.Join(directory, "input")
	binary := filepath.Join(directory, "qrencode")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + input + ".args\"\ncat > \"" + input + "\"\nprintf '%s' '" + tuiQRTestText + "'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	a.cfg.QREncodeBin = binary
	return input
}

func assertTUIQRPayload(t *testing.T, input, payload string) {
	t.Helper()
	data, err := os.ReadFile(input)
	if err != nil || string(data) != payload {
		t.Fatalf("QR payload = %q, err = %v", data, err)
	}
	args, err := os.ReadFile(input + ".args")
	if err != nil || string(args) != "-t\nUTF8i\n-m\n4\n" {
		t.Fatalf("QR arguments = %q, err = %v", args, err)
	}
}

func TestTUIQRCodeUsesStdinAndRetainsTheEncoderMatrix(t *testing.T) {
	a := newApp(strings.NewReader(""), io.Discard, io.Discard)
	input := installTUITestQREncoder(t, a)
	payload := "private-pairing-code\nwith-another-line"
	qr := a.tuiQRCode(payload)
	assertTUIQRPayload(t, input, payload)
	if qr.width != 29 || qr.height != 15 || qr.text+"\n" != tuiQRTestText {
		t.Fatalf("QR dimensions = %d × %d", qr.width, qr.height)
	}
}

func TestTUIQRCodeAcceptsRealEncoderOutput(t *testing.T) {
	binary, err := exec.LookPath("qrencode")
	if err != nil {
		t.Skip("qrencode is not installed")
	}
	a := newApp(strings.NewReader(""), io.Discard, io.Discard)
	a.cfg.QREncodeBin = binary
	for _, payload := range []string{"test", testDropID, strings.Repeat("pairing", 30)} {
		qr := a.tuiQRCode(payload)
		if qr.width == 0 {
			t.Fatal("real encoder output was rejected")
		}
		model := newTUIModel(a)
		model.screen, model.qr = tuiResult, &qr
		model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		model.Update(tuiTestKey('v'))
		view := ansi.Strip(model.View().Content)
		assertTUIQRIsWholeOrHidden(t, view, qr)
		if qr.height <= 19 && !strings.Contains(view, "█") {
			t.Fatal("the full QR view hides a code that fits an 80 × 24 terminal")
		}
	}
}

func TestTUIQRCodeInheritsTerminalColorsAndLeavesTheQuietZoneUnpainted(t *testing.T) {
	qr := parseTUIQRCode(tuiQRTestText)
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.screen, model.status, model.qr = tuiResult, "Completed", &qr
	model.view.SetContent("ID: text-alternative")
	for _, background := range []color.Color{nil, color.Black, color.White, color.Black} {
		if background != nil {
			model.Update(tea.BackgroundColorMsg{Color: background})
		}
		for _, qrOnly := range []bool{false, true} {
			model.qrOnly = qrOnly
			model.resize()
			body, _ := model.body()
			if strings.Contains(body, "\x1b") {
				t.Fatal("QR imposes foreground or background colors")
			}
			assertTUIQRIsWholeOrHidden(t, body, qr)
			if !strings.Contains(body, "█") {
				t.Fatal("QR is missing")
			}
			if qrOnly && body != qr.text {
				t.Fatal("QR view changes modules or paints the quiet zone")
			}
		}
		if model.qr != &qr || qr.text+"\n" != tuiQRTestText {
			t.Fatal("theme change replaced the encoded QR")
		}
	}
}

func TestTUIQRCodeRejectsIncompleteOrUnsafeEncoderOutput(t *testing.T) {
	for _, text := range []string{
		"", "\x1b[2J" + tuiQRTestText,
		strings.Replace(tuiQRTestText, "█", "\x1b]52;c;payload\a", 1),
		strings.Replace(tuiQRTestText, "█", "xx", 1),
		strings.Replace(tuiQRTestText, "    ", "█   ", 1),
		strings.Replace(tuiQRTestText, "\n", "", 1),
		strings.Repeat(" ", 189) + "\n",
		strings.Repeat(strings.Repeat(" ", 29)+"\n", 15),
	} {
		if qr := parseTUIQRCode(text); qr.width != 0 || qr.text != "" {
			t.Fatal("unsafe or incomplete QR reached the renderer")
		}
	}
}

func TestTUIQRCodeLayoutPreservesTheWholeSymbolAcrossSizesAndThemes(t *testing.T) {
	qr := parseTUIQRCode(tuiQRTestText)
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.screen, model.status, model.qr = tuiResult, "Completed", &qr
	model.view.SetContent("ID: text-alternative")
	for _, dark := range []bool{false, true} {
		model.setTheme(backgroundTUITheme(dark))
		for _, size := range [][2]int{{80, 24}, {120, 40}, {48, 16}, {48, 20}, {48, 30}} {
			model.qrOnly = false
			model.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			view := ansi.Strip(model.View().Content)
			if !strings.Contains(view, "text-alternative") || !strings.Contains(view, "v QR") {
				t.Fatalf("size %v hides text or QR navigation", size)
			}
			assertTUIQRIsWholeOrHidden(t, view, qr)
			if size[1] >= 24 && !strings.Contains(view, "█") {
				t.Fatalf("size %v can fit an inline QR but hides it", size)
			}
			model.Update(tuiTestKey('v'))
			view = ansi.Strip(model.View().Content)
			if !strings.Contains(view, "v details") {
				t.Fatal("QR view has no return control")
			}
			assertTUIQRIsWholeOrHidden(t, view, qr)
			if size[1] >= qr.height+5 && !strings.Contains(view, "█") {
				t.Fatalf("size %v can fit the QR but hides it", size)
			}
			for _, line := range strings.Split(view, "\n") {
				if ansi.StringWidth(line) > size[0] {
					t.Fatalf("size %v overflows", size)
				}
			}
		}
	}
}

func TestTUIQRCodeNavigationClearsTheSymbolAndRestoresTheMenu(t *testing.T) {
	qr := parseTUIQRCode(tuiQRTestText)
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.screen, model.qr, model.qrOnly = tuiResult, &qr, true
	model.Update(tuiTestKey(tea.KeyEnter))
	if model.qr != nil || model.qrOnly || model.screen != tuiHome {
		t.Fatal("returning to the menu retained the QR view")
	}
	model.screen, model.qr, model.qrOnly = tuiResult, &qr, true
	model.start([]string{"help"})
	t.Cleanup(func() { finishTUITestOperation(t, model.operation) })
	model.Update(awaitTUITestEvent(t, model.operation))
	if model.qr != nil || model.qrOnly {
		t.Fatal("another command retained the previous QR")
	}
}

func assertTUIQRIsWholeOrHidden(t *testing.T, view string, qr tuiQRCode) {
	t.Helper()
	if !strings.Contains(view, "█") {
		return
	}
	rows := strings.Split(qr.text, "\n")
	lines := strings.Split(view, "\n")
	for index, line := range lines {
		if offset := strings.Index(line, rows[2]); offset >= 0 && index >= 2 && index+qr.height-2 <= len(lines) {
			for row := range rows {
				if !strings.HasPrefix(lines[index-2+row][min(offset, len(lines[index-2+row])):], rows[row]) {
					t.Fatalf("QR row %d is clipped or changed", row)
				}
			}
			return
		}
	}
	t.Fatal("QR was partially displayed")
}

func TestTUIMissingQRCodeEncoderPreservesASuccessfulUpload(t *testing.T) {
	a, transport, _, _ := newDropTestApp(t, "")
	a.cfg.QREncodeBin = filepath.Join(t.TempDir(), "absent")
	transport.respond = uploadJSONResponder(testDropID)
	operation := startTUIOperation(a, []string{"upload", "-m", "hello", "--passphrase"})
	t.Cleanup(func() { finishTUITestOperation(t, operation) })
	request := awaitTUITestEvent(t, operation).(*tuiTerminalMsg)
	request.answer <- request.command.Run()
	event := awaitTUITestEvent(t, operation).(tuiQRCodeMsg)
	if event.qr.width != 0 {
		t.Fatal("missing encoder displayed a QR")
	}
	result := awaitTUITestEvent(t, operation).(tuiDoneMsg)
	if result.err != nil {
		t.Fatal(result.err)
	}
	model := newTUIModel(a)
	model.operation, model.screen, model.busy = operation, tuiRunning, true
	model.Update(event)
	model.Update(result)
	view := ansi.Strip(model.View().Content)
	if !strings.Contains(view, testDropID) || !strings.Contains(view, "QR unavailable") {
		t.Fatalf("fallback = %q", view)
	}
}

func TestTUIQRCodeEncoderRespectsCancellation(t *testing.T) {
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, io.Discard)
	a.cfg.QREncodeBin = "qrencode"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.commandCtx = ctx
	if qr := a.tuiQRCode("secret"); qr.width != 0 {
		t.Fatal("cancelled encoding displayed a QR")
	}
}
