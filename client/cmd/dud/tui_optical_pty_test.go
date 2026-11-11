//go:build darwin || linux

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTUIOpticalTerminalUsesMinimumCellsWithRedirectedDiagnostics(t *testing.T) {
	t.Setenv("TERM", "xterm-kitty")
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close() }()
	name, err := tuiOpticalTestPTYName(master)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = terminal.Close() }()
	diagnostics, err := os.Create(filepath.Join(t.TempDir(), "errors.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = diagnostics.Close() }()
	parent, _, _, _ := newOpticalTestApp(t, "")
	parent.newOpticalRenderer = nil
	// The missing source stops after renderer preflight without entering a
	// display loop or requiring the PTY to be the process's controlling terminal.
	form := newTUIOpticalForm("optical-files")
	setTUITestValue(form, "renderer", "terminal")
	setTUITestValue(form, "path", filepath.Join(t.TempDir(), "missing"))
	args, err := form.opticalArguments()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		columns, rows uint16
		failure       string
	}{
		{"fits", 290, 146, "Optical source preparation failed"},
		{"too-small", 174, 60, "require at least 290 columns and 146 rows; terminal has 174 columns and 60 rows"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := unix.IoctlSetWinsize(int(terminal.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: test.columns, Row: test.rows}); err != nil {
				t.Fatal(err)
			}
			operation := startTUIOperation(parent, args)
			defer finishTUITestOperation(t, operation)
			request := awaitTUITestEvent(t, operation).(*tuiTerminalMsg)
			command := &tuiTerminalCommand{request: request, output: operation.output}
			command.SetStdin(strings.NewReader(""))
			command.SetStdout(terminal)
			command.SetStderr(diagnostics)
			request.answer <- command.Run()
			result := awaitTUITestEvent(t, operation).(tuiDoneMsg)
			if result.err == nil || !strings.Contains(result.err.Error(), test.failure) {
				t.Fatalf("unexpected renderer preflight result: %v", result.err)
			}
		})
	}
	if _, err := diagnostics.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(diagnostics)
	if err != nil || strings.Contains(string(data), "\x1b") {
		t.Fatalf("display control sequences reached diagnostics: %q, %v", data, err)
	}
}
