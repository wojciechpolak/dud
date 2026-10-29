// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"
)

const tuiOutputLimit = 128 * 1024

// tuiOutput bounds retained command output and coalesces progress so file reads
// never wait for terminal redraws. Only the UI goroutine owns Bubble Tea models.
type tuiOutput struct {
	mu        sync.Mutex
	text      string
	truncated bool
	progress  v2ProgressSnapshot
}

func (output *tuiOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if len(data) >= tuiOutputLimit {
		output.text = string(data[len(data)-tuiOutputLimit:])
		output.truncated = true
	} else {
		output.text += string(data)
		if len(output.text) > tuiOutputLimit {
			output.text = output.text[len(output.text)-tuiOutputLimit:]
			output.truncated = true
		}
	}
	return len(data), nil
}

func (output *tuiOutput) observe(snapshot v2ProgressSnapshot) {
	output.mu.Lock()
	defer output.mu.Unlock()
	output.progress = snapshot
}

func (output *tuiOutput) snapshot() (string, v2ProgressSnapshot) {
	output.mu.Lock()
	defer output.mu.Unlock()
	content := tuiSafeLines(output.text)
	if output.truncated {
		content = "[Earlier output omitted]\n" + content
	}
	return content, output.progress
}

// Command output can contain payloads and server-supplied text. Preserve line
// breaks while escaping terminal controls, including OSC hyperlinks and bidi.
func tuiSafeLines(value string) string {
	lines := strings.Split(strings.ToValidUTF8(value, "�"), "\n")
	for index := range lines {
		lines[index] = safeTerminalText(lines[index])
	}
	return strings.Join(lines, "\n")
}

type tuiDoneMsg struct{ err error }
type tuiPairingCodeMsg struct {
	display v2PairingCodeDisplay
	qr      tuiQRCode
}
type tuiQRCodeMsg struct{ qr tuiQRCode }
type tuiConfirmMsg struct {
	preview string
	answer  chan bool
}
type tuiTerminalMsg struct {
	command *exec.Cmd
	answer  chan error
	// Pending requests may be cancelled before age starts. A running age must
	// exit before the worker removes the files it is encrypting or decrypting.
	state atomic.Int32
}

const (
	tuiTerminalPending int32 = iota
	tuiTerminalRunning
	tuiTerminalCancelled
)

type tuiOperation struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	events chan tea.Msg
	output *tuiOutput
}

func startTUIOperation(parent *app, args []string) *tuiOperation {
	return startTUIOperationWithInput(parent, args, tuiSetupInput{})
}

// tuiSetupInput keeps interactive credentials out of command arguments and logs.
type tuiSetupInput struct {
	pairingCode      string
	enrollmentSecret string
}

func startTUIOperationWithInput(parent *app, args []string, input tuiSetupInput) *tuiOperation {
	ctx, cancel := context.WithCancel(parent.commandContext())
	operation := &tuiOperation{
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		events: make(chan tea.Msg, 2), output: &tuiOutput{},
	}
	worker := *parent
	worker.commandCtx = ctx
	worker.in = strings.NewReader("")
	worker.out, worker.errOut = operation.output, operation.output
	worker.observeProgress = operation.output.observe
	worker.confirmCollection = operation.confirmCollection
	worker.terminalCommand = operation.terminalCommand
	worker.readPairingCode = func() (string, error) {
		if input.pairingCode == "" {
			return "", errors.New("Enter the pairing code to accept a new invitation.")
		}
		return input.pairingCode, nil
	}
	worker.showPairingCode = func(display v2PairingCodeDisplay) error {
		qr := worker.tuiQRCode(display.Code)
		select {
		case operation.events <- tuiPairingCodeMsg{display, qr}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	worker.showQRCode = func(payload string) error {
		qr := worker.tuiQRCode(payload)
		select {
		case operation.events <- tuiQRCodeMsg{qr}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if input.enrollmentSecret != "" {
		worker.cfg.V2Secret = input.enrollmentSecret
	}
	go func() {
		defer close(operation.done)
		operation.events <- tuiDoneMsg{worker.run(args)}
	}()
	return operation
}

func (operation *tuiOperation) nextEvent() tea.Msg {
	return <-operation.events
}

func (operation *tuiOperation) confirmCollection(entries []v2CollectionEntry) bool {
	var preview strings.Builder
	preview.WriteString("Verified collection contents:\n")
	for index, entry := range entries {
		name := safeTerminalText(entry.name)
		if preview.Len()+len(name)+64 > tuiOutputLimit {
			fmt.Fprintf(&preview, "\n%d further entries omitted. Receive with --no-extract to inspect the full archive.\n", len(entries)-index)
			break
		}
		preview.WriteString("  " + name)
		if entry.dir {
			preview.WriteString("/")
		} else {
			fmt.Fprintf(&preview, " (%d bytes)", entry.size)
		}
		preview.WriteByte('\n')
	}
	request := tuiConfirmMsg{preview.String(), make(chan bool, 1)}
	select {
	case operation.events <- request:
	case <-operation.ctx.Done():
		return false
	}
	select {
	case answer := <-request.answer:
		return answer && operation.ctx.Err() == nil
	case <-operation.ctx.Done():
		return false
	}
}

func (operation *tuiOperation) terminalCommand(command *exec.Cmd) error {
	request := &tuiTerminalMsg{command: command, answer: make(chan error, 1)}
	select {
	case operation.events <- request:
	case <-operation.ctx.Done():
		return operation.ctx.Err()
	}
	select {
	case err := <-request.answer:
		return err
	case <-operation.ctx.Done():
		if !request.state.CompareAndSwap(tuiTerminalPending, tuiTerminalCancelled) {
			<-request.answer
		}
		return operation.ctx.Err()
	}
}

// tuiTerminalCommand captures diagnostics while Bubble Tea lends the terminal
// to age, whose passphrase prompt reads the controlling terminal directly.
type tuiTerminalCommand struct {
	request *tuiTerminalMsg
	output  io.Writer
}

func (command tuiTerminalCommand) Run() error {
	if !command.request.state.CompareAndSwap(tuiTerminalPending, tuiTerminalRunning) {
		return context.Canceled
	}
	return command.request.command.Run()
}
func (command tuiTerminalCommand) SetStdin(reader io.Reader) { command.request.command.Stdin = reader }
func (command tuiTerminalCommand) SetStdout(writer io.Writer) {
	command.request.command.Stdout = io.MultiWriter(writer, command.output)
}
func (command tuiTerminalCommand) SetStderr(writer io.Writer) {
	command.request.command.Stderr = io.MultiWriter(writer, command.output)
}
