// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func (form *tuiForm) addChoice(key, label string, choices ...string) {
	form.addInput(key, label, choices[0])
	form.fields[len(form.fields)-1].choices = choices
}

func (field *tuiField) cycleChoice(backward bool) {
	index := slices.Index(field.choices, field.input.Value())
	step := 1
	if backward {
		step = -1
	}
	field.input.SetValue(field.choices[(index+step+len(field.choices))%len(field.choices)])
}

func newTUIOpticalForm(action string) *tuiForm {
	if action == "optical-recover" {
		form := &tuiForm{action: action}
		form.addInput("path", "Encrypted capsule transferred from the camera receiver (Ctrl+O browse)", "")
		form.addInput("out", "Output file, or destination directory when extracting", "")
		form.addInput("identity", "Age identity file (blank: age asks for a passphrase)", "")
		form.fields = append(form.fields, tuiField{key: "extract", label: "Extract a collection", toggle: true})
		form.setTheme(defaultTUITheme())
		return form
	}
	form := newTUIForm(strings.TrimPrefix(action, "optical-"), true)
	form.action = action
	fields := form.fields[:0]
	for _, field := range form.fields {
		if field.key == "path" || field.key == "recipient" {
			fields = append(fields, field)
		}
	}
	form.fields = fields
	renderers := []string{"terminal"}
	if opticalKittySupported {
		renderers = []string{"kitty", "terminal"}
	}
	if display.NativeWindow {
		renderers = append(renderers, "window")
	}
	form.addChoice("renderer", "Display renderer", renderers...)
	form.addChoice("profile", "QR profile", "balanced", "high-rate")
	return form
}

func (form *tuiForm) opticalArguments() ([]string, error) {
	paths := append([]string(nil), form.paths...)
	if path := form.value("path"); path != "" {
		paths = append(paths, path)
	}
	if form.action == "optical-recover" {
		return form.opticalRecoveryArguments(paths)
	}
	args := []string{"optical", "send", "--optical-renderer", form.value("renderer"), "--optical-profile", form.value("profile")}
	if form.value("renderer") == "terminal" {
		args = append(args, "--optical-scale", "1")
	}
	if form.hasMessage {
		if form.message.Value() == "" {
			return nil, errors.New("Enter a message.")
		}
		args = append(args, "-m", form.message.Value())
	} else {
		if len(paths) == 0 {
			return nil, errors.New("Choose at least one file or directory.")
		}
		for _, path := range paths {
			args = append(args, "--file", path)
		}
	}
	if recipient := form.value("recipient"); recipient != "" {
		args = append(args, "--recipient", recipient)
	} else {
		args = append(args, "--passphrase")
	}
	opts, err := parseUploadOptions(append([]string{"--optical"}, args[2:]...), "", "")
	if err != nil {
		return nil, err
	}
	return args, validateOpticalUploadOptions(opts)
}

func (form *tuiForm) opticalRecoveryArguments(paths []string) ([]string, error) {
	if len(paths) != 1 {
		return nil, errors.New("Choose one saved optical capsule.")
	}
	args := []string{"optical", "decrypt", "--file", paths[0]}
	if form.checked("extract") {
		args = append(args, "--extract")
		if output := form.value("out"); output != "" {
			args = append(args, "--out-dir", output)
		}
	} else {
		args = append(args, "--out", form.value("out"))
	}
	if identity := form.value("identity"); identity != "" {
		args = append(args, "--identity", identity)
	}
	opts, err := parseDownloadOptions(args[2:], "", "")
	if err != nil {
		return nil, err
	}
	return args, validateOpticalDecryptOptions(opts)
}

// The complete optical operation owns the terminal, including display preflight
// and age prompts. Plaintext stays in memory rather than subprocess arguments.
func (operation *tuiOperation) runOptical(worker *app, args []string) error {
	request := &tuiTerminalMsg{answer: make(chan error, 1)}
	request.run = func(input io.Reader, output io.Writer, diagnostic io.Writer) error {
		worker.in, worker.errOut = input, diagnostic
		worker.terminalCommand = nil
		if args[1] == "send" && worker.newOpticalRenderer == nil {
			opts, err := parseUploadOptions(append([]string{"--optical"}, args[2:]...), "", "")
			if err != nil {
				return err
			}
			// Bubble Tea's output owns the display; stderr can be redirected.
			displayApp := *worker
			displayApp.errOut = output
			worker.newOpticalRenderer = func(ctx context.Context, options display.Options) (display.Renderer, error) {
				return displayApp.openOpticalRenderer(ctx, opts.opticalRenderer, options)
			}
		}
		return worker.run(args)
	}
	return operation.requestTerminal(request)
}
