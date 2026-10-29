// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
)

type tuiField struct {
	key, label      string
	input           textinput.Model
	toggle, checked bool
}

type tuiForm struct {
	action     string
	fields     []tuiField
	message    textarea.Model
	hasMessage bool
	paths      []string
	focus      int
	err        string
	theme      tuiTheme
}

func newTUIForm(action string, deadDrop bool) *tuiForm {
	if isTUISetupAction(action) {
		return newTUISetupForm(action)
	}
	if isTUIUtilityAction(action) {
		return newTUIUtilityForm(action, deadDrop)
	}
	form := &tuiForm{action: action}
	add := form.addInput
	check := func(key, label string) {
		form.fields = append(form.fields, tuiField{key: key, label: label, toggle: true})
	}
	switch action {
	case "message", "files":
		if action == "message" {
			form.hasMessage = true
			form.message = textarea.New()
			form.message.Placeholder = "Type or paste a message"
			form.message.ShowLineNumbers = false
			form.message.CharLimit = 1 << 20
			form.message.SetHeight(4)
		} else {
			add("path", "File or directory (Ctrl+O browse, Ctrl+N add another)", "")
		}
		ttl := "168h"
		if deadDrop {
			ttl = "24h"
			add("recipient", "Age recipient (blank: age asks for a passphrase)", "")
		}
		add("ttl", "Lifetime", ttl)
		check("delete", "Delete after read")
	case "receive":
		if deadDrop {
			add("id", "Dead drop ID", "")
			add("out", "Output file, or directory when extracting an archive", "")
			add("identity", "Age identity file (blank: age asks for a passphrase)", "")
			check("extract", "Extract archive")
		} else {
			add("out", "Single output file (blank: automatic or directory output)", "")
			add("outdir", "Destination directory (blank: command default)", "")
			add("wait", "Wait for a delivery", "0s")
			add("max", "Maximum deliveries (0: drain queue)", "0")
			check("raw", "Keep collections as tar archives")
		}
	}
	form.setTheme(defaultTUITheme())
	return form
}

func (form *tuiForm) addInput(key, label, value string) {
	input := textinput.New()
	input.Prompt = "> "
	input.CharLimit = 4096
	input.SetValue(value)
	form.fields = append(form.fields, tuiField{key: key, label: label, input: input})
}

func (form *tuiForm) count() int {
	count := len(form.fields)
	if form.hasMessage {
		count++
	}
	return count
}

func (form *tuiForm) activeField() *tuiField {
	index := form.focus
	if form.hasMessage {
		index--
	}
	if index < 0 || index >= len(form.fields) {
		return nil
	}
	return &form.fields[index]
}

func (form *tuiForm) focusInput() tea.Cmd {
	form.message.Blur()
	for index := range form.fields {
		form.fields[index].input.Blur()
	}
	if form.hasMessage && form.focus == 0 {
		return form.message.Focus()
	}
	if field := form.activeField(); field != nil && !field.toggle {
		return field.input.Focus()
	}
	return nil
}

func (form *tuiForm) resize(width int) {
	if form.hasMessage {
		form.message.SetWidth(width)
	}
	for index := range form.fields {
		form.fields[index].input.SetWidth(max(1, width-2))
	}
}

func (form *tuiForm) value(key string) string {
	for _, field := range form.fields {
		if field.key == key {
			return field.input.Value()
		}
	}
	return ""
}

func (form *tuiForm) checked(key string) bool {
	for _, field := range form.fields {
		if field.key == key {
			return field.checked
		}
	}
	return false
}

func (form *tuiForm) addPath(path string) error {
	if path == "" {
		return errors.New("Choose a file or directory.")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return errors.New("Choose a regular file or directory.")
	}
	for _, previous := range form.paths {
		if previous == path {
			return nil
		}
	}
	form.paths = append(form.paths, path)
	for index := range form.fields {
		if form.fields[index].key == "path" {
			form.fields[index].input.SetValue("")
		}
	}
	return nil
}

func (form *tuiForm) arguments(target tuiItem, cfg config) ([]string, error) {
	if isTUISetupAction(form.action) {
		return form.setupArguments()
	}
	if isTUIUtilityAction(form.action) {
		return form.utilityArguments(target, cfg)
	}
	if form.action == "receive" {
		if target.deadDrop {
			args := []string{"download", "--id", form.value("id")}
			if form.checked("extract") {
				args = append(args, "--extract", "--out-dir", form.value("out"))
			} else {
				args = append(args, "--out", form.value("out"))
			}
			if identity := form.value("identity"); identity != "" {
				args = append(args, "--identity", identity)
			}
			opts, err := parseDownloadOptions(args[1:], cfg.DropBaseURL, cfg.DOHURL)
			if err != nil {
				return nil, err
			}
			return args, validateDownloadOptions(opts)
		}
		args := []string{"receive", target.id, "--interactive", "--wait", form.value("wait")}
		if output := form.value("out"); output != "" {
			args = append(args, "--out", output)
		}
		if limit := form.value("max"); limit != "0" && limit != "" {
			args = append(args, "--max", limit)
		}
		if destination := form.value("outdir"); destination != "" {
			args = append(args, "--out-dir", destination)
		}
		if form.checked("raw") {
			args = append(args, "--no-extract")
		}
		_, err := parseV2PeerReceiveOptions(args[1:])
		return args, err
	}
	args := []string{"send", target.id}
	if target.deadDrop {
		args = []string{"upload"}
	}
	if form.hasMessage {
		if form.message.Value() == "" {
			return nil, errors.New("Enter a message.")
		}
		args = append(args, "-m", form.message.Value())
	} else {
		paths := append([]string(nil), form.paths...)
		if path := form.value("path"); path != "" {
			paths = append(paths, path)
		}
		if len(paths) == 0 {
			return nil, errors.New("Choose at least one file or directory.")
		}
		for _, path := range paths {
			args = append(args, "--file", path)
		}
	}
	args = append(args, "--ttl", form.value("ttl"))
	if form.checked("delete") {
		args = append(args, "--delete-after-read")
	}
	if target.deadDrop {
		if recipient := form.value("recipient"); recipient != "" {
			args = append(args, "--recipient", recipient)
		} else {
			args = append(args, "--passphrase")
		}
		opts, err := parseUploadOptions(args[1:], cfg.DropBaseURL, cfg.DOHURL)
		if err != nil {
			return nil, err
		}
		return args, validateUploadOptions(opts, cfg)
	}
	_, err := parseV2PeerSendOptions(args[1:])
	return args, err
}

func (form *tuiForm) View(width, height int) string {
	var body strings.Builder
	focusLine, focusEnd := 0, 0
	row := func(index int, content string) {
		start := strings.Count(body.String(), "\n")
		body.WriteString(content + "\n\n")
		if form.focus == index {
			focusLine, focusEnd = start, strings.Count(body.String(), "\n")
		}
	}
	offset := 0
	if form.hasMessage {
		message := form.message
		message.SetWidth(width)
		row(0, "Message\n"+message.View())
		offset = 1
	}
	for index, field := range form.fields {
		label := field.label
		if form.focus == index+offset {
			label = form.theme.accentStyle().Render(label)
		}
		if field.toggle {
			mark := "[ ] "
			if field.checked {
				mark = "[x] "
			}
			row(index+offset, mark+label)
		} else {
			input := field.input
			input.SetWidth(max(1, width-2))
			row(index+offset, label+"\n"+input.View())
			if field.key == "path" && len(form.paths) > 0 {
				fmt.Fprintf(&body, "%d selected (Ctrl+D removes the last):\n", len(form.paths))
				for _, path := range form.paths[max(0, len(form.paths)-3):] {
					body.WriteString("  " + safeTerminalText(path) + "\n")
				}
				body.WriteByte('\n')
			}
		}
	}
	button := "[ " + form.submitLabel() + " ]"
	if form.focus == form.count() {
		button = form.theme.accentStyle().Render(button)
	}
	row(form.count(), button)
	view := viewport.New(viewport.WithWidth(width), viewport.WithHeight(height))
	view.SetContent(body.String())
	view.SetYOffset(max(0, min(focusLine, focusEnd-height)))
	return view.View()
}
