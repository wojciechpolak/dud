// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"image/color"
	"io"
	"math"
	"strings"
	"testing"

	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func tuiTestLuminance(value color.Color) float64 {
	r, g, b, _ := value.RGBA()
	linear := func(channel uint32) float64 {
		v := float64(channel) / 65535
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*linear(r) + 0.7152*linear(g) + 0.0722*linear(b)
}

func tuiTestContrast(foreground, background color.Color) float64 {
	first, second := tuiTestLuminance(foreground), tuiTestLuminance(background)
	return (max(first, second) + 0.05) / (min(first, second) + 0.05)
}

func TestTUIUnansweredBackgroundQueryInheritsTerminalText(t *testing.T) {
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.Update(tuiTargetsMsg{items: []list.Item{
		tuiItem{id: "laptop", title: "laptop", description: "Peer device", active: true},
		tuiItem{title: "Dead drop", description: "Share by ID", deadDrop: true, active: true},
	}})
	if text := model.View().Content; strings.Contains(text, "\x1b[38;") || strings.Contains(text, "\x1b[48;") {
		t.Fatalf("an unanswered background query imposes colors: %q", text)
	}
	model.Update(tuiTestKey(tea.KeyEnter))
	model.Update(tuiTestKey(tea.KeyEnter))
	if text := model.View().Content; strings.Contains(text, "\x1b[38;") || strings.Contains(text, "\x1b[48;") {
		t.Fatalf("form imposes colors before the terminal background is known: %q", text)
	}
}

func TestTUIThemeKeepsDescriptionsAndPromptsReadableOnBothBackgrounds(t *testing.T) {
	for _, background := range []color.Color{color.White, color.RGBA{R: 20, G: 20, B: 20, A: 255}} {
		t.Run(tea.BackgroundColorMsg{Color: background}.String(), func(t *testing.T) {
			model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
			model.form = newTUIForm("message", true)
			model.Update(tea.BackgroundColorMsg{Color: background})
			delegate := model.theme.delegate()
			fields := map[string]color.Color{
				"description":          delegate.Styles.NormalDesc.GetForeground(),
				"selected title":       delegate.Styles.SelectedTitle.GetForeground(),
				"selected description": delegate.Styles.SelectedDesc.GetForeground(),
				"pagination":           model.menu.Styles.InactivePaginationDot.GetForeground(),
				"field placeholder":    model.form.fields[0].input.Styles().Focused.Placeholder.GetForeground(),
				"message placeholder":  model.form.message.Styles().Focused.Placeholder.GetForeground(),
				"progress":             model.bar.FullColor,
			}
			for name, foreground := range fields {
				if contrast := tuiTestContrast(foreground, background); contrast < 4.5 {
					t.Errorf("%s contrast=%.2f", name, contrast)
				}
			}
			for name, value := range map[string]color.Color{
				"title":              delegate.Styles.NormalTitle.GetForeground(),
				"field text":         model.form.fields[0].input.Styles().Blurred.Text.GetForeground(),
				"message text":       model.form.message.Styles().Blurred.Text.GetForeground(),
				"message background": model.form.message.Styles().Focused.CursorLine.GetBackground(),
			} {
				if _, ok := value.(lipgloss.NoColor); !ok {
					t.Errorf("%s overrides terminal defaults: %v", name, value)
				}
			}
		})
	}
}

func TestTUIBackgroundRepliesPreserveFormContentsFocusAndSelection(t *testing.T) {
	model := newTUIModel(newApp(strings.NewReader(""), io.Discard, io.Discard))
	model.target = tuiItem{id: "laptop", title: "laptop", active: true}
	model.showActions()
	model.selectAction()
	model.form.message.SetValue("Keep this message\nSecond line")
	setTUITestValue(model.form, "ttl", "12h")
	model.form.focus = 1
	model.form.focusInput()
	for _, background := range []color.Color{color.White, color.Black, color.White} {
		model.Update(tea.BackgroundColorMsg{Color: background})
		if model.form.message.Value() != "Keep this message\nSecond line" || model.form.value("ttl") != "12h" || model.form.focus != 1 || model.screen != tuiEditing || model.menu.Index() != 0 {
			t.Fatal("background reply changed editing state")
		}
	}
	model.showActions()
	model.menu.Select(1)
	model.selectAction()
	styles := model.form.fields[0].input.Styles()
	if got := tuiTestContrast(styles.Focused.Placeholder.GetForeground(), color.White); got < 4.5 {
		t.Fatalf("new form did not inherit the detected theme: contrast %.2f", got)
	}
}
