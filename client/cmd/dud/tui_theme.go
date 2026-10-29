// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"image/color"

	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
)

type tuiTheme struct {
	accent, muted color.Color
}

// Inherit the terminal foreground until it reports its background. Terminals
// that do not answer the color query retain their own text contrast.
func defaultTUITheme() tuiTheme {
	return tuiTheme{accent: lipgloss.NoColor{}, muted: lipgloss.NoColor{}}
}

func backgroundTUITheme(dark bool) tuiTheme {
	if dark {
		return tuiTheme{accent: lipgloss.Color("#8CB5D9"), muted: lipgloss.Color("#B8C2CE")}
	}
	return tuiTheme{accent: lipgloss.Color("#245780"), muted: lipgloss.Color("#4B5563")}
}

func (theme tuiTheme) accentStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(theme.accent)
}

func (theme tuiTheme) delegate() list.DefaultDelegate {
	delegate := list.NewDefaultDelegate()
	styles := &delegate.Styles
	styles.NormalTitle = styles.NormalTitle.Foreground(lipgloss.NoColor{})
	styles.NormalDesc = styles.NormalDesc.Foreground(theme.muted)
	styles.DimmedTitle = styles.DimmedTitle.Foreground(lipgloss.NoColor{})
	styles.DimmedDesc = styles.DimmedDesc.Foreground(theme.muted)
	styles.SelectedTitle = styles.SelectedTitle.Foreground(theme.accent).BorderForeground(theme.accent).Bold(true)
	styles.SelectedDesc = styles.SelectedDesc.Foreground(theme.accent).BorderForeground(theme.accent)
	return delegate
}

func (model *tuiModel) setTheme(theme tuiTheme) {
	model.theme = theme
	delegate := theme.delegate()
	if model.screen == tuiHome {
		delegate.ShowDescription = false
		delegate.SetSpacing(0)
	}
	model.menu.SetDelegate(delegate)
	styles := &model.menu.Styles
	styles.NoItems = styles.NoItems.Foreground(theme.muted)
	styles.ActivePaginationDot = styles.ActivePaginationDot.Foreground(theme.accent)
	styles.InactivePaginationDot = styles.InactivePaginationDot.Foreground(theme.muted)
	styles.ArabicPagination = styles.ArabicPagination.Foreground(theme.muted)
	model.bar.FullColor, model.bar.EmptyColor = theme.accent, theme.muted
	if model.form != nil {
		model.form.setTheme(theme)
	}
}

func (theme tuiTheme) inputStyles(styles textinput.Styles) textinput.Styles {
	for _, state := range []*textinput.StyleState{&styles.Focused, &styles.Blurred} {
		state.Text = lipgloss.NewStyle()
		state.Prompt = lipgloss.NewStyle()
		state.Placeholder = lipgloss.NewStyle().Foreground(theme.muted)
		state.Suggestion = state.Placeholder
	}
	styles.Focused.Prompt = theme.accentStyle()
	styles.Cursor.Color = lipgloss.NoColor{}
	return styles
}

func (theme tuiTheme) messageStyles(styles textarea.Styles) textarea.Styles {
	for _, state := range []*textarea.StyleState{&styles.Focused, &styles.Blurred} {
		state.Text = lipgloss.NewStyle()
		state.Prompt = lipgloss.NewStyle()
		state.CursorLine = lipgloss.NewStyle()
		state.Placeholder = lipgloss.NewStyle().Foreground(theme.muted)
		state.EndOfBuffer = state.Placeholder
		state.LineNumber = state.Placeholder
		state.CursorLineNumber = state.Placeholder
		state.Selection = lipgloss.NewStyle().Reverse(true)
	}
	styles.Focused.Prompt = theme.accentStyle()
	styles.Cursor.Color = lipgloss.NoColor{}
	return styles
}

func (form *tuiForm) setTheme(theme tuiTheme) {
	form.theme = theme
	for index := range form.fields {
		input := &form.fields[index].input
		if !form.fields[index].toggle {
			input.SetStyles(theme.inputStyles(input.Styles()))
		}
	}
	if form.hasMessage {
		form.message.SetStyles(theme.messageStyles(form.message.Styles()))
	}
}
