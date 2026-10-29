// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
)

type tuiQRCode struct {
	text          string
	width, height int
}

func (a *app) tuiQRCode(payload string) tuiQRCode {
	ctx, cancel := context.WithTimeout(a.commandContext(), 5*time.Second)
	defer cancel()
	// UTF8i paints modules with the terminal foreground and leaves the quiet
	// zone in its background. Stdin keeps invitation codes out of process args.
	command := exec.CommandContext(ctx, a.cfg.QREncodeBin, "-t", "UTF8i", "-m", "4")
	command.Stdin = strings.NewReader(payload)
	output := &tuiOutput{}
	command.Stdout, command.Stderr = output, io.Discard
	if err := command.Run(); err != nil {
		return tuiQRCode{}
	}
	text, _ := output.snapshot()
	return parseTUIQRCode(text)
}

// Accept only a complete QR rectangle with a four-module quiet zone. External
// encoder output never supplies terminal escapes to the TUI renderer.
func parseTUIQRCode(text string) tuiQRCode {
	text = strings.TrimSuffix(text, "\n")
	lines := strings.Split(text, "\n")
	width := utf8.RuneCountInString(lines[0])
	if width < 29 || width > 185 || (width-29)%4 != 0 || len(lines) != (width+1)/2 || !strings.ContainsAny(text, "█▀▄") {
		return tuiQRCode{}
	}
	blank := strings.Repeat(" ", width)
	for index, line := range lines {
		if utf8.RuneCountInString(line) != width || !strings.HasPrefix(line, "    ") || !strings.HasSuffix(line, "    ") {
			return tuiQRCode{}
		}
		if (index < 2 || index >= len(lines)-2) && line != blank {
			return tuiQRCode{}
		}
		for _, cell := range line {
			if cell != ' ' && cell != '█' && cell != '▀' && cell != '▄' {
				return tuiQRCode{}
			}
		}
	}
	return tuiQRCode{text: text, width: width, height: len(lines)}
}

func (model *tuiModel) qrBesideDetails() bool {
	return model.qr != nil && model.qr.width > 0 && model.width-4 >= model.qr.width+2+32 && model.height-7 >= model.qr.height
}

func (model *tuiModel) withQRCode(details string) string {
	if model.qr == nil {
		return details
	}
	qr := model.qr
	if qr.width == 0 {
		return details + "\n\nQR unavailable; use the text code."
	}
	if model.qrOnly {
		if model.width-4 >= qr.width && model.height-5 >= qr.height {
			return qr.text
		}
		return fmt.Sprintf("QR needs %d × %d.\nPress v for the text code.", max(48, qr.width+4), max(16, qr.height+5))
	}
	if model.qrBesideDetails() {
		left := lipgloss.NewStyle().Width(model.width - 4 - qr.width - 2).MaxHeight(model.height - 7).Render(details)
		return lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", qr.text)
	}
	if qr.width <= model.width-4 && lipgloss.Height(details)+1+qr.height <= model.height-7 {
		return details + "\n\n" + qr.text
	}
	return details + fmt.Sprintf("\n\nQR: v to open · inline needs %d × %d.", qr.width+38, qr.height+7)
}

func (model *tuiModel) qrFooter(footer string) string {
	if model.qr == nil || model.qr.width == 0 {
		return footer
	}
	if model.qrOnly {
		if model.busy {
			return "v details · Esc cancel · Ctrl+C cancel and quit"
		}
		return "v details · Enter/Esc/← back · q quit"
	}
	return "v QR · " + footer
}
