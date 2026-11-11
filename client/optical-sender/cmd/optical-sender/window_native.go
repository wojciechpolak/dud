// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build nativewindow

package main

import (
	"io"

	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
	"github.com/wojciechpolak/dud/client/optical-sender/display/window"
)

func runWindow(encoder *optical.Encoder, scheduler *display.Scheduler, settings display.QRSettings, first display.Frame, symbols, fps int, output io.Writer) error {
	return window.RunWindow(encoder, scheduler, settings, first, symbols, fps, output)
}
