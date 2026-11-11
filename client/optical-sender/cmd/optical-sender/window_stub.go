// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build !nativewindow

package main

import (
	"errors"
	"io"

	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func runWindow(_ *optical.Encoder, _ *display.Scheduler, _ display.QRSettings, _ display.Frame, _, _ int, _ io.Writer) error {
	return errors.New("window renderer is unavailable; build this command with -tags nativewindow")
}
