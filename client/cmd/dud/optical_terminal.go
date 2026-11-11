// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"os"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func (a *app) openOpticalTerminal(options display.Options) (display.Renderer, error) {
	if os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" {
		return nil, opticalFailure("renderer-unavailable", "Optical terminal renderer requires an ANSI-capable TERM; TERM is empty or dumb")
	}
	file, ok := a.errOut.(*os.File)
	if !ok || !isTerminal(file.Fd()) {
		return nil, opticalFailure("renderer-unavailable", "Optical terminal renderer requires a TTY display output")
	}
	restore, err := enableOpticalTerminal(file)
	if err != nil {
		return nil, opticalFailure("renderer-unavailable", "Optical terminal renderer cannot enable ANSI output")
	}
	renderer, err := display.OpenTerminal(file, options, func() (int, int, error) { return opticalTerminalSize(file) }, restore)
	if err != nil {
		_ = restore()
		return nil, opticalFailure("renderer-unavailable", "Optical terminal unavailable: "+err.Error())
	}
	return renderer, nil
}
