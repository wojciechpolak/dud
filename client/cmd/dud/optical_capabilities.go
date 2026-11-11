// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"fmt"
	"runtime"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func (a *app) cmdLocalCapabilities(args []string) error {
	jsonOutput := false
	for _, argument := range args {
		switch argument {
		case "--local":
		case "--json":
			jsonOutput = true
		default:
			return fatalError("Unknown local capabilities option: " + argument)
		}
	}
	variant := "headless"
	if display.NativeWindow {
		variant = "desktop"
	}
	report := map[string]any{
		"version": version, "platform": runtime.GOOS, "architecture": runtime.GOARCH,
		"variant": variant, "http_dead_drop": true, "peer": true, "optical": true,
		"optical_terminal": true, "optical_window_build": display.NativeWindow,
		"optical_kitty":    opticalKittySupported,
		"optical_recovery": true,
	}
	if jsonOutput {
		return writeJSON(a.out, report)
	}
	fmt.Fprintf(a.out, "DUD %s %s/%s, %s\nHTTP dead drops and peer transfers: supported\nOptical transfer terminal and recovery: supported\nOptical transfer Kitty build: %t, requires a compatible terminal and pixel-size replies\nOptical transfer window build: %t, requires its sibling helper and a graphical session\n", version, runtime.GOOS, runtime.GOARCH, variant, opticalKittySupported, display.NativeWindow)
	return nil
}
