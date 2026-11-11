// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

const opticalKittySupported = false

func (a *app) openOpticalKitty(_ context.Context, _ display.Options) (display.Renderer, error) {
	return nil, opticalFailure("renderer-unavailable", "Kitty optical display requires a Linux or macOS terminal; select terminal for ANSI display")
}
