// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build nativewindow

package display

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// NativeWindow identifies builds that can start the sibling window renderer.
const NativeWindow = true

// OpenWindow starts a sibling renderer. Ebitengine initializes only in that
// process, so absent displays cannot prevent HTTP commands or CLI error reports.
func OpenWindow(ctx context.Context, directory string, options Options) (Renderer, error) {
	if runtime.GOOS == "linux" {
		value := os.Getenv("DISPLAY")
		if !strings.HasPrefix(value, ":") && !strings.HasPrefix(value, "unix:") {
			return nil, errors.New("optical window requires a local X11 display")
		}
	}
	name := "dud-optical-window"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return OpenWindowHelper(ctx, filepath.Join(directory, name), options)
}
