// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build !nativewindow

package display

import (
	"context"
	"errors"
)

// NativeWindow identifies builds that can start the sibling window renderer.
const NativeWindow = false

func OpenWindow(_ context.Context, _ string, _ Options) (Renderer, error) {
	return nil, errors.New("window renderer requires a nativewindow build and its local window helper")
}
