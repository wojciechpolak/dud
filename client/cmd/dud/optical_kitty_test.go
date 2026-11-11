// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestOpticalKittyRejectsUnavailableTerminalBeforeReadingInput(t *testing.T) {
	var output, diagnostics bytes.Buffer
	a := newApp(opticalUnreadableInput{t}, &output, &diagnostics)
	if code := a.main([]string{"upload", "--optical", "--optical-renderer", "kitty", "--json"}); code != 1 {
		t.Fatalf("code=%d", code)
	}
	report := opticalJSON(t, &output)
	failure := report["error"].(map[string]any)
	if failure["code"] != "renderer-unavailable" || !strings.Contains(failure["message"].(string), "Kitty") {
		t.Fatalf("missing Kitty capability error: %#v", failure)
	}
}

func TestOpticalKittySelectionPreservesProfileAndReportsRenderer(t *testing.T) {
	a, renderer, output, _ := newOpticalTestApp(t, "")
	if err := a.run([]string{"send", "--optical", "--optical-renderer", "kitty", "--optical-profile", "balanced", "-m", "message", "--json"}); err != nil {
		t.Fatal(err)
	}
	report := opticalJSON(t, output)
	if report["renderer"] != "kitty" || report["profile"] != "balanced" || renderer.options.Settings.Scale != 2 || renderer.options.FPS != 30 || !renderer.closed {
		t.Fatal("Kitty selection changed optical profile, scale, reporting or cleanup", report)
	}
}
