// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func TestLocalCapabilitiesIgnoreNetworkAndProfileConfiguration(t *testing.T) {
	setTestV2Homes(t)
	t.Setenv("DUD_PEER_BASE_URL", "invalid")
	t.Setenv("DUD_DOH_URL", "invalid")
	t.Setenv("DUD_CONNECT_TO", "invalid")
	t.Setenv("DUD_PROFILE", "../invalid")
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		t.Fatal("local capabilities constructed a transport")
		return nil, nil
	}
	if code := a.main([]string{"capabilities", "--json", "--local"}); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report["optical_window_build"] != display.NativeWindow || report["http_dead_drop"] != true || report["peer"] != true || report["optical_recovery"] != true || report["optical"] != true {
		t.Fatalf("report = %#v", report)
	}
	if report["optical_kitty"] != opticalKittySupported {
		t.Fatalf("Kitty capability = %v", report["optical_kitty"])
	}
	stdout.Reset()
	if code := a.main([]string{"capabilities", "--local", "--url", "https://example.com"}); code != 1 || stdout.Len() != 0 {
		t.Fatalf("network options accepted: %d %s", code, stdout.String())
	}
}
