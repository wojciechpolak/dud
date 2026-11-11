// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestOpticalTerminalCapabilityFailuresExplainEnvironmentBeforeReadingInput(t *testing.T) {
	for _, test := range []struct{ term, failure string }{
		{"", "TERM is empty or dumb"},
		{"dumb", "TERM is empty or dumb"},
		{"xterm-256color", "requires a TTY display output"},
	} {
		t.Run(test.term, func(t *testing.T) {
			t.Setenv("TERM", test.term)
			var output, diagnostics bytes.Buffer
			a := newApp(opticalUnreadableInput{t}, &output, &diagnostics)
			if code := a.main([]string{"optical", "send", "--optical-renderer", "terminal", "--json"}); code != 1 {
				t.Fatalf("exit code = %d", code)
			}
			failure := opticalJSON(t, &output)["error"].(map[string]any)
			if failure["code"] != "renderer-unavailable" || !strings.Contains(failure["message"].(string), test.failure) {
				t.Fatalf("missing terminal capability diagnostic: %+v", failure)
			}
		})
	}
}
