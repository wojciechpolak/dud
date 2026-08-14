// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestFlushRendersJSONTextPartialAndInvalidResponses(t *testing.T) {
	for _, test := range []struct {
		body string
		args []string
		want string
	}{
		{`{"ok":true,"deletedCount":2,"partial":false}`, nil, "Deleted"},
		{`{"ok":true,"deletedCount":2,"partial":true}`, nil, "run it again"},
		{`{"ok":true,"deletedCount":2,"partial":false}`, []string{"--json"}, `"deletedCount":2`},
		{`{"ok":true,"deletedCount":2,"partial":false}`, []string{"--url", "https://dud.example.com", "--doh-url", "https://dns.google/dns-query", "--json"}, `"deletedCount":2`},
		{"not JSON", nil, "not JSON"},
	} {
		var stdout bytes.Buffer
		a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
		a.cfg.BaseURL = "https://dud.example.com"
		a.cfg.DOHURL = "https://dns.google/dns-query"
		a.cfg.ECHMode = "off"
		a.cfg.SecretToken = "secret"
		a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
			return &v2CoverageResponseTransport{response: &v2Response{StatusCode: 200, Body: []byte(test.body)}}, nil
		}
		if err := a.cmdFlush(test.args); err != nil {
			t.Fatalf("flush %v: %v", test.args, err)
		}
		if !strings.Contains(stdout.String(), test.want) {
			t.Fatalf("flush output = %q, want %q", stdout.String(), test.want)
		}
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err := a.cmdFlush(nil); err == nil {
		t.Fatal("flush without secret accepted")
	}
	for _, args := range [][]string{{"--url"}, {"--doh-url"}, {"--json", "--json"}, {"--wat"}} {
		if err := a.cmdFlush(args); err == nil {
			t.Fatalf("flush options accepted: %v", args)
		}
	}
}
