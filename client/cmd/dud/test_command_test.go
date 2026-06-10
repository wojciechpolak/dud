// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "testing"

func TestParseECHTrace(t *testing.T) {
	trace := "* noise\n* ECH: result: status is succeeded, inner is dud.example.com, outer is cloudflare-ech.com\n"

	status, inner, outer := parseECHTrace(trace)
	if status != "succeeded" || inner != "dud.example.com" || outer != "cloudflare-ech.com" {
		t.Fatalf("unexpected parse result: %q %q %q", status, inner, outer)
	}
}

func TestParseECHTraceReportsStatusOnlyLines(t *testing.T) {
	trace := "* noise\n* ECH: result: status is not attempted\n"

	status, inner, outer := parseECHTrace(trace)
	if status != "not attempted" || inner != "" || outer != "" {
		t.Fatalf("unexpected parse result: %q %q %q", status, inner, outer)
	}
}

func TestParseECHTraceUsesFirstStatusLine(t *testing.T) {
	trace := "* ECH: result: status is rejected\n" +
		"* ECH: result: status is succeeded, inner is dud.example.com, outer is cloudflare-ech.com\n"

	status, inner, outer := parseECHTrace(trace)
	if status != "rejected" || inner != "dud.example.com" || outer != "cloudflare-ech.com" {
		t.Fatalf("unexpected parse result: %q %q %q", status, inner, outer)
	}
}
