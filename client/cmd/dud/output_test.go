// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"strings"
	"testing"
)

func TestTextReportAlignsLabelsWithinEachSection(t *testing.T) {
	report := &textReport{}
	header := report.section("")
	header.add("Device", "laptop")
	local := report.section("Local state")
	local.add("peers", "1")
	local.add("schema", "v3")
	tools := report.section("Tools")
	tools.add("age", "ok")
	tools.add("age-keygen", "ok")

	want := strings.Join([]string{
		"Device  laptop",
		"",
		"Local state",
		"  peers   1",
		"  schema  v3",
		"",
		"Tools",
		"  age         ok",
		"  age-keygen  ok",
		"",
	}, "\n")
	if got := report.String(); got != want {
		t.Fatalf("report =\n%q\nwant\n%q", got, want)
	}
}

func TestTextReportAlignsNoteColumn(t *testing.T) {
	report := &textReport{}
	origin := report.section("Origin: global")
	origin.addNote("url", "https://dud.example.com", "environment")
	origin.addNote("doh", "https://dns.google/dns-query", "config")
	origin.add("transport", "ok (HTTP 200)")

	want := strings.Join([]string{
		"Origin: global",
		"  url        https://dud.example.com       (environment)",
		"  doh        https://dns.google/dns-query  (config)",
		"  transport  ok (HTTP 200)",
		"",
	}, "\n")
	if got := report.String(); got != want {
		t.Fatalf("report =\n%q\nwant\n%q", got, want)
	}
}

func TestTextReportRendersListItemsUnderTheirRow(t *testing.T) {
	report := &textReport{}
	local := report.section("Local state")
	local.add("peers", "0")
	local.addList("issues", "2", []string{"state directory is world-accessible", "schema is stale"})

	want := strings.Join([]string{
		"Local state",
		"  peers   0",
		"  issues  2",
		"          - state directory is world-accessible",
		"          - schema is stale",
		"",
	}, "\n")
	if got := report.String(); got != want {
		t.Fatalf("report =\n%q\nwant\n%q", got, want)
	}
}

func TestTextReportNestsChildSections(t *testing.T) {
	report := &textReport{}
	origin := report.section("Origin: peer desktop")
	origin.add("transport", "ok (HTTP 200)")
	delivery := origin.child("Delivery")
	delivery.add("queued deliveries", "0")
	delivery.add("halted", "no")

	want := strings.Join([]string{
		"Origin: peer desktop",
		"  transport  ok (HTTP 200)",
		"",
		"  Delivery",
		"    queued deliveries  0",
		"    halted             no",
		"",
	}, "\n")
	if got := report.String(); got != want {
		t.Fatalf("report =\n%q\nwant\n%q", got, want)
	}
}

func TestTextReportWrapsNotesAtAFixedWidth(t *testing.T) {
	report := &textReport{}
	origin := report.section("Origin: global")
	origin.add("doh", "https://doh.example.net/dns-query")
	origin.note("Note: the system resolver sees the distinctive DoH hostname " +
		"\"doh.example.net\"; configure pinned bootstrap addresses to avoid that lookup.")

	lines := strings.Split(strings.TrimRight(report.String(), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected a wrapped note, got %q", report.String())
	}
	for _, line := range lines[2:] {
		if len(line) > textNoteWidth {
			t.Fatalf("note line exceeds %d columns: %q", textNoteWidth, line)
		}
		if !strings.HasPrefix(line, "  ") {
			t.Fatalf("note line is not indented with its section: %q", line)
		}
	}
	joined := strings.Join(lines[2:], " ")
	if !strings.Contains(joined, "pinned bootstrap addresses") {
		t.Fatalf("note text was mangled: %q", joined)
	}
}

func TestWrapTextKeepsLongWordsIntact(t *testing.T) {
	long := "https://a-very-long-hostname.example.com/dns-query-endpoint-that-is-long"
	lines := wrapText("resolver "+long+" end", 40)
	found := false
	for _, line := range lines {
		if line == long {
			found = true
		}
	}
	if !found {
		t.Fatalf("long word was split across lines: %#v", lines)
	}
}

func TestTextReportSkipsEmptySections(t *testing.T) {
	report := &textReport{}
	report.section("")
	filled := report.section("Tools")
	filled.add("git", "ok")
	report.section("Origins")

	want := "Tools\n  git  ok\n"
	if got := report.String(); got != want {
		t.Fatalf("report = %q, want %q", got, want)
	}
}

func TestParseJSONOptionRejectsRepeats(t *testing.T) {
	jsonOutput := false
	matched, rest, err := parseJSONOption([]string{"--json", "--json"}, &jsonOutput)
	if err != nil || !matched || !jsonOutput || len(rest) != 1 {
		t.Fatalf("first --json: matched=%v rest=%v err=%v", matched, rest, err)
	}
	if _, _, err := parseJSONOption(rest, &jsonOutput); err == nil {
		t.Fatal("repeated --json was accepted")
	}
	other := false
	matched, rest, err = parseJSONOption([]string{"--url", "x"}, &other)
	if err != nil || matched || len(rest) != 2 || other {
		t.Fatalf("unrelated option: matched=%v rest=%v err=%v", matched, rest, err)
	}
}

func TestOnlyJSONOptionRejectsUnknownOptions(t *testing.T) {
	value, err := onlyJSONOption([]string{"--json"})
	if err != nil || !value {
		t.Fatalf("onlyJSONOption = %v, %v", value, err)
	}
	if _, err := onlyJSONOption([]string{"--verbose"}); err == nil {
		t.Fatal("unknown option was accepted")
	}
	if _, err := onlyJSONOption([]string{"--json", "--json"}); err == nil {
		t.Fatal("repeated --json was accepted")
	}
}

func TestJoinValuesRendersListsWithoutGoSyntax(t *testing.T) {
	if got := joinValues([]string{"a", "b"}); got != "a, b" {
		t.Fatalf("joinValues = %q", got)
	}
	if got := joinValues([]uint64{}); got != "none" {
		t.Fatalf("empty joinValues = %q", got)
	}
}

func TestSafeTerminalTextEscapesControlAndFormatRunes(t *testing.T) {
	if got := safeTerminalText("report.txt"); got != "report.txt" {
		t.Fatalf("safe text = %q", got)
	}
	for _, value := range []string{"bad\x1b]0;title\a", "bad\rname", "bad\u202ename"} {
		got := safeTerminalText(value)
		if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\r') || strings.ContainsRune(got, '\u202e') {
			t.Fatalf("unsafe terminal text %q", got)
		}
	}
}
