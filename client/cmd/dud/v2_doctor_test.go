// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runDoctorJSON(t *testing.T, args ...string) (map[string]any, int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &stubV2Transport{}, nil
	}
	code := a.main(append([]string{"doctor", "--json"}, args...))
	report := map[string]any{}
	if stdout.Len() != 0 {
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("doctor JSON is invalid: %v\n%s", err, stdout.String())
		}
	}
	return report, code, stdout.String()
}

// walkStrings collects every string in a decoded JSON document, so a redaction
// check covers values the report gains later without being updated.
func walkStrings(value any, into *[]string) {
	switch typed := value.(type) {
	case string:
		*into = append(*into, typed)
	case []any:
		for _, item := range typed {
			walkStrings(item, into)
		}
	case map[string]any:
		for _, item := range typed {
			walkStrings(item, into)
		}
	}
}

func TestDoctorReportsLocalStateAndToolDiagnostics(t *testing.T) {
	setTestV2Homes(t)
	if _, _, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers["laptop"] = v2PeerProfile{Status: "unpaired", GitRemote: "laptop"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	report, code, raw := runDoctorJSON(t)
	if code != 0 {
		t.Fatalf("doctor code = %d: %s", code, raw)
	}
	local, ok := report["local"].(map[string]any)
	if !ok {
		t.Fatalf("doctor report has no local section: %s", raw)
	}
	if local["ok"] != true || local["peers"] != float64(1) ||
		local["schema_version"] != float64(v2ConfigSchemaVersion) {
		t.Fatalf("local diagnostics = %#v", local)
	}
	if issues, _ := local["issues"].([]any); len(issues) != 0 {
		t.Fatalf("healthy state reported issues %#v", issues)
	}
	statuses, _ := local["peer_statuses"].(map[string]any)
	if statuses["unpaired"] != float64(1) {
		t.Fatalf("peer statuses = %#v", statuses)
	}
	tools, ok := report["tools"].(map[string]any)
	if !ok {
		t.Fatalf("doctor report has no tools section: %s", raw)
	}
	for _, name := range []string{"age", "age-keygen", "git", "qrencode"} {
		entry, entryOK := tools[name].(map[string]any)
		if !entryOK || entry["configured"] == "" {
			t.Fatalf("tool %q = %#v", name, tools[name])
		}
		if _, present := entry["available"].(bool); !present {
			t.Fatalf("tool %q has no availability: %#v", name, entry)
		}
	}
	// Peer transfers carry their own Go transport, so curl is not a peer-mode
	// dependency and must not be reported as one.
	if _, present := tools["curl"]; present {
		t.Fatalf("doctor still reports curl as a peer-mode tool: %#v", tools)
	}
}

// loadV2Config already refuses a world-readable configuration or seed, so the
// diagnostics cover the state that nothing else validates.
func TestDoctorReportsExposedLocalDirectories(t *testing.T) {
	setTestV2Homes(t)
	_, paths, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	report, code, raw := runDoctorJSON(t)
	if code == 0 {
		t.Fatalf("doctor accepted a world-readable state directory: %s", raw)
	}
	if report["ok"] != false {
		t.Fatalf("doctor reported ok with a local issue: %s", raw)
	}
	local := report["local"].(map[string]any)
	issues, _ := local["issues"].([]any)
	if len(issues) != 1 || !strings.Contains(issues[0].(string), "world-accessible") {
		t.Fatalf("local issues = %#v", issues)
	}

	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &stubV2Transport{}, nil
	}
	if code := a.main([]string{"doctor"}); code == 0 {
		t.Fatalf("text doctor accepted a world-readable state directory: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "- state directory is group- or world-accessible") {
		t.Fatalf("doctor text omitted the issue: %s", stdout.String())
	}
}

func TestDoctorFlagsAnExposedAdminCapability(t *testing.T) {
	setTestV2Homes(t)
	_, paths, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.AdminCapability, []byte("opaque\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, code, raw := runDoctorJSON(t)
	if code == 0 {
		t.Fatalf("doctor accepted a world-readable admin capability: %s", raw)
	}
	local := report["local"].(map[string]any)
	if local["admin_capability"] != "present" {
		t.Fatalf("admin capability = %#v", local["admin_capability"])
	}
	issues, _ := local["issues"].([]any)
	if len(issues) != 1 || !strings.Contains(issues[0].(string), "administrative capability") {
		t.Fatalf("local issues = %#v", issues)
	}
}

// The report is meant to be pasted into a bug report, so it must never carry
// the device seed or any capability material.
func TestDoctorReportNeverCarriesLocalSecrets(t *testing.T) {
	setTestV2Homes(t)
	if _, _, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	); err != nil {
		t.Fatal(err)
	}
	const capabilityReference = "capability-reference-that-must-not-appear"
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers["laptop"] = v2PeerProfile{
			Status:                   "unpaired",
			InboxCapabilityReference: capabilityReference,
			GitRemote:                "laptop",
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.Seed == "" {
		t.Fatal("initialization produced no device seed")
	}
	report, _, raw := runDoctorJSON(t)
	var values []string
	walkStrings(report, &values)
	for _, secret := range []string{cfg.Identity.Seed, capabilityReference} {
		for _, value := range values {
			if strings.Contains(value, secret) {
				t.Fatalf("doctor leaked local secret material: %s", raw)
			}
		}
	}
}

func TestDoctorTextOutputSummarizesLocalStateAndTools(t *testing.T) {
	setTestV2Homes(t)
	toolDirectory := t.TempDir()
	for _, name := range []string{"age", "git"} {
		if err := os.WriteFile(
			filepath.Join(toolDirectory, name),
			[]byte("#!/bin/sh\nexit 0\n"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", toolDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, _, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &stubV2Transport{}, nil
	}
	if code := a.main([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor code = %d, stderr = %s", code, stderr.String())
	}
	for _, fragment := range []string{
		"Local state\n  peers             0\n  schema            v3\n  issues            none",
		"Tools\n  age         ok",
		"git         ok",
	} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Fatalf("doctor text omitted %q: %s", fragment, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "curl") {
		t.Fatalf("doctor text still lists curl: %s", stdout.String())
	}
}
