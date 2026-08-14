// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every environment variable the dead drop documentation promises must still
// reach the field it has always populated.
func TestV1EnvironmentContract(t *testing.T) {
	tests := []struct {
		variable string
		value    string
		read     func(config) string
	}{
		{"DUD_BASE_URL", "https://v1.example.test", func(c config) string { return c.BaseURL }},
		{"DUD_DOH_URL", "https://resolver.example.test/dns-query", func(c config) string { return c.DOHURL }},
		{"DUD_ECH_MODE", "off", func(c config) string { return c.ECHMode }},
		{"DUD_DROP_SECRET", "shared", func(c config) string { return c.SecretToken }},
		{"DUD_CA_BUNDLE", "/ca.pem", func(c config) string { return c.CABundle }},
		{"DUD_CONNECT_TO", "dud.example.com:443:127.0.0.1:8443", func(c config) string { return c.ConnectTo }},
		{"DUD_AGE_BIN", "/usr/local/bin/age", func(c config) string { return c.AgeBin }},
		{"DUD_AGE_KEYGEN_BIN", "/usr/local/bin/age-keygen", func(c config) string { return c.AgeKeygenBin }},
		{"DUD_GIT_BIN", "/usr/local/bin/git", func(c config) string { return c.GitBin }},
		{"DUD_QRENCODE_BIN", "/usr/local/bin/qrencode", func(c config) string { return c.QREncodeBin }},
		{"DUD_IMAGE", "example.test/dud:pinned", func(c config) string { return c.Image }},
	}
	for _, test := range tests {
		t.Run(test.variable, func(t *testing.T) {
			t.Setenv(test.variable, test.value)
			if got := test.read(loadConfig()); got != test.value {
				t.Fatalf("%s = %q, want %q", test.variable, got, test.value)
			}
		})
	}
}

// DUD_CURL_BIN went away with the curl subprocess. Setting it must change
// nothing rather than populate an option that does nothing.
func TestV1CurlBinaryOverrideIsInert(t *testing.T) {
	for _, variable := range []string{"DUD_BASE_URL", "DUD_DOH_URL", "DUD_ECH_MODE"} {
		t.Setenv(variable, "")
	}
	before := loadConfig()
	t.Setenv("DUD_CURL_BIN", "/usr/local/bin/curl")
	if loadConfig() != before {
		t.Fatal("DUD_CURL_BIN still changes the loaded configuration")
	}
}

// The compiled defaults are part of the dead drop contract: a client with no
// environment at all still targets the same origin, resolver, and image.
func TestV1CompiledDefaults(t *testing.T) {
	for _, variable := range []string{
		"DUD_BASE_URL", "DUD_DOH_URL", "DUD_ECH_MODE", "DUD_DROP_SECRET", "DUD_PEER_SECRET",
		"DUD_CA_BUNDLE", "DUD_CONNECT_TO", "DUD_AGE_BIN",
		"DUD_AGE_KEYGEN_BIN", "DUD_GIT_BIN", "DUD_QRENCODE_BIN", "DUD_IMAGE",
	} {
		t.Setenv(variable, "")
	}
	cfg := loadConfig()
	want := config{
		BaseURL:      "https://dud.example.com",
		DOHURL:       "https://cloudflare-dns.com/dns-query",
		ECHMode:      "hard",
		AgeBin:       "age",
		AgeKeygenBin: "age-keygen",
		GitBin:       "git",
		QREncodeBin:  "qrencode",
		Image:        "ghcr.io/wojciechpolak/dud/dud-client:latest",
	}
	if cfg != want {
		t.Fatalf("defaults = %#v, want %#v", cfg, want)
	}
}

// Every dead drop invocation must keep producing the same request: the same
// origin, the same route, the same method, and the same headers.
func TestV1InvocationContract(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantMethod string
		wantOrigin string
		wantPath   string
		wantHeader map[string]string
	}{
		{
			name:       "test",
			args:       []string{"test"},
			wantMethod: http.MethodGet,
			wantOrigin: "https://dud.example.com",
			wantPath:   "/v1/test",
		},
		{
			name:       "test with url override",
			args:       []string{"test", "--url", "https://alt.example.test/v1/test"},
			wantMethod: http.MethodGet,
			wantOrigin: "https://alt.example.test",
			wantPath:   "/v1/test",
		},
		{
			name:       "upload message",
			args:       []string{"upload", "--passphrase", "-m", "hello", "--json"},
			wantMethod: http.MethodPost,
			wantOrigin: "https://dud.example.com",
			wantPath:   "/v1/files",
			wantHeader: map[string]string{
				"content-type":            "application/octet-stream",
				"x-dud-ttl":               "24h",
				"x-dud-delete-after-read": "false",
				"x-dud-secret-token":      "top-secret",
			},
		},
		{
			name:       "upload with ttl and delete-after-read",
			args:       []string{"upload", "--passphrase", "-m", "hi", "--ttl", "15m", "--delete-after-read", "--json"},
			wantMethod: http.MethodPost,
			wantOrigin: "https://dud.example.com",
			wantPath:   "/v1/files",
			wantHeader: map[string]string{
				"x-dud-ttl":               "15m",
				"x-dud-delete-after-read": "true",
			},
		},
		{
			name:       "download to a file",
			args:       []string{"download", "--id", "abcd", "--out", "OUT"},
			wantMethod: http.MethodGet,
			wantOrigin: "https://dud.example.com",
			wantPath:   "/v1/files/abcd",
		},
		{
			name:       "download with url override",
			args:       []string{"download", "--id", "abcd", "--stdout", "--url", "https://alt.example.test"},
			wantMethod: http.MethodGet,
			wantOrigin: "https://alt.example.test",
			wantPath:   "/v1/files/abcd",
		},
		{
			name:       "flush",
			args:       []string{"flush"},
			wantMethod: http.MethodPost,
			wantOrigin: "https://dud.example.com",
			wantPath:   "/v1/admin/flush",
			wantHeader: map[string]string{"x-dud-secret-token": "top-secret"},
		},
		{
			name:       "dead drop git fetch by id",
			args:       []string{"git", "fetch", "--id", "abcd", "--remote", "peer"},
			wantMethod: http.MethodGet,
			wantOrigin: "https://dud.example.com",
			wantPath:   "/v1/files/abcd",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, transport, _, stderr := newDropTestApp(t, "")
			// `test` asserts an accepted handshake under the default hard mode,
			// which a recording transport cannot produce.
			a.cfg.ECHMode = "off"
			transport.respond = uploadJSONResponder("aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa")
			args := append([]string(nil), test.args...)
			for index, value := range args {
				if value == "OUT" {
					args[index] = filepath.Join(t.TempDir(), "out")
				}
			}
			if test.name == "dead drop git fetch by id" {
				a.cfg.GitBin = writeStubbedGit(t)
			}
			_ = a.run(args)
			request := transport.only(t)
			if request.Method != test.wantMethod {
				t.Fatalf("method = %q, want %q (stderr %s)", request.Method, test.wantMethod, stderr.String())
			}
			if request.Origin != test.wantOrigin || request.Path != test.wantPath {
				t.Fatalf("target = %s%s, want %s%s", request.Origin, request.Path, test.wantOrigin, test.wantPath)
			}
			for name, want := range test.wantHeader {
				if got := request.header(name); got != want {
					t.Fatalf("header %s = %q, want %q", name, got, want)
				}
			}
			// The transport contract itself: DoH resolution and the selected
			// ECH mode are not per-call options a command may skip.
			if len(transport.options) != 1 {
				t.Fatalf("transports built = %d, want 1", len(transport.options))
			}
			if transport.options[0].DOHURL != "https://cloudflare-dns.com/dns-query" ||
				transport.options[0].ECHMode != "off" {
				t.Fatalf("transport options = %#v", transport.options[0])
			}
		})
	}
}

// The dead drop routes accept the raw and dashed object-ID forms and forward
// each unchanged.
func TestV1ObjectIDFormsReachTheSameRoute(t *testing.T) {
	raw := strings.Repeat("a", 32)
	for _, id := range []string{
		raw,
		"aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa",
		"aaaaaaaa-aaaaaaaa-aaaaaaaa-aaaaaaaa",
	} {
		t.Run(id, func(t *testing.T) {
			a, transport, _, _ := newDropTestApp(t, "")
			_ = a.run([]string{"download", "--id", id, "--out", filepath.Join(t.TempDir(), "out")})
			if got := transport.only(t).Path; got != "/v1/files/"+id {
				t.Fatalf("route = %q, want %q", got, "/v1/files/"+id)
			}
		})
	}
}

// A failing transfer must surface a usable exit status, never a Go error code.
func TestV1TransferFailuresPropagateExitCodes(t *testing.T) {
	commands := [][]string{
		{"test"},
		{"upload", "--passphrase", "-m", "hello", "--json"},
		{"download", "--id", strings.Repeat("a", 32), "--stdout"},
		{"flush"},
	}
	for _, args := range commands {
		t.Run(args[0], func(t *testing.T) {
			a, transport, _, stderr := newDropTestApp(t, "")
			transport.respond = func(recordedDropRequest) (*v2Response, error) {
				return &v2Response{StatusCode: http.StatusNotFound}, nil
			}
			if code := a.main(args); code != 22 {
				t.Fatalf("%v exit = %d, want 22 (stderr %s)", args, code, stderr.String())
			}
		})
	}
}

func writeStubbedGit(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git-stub.sh")
	script := `#!/bin/sh
case "$1" in
  rev-parse) printf '.git\n'; exit 0 ;;
  bundle|fetch) exit 0 ;;
  ls-remote) printf 'abc123\trefs/heads/master\n'; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// digestLocalTree summarizes a directory so a test can prove nothing inside it
// changed.
func digestLocalTree(t *testing.T, root string) []string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		entries = append(entries, relative+" "+hex.EncodeToString(digest[:]))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	return entries
}

// Downgrading to a drop-only client must leave peer local state untouched, so
// that upgrading again finds the same device identity and peer graph.
func TestClientDowngradeLeavesV2LocalStateIntact(t *testing.T) {
	setTestV2Homes(t)
	t.Setenv("TMPDIR", t.TempDir())
	dudHome := os.Getenv("DUD_HOME")
	if _, _, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	); err != nil {
		t.Fatal(err)
	}
	before := digestLocalTree(t, dudHome)
	if len(before) == 0 {
		t.Fatal("peer initialization wrote no local state")
	}

	for _, args := range [][]string{
		{"test"},
		{"upload", "--passphrase", "-m", "hello", "--json"},
		{"download", "--id", strings.Repeat("a", 32), "--out", filepath.Join(t.TempDir(), "out")},
		{"flush"},
		{"install"},
		{"shell-init"},
	} {
		a, transport, _, stderr := newDropTestApp(t, "")
		a.cfg.ECHMode = "off"
		transport.respond = uploadJSONResponder("aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa")
		if code := a.main(args); code != 0 {
			t.Fatalf("%v exit = %d (stderr %s)", args, code, stderr.String())
		}
	}

	after := digestLocalTree(t, dudHome)
	if strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Fatalf("dead drop commands modified peer local state:\nbefore %v\nafter  %v", before, after)
	}

	// Upgrading again must still find a usable configuration.
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	if code := a.main([]string{"config", "validate", "--json"}); code != 0 {
		t.Fatalf("post-downgrade configuration is unusable: %s", stdout.String())
	}
}
