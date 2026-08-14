// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The encodings every long-lived secret in this client uses, so a leak is
// caught whatever field it escaped through. The base64url arm is kept separate
// because a filesystem path can match it by coincidence, and paths are printed
// on purpose.
var (
	secretShapedPattern = regexp.MustCompile(
		`AGE-SECRET-KEY[-0-9A-Z]*|\b[0-9a-f]{64}\b`)
	base64SecretPattern = regexp.MustCompile(`\b[A-Za-z0-9_-]{43}\b`)
)

// findSecretShaped reports the first secret-shaped token in a value, ignoring
// the base64url shape inside anything that is plainly a filesystem path.
func findSecretShaped(value string) string {
	if match := secretShapedPattern.FindString(value); match != "" {
		return match
	}
	if strings.ContainsRune(value, os.PathSeparator) {
		return ""
	}
	return base64SecretPattern.FindString(value)
}

// TestV2SecretsNeverReachArgvOrTheEnvironment proves the client passes key
// material through files and standard input only. Argv and the environment are
// world-readable on most systems, so a secret placed there leaks to every local
// process for the lifetime of the command.
func TestV2SecretsNeverReachArgvOrTheEnvironment(t *testing.T) {
	directory := testSourceDir(t)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	// Every construction of a subprocess argument vector must be inspectable
	// here, so the check is a source-level rule rather than a runtime sample.
	forbidden := []struct {
		pattern *regexp.Regexp
		reason  string
	}{
		{regexp.MustCompile(`"--identity",\s*(?:string\()?\w*[Ss]ecret`),
			"passes an identity secret as an argument"},
		{regexp.MustCompile(`Setenv\(\s*"(?:DUD_[A-Z_]*SECRET|AGE_SECRET[A-Z_]*)"`),
			"exports a secret through the environment"},
		{regexp.MustCompile(`Env\s*=\s*append\([^)]*[Ss]ecret`),
			"appends a secret to a subprocess environment"},
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range forbidden {
			if rule.pattern.Match(body) {
				t.Errorf("%s %s", name, rule.reason)
			}
		}
	}
}

// TestV2MasterSeedStaysPrivateOnDisk covers the at-rest half of the same
// property: the seed file and its directory must not be readable by other
// local accounts, and the seed must never appear in the readable config.
func TestV2MasterSeedStaysPrivateOnDisk(t *testing.T) {
	setTestV2Homes(t)
	clearV2NetworkEnvironment(t)
	_, paths, err := initializeV2Config(
		"desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(paths.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("master seed mode = %o", info.Mode().Perm())
	}
	directory, err := os.Stat(filepath.Dir(paths.Seed))
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm()&0o077 != 0 {
		t.Fatalf("seed directory mode = %o", directory.Mode().Perm())
	}

	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(config, seed) {
		t.Fatal("the readable config carries the master seed")
	}
	for _, field := range strings.Fields(string(config)) {
		if match := findSecretShaped(field); match != "" {
			t.Fatalf("the readable config carries secret-shaped material %q", match)
		}
	}
}

// TestV2DiagnosticsAreRedacted checks the two surfaces an operator is most
// likely to paste into a bug report.
func TestV2DiagnosticsAreRedacted(t *testing.T) {
	setTestV2Homes(t)
	clearV2NetworkEnvironment(t)
	if _, _, err := initializeV2Config(
		"desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard",
	); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"doctor"},
		{"doctor", "--json"},
		{"capabilities"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := newApp(strings.NewReader(""), &stdout, &stderr)
			a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
				return &stubV2Transport{}, nil
			}
			_ = a.main(args)
			for label, stream := range map[string]*bytes.Buffer{
				"stdout": &stdout, "stderr": &stderr,
			} {
				for _, field := range strings.Fields(stream.String()) {
					if match := findSecretShaped(field); match != "" {
						t.Fatalf("%s carries secret-shaped material %q", label, match)
					}
				}
			}
		})
	}
}

// TestV2DoctorJSONHasBoundedCardinality guards the metrics surface: a
// diagnostic that keys anything by peer, relationship or capability identifier
// would turn a redacted report into a peer graph.
func TestV2DoctorJSONHasBoundedCardinality(t *testing.T) {
	setTestV2Homes(t)
	clearV2NetworkEnvironment(t)
	if _, _, err := initializeV2Config(
		"desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard",
	); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &stubV2Transport{}, nil
	}
	if code := a.main([]string{"doctor", "--json"}); code != 0 {
		t.Fatalf("doctor code = %d", code)
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(
		`(?i)relationship_id|capability_id|token_secret|slot|master_seed|identity`)
	var walk func(prefix string, value any)
	walk = func(prefix string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, nested := range typed {
				if forbidden.MatchString(key) {
					t.Errorf("diagnostic key %s%s exposes peer metadata", prefix, key)
				}
				walk(prefix+key+".", nested)
			}
		case []any:
			for _, nested := range typed {
				walk(prefix, nested)
			}
		case string:
			if match := findSecretShaped(typed); match != "" {
				t.Errorf("diagnostic value at %s carries %q", prefix, match)
			}
		}
	}
	walk("", report)
}

// TestV2TempFilesAreRemovedOnSignal covers the interruption path: deferred
// cleanup never runs when a signal kills the process, so plaintext staged in
// the temp directory has to be removed by the signal handler instead.
func TestV2TempFilesAreRemovedOnSignal(t *testing.T) {
	path, err := tempFile("dud-privacy-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	removeAllTempFiles()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("staged plaintext survived cleanup: %v", err)
	}
	// The handler the process installs must cover the signals a terminal and a
	// supervisor actually send, and the umask must be tightened before it.
	source, err := os.ReadFile(filepath.Join(testSourceDir(t), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"syscall.SIGINT", "syscall.SIGTERM", "syscall.SIGHUP"} {
		if !strings.Contains(string(source), expected) {
			t.Errorf("the signal handler does not cover %s", expected)
		}
	}
	if !strings.Contains(string(source), "syscall.Umask(0o077)") {
		t.Error("the process does not restrict its umask before creating files")
	}
}

// TestV2TempFilesAreCreatedPrivately closes the window the umask alone leaves:
// a file created before the umask took effect, or with a wider mode, would be
// readable by other accounts for as long as it exists.
func TestV2TempFilesAreCreatedPrivately(t *testing.T) {
	path, err := tempFile("dud-privacy-mode-*")
	if err != nil {
		t.Fatal(err)
	}
	defer removeTempFile(path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("temporary file mode = %o", info.Mode().Perm())
	}
}

// testSourceDir returns this package's directory so a rule can be enforced
// against the sources themselves rather than a sampled runtime path.
func testSourceDir(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the package source directory")
	}
	return filepath.Dir(source)
}
