// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2InitCreatesPrivateAtomicState(t *testing.T) {
	setTestV2Homes(t)
	cfg, paths, err := initializeV2Config(
		"desktop",
		"https://DUD.Example.COM",
		"https://cloudflare-dns.com/dns-query",
		"hard",
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != "https://dud.example.com" {
		t.Fatalf("base URL = %q", cfg.BaseURL)
	}
	for _, path := range []string{paths.ConfigDir, paths.StateDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("%s mode = %o", path, got)
		}
	}
	for _, path := range []string{paths.Config, paths.Seed} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o", path, got)
		}
	}
	loaded, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Identity.DeviceID != cfg.Identity.DeviceID {
		t.Fatal("device identity changed after config round trip")
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 32 {
		t.Fatalf("seed length = %d", len(seed))
	}
	if matches, _ := filepath.Glob(filepath.Join(paths.ConfigDir, ".config.toml.tmp-*")); len(matches) != 0 {
		t.Fatalf("atomic temp files remain: %v", matches)
	}
}

func TestV2ConfigRejectsReadableSeed(t *testing.T) {
	setTestV2Homes(t)
	_, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.Seed, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadV2Config(); err == nil || !strings.Contains(err.Error(), "group- or world-accessible") {
		t.Fatalf("readable seed error = %v", err)
	}
}

func TestV2ConfigParserRejectsDuplicateKeys(t *testing.T) {
	_, err := parseV2Config([]byte("version = 2\nversion = 2\n"))
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate config error = %v", err)
	}
}

func TestV2PeerProfileLifecycleAndRedaction(t *testing.T) {
	setTestV2Homes(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	if code := a.main([]string{"init", "--device", "desktop", "--url", "https://dud.example.com", "--json"}); code != 0 {
		t.Fatalf("init code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers["laptop"] = v2PeerProfile{
			Status:    "unpaired",
			BaseURL:   cfg.BaseURL,
			GitRemote: "laptop",
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code := a.main([]string{"peer", "rename", "laptop", "notebook"}); code != 0 {
		t.Fatalf("peer rename code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	if code := a.main([]string{"config", "show", "--json"}); code != 0 {
		t.Fatalf("config show code = %d, stderr = %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), `"seed": "seed"`) || !strings.Contains(stdout.String(), `"seed": "<private>"`) {
		t.Fatalf("config output did not redact seed: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"notebook"`) {
		t.Fatalf("renamed peer absent: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := a.main([]string{"peer", "remove", "notebook"}); code != 1 {
		t.Fatalf("unconfirmed remove code = %d", code)
	}
	if !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("unconfirmed remove error = %s", stderr.String())
	}
	stderr.Reset()
	if code := a.main([]string{"peer", "remove", "notebook", "--yes", "--json"}); code != 0 {
		t.Fatalf("peer remove code = %d, stderr = %s", code, stderr.String())
	}
}

func TestV2PeerRenameRejectsPendingPairing(t *testing.T) {
	setTestV2Homes(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	if code := a.main([]string{"init", "--device", "desktop", "--url", "https://dud.example.com"}); code != 0 {
		t.Fatalf("init code = %d, stderr = %s", code, stderr.String())
	}
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers["laptop"] = v2PeerProfile{Status: "pending", BaseURL: cfg.BaseURL}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, paths, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureV2PeerStateDirectories(paths); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pairingStatePath(paths, "laptop"), []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := a.main([]string{"peer", "rename", "laptop", "notebook"}); code != 1 {
		t.Fatalf("rename code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "pending pairing") {
		t.Fatalf("rename error = %s", stderr.String())
	}
	cfg, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := cfg.Peers["laptop"]; !exists {
		t.Fatal("pending peer was renamed")
	}
}

func TestV2ConfigSchemaMigrationRejectsLegacyV2State(t *testing.T) {
	setTestV2Homes(t)
	_, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.Replace(body, []byte("version = 3"), []byte("version = 2"), 1)
	if err := os.WriteFile(paths.Config, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code := a.main([]string{"migrate", "--json"}); code == 0 {
		t.Fatal("peer configuration at an unsupported schema version was migrated")
	}
	if !strings.Contains(stderr.String(), "erase local peer state") || !strings.Contains(stderr.String(), "re-pair") {
		t.Fatalf("migration error = %s", stderr.String())
	}
}

func TestV2DoctorUsesOnlyInjectedTransportBoundary(t *testing.T) {
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
		cfg.Peers["laptop"] = v2PeerProfile{
			Status:    "unpaired",
			BaseURL:   "https://peer.example.com",
			ECHMode:   "off",
			GitRemote: "laptop",
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	stub := &stubV2Transport{}
	var optionsSeen []v2TransportOptions
	a.newV2Transport = func(options v2TransportOptions) (v2Transport, error) {
		optionsSeen = append(optionsSeen, options)
		return stub, nil
	}
	if code := a.main([]string{"doctor", "--json"}); code != 0 {
		t.Fatalf("doctor code = %d, stderr = %s", code, stderr.String())
	}
	if stub.called != 2 {
		t.Fatalf("doctor did not use transport boundary: %#v", stub)
	}
	if len(optionsSeen) != 2 || optionsSeen[0].ECHMode != "hard" || optionsSeen[1].ECHMode != "off" {
		t.Fatalf("doctor transport options = %#v", optionsSeen)
	}
	if !strings.Contains(stdout.String(), `"transport_status": 200`) {
		t.Fatalf("doctor output = %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"label": "peer:laptop"`) {
		t.Fatalf("doctor omitted peer origin: %s", stdout.String())
	}
}

func TestInteractiveV2DeviceInitializationUsesSameCommandPath(t *testing.T) {
	setTestV2Homes(t)
	t.Setenv("DUD_TEST_STDIN_TTY", "1")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	input := strings.NewReader("setup\n1\ndesktop\nhttps://dud.example.com\nhttps://dns.google/dns-query\nhard\n")
	a := newApp(input, &stdout, &stderr)
	if code := a.main(nil); code != 0 {
		t.Fatalf("interactive init code = %d, stderr = %s", code, stderr.String())
	}
	cfg, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Device != "desktop" {
		t.Fatalf("interactive device = %q", cfg.Device)
	}
}

// Peer status reads as a state, not as prose, so the human-readable listings
// shout it. The JSON form is parsed by other tools and validated against the
// stored configuration, so it stays lower case.
func TestV2PeerStatusIsUpperCaseOnlyWhereItIsRead(t *testing.T) {
	setTestV2Homes(t)
	initializeInteractiveTestPeers(t)
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	if err := a.cmdPeerList(nil); err != nil {
		t.Fatal(err)
	}
	if listing := stdout.String(); listing != "archive  UNPAIRED\nlaptop   ACTIVE\nphone    ACTIVE\n" {
		t.Fatalf("peer list = %q", listing)
	}
	stdout.Reset()
	if err := a.cmdPeerShow([]string{"laptop"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Status  ACTIVE\n") {
		t.Fatalf("peer show = %q", stdout.String())
	}
	for _, args := range [][]string{{"--json"}, {"laptop", "--json"}} {
		stdout.Reset()
		var err error
		if len(args) == 1 {
			err = a.cmdPeerList(args)
		} else {
			err = a.cmdPeerShow(args)
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), `"status": "active"`) {
			t.Fatalf("json %q = %q", args, stdout.String())
		}
	}
}

func TestInitAndConfigCommandsReportRedactedConfiguration(t *testing.T) {
	setTestV2Homes(t)
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	if err := a.run([]string{"init", "--device", "desktop", "--json"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"initialized": true`) || strings.Contains(stdout.String(), "master_seed") {
		t.Fatalf("init output = %s", stdout.String())
	}
	stdout.Reset()
	if err := a.run([]string{"config", "show", "--json"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"device": "desktop"`) || !strings.Contains(stdout.String(), `"seed": "<private>"`) {
		t.Fatalf("config show = %s", stdout.String())
	}
	stdout.Reset()
	if err := a.run([]string{"config", "validate", "--json"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"valid": true`) {
		t.Fatalf("config validate = %s", stdout.String())
	}
}

func TestV2ConfigParserAcceptsBootstrapArraysAndRejectsMalformedArrays(t *testing.T) {
	cfg, err := parseV2Config([]byte("version = 3\ndevice = \"desktop\"\nbase_url = \"https://dud.example.com\"\ndoh_url = \"https://dns.google/dns-query\"\nech_mode = \"hard\"\ndoh_bootstrap = [\"1.1.1.1\", \"[2606:4700:4700::1111]\"]\n[identity]\ndevice_id = \"0123456789abcdef0123456789abcdef\"\nseed = \"private\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DOHBootstrap) != 2 || cfg.DOHBootstrap[1] != "[2606:4700:4700::1111]" {
		t.Fatalf("bootstrap = %#v", cfg.DOHBootstrap)
	}
	for _, raw := range []string{"not-an-array", "[unquoted]", "[\"unterminated]"} {
		if _, err := parseV2TOMLStringArray(raw); err == nil {
			t.Fatalf("malformed array accepted: %q", raw)
		}
	}
}

func TestValidateV2ConfigRejectsInvalidLocalAndPeerSettings(t *testing.T) {
	setTestV2Homes(t)
	base, _, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	clone := func() *v2LocalConfig {
		copy := *base
		copy.Peers = map[string]v2PeerProfile{}
		return &copy
	}
	tests := []struct {
		name   string
		mutate func(*v2LocalConfig)
	}{
		{"version", func(cfg *v2LocalConfig) { cfg.Version = 99 }},
		{"device", func(cfg *v2LocalConfig) { cfg.Device = "\n" }},
		{"device ID length", func(cfg *v2LocalConfig) { cfg.Identity.DeviceID = "bad" }},
		{"device ID upper", func(cfg *v2LocalConfig) { cfg.Identity.DeviceID = strings.ToUpper(cfg.Identity.DeviceID) }},
		{"origin", func(cfg *v2LocalConfig) { cfg.BaseURL = "http://dud.example.com" }},
		{"doh", func(cfg *v2LocalConfig) { cfg.DOHURL = "http://dns.google/dns-query" }},
		{"ech", func(cfg *v2LocalConfig) { cfg.ECHMode = "maybe" }},
		{"bootstrap", func(cfg *v2LocalConfig) { cfg.DOHBootstrap = []string{"0.0.0.0"} }},
		{"peer alias", func(cfg *v2LocalConfig) { cfg.Peers["bad/name"] = v2PeerProfile{Status: "active"} }},
		{"peer status", func(cfg *v2LocalConfig) { cfg.Peers["peer"] = v2PeerProfile{Status: "other"} }},
		{"peer epoch", func(cfg *v2LocalConfig) { cfg.Peers["peer"] = v2PeerProfile{Status: "active", KeyEpoch: 1} }},
		{"peer origin", func(cfg *v2LocalConfig) {
			cfg.Peers["peer"] = v2PeerProfile{Status: "active", BaseURL: "https://dud.example.com/"}
		}},
		{"peer doh", func(cfg *v2LocalConfig) {
			cfg.Peers["peer"] = v2PeerProfile{Status: "active", DOHURL: "http://dns.google/dns-query"}
		}},
		{"peer ech", func(cfg *v2LocalConfig) { cfg.Peers["peer"] = v2PeerProfile{Status: "active", ECHMode: "maybe"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := clone()
			test.mutate(cfg)
			if err := validateV2Config(cfg); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestV2ConfigFileAndLockFailuresAreReported(t *testing.T) {
	setTestV2Homes(t)
	if _, _, err := loadV2Config(); err == nil {
		t.Fatal("uninitialized configuration accepted")
	}
	cfg, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.Config, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadV2Config(); err == nil {
		t.Fatal("readable configuration accepted")
	}
	if err := os.Chmod(paths.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Seed, []byte("bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadV2MasterSeed(paths); err == nil {
		t.Fatal("invalid seed accepted")
	}
	if err := os.WriteFile(paths.Seed, []byte(strings.Repeat("01", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeV2Config(paths, cfg); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := acquireV2ConfigLock(paths); err == nil {
		t.Fatal("second config lock acquired")
	}
}

func TestDUDProfileSelectsASeparatePeerWorld(t *testing.T) {
	setTestV2Homes(t)
	root := os.Getenv("DUD_HOME")
	defaultPaths, err := resolveV2Paths()
	if err != nil {
		t.Fatal(err)
	}
	if defaultPaths.Root != filepath.Join(root, "default") {
		t.Fatalf("unexpected default world directory %q", defaultPaths.Root)
	}
	if defaultPaths.ConfigDir != filepath.Join(root, "default", "config") {
		t.Fatalf("unexpected default config directory %q", defaultPaths.ConfigDir)
	}
	if defaultPaths.StateDir != filepath.Join(root, "default", "state") {
		t.Fatalf("unexpected default state directory %q", defaultPaths.StateDir)
	}
	// Naming the default world explicitly selects the same directory rather than
	// a second one beside it.
	t.Setenv("DUD_PROFILE", "default")
	if named, err := resolveV2Paths(); err != nil {
		t.Fatal(err)
	} else if named.Root != defaultPaths.Root {
		t.Fatalf("DUD_PROFILE=default resolved %q instead of the default world", named.Root)
	}
	t.Setenv("DUD_PROFILE", "test")
	profilePaths, err := resolveV2Paths()
	if err != nil {
		t.Fatal(err)
	}
	if profilePaths.Root != filepath.Join(root, "test") {
		t.Fatalf("unexpected profile world directory %q", profilePaths.Root)
	}
	// Every other path is derived from the world, so the whole of it moves.
	for _, path := range []string{
		profilePaths.Config,
		profilePaths.Seed,
		profilePaths.AdminCapability,
		profilePaths.Lock,
	} {
		if filepath.Dir(path) != profilePaths.ConfigDir {
			t.Fatalf("path %q escaped the profile directory", path)
		}
	}
	for _, path := range []string{profilePaths.ConfigDir, profilePaths.StateDir} {
		if filepath.Dir(path) != profilePaths.Root {
			t.Fatalf("path %q escaped the profile directory", path)
		}
	}
	// A profile is a whole device, so initializing one leaves the default world
	// uninitialized rather than sharing its identity.
	if _, _, err := initializeV2Config("laptop-test", "https://dud.example.com", "https://dns.google/dns-query", "hard"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DUD_PROFILE", "")
	if _, _, err := loadV2Config(); err == nil {
		t.Fatal("the default world saw the profile configuration")
	}
}

func TestDUDProfileRejectsNamesThatWouldLeaveTheDUDRoot(t *testing.T) {
	setTestV2Homes(t)
	for _, profile := range []string{
		"../escape",
		"a/b",
		"-x",
		".hidden",
		"_leading",
		"has space",
		strings.Repeat("p", 65),
	} {
		t.Run(profile, func(t *testing.T) {
			t.Setenv("DUD_PROFILE", profile)
			if _, err := resolveV2Paths(); err == nil {
				t.Fatalf("profile %q was accepted", profile)
			} else if !strings.Contains(err.Error(), "DUD_PROFILE") {
				t.Fatalf("error does not name the variable: %v", err)
			}
		})
	}
	for _, profile := range []string{"test", "dud2", "a", "second.deployment", "with_underscore", "with-dash"} {
		t.Run(profile, func(t *testing.T) {
			t.Setenv("DUD_PROFILE", profile)
			paths, err := resolveV2Paths()
			if err != nil {
				t.Fatalf("profile %q was rejected: %v", profile, err)
			}
			if filepath.Base(paths.Root) != profile {
				t.Fatalf("unexpected world directory %q", paths.Root)
			}
		})
	}
}

func TestDUDHomeMustBeAbsolute(t *testing.T) {
	setTestV2Homes(t)
	t.Setenv("DUD_HOME", "relative/root")
	if _, err := resolveV2Paths(); err == nil {
		t.Fatal("a relative DUD_HOME was accepted")
	} else if !strings.Contains(err.Error(), "DUD_HOME") {
		t.Fatalf("error does not name the variable: %v", err)
	}
}

type stubV2Transport struct {
	called int
}

func (transport *stubV2Transport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.called++
	if request.Method != "GET" || request.Path != "/v2/capabilities" {
		return nil, errors.New("unexpected doctor request")
	}
	body, err := v2EncMode.Marshal(map[int]any{
		1: []uint64{1, 2},
		2: []uint64{2, 3, 5, 9, 10, 11},
		3: map[uint64]uint64{
			1: 104857600,
			2: 262144,
			3: 2592000,
			4: 64,
			5: 256,
			6: 4,
			7: 60,
			8: 209715200,
			9: 4096,
		},
		4: map[uint64]uint64{1: 2, 2: 0},
	})
	if err != nil {
		return nil, err
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
}

// clearV2TestEnvironment removes the ambient DUD_* configuration. Every test
// that plants its own DUD root must call it: the variables reach peer commands
// too, so a developer shell that exports DUD_BASE_URL for dead drops would
// otherwise change what the test under it resolves.
func clearV2TestEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"DUD_BASE_URL",
		"DUD_DOH_URL",
		"DUD_ECH_MODE",
		"DUD_CONNECT_TO",
		"DUD_PROFILE",
	} {
		t.Setenv(name, "")
	}
}

func setV2TestHomes(t *testing.T, root string) {
	t.Helper()
	t.Setenv("DUD_HOME", filepath.Join(root, "dud"))
	clearV2TestEnvironment(t)
}

func setTestV2Homes(t *testing.T) {
	t.Helper()
	setV2TestHomes(t, t.TempDir())
}
