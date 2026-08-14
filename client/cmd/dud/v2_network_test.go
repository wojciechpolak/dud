// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func clearV2NetworkEnvironment(t *testing.T) {
	t.Helper()
	clearV2TestEnvironment(t)
}

func testV2NetworkConfig() *v2LocalConfig {
	return &v2LocalConfig{
		BaseURL: "https://config.example.com",
		DOHURL:  "https://dns.config.example.com/dns-query",
		ECHMode: "hard",
	}
}

func testV2NetworkPeer() *v2PeerProfile {
	return &v2PeerProfile{
		BaseURL: "https://peer.example.com",
		DOHURL:  "https://dns.peer.example.com/dns-query",
		ECHMode: "off",
	}
}

func TestV2NetworkOptionPrecedenceWalksEveryLayer(t *testing.T) {
	clearV2NetworkEnvironment(t)
	cfg := testV2NetworkConfig()
	peer := testV2NetworkPeer()
	cli := v2NetworkOverrides{
		BaseURL: "https://cli.example.com",
		DOHURL:  "https://dns.cli.example.com/dns-query",
		ECHMode: "hard",
	}

	// 1. The command line outranks every other layer.
	t.Setenv("DUD_BASE_URL", "https://env.example.com")
	t.Setenv("DUD_DOH_URL", "https://dns.env.example.com/dns-query")
	t.Setenv("DUD_ECH_MODE", "off")
	settings, err := resolveV2Network(cfg, peer, cli)
	if err != nil {
		t.Fatal(err)
	}
	if base, doh, ech := settings.values(); base != cli.BaseURL || doh != cli.DOHURL || ech != cli.ECHMode {
		t.Fatalf("command-line layer = %q, %q, %q", base, doh, ech)
	}
	if sources := settings.sources(); sources["base_url"] != v2NetworkSourceCLI ||
		sources["doh_url"] != v2NetworkSourceCLI || sources["ech_mode"] != v2NetworkSourceCLI {
		t.Fatalf("command-line sources = %#v", settings.sources())
	}

	// 2. Without command-line options the peer profile wins, even though the
	// environment is still set: a pinned relationship outranks ambient values.
	settings, err = resolveV2Network(cfg, peer, v2NetworkOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if base, doh, ech := settings.values(); base != peer.BaseURL || doh != peer.DOHURL || ech != peer.ECHMode {
		t.Fatalf("peer layer = %q, %q, %q", base, doh, ech)
	}
	if settings.ECHMode.Source != v2NetworkSourcePeer {
		t.Fatalf("peer source = %q", settings.ECHMode.Source)
	}

	// 3. Without a peer profile the environment wins.
	settings, err = resolveV2Network(cfg, &v2PeerProfile{}, v2NetworkOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if base, doh, ech := settings.values(); base != "https://env.example.com" ||
		doh != "https://dns.env.example.com/dns-query" || ech != "off" {
		t.Fatalf("environment layer = %q, %q, %q", base, doh, ech)
	}
	if settings.BaseURL.Source != v2NetworkSourceEnvironment {
		t.Fatalf("environment source = %q", settings.BaseURL.Source)
	}

	// 4. Without the environment the local configuration wins.
	clearV2NetworkEnvironment(t)
	settings, err = resolveV2Network(cfg, &v2PeerProfile{}, v2NetworkOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if base, doh, ech := settings.values(); base != cfg.BaseURL || doh != cfg.DOHURL || ech != cfg.ECHMode {
		t.Fatalf("configuration layer = %q, %q, %q", base, doh, ech)
	}
	if settings.DOHURL.Source != v2NetworkSourceConfig {
		t.Fatalf("configuration source = %q", settings.DOHURL.Source)
	}

	// 5. With nothing configured the compiled defaults remain.
	settings, err = resolveV2Network(&v2LocalConfig{}, nil, v2NetworkOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if base, doh, ech := settings.values(); base != v2DefaultBaseURL ||
		doh != v2DefaultDOHURL || ech != v2DefaultECHMode {
		t.Fatalf("compiled defaults = %q, %q, %q", base, doh, ech)
	}
	if sources := settings.sources(); sources["base_url"] != v2NetworkSourceDefault ||
		sources["doh_url"] != v2NetworkSourceDefault || sources["ech_mode"] != v2NetworkSourceDefault {
		t.Fatalf("compiled default sources = %#v", settings.sources())
	}
}

func TestV2NetworkLayersMixIndependently(t *testing.T) {
	clearV2NetworkEnvironment(t)
	cfg := testV2NetworkConfig()
	peer := &v2PeerProfile{BaseURL: "https://peer.example.com"}
	t.Setenv("DUD_ECH_MODE", "off")
	settings, err := resolveV2Network(cfg, peer, v2NetworkOverrides{DOHURL: "https://dns.cli.example.com/dns-query"})
	if err != nil {
		t.Fatal(err)
	}
	if settings.DOHURL.Source != v2NetworkSourceCLI ||
		settings.ECHMode.Source != v2NetworkSourceEnvironment ||
		settings.BaseURL.Source != v2NetworkSourcePeer {
		t.Fatalf("mixed sources = %#v", settings.sources())
	}
	if settings.ECHMode.Value != "off" || settings.BaseURL.Value != peer.BaseURL {
		t.Fatalf("mixed values = %#v", settings)
	}

	// The mirror case: an option the profile does pin keeps its pinned value
	// while the same environment variable is set.
	peer.ECHMode = "hard"
	settings, err = resolveV2Network(cfg, peer, v2NetworkOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.ECHMode.Value != "hard" || settings.ECHMode.Source != v2NetworkSourcePeer {
		t.Fatalf("pinned ECH mode = %q (%q)", settings.ECHMode.Value, settings.ECHMode.Source)
	}
}

// A paired peer's transport is what its signed descriptors are bound to, so the
// commands that carry no network options must ignore the ambient environment.
func TestV2PeerCommandsUseThePinnedProfileOverTheEnvironment(t *testing.T) {
	clearV2NetworkEnvironment(t)
	cfg := testV2NetworkConfig()
	peer := testV2NetworkPeer()
	t.Setenv("DUD_BASE_URL", "https://env.example.com")
	t.Setenv("DUD_DOH_URL", "https://dns.env.example.com/dns-query")
	t.Setenv("DUD_ECH_MODE", "hard")
	baseURL, dohURL, echMode, err := effectiveV2NetworkConfig(cfg, peer)
	if err != nil {
		t.Fatal(err)
	}
	if baseURL != peer.BaseURL || dohURL != peer.DOHURL || echMode != peer.ECHMode {
		t.Fatalf("effective peer network = %q, %q, %q", baseURL, dohURL, echMode)
	}
}

func TestV2NetworkReportsWhatTheProfilePinnedAndWhatItOverrode(t *testing.T) {
	clearV2NetworkEnvironment(t)
	cfg := testV2NetworkConfig()
	peer := testV2NetworkPeer()
	if pinned := pinnedV2Network(*peer); pinned["base_url"] != peer.BaseURL ||
		pinned["doh_url"] != peer.DOHURL || pinned["ech_mode"] != peer.ECHMode {
		t.Fatalf("pinned network = %#v", pinnedV2Network(*peer))
	}
	if pinned := pinnedV2Network(v2PeerProfile{}); pinned["base_url"] != "" ||
		pinned["doh_url"] != "" || pinned["ech_mode"] != "" {
		t.Fatalf("unpaired pinned network = %#v", pinnedV2Network(v2PeerProfile{}))
	}

	// Nothing to report while the peer is used as it was paired.
	settings, err := resolveV2Network(cfg, peer, v2NetworkOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if overridden := overriddenV2NetworkEnvironment(settings); len(overridden) != 0 {
		t.Fatalf("overrode %v without an environment", overridden)
	}
	section := &textSection{title: "Origin: peer desktop"}
	renderPinnedV2Network(section, pinnedV2Network(*peer), settings)
	if !section.empty() {
		t.Fatalf("pinned rows rendered without a divergence: %#v", section.rows)
	}

	// An environment variable that repeats the pinned value, in any spelling,
	// overrode nothing.
	t.Setenv("DUD_BASE_URL", "HTTPS://Peer.Example.com:443/")
	settings, err = resolveV2Network(cfg, peer, v2NetworkOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if overridden := overriddenV2NetworkEnvironment(settings); len(overridden) != 0 {
		t.Fatalf("overrode %v while agreeing with the pinned origin", overridden)
	}
	clearV2NetworkEnvironment(t)

	// A set variable the profile outranked is named, and a command-line
	// override that beat the profile shows the pinned value it displaced.
	t.Setenv("DUD_BASE_URL", "https://env.example.com")
	t.Setenv("DUD_ECH_MODE", "hard")
	settings, err = resolveV2Network(cfg, peer, v2NetworkOverrides{DOHURL: "https://dns.cli.example.com/dns-query"})
	if err != nil {
		t.Fatal(err)
	}
	if overridden := overriddenV2NetworkEnvironment(settings); len(overridden) != 2 ||
		overridden[0] != "DUD_BASE_URL" || overridden[1] != "DUD_ECH_MODE" {
		t.Fatalf("overridden environment = %v", overriddenV2NetworkEnvironment(settings))
	}
	report := &textReport{}
	origin := report.section("Origin: peer desktop")
	renderPinnedV2Network(origin, pinnedV2Network(*peer), settings)
	rendered := report.String()
	if !strings.Contains(rendered, "pinned doh  "+peer.DOHURL+"  (peer profile)") {
		t.Fatalf("pinned DoH row missing from %q", rendered)
	}
	if strings.Contains(rendered, "pinned url") || strings.Contains(rendered, "pinned ech") {
		t.Fatalf("rendered a pinned row for a value that did not diverge: %q", rendered)
	}
	if !strings.Contains(rendered, "DUD_BASE_URL, DUD_ECH_MODE set in the environment") {
		t.Fatalf("overridden environment note missing from %q", rendered)
	}
}

func TestV2NetworkOverridesAreCanonicalizedAndValidated(t *testing.T) {
	clearV2NetworkEnvironment(t)
	cfg := testV2NetworkConfig()
	settings, err := resolveV2Network(cfg, nil, v2NetworkOverrides{
		BaseURL: "HTTPS://Override.Example.COM:443/",
		DOHURL:  "https://Dns.Example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if settings.BaseURL.Value != "https://override.example.com" {
		t.Fatalf("canonical base URL = %q", settings.BaseURL.Value)
	}
	if settings.DOHURL.Value != "https://dns.example.com/dns-query" {
		t.Fatalf("canonical DoH URL = %q", settings.DOHURL.Value)
	}
	for name, override := range map[string]v2NetworkOverrides{
		"--url":      {BaseURL: "http://plain.example.com"},
		"--doh-url":  {DOHURL: "http://plain.example.com/dns-query"},
		"--ech-mode": {ECHMode: "soft"},
	} {
		if _, err := resolveV2Network(cfg, nil, override); err == nil ||
			!strings.Contains(err.Error(), name) {
			t.Fatalf("invalid %s override produced %v", name, err)
		}
	}
}

func TestV2NetworkEnvironmentFailuresNameTheirLayer(t *testing.T) {
	clearV2NetworkEnvironment(t)
	cfg := testV2NetworkConfig()
	t.Setenv("DUD_ECH_MODE", "relaxed")
	if _, err := resolveV2Network(cfg, nil, v2NetworkOverrides{}); err == nil ||
		!strings.Contains(err.Error(), "DUD_ECH_MODE") {
		t.Fatalf("invalid environment ECH mode produced %v", err)
	}
	t.Setenv("DUD_ECH_MODE", "")
	t.Setenv("DUD_BASE_URL", "https://192.0.2.10")
	if _, err := resolveV2Network(cfg, nil, v2NetworkOverrides{}); err == nil ||
		!strings.Contains(err.Error(), "DUD_BASE_URL") {
		t.Fatalf("invalid environment base URL produced %v", err)
	}
}

func TestV2NetworkProvenanceNamesEveryLayerAndOmitsUnknownOnes(t *testing.T) {
	tests := []struct {
		originSource  string
		echModeSource string
		want          string
	}{
		{v2NetworkSourceDefault, v2NetworkSourceDefault, " (target from the compiled default, ECH mode from the compiled default)"},
		{v2NetworkSourceEnvironment, v2NetworkSourceEnvironment, " (target from DUD_BASE_URL, ECH mode from DUD_ECH_MODE)"},
		{v2NetworkSourcePeer, v2NetworkSourceConfig, " (target from the peer profile, ECH mode from the local configuration)"},
		{v2NetworkSourceCLI, "", " (target from --url)"},
		{"", "", ""},
	}
	for _, test := range tests {
		if got := v2NetworkProvenance(test.originSource, test.echModeSource); got != test.want {
			t.Fatalf("provenance(%q, %q) = %q, want %q",
				test.originSource, test.echModeSource, got, test.want)
		}
	}
}

func TestV2PeerCommandsRejectNetworkOverrides(t *testing.T) {
	for _, args := range [][]string{
		{"send", "laptop", "-m", "hello", "--url", "https://other.example.com"},
		{"send", "laptop", "-m", "hello", "--ech-mode", "off"},
		{"receive", "laptop", "--doh-url", "https://dns.example.com/dns-query"},
		{"sync", "laptop", "--url", "https://other.example.com"},
	} {
		a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		err := a.run(args)
		if err == nil || !strings.Contains(err.Error(), "conflicts with the paired peer profile") {
			t.Fatalf("%v produced %v", args, err)
		}
	}
}

func TestV2DoctorReportsEffectiveNetworkSources(t *testing.T) {
	setTestV2Homes(t)
	clearV2NetworkEnvironment(t)
	if _, _, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &stubV2Transport{}, nil }
	t.Setenv("DUD_DOH_URL", "https://dns.quad9.net/dns-query")
	if code := a.main([]string{"doctor", "--url", "https://cli.example.com", "--json"}); code != 0 {
		t.Fatalf("doctor code = %d", code)
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	origins, ok := report["origins"].([]any)
	if !ok || len(origins) != 1 {
		t.Fatalf("doctor origins = %#v", report["origins"])
	}
	origin := origins[0].(map[string]any)
	sources := origin["network_sources"].(map[string]any)
	if origin["base_url"] != "https://cli.example.com" || sources["base_url"] != v2NetworkSourceCLI {
		t.Fatalf("doctor base URL = %v (%v)", origin["base_url"], sources["base_url"])
	}
	if origin["doh_url"] != "https://dns.quad9.net/dns-query" || sources["doh_url"] != v2NetworkSourceEnvironment {
		t.Fatalf("doctor DoH URL = %v (%v)", origin["doh_url"], sources["doh_url"])
	}
	if origin["ech_mode"] != "hard" || sources["ech_mode"] != v2NetworkSourceConfig {
		t.Fatalf("doctor ECH mode = %v (%v)", origin["ech_mode"], sources["ech_mode"])
	}
}

// The global target still follows the environment while a peer target keeps the
// origin it was paired against, and the report says so in both places.
func TestV2DoctorSeparatesTheGlobalEnvironmentFromPinnedPeers(t *testing.T) {
	setTestV2Homes(t)
	clearV2NetworkEnvironment(t)
	if _, _, err := initializeV2Config(
		"laptop",
		"https://config.example.com",
		"https://dns.google/dns-query",
		"hard",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers["desktop"] = v2PeerProfile{
			Status:  "active",
			BaseURL: "https://peer.example.com",
			ECHMode: "hard",
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DUD_BASE_URL", "https://env.example.com")

	report, code, _ := runDoctorJSON(t)
	if code != 0 {
		t.Fatalf("doctor code = %d", code)
	}
	origins, ok := report["origins"].([]any)
	if !ok || len(origins) != 2 {
		t.Fatalf("doctor origins = %#v", report["origins"])
	}
	global := origins[0].(map[string]any)
	globalSources := global["network_sources"].(map[string]any)
	if global["base_url"] != "https://env.example.com" ||
		globalSources["base_url"] != v2NetworkSourceEnvironment {
		t.Fatalf("global origin = %v (%v)", global["base_url"], globalSources["base_url"])
	}
	if _, exists := global["pinned"]; exists {
		t.Fatalf("global origin carries a pinned profile: %#v", global)
	}
	peer := origins[1].(map[string]any)
	peerSources := peer["network_sources"].(map[string]any)
	if peer["base_url"] != "https://peer.example.com" ||
		peerSources["base_url"] != v2NetworkSourcePeer {
		t.Fatalf("peer origin = %v (%v)", peer["base_url"], peerSources["base_url"])
	}
	pinned, ok := peer["pinned"].(map[string]any)
	if !ok || pinned["base_url"] != "https://peer.example.com" || pinned["doh_url"] != "" {
		t.Fatalf("peer pinned profile = %#v", peer["pinned"])
	}

	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &stubV2Transport{}, nil }
	if code := a.main([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor code = %d", code)
	}
	for _, want := range []string{
		"url        https://env.example.com       (environment)",
		"url        https://peer.example.com      (peer)",
		"Note: DUD_BASE_URL set in the environment, but this peer pins its own",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor text omitted %q: %s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "pinned url") {
		t.Fatalf("doctor rendered a pinned row without a divergence: %s", stdout.String())
	}

	// An explicit override does outrank the profile, and then the report shows
	// the pinned origin it displaced.
	stdout.Reset()
	a = newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &stubV2Transport{}, nil }
	if code := a.main([]string{"doctor", "--url", "https://cli.example.com"}); code != 0 {
		t.Fatalf("doctor code = %d", code)
	}
	for _, want := range []string{
		"url         https://cli.example.com       (cli)",
		"pinned url  https://peer.example.com      (peer profile)",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor text omitted %q: %s", want, stdout.String())
		}
	}
}

func TestV2DoctorTextReportsTheResolvedLayer(t *testing.T) {
	setTestV2Homes(t)
	clearV2NetworkEnvironment(t)
	if _, _, err := initializeV2Config(
		"desktop",
		"https://dud.example.com",
		"https://dns.google/dns-query",
		"hard",
	); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &stubV2Transport{}, nil }
	if code := a.main([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor code = %d", code)
	}
	for _, want := range []string{
		"Origin: global",
		"url        https://dud.example.com       (config)",
		"doh        https://dns.google/dns-query  (config)",
		"ech        hard                          (config)",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor text omitted %q: %s", want, stdout.String())
		}
	}
}
