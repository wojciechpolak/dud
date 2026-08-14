// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"fmt"
	"os"
	"strings"
)

// Compiled defaults. They are the last layer of every network option and are
// shared with the V1 configuration loader so the two cannot drift apart.
const (
	v2DefaultBaseURL = "https://dud.example.com"
	v2DefaultDOHURL  = "https://cloudflare-dns.com/dns-query"
	v2DefaultECHMode = "hard"
)

// Layer names, ordered from the strongest to the weakest.
const (
	v2NetworkSourceCLI         = "cli"
	v2NetworkSourceEnvironment = "environment"
	v2NetworkSourcePeer        = "peer"
	v2NetworkSourceConfig      = "config"
	v2NetworkSourceDefault     = "default"
)

// v2NetworkOverrides carries the explicit command-line network options of the
// commands that accept them. Peer-scoped commands deliberately reject these
// options instead of overriding a paired relationship's pinned origin.
type v2NetworkOverrides struct {
	BaseURL string
	DOHURL  string
	ECHMode string
}

type v2NetworkOption struct {
	Value  string
	Source string
}

type v2NetworkSettings struct {
	BaseURL v2NetworkOption
	DOHURL  v2NetworkOption
	ECHMode v2NetworkOption
}

func (settings v2NetworkSettings) values() (string, string, string) {
	return settings.BaseURL.Value, settings.DOHURL.Value, settings.ECHMode.Value
}

func (settings v2NetworkSettings) sources() map[string]any {
	return map[string]any{
		"base_url": settings.BaseURL.Source,
		"doh_url":  settings.DOHURL.Source,
		"ech_mode": settings.ECHMode.Source,
	}
}

type v2NetworkLayer struct {
	source string
	value  string
}

// firstV2NetworkLayer returns the strongest layer that supplied a value. The
// compiled default is always last and always set, so the result is total.
func firstV2NetworkLayer(layers ...v2NetworkLayer) v2NetworkOption {
	for _, layer := range layers {
		if layer.value != "" {
			return v2NetworkOption{Value: layer.value, Source: layer.source}
		}
	}
	return v2NetworkOption{}
}

func v2NetworkLayerName(source, option string) string {
	switch source {
	case v2NetworkSourceCLI:
		return option
	case v2NetworkSourceEnvironment:
		switch option {
		case "--url":
			return "DUD_BASE_URL"
		case "--doh-url":
			return "DUD_DOH_URL"
		default:
			return "DUD_ECH_MODE"
		}
	case v2NetworkSourcePeer:
		return "the peer profile"
	case v2NetworkSourceConfig:
		return "the local configuration"
	default:
		return "the compiled default"
	}
}

// v2NetworkProvenance names the layers that chose a target and its ECH mode.
// A resolution failure otherwise reports a hostname the reader never typed —
// a dead drop command falling back to the compiled default base URL and a peer
// command reading a pinned origin out of the profile produce the same sentence
// — so the layer to correct is part of the error rather than something to
// rediscover. Sources are diagnostic only: an empty one drops its clause.
func v2NetworkProvenance(originSource, echModeSource string) string {
	clauses := []string{}
	if originSource != "" {
		clauses = append(clauses, "target from "+v2NetworkLayerName(originSource, "--url"))
	}
	if echModeSource != "" {
		clauses = append(clauses, "ECH mode from "+v2NetworkLayerName(echModeSource, "--ech-mode"))
	}
	if len(clauses) == 0 {
		return ""
	}
	return " (" + strings.Join(clauses, ", ") + ")"
}

// resolveV2Network applies one fixed precedence to every network option:
// command line, peer profile, environment, local configuration, compiled
// default. Values that did not come from the already-validated configuration
// are canonicalized here so an override cannot introduce an origin form that
// silently fails signature binding later.
//
// The peer profile deliberately outranks the environment. A paired relationship
// pins the origin that every one of its signed descriptors is bound to, and the
// DUD_* variables are ambient: they are also the only way to point dead drop
// commands at a deployment, so a shell that exports them for drops must not
// silently retarget a peer. An explicit per-invocation override still wins,
// which is why peer-scoped commands reject the command-line options outright.
func resolveV2Network(
	cfg *v2LocalConfig,
	peer *v2PeerProfile,
	cli v2NetworkOverrides,
) (v2NetworkSettings, error) {
	peerBaseURL, peerDOHURL, peerECHMode := "", "", ""
	if peer != nil {
		peerBaseURL, peerDOHURL, peerECHMode = peer.BaseURL, peer.DOHURL, peer.ECHMode
	}
	configBaseURL, configDOHURL, configECHMode := "", "", ""
	if cfg != nil {
		configBaseURL, configDOHURL, configECHMode = cfg.BaseURL, cfg.DOHURL, cfg.ECHMode
	}
	settings := v2NetworkSettings{
		BaseURL: firstV2NetworkLayer(
			v2NetworkLayer{v2NetworkSourceCLI, cli.BaseURL},
			v2NetworkLayer{v2NetworkSourcePeer, peerBaseURL},
			v2NetworkLayer{v2NetworkSourceEnvironment, os.Getenv("DUD_BASE_URL")},
			v2NetworkLayer{v2NetworkSourceConfig, configBaseURL},
			v2NetworkLayer{v2NetworkSourceDefault, v2DefaultBaseURL},
		),
		DOHURL: firstV2NetworkLayer(
			v2NetworkLayer{v2NetworkSourceCLI, cli.DOHURL},
			v2NetworkLayer{v2NetworkSourcePeer, peerDOHURL},
			v2NetworkLayer{v2NetworkSourceEnvironment, os.Getenv("DUD_DOH_URL")},
			v2NetworkLayer{v2NetworkSourceConfig, configDOHURL},
			v2NetworkLayer{v2NetworkSourceDefault, v2DefaultDOHURL},
		),
		ECHMode: firstV2NetworkLayer(
			v2NetworkLayer{v2NetworkSourceCLI, cli.ECHMode},
			v2NetworkLayer{v2NetworkSourcePeer, peerECHMode},
			v2NetworkLayer{v2NetworkSourceEnvironment, os.Getenv("DUD_ECH_MODE")},
			v2NetworkLayer{v2NetworkSourceConfig, configECHMode},
			v2NetworkLayer{v2NetworkSourceDefault, v2DefaultECHMode},
		),
	}
	origin, err := canonicalV2Origin(settings.BaseURL.Value)
	if err != nil {
		return v2NetworkSettings{}, fmt.Errorf(
			"effective base URL from %s is not a canonical HTTPS origin: %w",
			v2NetworkLayerName(settings.BaseURL.Source, "--url"),
			err,
		)
	}
	settings.BaseURL.Value = origin
	doh, err := canonicalV2DOHURL(settings.DOHURL.Value)
	if err != nil {
		return v2NetworkSettings{}, fmt.Errorf(
			"effective DoH URL from %s is invalid: %w",
			v2NetworkLayerName(settings.DOHURL.Source, "--doh-url"),
			err,
		)
	}
	settings.DOHURL.Value = doh
	if settings.ECHMode.Value != "hard" && settings.ECHMode.Value != "off" {
		return v2NetworkSettings{}, fmt.Errorf(
			"effective ECH mode from %s must be either 'hard' or 'off'",
			v2NetworkLayerName(settings.ECHMode.Source, "--ech-mode"),
		)
	}
	return settings, nil
}

// pinnedV2Network reports the network options a peer profile pins for itself.
// Every key is present so a JSON consumer can read the object unconditionally;
// an empty value means the profile pins nothing for that option, which is the
// normal state of a peer that has not finished pairing.
func pinnedV2Network(peer v2PeerProfile) map[string]any {
	return map[string]any{
		"base_url": peer.BaseURL,
		"doh_url":  peer.DOHURL,
		"ech_mode": peer.ECHMode,
	}
}

// overriddenV2NetworkEnvironment names the DUD_* variables the peer profile
// outranked with a different value. Those variables are ambient — the same ones
// point dead drop commands at a deployment — so a report says when a pinned
// profile won instead of leaving the operator to wonder why an export had no
// effect. A variable that merely repeats what the profile pins overrode nothing
// and is not reported, which keeps the usual single-deployment shell quiet.
//
// The environment value is canonicalized before the comparison because the
// losing layer is never validated: only the winning value passed through
// resolveV2Network, so a spelling difference alone must not read as an override.
func overriddenV2NetworkEnvironment(settings v2NetworkSettings) []string {
	names := []string{}
	for _, resolved := range []struct {
		option    v2NetworkOption
		name      string
		canonical func(string) (string, error)
	}{
		{settings.BaseURL, "--url", canonicalV2Origin},
		{settings.DOHURL, "--doh-url", canonicalV2DOHURL},
		{settings.ECHMode, "--ech-mode", nil},
	} {
		variable := v2NetworkLayerName(v2NetworkSourceEnvironment, resolved.name)
		value := os.Getenv(variable)
		if value == "" || resolved.option.Source != v2NetworkSourcePeer {
			continue
		}
		if resolved.canonical != nil {
			if canonical, err := resolved.canonical(value); err == nil {
				value = canonical
			}
		}
		if value != resolved.option.Value {
			names = append(names, variable)
		}
	}
	return names
}

// renderPinnedV2Network adds what a peer profile pins to a report section that
// already carries the effective values. A row appears only where the two differ,
// so the common case — a paired peer used as it was paired — reads exactly as it
// did before this provenance existed. Reaching a row means either a command-line
// override is in play, or the profile pins nothing and a weaker layer supplied
// the value.
func renderPinnedV2Network(section *textSection, pinned map[string]any, settings v2NetworkSettings) {
	for _, row := range []struct {
		label  string
		key    string
		option v2NetworkOption
	}{
		{"pinned url", "base_url", settings.BaseURL},
		{"pinned doh", "doh_url", settings.DOHURL},
		{"pinned ech", "ech_mode", settings.ECHMode},
	} {
		value, _ := pinned[row.key].(string)
		if value == "" || value == row.option.Value {
			continue
		}
		section.addNote(row.label, value, "peer profile")
	}
	if overridden := overriddenV2NetworkEnvironment(settings); len(overridden) != 0 {
		section.notef(
			"Note: %s set in the environment, but this peer pins its own transport; "+
				"the pinned values are the ones in use.",
			joinValues(overridden),
		)
	}
}

// parseV2NetworkOption consumes one command-line network option. It reports
// whether args started with such an option so callers can keep their own
// option handling in one switch.
func parseV2NetworkOption(args []string, overrides *v2NetworkOverrides) (bool, []string, error) {
	if len(args) == 0 {
		return false, args, nil
	}
	target := map[string]*string{
		"--url":      &overrides.BaseURL,
		"--doh-url":  &overrides.DOHURL,
		"--ech-mode": &overrides.ECHMode,
	}[args[0]]
	if target == nil {
		return false, args, nil
	}
	if err := needValue(args, args[0]); err != nil {
		return true, args, err
	}
	if *target != "" {
		return true, args, fmt.Errorf("%s may be specified only once", args[0])
	}
	*target = args[1]
	return true, args[2:], nil
}

// v2PeerNetworkOptionError is the shared refusal for peer-scoped commands: a
// paired relationship pins its own origin and ECH mode, and a per-invocation
// override would silently break descriptor origin binding.
func v2PeerNetworkOptionError(option string) error {
	return fmt.Errorf("%s conflicts with the paired peer profile", option)
}
