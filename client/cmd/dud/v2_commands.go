// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (a *app) cmdInit(args []string) error {
	device := ""
	baseURL := a.cfg.BaseURL
	dohURL := a.cfg.DOHURL
	echMode := a.cfg.ECHMode
	jsonOutput := false
	for len(args) != 0 {
		switch args[0] {
		case "--device":
			if err := needValue(args, "--device"); err != nil {
				return err
			}
			device, args = args[1], args[2:]
		case "--url":
			if err := needValue(args, "--url"); err != nil {
				return err
			}
			baseURL, args = args[1], args[2:]
		case "--doh-url":
			if err := needValue(args, "--doh-url"); err != nil {
				return err
			}
			dohURL, args = args[1], args[2:]
		case "--ech-mode":
			if err := needValue(args, "--ech-mode"); err != nil {
				return err
			}
			echMode, args = args[1], args[2:]
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
			args = args[1:]
		default:
			return fatalError("Unknown init option: " + args[0])
		}
	}
	if device == "" {
		return fatalError("dud init requires --device NAME")
	}
	cfg, paths, err := initializeV2Config(device, baseURL, dohURL, echMode)
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(a.out, map[string]any{
			"initialized": true,
			"device":      cfg.Device,
			"device_id":   cfg.Identity.DeviceID,
			"root":        paths.Root,
			"config_dir":  paths.ConfigDir,
			"state_dir":   paths.StateDir,
			"ech_mode":    cfg.ECHMode,
		})
	}
	fmt.Fprintf(a.out, "Initialized device %q for peer transfers.\n", cfg.Device)
	report := &textReport{}
	section := report.section("")
	section.add("Device", cfg.Device)
	section.add("Root", paths.Root)
	section.add("Config", paths.Config)
	section.add("State", paths.StateDir)
	return report.write(a.out)
}

func (a *app) cmdConfig(args []string) error {
	if len(args) == 0 {
		return fatalError("Usage: dud config show|validate [--json]")
	}
	subcommand := args[0]
	jsonOutput, err := onlyJSONOption(args[1:])
	if err != nil {
		return err
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	switch subcommand {
	case "show":
		value := redactedV2Config(cfg)
		if jsonOutput {
			return writeJSON(a.out, value)
		}
		report := &textReport{}
		section := report.section("")
		section.add("Device", cfg.Device)
		section.add("Device ID", cfg.Identity.DeviceID)
		section.add("URL", cfg.BaseURL)
		section.add("DoH", cfg.DOHURL)
		section.add("ECH", cfg.ECHMode)
		section.add("Seed", "<private>")
		section.addf("Peers", "%d", len(cfg.Peers))
		return report.write(a.out)
	case "validate":
		if err := validatePrivateV2File(paths.Config); err != nil {
			return err
		}
		if err := validatePrivateV2File(paths.Seed); err != nil {
			return err
		}
		if _, err := loadV2MasterSeed(paths); err != nil {
			return err
		}
		if jsonOutput {
			return writeJSON(a.out, map[string]any{"valid": true, "version": cfg.Version})
		}
		fmt.Fprintln(a.out, "Configuration is valid.")
		return nil
	default:
		return fatalError("Unknown config command: " + subcommand)
	}
}

func (a *app) cmdMigrate(args []string) error {
	jsonOutput, err := onlyJSONOption(args)
	if err != nil {
		return err
	}
	paths, err := resolveV2Paths()
	if err != nil {
		return err
	}
	if err := validatePrivateV2File(paths.Config); err != nil {
		return err
	}
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return err
	}
	defer unlock()
	body, err := os.ReadFile(paths.Config)
	if err != nil {
		return err
	}
	cfg, err := parseV2Config(body)
	if err != nil {
		return err
	}
	if cfg.Version != v2ConfigSchemaVersion {
		return fmt.Errorf("local peer state is at an unsupported schema version and cannot be migrated; %s", v2LocalStateResetInstruction)
	}
	if jsonOutput {
		return writeJSON(a.out, map[string]any{"migrated": false, "from": cfg.Version, "to": cfg.Version})
	}
	fmt.Fprintf(a.out, "Configuration is already at schema version %d.\n", v2ConfigSchemaVersion)
	return nil
}

func (a *app) cmdPeer(args []string) error {
	if len(args) == 0 {
		return fatalError("Usage: dud peer invite|accept|list|show|rename|resume|revoke|remove|enrollment-key ...")
	}
	switch args[0] {
	case "enrollment-key":
		return a.cmdPeerEnrollmentKey(args[1:])
	case "accept":
		return a.cmdPeerAccept(args[1:])
	case "list":
		return a.cmdPeerList(args[1:])
	case "show":
		return a.cmdPeerShow(args[1:])
	case "rename":
		return a.cmdPeerRename(args[1:])
	case "remove":
		return a.cmdPeerRemove(args[1:])
	case "invite":
		return a.cmdPeerInvite(args[1:])
	case "resume":
		return a.cmdPeerResume(args[1:])
	case "revoke":
		return a.cmdPeerRevoke(args[1:])
	default:
		return fatalError("Unknown peer command: " + args[0])
	}
}

func (a *app) cmdPeerAccept(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fatalError("dud peer accept requires NAME")
	}
	alias := args[0]
	jsonOutput := false
	rest := args[1:]
	for len(rest) != 0 {
		switch rest[0] {
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
			rest = rest[1:]
		default:
			return fatalError("Unknown peer accept option: " + rest[0])
		}
	}
	if err := validateV2PeerAlias(alias); err != nil {
		return err
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	if pending, pendingErr := loadV2PendingPairing(paths, alias); pendingErr == nil && pending.Role == 1 {
		if pending.ExpiresAt > uint64(time.Now().Unix()) {
			// The pending pairing already fixed the origin both sides meet on;
			// everything else still resolves the way the first attempt did.
			peer := v2PeerProfile{BaseURL: pending.CanonicalOrigin}
			_, _, echMode, err := effectiveV2NetworkConfig(cfg, &peer)
			if err != nil {
				return err
			}
			transport, err := newV2PeerTransport(a, cfg, &peer, 30*time.Second)
			if err != nil {
				return err
			}
			if !jsonOutput {
				fmt.Fprintf(a.out, "Resuming pairing with %q...\n", alias)
			}
			if err := a.resumeV2Acceptance(paths, pending, transport); err != nil {
				return err
			}
			if err := ensureV2InviteePendingProfile(alias, pending, echMode); err != nil {
				return err
			}
			return a.waitV2Pairing(cfg, paths, pending, transport, jsonOutput)
		}
		_ = removeV2PendingPairing(paths, alias)
	}
	code, err := readV2TTYLine("Pairing code: ", false)
	if err != nil {
		return err
	}
	return a.acceptV2PeerInvitation(alias, code, jsonOutput)
}

func (a *app) cmdPeerList(args []string) error {
	jsonOutput, err := onlyJSONOption(args)
	if err != nil {
		return err
	}
	cfg, _, err := loadV2Config()
	if err != nil {
		return err
	}
	aliases := make([]string, 0, len(cfg.Peers))
	for alias := range cfg.Peers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	if jsonOutput {
		values := make([]map[string]any, 0, len(aliases))
		for _, alias := range aliases {
			values = append(values, redactedV2Peer(alias, cfg.Peers[alias]))
		}
		return writeJSON(a.out, values)
	}
	report := &textReport{}
	if len(aliases) == 0 {
		report.section("").add("Peers", "none")
		return report.write(a.out)
	}
	peers := report.section("")
	for _, alias := range aliases {
		peers.add(alias, displayV2PeerStatus(cfg.Peers[alias].Status))
	}
	return report.write(a.out)
}

// displayV2PeerStatus uppercases a peer status for the human-readable listings
// only. The stored and JSON forms stay lower case, because they are the values
// the configuration validates and other tools parse.
func displayV2PeerStatus(status string) string {
	return strings.ToUpper(status)
}

func (a *app) cmdPeerShow(args []string) error {
	if len(args) == 0 {
		return fatalError("dud peer show requires NAME")
	}
	alias := args[0]
	jsonOutput, err := onlyJSONOption(args[1:])
	if err != nil {
		return err
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	peer, exists := cfg.Peers[alias]
	if !exists {
		return fmt.Errorf("unknown peer %q", alias)
	}
	settings, err := resolveV2Network(cfg, &peer, v2NetworkOverrides{})
	if err != nil {
		return err
	}
	value := redactedV2Peer(alias, peer)
	value["effective_base_url"] = settings.BaseURL.Value
	value["effective_doh_url"] = settings.DOHURL.Value
	value["effective_ech_mode"] = settings.ECHMode.Value
	value["network_sources"] = settings.sources()
	pinned := pinnedV2Network(peer)
	value["pinned"] = pinned
	var status *v2DeliveryStatus
	if peer.Status == "active" && peer.RelationshipID != "" {
		if state, stateErr := loadV2PeerDeliveryState(paths, peer.RelationshipID); stateErr == nil {
			resolved := v2DeliveryStatusOf(state)
			status = &resolved
			resolved.merge(value)
			value["capabilities_issued_at"] = state.CapabilitiesIssuedAt
			value["capabilities_expire_at"] = state.CapabilitiesExpireAt
			value["capability_reissues"] = state.CapabilityReissues
		} else {
			value["delivery_state_error"] = stateErr.Error()
		}
	}
	if jsonOutput {
		return writeJSON(a.out, value)
	}
	report := &textReport{}
	header := report.section("")
	header.add("Peer", alias)
	header.add("Status", displayV2PeerStatus(peer.Status))

	profile := report.section("Profile")
	profile.addf("key epoch", "%d", peer.KeyEpoch)
	profile.addNote("url", settings.BaseURL.Value, settings.BaseURL.Source)
	profile.addNote("doh", settings.DOHURL.Value, settings.DOHURL.Source)
	profile.addNote("ech", settings.ECHMode.Value, settings.ECHMode.Source)
	renderPinnedV2Network(profile, pinned, settings)
	profile.add("git remote", peer.GitRemote)
	profile.addf("capability", "%v", value["capability"])

	if status != nil {
		delivery := report.section("Delivery")
		delivery.addRows(status.rows())
		delivery.addf("last successful drain", "%d", status.LastSuccessfulDrain)
		delivery.addf("capabilities issued at", "%v", value["capabilities_issued_at"])
		delivery.addf("capabilities expire at", "%v", value["capabilities_expire_at"])
		delivery.addf("capability reissues", "%v", value["capability_reissues"])
	} else if failure, exists := value["delivery_state_error"]; exists {
		report.section("Delivery").addf("state error", "%v", failure)
	}
	return report.write(a.out)
}

func (a *app) cmdPeerRename(args []string) error {
	if len(args) < 2 {
		return fatalError("dud peer rename requires OLD NEW")
	}
	oldAlias, newAlias := args[0], args[1]
	jsonOutput, err := onlyJSONOption(args[2:])
	if err != nil {
		return err
	}
	if err := validateV2PeerAlias(newAlias); err != nil {
		return err
	}
	_, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(pairingStatePath(paths, oldAlias)); err == nil {
		return fmt.Errorf("peer %q has a pending pairing and cannot be renamed", oldAlias)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check pending pairing for peer %q: %w", oldAlias, err)
	}
	cfg, err := updateV2Config(func(cfg *v2LocalConfig) error {
		peer, exists := cfg.Peers[oldAlias]
		if !exists {
			return fmt.Errorf("unknown peer %q", oldAlias)
		}
		if _, exists := cfg.Peers[newAlias]; exists {
			return fmt.Errorf("peer %q already exists", newAlias)
		}
		delete(cfg.Peers, oldAlias)
		if peer.GitRemote == oldAlias {
			peer.GitRemote = newAlias
		}
		cfg.Peers[newAlias] = peer
		return nil
	})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(a.out, redactedV2Peer(newAlias, cfg.Peers[newAlias]))
	}
	fmt.Fprintf(a.out, "Renamed peer %q to %q.\n", oldAlias, newAlias)
	return nil
}

func (a *app) cmdPeerRemove(args []string) error {
	if len(args) == 0 {
		return fatalError("dud peer remove requires NAME --yes")
	}
	alias := args[0]
	confirmed := false
	jsonOutput := false
	for _, arg := range args[1:] {
		switch arg {
		case "--yes":
			confirmed = true
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
		default:
			return fatalError("Unknown peer remove option: " + arg)
		}
	}
	if !confirmed {
		return fatalError("dud peer remove is destructive; rerun with --yes")
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	if pending, pendingErr := loadV2PendingPairing(paths, alias); pendingErr == nil {
		if pending.ExpiresAt > uint64(time.Now().Unix()) {
			peer := cfg.Peers[alias]
			peer.BaseURL = pending.CanonicalOrigin
			transport, err := newV2PeerTransport(a, cfg, &peer, 30*time.Second)
			if err != nil {
				return err
			}
			bearer, err := decodeV2Base64URL(pending.StatusCapability, 32)
			if err != nil {
				return err
			}
			path := "/v2/pairing/rendezvous/" + pending.RendezvousLocator
			if _, err := doV2CBORRequest(context.Background(), transport, "DELETE", pending.CanonicalOrigin, path, bearer, nil, v2MaxDescriptorBytes); err != nil {
				return fmt.Errorf("cancel pending pairing: %w", err)
			}
		}
		if err := removeV2PendingPairing(paths, alias); err != nil {
			return err
		}
	}
	_, err = updateV2Config(func(cfg *v2LocalConfig) error {
		if _, exists := cfg.Peers[alias]; !exists {
			return fmt.Errorf("unknown peer %q", alias)
		}
		delete(cfg.Peers, alias)
		return nil
	})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(a.out, map[string]any{"removed": true, "alias": alias})
	}
	fmt.Fprintf(a.out, "Removed peer %q.\n", alias)
	return nil
}

func (a *app) cmdDoctor(args []string) error {
	jsonOutput := false
	overrides := v2NetworkOverrides{}
	for len(args) != 0 {
		matched, rest, err := parseV2NetworkOption(args, &overrides)
		if err != nil {
			return err
		}
		if matched {
			args = rest
			continue
		}
		matched, rest, err = parseJSONOption(args, &jsonOutput)
		if err != nil {
			return err
		}
		if !matched {
			return fatalError("Unknown doctor option: " + args[0])
		}
		args = rest
	}
	cfg, paths, err := loadV2Config()
	if err != nil {
		return err
	}
	bootstrap := v2BootstrapAddresses(cfg)
	targets := []doctorTarget{}
	globalSettings, err := resolveV2Network(cfg, nil, overrides)
	if err != nil {
		return err
	}
	targets = append(targets, doctorTarget{Label: "global", Settings: globalSettings})
	aliases := make([]string, 0, len(cfg.Peers))
	for alias := range cfg.Peers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		peer := cfg.Peers[alias]
		peerSettings, err := resolveV2Network(cfg, &peer, overrides)
		if err != nil {
			return err
		}
		delivery := map[string]any{}
		var status *v2DeliveryStatus
		if peer.Status == "active" && peer.RelationshipID != "" {
			if state, stateErr := loadV2PeerDeliveryState(paths, peer.RelationshipID); stateErr == nil {
				value := v2DeliveryStatusOf(state)
				status = &value
				delivery = value.fields()
			} else {
				delivery["state_error"] = stateErr.Error()
			}
		}
		targets = append(targets, doctorTarget{
			Label:    "peer:" + alias,
			Settings: peerSettings,
			Pinned:   pinnedV2Network(peer),
			Status:   status,
			Delivery: delivery,
		})
	}
	ctx := context.Background()
	results := make([]map[string]any, 0, len(targets))
	allOK := true
	for _, target := range targets {
		baseURL, dohURL, echMode := target.Settings.values()
		if echMode == "off" && !jsonOutput {
			fmt.Fprintf(a.errOut, "WARNING: %s uses v2 ECH off mode; the target hostname is visible in TLS SNI.\n", target.Label)
		}
		dohHost := ""
		if parsed, parseErr := url.Parse(dohURL); parseErr == nil {
			dohHost = strings.ToLower(parsed.Hostname())
		}
		wellKnown := isWellKnownV2Resolver(dohHost)
		result := map[string]any{
			"label":                target.Label,
			"base_url":             baseURL,
			"doh_url":              dohURL,
			"doh_bootstrap_pinned": len(bootstrap) != 0,
			"doh_resolver_public":  wellKnown,
			"ech_mode":             echMode,
			"network_sources":      target.Settings.sources(),
		}
		if target.Pinned != nil {
			result["pinned"] = target.Pinned
		}
		if len(target.Delivery) != 0 {
			result["delivery"] = target.Delivery
		}
		capabilities, transportStatus, transportErr := a.fetchV2Capabilities(
			ctx,
			target.Settings,
			bootstrap,
		)
		if transportErr != nil {
			allOK = false
			result["ok"] = false
			result["error"] = transportErr.Error()
		} else {
			result["ok"] = true
			result["transport_status"] = transportStatus
			result["capabilities"] = renderV2Capabilities(capabilities)
		}
		results = append(results, result)
	}
	local := v2LocalDiagnostics(cfg, paths)
	if local["ok"] != true {
		allOK = false
	}
	report := map[string]any{
		"ok":          allOK,
		"device":      cfg.Device,
		"device_id":   cfg.Identity.DeviceID,
		"config_file": paths.Config,
		"local":       local,
		"tools":       a.v2ToolDiagnostics(),
		"origins":     results,
	}
	if jsonOutput {
		if err := writeJSON(a.out, report); err != nil {
			return err
		}
		if !allOK {
			return fatalError("")
		}
		return nil
	}
	if err := a.renderDoctorReport(report, results, targets, len(bootstrap) != 0).write(a.out); err != nil {
		return err
	}
	if !allOK {
		return fatalError("")
	}
	return nil
}

// doctorTarget pairs one origin the report checks with the durable local state
// that belongs to it. Only peer origins carry delivery state and a pinned
// profile; the global origin is a transport check alone.
type doctorTarget struct {
	Label    string
	Settings v2NetworkSettings
	Pinned   map[string]any
	Status   *v2DeliveryStatus
	Delivery map[string]any
}

// renderDoctorReport turns the report the JSON mode emits into its text form.
// Both modes read the same values, so a field added to one is a row added here.
func (a *app) renderDoctorReport(
	report map[string]any,
	results []map[string]any,
	targets []doctorTarget,
	bootstrapPinned bool,
) *textReport {
	out := &textReport{}
	header := out.section("")
	header.addf("Device", "%v (%v)", report["device"], report["device_id"])
	header.addf("Config", "%v", report["config_file"])

	local, _ := report["local"].(map[string]any)
	state := out.section("Local state")
	state.addf("peers", "%v", local["peers"])
	state.addf("schema", "v%v", local["schema_version"])
	issues, _ := local["issues"].([]string)
	if len(issues) == 0 {
		state.add("issues", "none")
	} else {
		state.addList("issues", strconv.Itoa(len(issues)), issues)
	}
	state.addf("admin capability", "%v", local["admin_capability"])

	tools, _ := report["tools"].(map[string]any)
	toolSection := out.section("Tools")
	for _, name := range sortedKeys(tools) {
		entry, _ := tools[name].(map[string]any)
		toolSection.add(name, v2ToolState(entry["available"] == true))
	}

	for index, result := range results {
		sources, _ := result["network_sources"].(map[string]any)
		origin := out.section("Origin: " + doctorOriginTitle(result["label"]))
		origin.addNote("url", fmt.Sprint(result["base_url"]), fmt.Sprint(sources["base_url"]))
		origin.addNote("doh", fmt.Sprint(result["doh_url"]), fmt.Sprint(sources["doh_url"]))
		origin.addNote("ech", fmt.Sprint(result["ech_mode"]), fmt.Sprint(sources["ech_mode"]))
		renderPinnedV2Network(origin, targets[index].Pinned, targets[index].Settings)
		if result["ok"] == true {
			origin.addf("transport", "ok (HTTP %v)", result["transport_status"])
		} else {
			origin.addf("transport", "FAILED (%v)", result["error"])
		}
		if result["doh_resolver_public"] == false && !bootstrapPinned {
			parsed, _ := url.Parse(fmt.Sprint(result["doh_url"]))
			origin.notef(
				"Note: the system resolver sees the distinctive DoH hostname %q; "+
					"configure pinned bootstrap addresses to avoid that lookup.",
				strings.ToLower(parsed.Hostname()),
			)
		}
		if status := targets[index].Status; status != nil {
			status.renderInto(origin, "Delivery")
		} else if delivery, ok := result["delivery"].(map[string]any); ok {
			if stateError, failed := delivery["state_error"]; failed {
				origin.child("Delivery").addf("state", "unavailable (%v)", stateError)
			}
		}
	}
	return out
}

// doctorOriginTitle spells the JSON label for a human. The label itself stays
// machine-shaped ("peer:laptop") because scripts match on it.
func doctorOriginTitle(label any) string {
	text := fmt.Sprint(label)
	if alias, found := strings.CutPrefix(text, "peer:"); found {
		return "peer " + alias
	}
	return text
}

// effectiveV2NetworkConfig resolves the network options of a command that
// accepts no command-line overrides. Every other layer still applies in the
// fixed order documented on resolveV2Network.
func effectiveV2NetworkConfig(cfg *v2LocalConfig, peer *v2PeerProfile) (string, string, string, error) {
	settings, err := resolveV2Network(cfg, peer, v2NetworkOverrides{})
	if err != nil {
		return "", "", "", err
	}
	baseURL, dohURL, echMode := settings.values()
	return baseURL, dohURL, echMode, nil
}

func redactedV2Peer(alias string, peer v2PeerProfile) map[string]any {
	capability := "absent"
	if peer.InboxCapabilityReference != "" {
		capability = "<redacted>"
	}
	return map[string]any{
		"alias":                   alias,
		"status":                  peer.Status,
		"relationship_id":         peer.RelationshipID,
		"key_epoch":               peer.KeyEpoch,
		"peer_pseudonymous_id":    peer.PeerPseudonymousID,
		"peer_age_recipient":      peer.PeerAgeRecipient,
		"peer_signing_public_key": peer.PeerSigningPublicKey,
		"base_url":                peer.BaseURL,
		"doh_url":                 peer.DOHURL,
		"ech_mode":                peer.ECHMode,
		"git_remote":              peer.GitRemote,
		"capability":              capability,
	}
}

func isWellKnownV2Resolver(host string) bool {
	switch host {
	case "cloudflare-dns.com", "one.one.one.one", "dns.google", "dns.quad9.net":
		return true
	default:
		return false
	}
}

// v2LocalDiagnostics reports the health of local V2 state without disclosing
// any of it. Paths are the operator's own, and everything else is a count, a
// schema version, or a fixed problem description.
//
// Reaching this function means loadV2Config already refused to continue unless
// the configuration and seed files were regular and mode 0600, so the checks
// here are the ones nothing else enforces.
func v2LocalDiagnostics(cfg *v2LocalConfig, paths v2Paths) map[string]any {
	issues := []string{}
	for label, path := range map[string]string{
		"root directory":          paths.Root,
		"configuration directory": paths.ConfigDir,
		"state directory":         paths.StateDir,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			issues = append(issues, label+" is unavailable")
			continue
		}
		if !info.IsDir() {
			issues = append(issues, label+" is not a directory")
			continue
		}
		if info.Mode().Perm()&0o077 != 0 {
			issues = append(issues, label+" is group- or world-accessible")
		}
	}
	adminCapability := "absent"
	if err := validatePrivateV2File(paths.AdminCapability); err == nil {
		adminCapability = "present"
	} else if !errors.Is(err, os.ErrNotExist) {
		adminCapability = "present"
		issues = append(issues, "administrative capability file is not private (expected mode 0600)")
	}
	statuses := map[string]int{}
	for _, peer := range cfg.Peers {
		statuses[peer.Status]++
	}
	sort.Strings(issues)
	return map[string]any{
		"ok":               len(issues) == 0,
		"root":             paths.Root,
		"config_dir":       paths.ConfigDir,
		"state_dir":        paths.StateDir,
		"schema_version":   cfg.Version,
		"private_files":    "verified",
		"admin_capability": adminCapability,
		"peers":            len(cfg.Peers),
		"peer_statuses":    statuses,
		"issues":           issues,
		"summary": fmt.Sprintf("%d peer(s), schema v%d, %d issue(s)",
			len(cfg.Peers), cfg.Version, len(issues)),
	}
}

// v2ToolDiagnostics reports which external binaries the client resolved. It
// records the configured name and whether it is executable, never a version
// banner, because a banner is host fingerprinting the report does not need.
// `curl` is absent by design: the client carries its own transport in Go, in
// both transfer modes.
func (a *app) v2ToolDiagnostics() map[string]any {
	tools := map[string]any{}
	for name, binary := range map[string]string{
		"age":        a.cfg.AgeBin,
		"age-keygen": a.cfg.AgeKeygenBin,
		"git":        a.cfg.GitBin,
		"qrencode":   a.cfg.QREncodeBin,
	} {
		resolved, err := exec.LookPath(binary)
		tools[name] = map[string]any{
			"configured": binary,
			"resolved":   resolved,
			"available":  err == nil,
		}
	}
	return tools
}

// v2ToolState is the one spelling every report uses for a resolved external
// binary, so "missing" reads the same in doctor as it does anywhere else.
func v2ToolState(available bool) string {
	if available {
		return "ok"
	}
	return "missing"
}
