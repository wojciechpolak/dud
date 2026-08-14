// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type v2LocalConfig struct {
	Version      int
	Device       string
	BaseURL      string
	DOHURL       string
	ECHMode      string
	DOHBootstrap []string
	Identity     v2LocalIdentity
	Peers        map[string]v2PeerProfile
}

const v2ConfigSchemaVersion = 3

const v2LocalStateResetInstruction = "erase local peer state with 'dud erase all --yes', initialize again with 'dud init', and re-pair"

type v2LocalIdentity struct {
	DeviceID string
	Seed     string
}

type v2PeerProfile struct {
	Status                   string
	RelationshipID           string
	KeyEpoch                 uint64
	PeerPseudonymousID       string
	PeerAgeRecipient         string
	PeerSigningPublicKey     string
	BaseURL                  string
	DOHURL                   string
	ECHMode                  string
	InboxCapabilityReference string
	GitRemote                string
}

type v2Paths struct {
	Root            string
	ConfigDir       string
	StateDir        string
	Config          string
	Seed            string
	AdminCapability string
	Lock            string
}

// v2DefaultWorldName is the world a bare invocation resolves. DUD_PROFILE may
// name it explicitly; that selects the same directory rather than a second one.
const v2DefaultWorldName = "default"

// resolveV2Root locates the directory that holds every world. DUD_HOME overrides
// it; the default keeps all peer state under a single directory so that no part
// of it lands on a path convention tells people to synchronize. The device
// master seed in particular must never sit under ~/.config, which dotfile
// managers routinely commit to a repository.
func resolveV2Root() (string, error) {
	if home := os.Getenv("DUD_HOME"); home != "" {
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("DUD_HOME must be an absolute path, got %q", home)
		}
		return filepath.Clean(home), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".dud"), nil
}

// resolveV2Paths locates the peer configuration and state directories. DUD_PROFILE
// selects a separate world: one device identity, one seed, one administrative
// capability, and one peer graph live under each, so testing a second deployment
// is a second profile rather than a second peer. Configuration and state remain
// separate directories inside a world, so only the roots moved. Dead drop
// commands read no configuration file and are unaffected.
func resolveV2Paths() (v2Paths, error) {
	root, err := resolveV2Root()
	if err != nil {
		return v2Paths{}, err
	}
	world := v2DefaultWorldName
	if profile := os.Getenv("DUD_PROFILE"); profile != "" {
		if err := validateV2ProfileName(profile); err != nil {
			return v2Paths{}, err
		}
		world = profile
	}
	worldDir := filepath.Join(root, world)
	configDir := filepath.Join(worldDir, "config")
	stateDir := filepath.Join(worldDir, "state")
	return v2Paths{
		Root:            worldDir,
		ConfigDir:       configDir,
		StateDir:        stateDir,
		Config:          filepath.Join(configDir, "config.toml"),
		Seed:            filepath.Join(configDir, "seed"),
		AdminCapability: filepath.Join(configDir, "v2-admin-capability"),
		Lock:            filepath.Join(configDir, ".config.lock"),
	}, nil
}

func ensureV2Directories(paths v2Paths) error {
	for _, path := range []string{
		paths.Root,
		paths.ConfigDir,
		paths.StateDir,
		filepath.Join(paths.StateDir, "deliveries"),
		filepath.Join(paths.StateDir, "transfers"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func validatePrivateV2File(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is group- or world-accessible; expected mode 0600", path)
	}
	return nil
}

func acquireV2ConfigLock(paths v2Paths) (func(), error) {
	if err := ensureV2Directories(paths); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(paths.Lock, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another DUD process is updating local configuration")
	}
	if err := file.Truncate(0); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, err
	}
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}

func initializeV2Config(device, baseURL, dohURL, echMode string) (*v2LocalConfig, v2Paths, error) {
	if err := validateV2DeviceName(device); err != nil {
		return nil, v2Paths{}, err
	}
	origin, err := canonicalV2Origin(baseURL)
	if err != nil {
		return nil, v2Paths{}, fmt.Errorf("invalid base URL: %w", err)
	}
	doh, err := canonicalV2DOHURL(dohURL)
	if err != nil {
		return nil, v2Paths{}, err
	}
	if echMode != "hard" && echMode != "off" {
		return nil, v2Paths{}, errors.New("ECH mode must be either 'hard' or 'off'")
	}
	paths, err := resolveV2Paths()
	if err != nil {
		return nil, v2Paths{}, err
	}
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return nil, v2Paths{}, err
	}
	defer unlock()
	if _, err := os.Stat(paths.Config); err == nil {
		return nil, v2Paths{}, errors.New("this device is already initialized for peer transfers")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, v2Paths{}, err
	}
	seed := make([]byte, 32)
	deviceID := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return nil, v2Paths{}, err
	}
	if _, err := rand.Read(deviceID); err != nil {
		return nil, v2Paths{}, err
	}
	if err := atomicWriteV2File(paths.Seed, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, v2Paths{}, err
	}
	cfg := &v2LocalConfig{
		Version: v2ConfigSchemaVersion,
		Device:  device,
		BaseURL: origin,
		DOHURL:  doh,
		ECHMode: echMode,
		Identity: v2LocalIdentity{
			DeviceID: hex.EncodeToString(deviceID),
			Seed:     "seed",
		},
		Peers: map[string]v2PeerProfile{},
	}
	if err := writeV2Config(paths, cfg); err != nil {
		_ = os.Remove(paths.Seed)
		return nil, v2Paths{}, err
	}
	return cfg, paths, nil
}

func loadV2Config() (*v2LocalConfig, v2Paths, error) {
	paths, err := resolveV2Paths()
	if err != nil {
		return nil, v2Paths{}, err
	}
	if err := validatePrivateV2File(paths.Config); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, paths, errors.New("this device is not initialized for peer transfers; run 'dud init --device NAME'")
		}
		return nil, paths, err
	}
	body, err := os.ReadFile(paths.Config)
	if err != nil {
		return nil, paths, err
	}
	cfg, err := parseV2Config(body)
	if err != nil {
		return nil, paths, fmt.Errorf("parse %s: %w", paths.Config, err)
	}
	if cfg.Identity.Seed != "seed" {
		return nil, paths, errors.New("identity seed path must be the private file named 'seed'")
	}
	if err := validatePrivateV2File(paths.Seed); err != nil {
		return nil, paths, err
	}
	if err := validateV2Config(cfg); err != nil {
		return nil, paths, err
	}
	return cfg, paths, nil
}

func loadV2MasterSeed(paths v2Paths) ([]byte, error) {
	if err := validatePrivateV2File(paths.Seed); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(paths.Seed)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(seed) != 32 {
		return nil, errors.New("device master seed is invalid")
	}
	return seed, nil
}

func validateV2Config(cfg *v2LocalConfig) error {
	if cfg.Version != v2ConfigSchemaVersion {
		return fmt.Errorf("unsupported V2 config schema version %d; %s", cfg.Version, v2LocalStateResetInstruction)
	}
	if err := validateV2DeviceName(cfg.Device); err != nil {
		return err
	}
	if len(cfg.Identity.DeviceID) != 32 {
		return errors.New("config local device ID must be 128-bit lowercase hex")
	}
	if _, err := hex.DecodeString(cfg.Identity.DeviceID); err != nil || cfg.Identity.DeviceID != strings.ToLower(cfg.Identity.DeviceID) {
		return errors.New("config local device ID must be 128-bit lowercase hex")
	}
	origin, err := canonicalV2Origin(cfg.BaseURL)
	if err != nil || origin != cfg.BaseURL {
		return errors.New("config base URL is not a canonical HTTPS origin")
	}
	doh, err := canonicalV2DOHURL(cfg.DOHURL)
	if err != nil || doh != cfg.DOHURL {
		return errors.New("config DoH URL is not canonical HTTPS")
	}
	if cfg.ECHMode != "hard" && cfg.ECHMode != "off" {
		return errors.New("config ECH mode must be 'hard' or 'off'")
	}
	for _, raw := range cfg.DOHBootstrap {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("invalid DoH bootstrap address %q", raw)
		}
	}
	for alias, peer := range cfg.Peers {
		if err := validateV2PeerAlias(alias); err != nil {
			return err
		}
		if peer.Status != "unpaired" && peer.Status != "pending" && peer.Status != "active" && peer.Status != "revoked" {
			return fmt.Errorf("peer %q has invalid status %q", alias, peer.Status)
		}
		if peer.KeyEpoch != 0 {
			return fmt.Errorf("peer %q uses unsupported key epoch %d", alias, peer.KeyEpoch)
		}
		if peer.BaseURL != "" {
			peerOrigin, err := canonicalV2Origin(peer.BaseURL)
			if err != nil || peerOrigin != peer.BaseURL {
				return fmt.Errorf("peer %q has a non-canonical origin", alias)
			}
		}
		if peer.DOHURL != "" {
			peerDOH, err := canonicalV2DOHURL(peer.DOHURL)
			if err != nil || peerDOH != peer.DOHURL {
				return fmt.Errorf("peer %q has a non-canonical DoH URL", alias)
			}
		}
		if peer.ECHMode != "" && peer.ECHMode != "hard" && peer.ECHMode != "off" {
			return fmt.Errorf("peer %q has invalid ECH mode %q", alias, peer.ECHMode)
		}
	}
	return nil
}

func writeV2Config(paths v2Paths, cfg *v2LocalConfig) error {
	if err := validateV2Config(cfg); err != nil {
		return err
	}
	return atomicWriteV2File(paths.Config, formatV2Config(cfg), 0o600)
}

func updateV2Config(mutator func(*v2LocalConfig) error) (*v2LocalConfig, error) {
	cfg, paths, err := loadV2Config()
	if err != nil {
		return nil, err
	}
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// Reload after acquiring the lock so a completed writer cannot be lost.
	body, err := os.ReadFile(paths.Config)
	if err != nil {
		return nil, err
	}
	cfg, err = parseV2Config(body)
	if err != nil {
		return nil, err
	}
	if err := mutator(cfg); err != nil {
		return nil, err
	}
	if err := writeV2Config(paths, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func atomicWriteV2File(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	dirFile, err := os.Open(dir)
	if err == nil {
		defer dirFile.Close()
		return dirFile.Sync()
	}
	return nil
}

func formatV2Config(cfg *v2LocalConfig) []byte {
	var output strings.Builder
	fmt.Fprintf(&output, "version = %d\n", cfg.Version)
	fmt.Fprintf(&output, "device = %s\n", strconv.Quote(cfg.Device))
	fmt.Fprintf(&output, "base_url = %s\n", strconv.Quote(cfg.BaseURL))
	fmt.Fprintf(&output, "doh_url = %s\n", strconv.Quote(cfg.DOHURL))
	fmt.Fprintf(&output, "ech_mode = %s\n", strconv.Quote(cfg.ECHMode))
	if len(cfg.DOHBootstrap) != 0 {
		output.WriteString("doh_bootstrap = [")
		for i, value := range cfg.DOHBootstrap {
			if i != 0 {
				output.WriteString(", ")
			}
			output.WriteString(strconv.Quote(value))
		}
		output.WriteString("]\n")
	}
	output.WriteString("\n[identity]\n")
	fmt.Fprintf(&output, "device_id = %s\n", strconv.Quote(cfg.Identity.DeviceID))
	fmt.Fprintf(&output, "seed = %s\n", strconv.Quote(cfg.Identity.Seed))

	aliases := make([]string, 0, len(cfg.Peers))
	for alias := range cfg.Peers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		peer := cfg.Peers[alias]
		fmt.Fprintf(&output, "\n[peer.%s]\n", strconv.Quote(alias))
		writeV2TOMLString(&output, "status", peer.Status)
		if peer.RelationshipID != "" {
			writeV2TOMLString(&output, "relationship_id", peer.RelationshipID)
		}
		fmt.Fprintf(&output, "key_epoch = %d\n", peer.KeyEpoch)
		writeV2TOMLStringIfSet(&output, "peer_pseudonymous_id", peer.PeerPseudonymousID)
		writeV2TOMLStringIfSet(&output, "peer_age_recipient", peer.PeerAgeRecipient)
		writeV2TOMLStringIfSet(&output, "peer_signing_public_key", peer.PeerSigningPublicKey)
		writeV2TOMLStringIfSet(&output, "base_url", peer.BaseURL)
		writeV2TOMLStringIfSet(&output, "doh_url", peer.DOHURL)
		writeV2TOMLStringIfSet(&output, "ech_mode", peer.ECHMode)
		writeV2TOMLStringIfSet(&output, "inbox_capability", peer.InboxCapabilityReference)
		writeV2TOMLStringIfSet(&output, "git_remote", peer.GitRemote)
	}
	return []byte(output.String())
}

func writeV2TOMLString(output io.Writer, name, value string) {
	_, _ = fmt.Fprintf(output, "%s = %s\n", name, strconv.Quote(value))
}

func writeV2TOMLStringIfSet(output io.Writer, name, value string) {
	if value != "" {
		writeV2TOMLString(output, name, value)
	}
}

func parseV2Config(body []byte) (*v2LocalConfig, error) {
	cfg := &v2LocalConfig{Peers: map[string]v2PeerProfile{}}
	section := ""
	peerAlias := ""
	seenKeys := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: malformed table", lineNumber)
			}
			table := strings.TrimSpace(line[1 : len(line)-1])
			if table == "identity" {
				section, peerAlias = "identity", ""
				continue
			}
			if strings.HasPrefix(table, "peer.") {
				rawAlias := strings.TrimPrefix(table, "peer.")
				alias, err := strconv.Unquote(rawAlias)
				if err != nil {
					return nil, fmt.Errorf("line %d: peer alias must be quoted", lineNumber)
				}
				if err := validateV2PeerAlias(alias); err != nil {
					return nil, fmt.Errorf("line %d: %w", lineNumber, err)
				}
				section, peerAlias = "peer", alias
				if _, ok := cfg.Peers[alias]; ok {
					return nil, fmt.Errorf("line %d: duplicate peer %q", lineNumber, alias)
				}
				cfg.Peers[alias] = v2PeerProfile{}
				continue
			}
			return nil, fmt.Errorf("line %d: unknown table %q", lineNumber, table)
		}
		name, rawValue, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("line %d: expected key = value", lineNumber)
		}
		name = strings.TrimSpace(name)
		rawValue = strings.TrimSpace(rawValue)
		qualifiedName := section + "\x00" + peerAlias + "\x00" + name
		if seenKeys[qualifiedName] {
			return nil, fmt.Errorf("line %d: duplicate key %q", lineNumber, name)
		}
		seenKeys[qualifiedName] = true
		if err := assignV2ConfigValue(cfg, section, peerAlias, name, rawValue); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func assignV2ConfigValue(cfg *v2LocalConfig, section, alias, name, raw string) error {
	parseString := func() (string, error) {
		value, err := strconv.Unquote(raw)
		if err != nil {
			return "", fmt.Errorf("%s must be a quoted string", name)
		}
		return value, nil
	}
	parseUint := func() (uint64, error) {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s must be an unsigned integer", name)
		}
		return value, nil
	}
	if section == "" {
		switch name {
		case "version":
			value, err := parseUint()
			cfg.Version = int(value)
			return err
		case "device":
			value, err := parseString()
			cfg.Device = value
			return err
		case "base_url":
			value, err := parseString()
			cfg.BaseURL = value
			return err
		case "doh_url":
			value, err := parseString()
			cfg.DOHURL = value
			return err
		case "ech_mode":
			value, err := parseString()
			cfg.ECHMode = value
			return err
		case "doh_bootstrap":
			values, err := parseV2TOMLStringArray(raw)
			cfg.DOHBootstrap = values
			return err
		default:
			return fmt.Errorf("unknown root key %q", name)
		}
	}
	if section == "identity" {
		value, err := parseString()
		if err != nil {
			return err
		}
		switch name {
		case "device_id":
			cfg.Identity.DeviceID = value
		case "seed":
			cfg.Identity.Seed = value
		default:
			return fmt.Errorf("unknown identity key %q", name)
		}
		return nil
	}
	peer := cfg.Peers[alias]
	if name == "key_epoch" {
		value, err := parseUint()
		peer.KeyEpoch = value
		cfg.Peers[alias] = peer
		return err
	}
	value, err := parseString()
	if err != nil {
		return err
	}
	switch name {
	case "status":
		peer.Status = value
	case "relationship_id":
		peer.RelationshipID = value
	case "peer_pseudonymous_id":
		peer.PeerPseudonymousID = value
	case "peer_age_recipient":
		peer.PeerAgeRecipient = value
	case "peer_signing_public_key":
		peer.PeerSigningPublicKey = value
	case "base_url":
		peer.BaseURL = value
	case "doh_url":
		peer.DOHURL = value
	case "ech_mode":
		peer.ECHMode = value
	case "inbox_capability":
		peer.InboxCapabilityReference = value
	case "git_remote":
		peer.GitRemote = value
	default:
		return fmt.Errorf("unknown peer key %q", name)
	}
	cfg.Peers[alias] = peer
	return nil
}

func parseV2TOMLStringArray(raw string) ([]string, error) {
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return nil, errors.New("array must use square brackets")
	}
	content := strings.TrimSpace(raw[1 : len(raw)-1])
	if content == "" {
		return nil, nil
	}
	parts := strings.Split(content, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Unquote(strings.TrimSpace(part))
		if err != nil {
			return nil, errors.New("array values must be quoted strings")
		}
		result = append(result, value)
	}
	return result, nil
}

func validateV2PeerAlias(alias string) error {
	if len(alias) == 0 || len(alias) > 64 {
		return errors.New("peer alias must contain 1 through 64 characters")
	}
	for i, value := range alias {
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') {
			continue
		}
		if i != 0 && (value == '.' || value == '_' || value == '-') {
			continue
		}
		return fmt.Errorf("peer alias %q contains an unsupported character", alias)
	}
	return nil
}

// validateV2ProfileName applies the peer alias rule to DUD_PROFILE. The value
// becomes a directory name under the DUD root, so the leading character is
// alphanumeric and no separator is accepted: a profile can never escape the
// root it is meant to sit in.
func validateV2ProfileName(profile string) error {
	if err := validateV2PeerAlias(profile); err != nil {
		return errors.New(
			"DUD_PROFILE must contain 1 through 64 characters, starting with a letter " +
				"or digit and continuing with letters, digits, '.', '_', or '-'",
		)
	}
	return nil
}

func validateV2DeviceName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 64 {
		return errors.New("device name must contain 1 through 64 printable characters")
	}
	for _, value := range name {
		if value < 0x20 || value == 0x7f {
			return errors.New("device name must contain 1 through 64 printable characters")
		}
	}
	return nil
}

func redactedV2Config(cfg *v2LocalConfig) map[string]any {
	peers := make(map[string]any, len(cfg.Peers))
	for alias, peer := range cfg.Peers {
		peers[alias] = map[string]any{
			"status":             peer.Status,
			"relationship_id":    peer.RelationshipID,
			"key_epoch":          peer.KeyEpoch,
			"base_url":           peer.BaseURL,
			"doh_url":            peer.DOHURL,
			"ech_mode":           peer.ECHMode,
			"git_remote":         peer.GitRemote,
			"capability_present": peer.InboxCapabilityReference != "",
		}
	}
	return map[string]any{
		"version":       cfg.Version,
		"device":        cfg.Device,
		"base_url":      cfg.BaseURL,
		"doh_url":       cfg.DOHURL,
		"ech_mode":      cfg.ECHMode,
		"doh_bootstrap": cfg.DOHBootstrap,
		"identity": map[string]any{
			"device_id": cfg.Identity.DeviceID,
			"seed":      "<private>",
		},
		"peers": peers,
	}
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
