// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/sys/unix"
)

const (
	v2GitStateVersion       = 3
	v2GitMaximumObjectCount = 500_000
	v2GitMaximumDeltaDepth  = 50
	v2GitMaximumWallTime    = 120 * time.Second
	v2GitHistoryLimit       = 64
	v2GitMaximumOutputBytes = 64 * 1024 * 1024
)

// v2GitPermanentRejection marks a Git delivery this device will never be able
// to commit, however often it retries, because the cause is a deterministic
// function of signed content or of a durable local limit. Environment-dependent
// failures — free space, wall time, memory, transport — must never carry it:
// refusing those would discard a delivery a later run could have accepted.
//
// It is a distinct type rather than a matched message so that a new error site
// has to opt in deliberately instead of inheriting refusal by accident. See
// docs/threat-model-v2.md §3.19.
type v2GitPermanentRejection struct{ cause error }

func (rejection v2GitPermanentRejection) Error() string { return rejection.cause.Error() }
func (rejection v2GitPermanentRejection) Unwrap() error { return rejection.cause }

func rejectV2Git(err error) error {
	if err == nil {
		return nil
	}
	return v2GitPermanentRejection{cause: err}
}

func isV2GitPermanentRejection(err error) bool {
	var rejection v2GitPermanentRejection
	return errors.As(err, &rejection)
}

type v2GitRepository struct {
	CommonDir    string
	DUDDir       string
	ObjectFormat uint64
	ObjectHexLen int
	Limits       v2GitLimits
}

type v2GitLimits struct {
	BundleBytes    uint64
	ObjectCount    int
	DeltaDepth     uint64
	WallTime       time.Duration
	MemoryBytes    uint64
	DiskMultiplier uint64
}

type v2GitMetadata struct {
	RepositoryID  []byte
	ObjectFormat  uint64
	BundleVersion uint64
	Refs          map[string][]byte
	Prerequisites [][]byte
}

type v2GitPushOptions struct {
	Alias    string
	Branches []string
	Current  bool
	TTL      time.Duration
	JSON     bool
	Verbose  bool
}

type v2GitFetchOptions struct {
	Alias        string
	Associate    bool
	AllowRewrite bool
	JSON         bool
	Verbose      bool
}

type v2GitLimitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

// localV2GitCommand is the single subprocess construction point shared by V2
// Git synchronization and offline repository erasure. It never performs a
// network request.
func (a *app) localV2GitCommand(args ...string) *exec.Cmd {
	return exec.Command(a.cfg.GitBin, args...)
}

func (writer *v2GitLimitedBuffer) Write(value []byte) (int, error) {
	remaining := writer.limit - writer.buffer.Len()
	if remaining <= 0 {
		return 0, errors.New("Git command output exceeded the local limit")
	}
	if len(value) > remaining {
		_, _ = writer.buffer.Write(value[:remaining])
		return remaining, errors.New("Git command output exceeded the local limit")
	}
	return writer.buffer.Write(value)
}

func (writer *v2GitLimitedBuffer) Bytes() []byte  { return writer.buffer.Bytes() }
func (writer *v2GitLimitedBuffer) String() string { return writer.buffer.String() }

type v2GitOutboundState struct {
	Sequence         uint64            `json:"sequence"`
	DescriptorDigest string            `json:"descriptor_digest"`
	Refs             map[string]string `json:"refs"`
	Prerequisites    []string          `json:"prerequisites"`
	Acknowledged     bool              `json:"acknowledged"`
	AcknowledgedAt   uint64            `json:"acknowledged_at,omitempty"`
	Rejected         bool              `json:"rejected,omitempty"`
	RejectedAt       uint64            `json:"rejected_at,omitempty"`
}

type v2GitInboundState struct {
	Sequence         uint64            `json:"sequence"`
	DescriptorDigest string            `json:"descriptor_digest"`
	Phase            string            `json:"phase"`
	BundlePath       string            `json:"bundle_path"`
	Refs             map[string]string `json:"refs"`
	FetchedRefs      map[string]string `json:"fetched_refs,omitempty"`
	Prerequisites    []string          `json:"prerequisites"`
	OutputDigest     string            `json:"output_digest,omitempty"`
}

type v2GitHistoryEntry struct {
	Direction        string `json:"direction"`
	Sequence         uint64 `json:"sequence"`
	DescriptorDigest string `json:"descriptor_digest"`
	Phase            string `json:"phase"`
	RecordedAt       uint64 `json:"recorded_at"`
}

type v2GitPeerState struct {
	Version                      int                           `json:"version"`
	RepositoryID                 string                        `json:"repository_id"`
	PeerDeviceID                 string                        `json:"peer_device_id"`
	RelationshipKeyEpoch         uint64                        `json:"relationship_key_epoch"`
	LastReceivedSequence         uint64                        `json:"last_received_sequence"`
	LastReceivedDescriptorDigest string                        `json:"last_received_descriptor_digest,omitempty"`
	LastReceivedDeliveryID       string                        `json:"last_received_delivery_id,omitempty"`
	LastReceivedRefs             map[string]string             `json:"last_received_refs"`
	LastAcknowledgedSentSequence uint64                        `json:"last_acknowledged_sent_sequence"`
	LastAcknowledgedRefs         map[string]string             `json:"last_acknowledged_refs"`
	LastFullCheckpointSequence   uint64                        `json:"last_full_checkpoint_sequence"`
	Outbound                     map[string]v2GitOutboundState `json:"outbound"`
	Inbound                      map[string]v2GitInboundState  `json:"inbound"`
	History                      []v2GitHistoryEntry           `json:"history"`
}

func parseV2GitPushOptions(args []string) (v2GitPushOptions, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return v2GitPushOptions{}, errors.New("dud git push requires a positional peer alias")
	}
	opts := v2GitPushOptions{Alias: args[0], TTL: 7 * 24 * time.Hour}
	for args = args[1:]; len(args) != 0; {
		switch args[0] {
		case "--branch":
			if err := needValue(args, "--branch"); err != nil {
				return opts, err
			}
			opts.Branches = append(opts.Branches, args[1])
			args = args[2:]
		case "--current":
			opts.Current = true
			args = args[1:]
		case "--ttl":
			if err := needValue(args, "--ttl"); err != nil {
				return opts, err
			}
			value, err := time.ParseDuration(args[1])
			if err != nil || value <= 0 || value > 30*24*time.Hour {
				return opts, errors.New("--ttl must be between 1 second and 720 hours")
			}
			opts.TTL = value
			args = args[2:]
		case "--json":
			if err := markJSONOption(&opts.JSON); err != nil {
				return opts, err
			}
			args = args[1:]
		case "-v", "--verbose":
			if err := markVerboseOption(&opts.Verbose); err != nil {
				return opts, err
			}
			args = args[1:]
		case "--incremental", "--full":
			return opts, errors.New("incremental Git selection is unavailable in DUD 2.0; every peer push is a full checkpoint")
		case "--url", "--doh-url", "--ech-mode":
			return opts, v2PeerNetworkOptionError(args[0])
		default:
			if !strings.HasPrefix(args[0], "-") {
				return opts, errors.New("git push accepts exactly one positional peer alias")
			}
			return opts, fatalError("Unknown git push option: " + args[0])
		}
	}
	if opts.Current && len(opts.Branches) != 0 {
		return opts, errors.New("--current cannot be combined with --branch")
	}
	return opts, nil
}

func parseV2GitFetchOptions(args []string) (v2GitFetchOptions, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return v2GitFetchOptions{}, errors.New("dud git fetch requires a positional peer alias")
	}
	opts := v2GitFetchOptions{Alias: args[0]}
	for args = args[1:]; len(args) != 0; {
		switch args[0] {
		case "--associate":
			opts.Associate = true
			args = args[1:]
		case "--allow-rewrite":
			opts.AllowRewrite = true
			args = args[1:]
		case "--json":
			if err := markJSONOption(&opts.JSON); err != nil {
				return opts, err
			}
			args = args[1:]
		case "-v", "--verbose":
			if err := markVerboseOption(&opts.Verbose); err != nil {
				return opts, err
			}
			args = args[1:]
		case "--incremental":
			return opts, errors.New("incremental Git fetch is unavailable in DUD 2.0")
		case "--url", "--doh-url", "--ech-mode":
			return opts, v2PeerNetworkOptionError(args[0])
		default:
			if !strings.HasPrefix(args[0], "-") {
				return opts, errors.New("git fetch accepts exactly one positional peer alias")
			}
			return opts, fatalError("Unknown git fetch option: " + args[0])
		}
	}
	return opts, nil
}

func (a *app) resolveV2GitRepository(action string) (*v2GitRepository, error) {
	command := exec.Command(a.cfg.GitBin, "rev-parse", "--git-common-dir")
	command.Stderr = a.errOut
	output, err := command.Output()
	if err != nil {
		return nil, fatalError("git " + action + " requires a Git repository")
	}
	common := strings.TrimSpace(string(output))
	if common == "" {
		return nil, errors.New("Git returned an empty common directory")
	}
	common, err = filepath.Abs(common)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(common)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("Git common directory is not a directory")
	}
	formatCommand := exec.Command(a.cfg.GitBin, "rev-parse", "--show-object-format")
	formatOutput, err := formatCommand.Output()
	if err != nil {
		return nil, fmt.Errorf("detect Git object format: %w", err)
	}
	repository := &v2GitRepository{CommonDir: common, DUDDir: filepath.Join(common, "dud")}
	switch strings.TrimSpace(string(formatOutput)) {
	case "sha1":
		repository.ObjectFormat = 1
		repository.ObjectHexLen = 40
	case "sha256":
		repository.ObjectFormat = 2
		repository.ObjectHexLen = 64
	default:
		return nil, errors.New("Git repository uses an unsupported object format")
	}
	for _, directory := range []string{
		repository.DUDDir,
		filepath.Join(repository.DUDDir, "peers"),
		filepath.Join(repository.DUDDir, "transfers"),
		filepath.Join(repository.DUDDir, "quarantine"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, err
		}
	}
	repository.Limits, err = a.loadV2GitLimits()
	if err != nil {
		return nil, err
	}
	return repository, nil
}

func (a *app) v2GitLocalLimit(name string, defaultValue, minimum, maximum uint64) (uint64, error) {
	command := exec.Command(a.cfg.GitBin, "config", "--local", "--get", name)
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return defaultValue, nil
		}
		return 0, fmt.Errorf("read local Git limit %s: %w", name, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("local Git limit %s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func (a *app) loadV2GitLimits() (v2GitLimits, error) {
	var limits v2GitLimits
	var err error
	if limits.BundleBytes, err = a.v2GitLocalLimit("dud.gitBundleBytes", v2MaximumObjectBytes, 1, v2MaximumObjectBytes); err != nil {
		return limits, err
	}
	objectCount, err := a.v2GitLocalLimit("dud.gitObjectCount", v2GitMaximumObjectCount, 1, v2GitMaximumObjectCount)
	if err != nil {
		return limits, err
	}
	limits.ObjectCount = int(objectCount)
	if limits.DeltaDepth, err = a.v2GitLocalLimit("dud.gitDeltaDepth", v2GitMaximumDeltaDepth, 1, v2GitMaximumDeltaDepth); err != nil {
		return limits, err
	}
	wallSeconds, err := a.v2GitLocalLimit("dud.gitWallSeconds", uint64(v2GitMaximumWallTime/time.Second), 1, uint64(v2GitMaximumWallTime/time.Second))
	if err != nil {
		return limits, err
	}
	limits.WallTime = time.Duration(wallSeconds) * time.Second
	if limits.MemoryBytes, err = a.v2GitLocalLimit("dud.gitMemoryBytes", 1024*1024*1024, 64*1024*1024, 1024*1024*1024); err != nil {
		return limits, err
	}
	if limits.DiskMultiplier, err = a.v2GitLocalLimit("dud.gitDiskMultiplier", 3, 1, 3); err != nil {
		return limits, err
	}
	return limits, nil
}

func (repository *v2GitRepository) repoIDPath() string {
	return filepath.Join(repository.DUDDir, "repo-id")
}

func (repository *v2GitRepository) loadRepositoryID() ([]byte, error) {
	path := repository.repoIDPath()
	if err := validatePrivateV2File(path); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value, err := hex.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(value) != 16 {
		return nil, errors.New("Git repository ID is invalid")
	}
	return value, nil
}

func (repository *v2GitRepository) ensureRepositoryID() ([]byte, error) {
	value, err := repository.loadRepositoryID()
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	value, err = randomV2Bytes(16)
	if err != nil {
		return nil, err
	}
	if err := atomicWriteV2File(repository.repoIDPath(), []byte(hex.EncodeToString(value)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return value, nil
}

func (repository *v2GitRepository) associateRepositoryID(value []byte) error {
	if len(value) != 16 {
		return errors.New("received Git repository ID is invalid")
	}
	if _, err := os.Lstat(repository.repoIDPath()); err == nil {
		return errors.New("Git repository already has an identity")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWriteV2File(repository.repoIDPath(), []byte(hex.EncodeToString(value)+"\n"), 0o600)
}

func (repository *v2GitRepository) peerStatePath(peerID string) string {
	return filepath.Join(repository.DUDDir, "peers", peerID+".json")
}

func (repository *v2GitRepository) acquirePeerLock(peerID string) (func(), error) {
	path := filepath.Join(repository.DUDDir, "peers", peerID+".lock")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another Git operation for peer %s is in progress", peerID)
	}
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}

func newV2GitPeerState(repositoryID []byte, peerID string) *v2GitPeerState {
	return &v2GitPeerState{
		Version:              v2GitStateVersion,
		RepositoryID:         hex.EncodeToString(repositoryID),
		PeerDeviceID:         peerID,
		LastReceivedRefs:     map[string]string{},
		LastAcknowledgedRefs: map[string]string{},
		Outbound:             map[string]v2GitOutboundState{},
		Inbound:              map[string]v2GitInboundState{},
		History:              []v2GitHistoryEntry{},
	}
}

func (repository *v2GitRepository) loadPeerState(repositoryID []byte, peerID string) (*v2GitPeerState, error) {
	path := repository.peerStatePath(peerID)
	if err := validatePrivateV2File(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newV2GitPeerState(repositoryID, peerID), nil
		}
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state v2GitPeerState
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, fmt.Errorf("parse per-peer Git state: %w", err)
	}
	if state.Version != v2GitStateVersion ||
		state.RepositoryID != hex.EncodeToString(repositoryID) ||
		state.PeerDeviceID != peerID ||
		state.RelationshipKeyEpoch != 0 {
		return nil, fmt.Errorf("per-peer Git state identity is invalid; %s", v2LocalStateResetInstruction)
	}
	if state.LastReceivedRefs == nil {
		state.LastReceivedRefs = map[string]string{}
	}
	if state.LastAcknowledgedRefs == nil {
		state.LastAcknowledgedRefs = map[string]string{}
	}
	if state.Outbound == nil {
		state.Outbound = map[string]v2GitOutboundState{}
	}
	if state.Inbound == nil {
		state.Inbound = map[string]v2GitInboundState{}
	}
	return &state, nil
}

func (repository *v2GitRepository) writePeerState(state *v2GitPeerState) error {
	if state.Version != v2GitStateVersion || state.RelationshipKeyEpoch != 0 {
		return fmt.Errorf("refusing to write invalid per-peer Git state; %s", v2LocalStateResetInstruction)
	}
	if len(state.History) > v2GitHistoryLimit {
		state.History = append([]v2GitHistoryEntry(nil), state.History[len(state.History)-v2GitHistoryLimit:]...)
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteV2File(repository.peerStatePath(state.PeerDeviceID), append(body, '\n'), 0o600)
}

func stringGitRefs(refs map[string][]byte) map[string]string {
	result := make(map[string]string, len(refs))
	for name, oid := range refs {
		result[name] = hex.EncodeToString(oid)
	}
	return result
}

func byteGitRefs(refs map[string]string, objectBytes int) (map[string][]byte, error) {
	result := make(map[string][]byte, len(refs))
	for name, value := range refs {
		oid, err := hex.DecodeString(value)
		if err != nil || len(oid) != objectBytes {
			return nil, fmt.Errorf("stored Git ref %s has an invalid object ID", name)
		}
		result[name] = oid
	}
	return result, nil
}

func appendV2GitHistory(state *v2GitPeerState, direction string, sequence uint64, digest, phase string) {
	state.History = append(state.History, v2GitHistoryEntry{
		Direction: direction, Sequence: sequence, DescriptorDigest: digest,
		Phase: phase, RecordedAt: uint64(time.Now().Unix()),
	})
}

func encodeV2GitMetadata(metadata v2GitMetadata) map[int]any {
	return map[int]any{
		1: metadata.RepositoryID,
		2: metadata.ObjectFormat,
		3: metadata.BundleVersion,
		4: metadata.Refs,
		5: metadata.Prerequisites,
	}
}

func decodeV2GitMetadata(value any) (*v2GitMetadata, error) {
	encoded, err := v2EncMode.Marshal(value)
	if err != nil {
		return nil, errors.New("Git metadata is invalid")
	}
	var raw map[int]cbor.RawMessage
	if err := v2DecMode.Unmarshal(encoded, &raw); err != nil {
		return nil, errors.New("Git metadata is invalid")
	}
	keys := make([]int, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	if err := validateV2MetadataKeys(keys, []int{1, 2, 3, 4, 5}, nil); err != nil {
		return nil, fmt.Errorf("Git metadata is invalid: %w", err)
	}
	for key := 1; key <= 5; key++ {
		if raw[key] == nil {
			return nil, fmt.Errorf("Git metadata is missing key %d", key)
		}
	}
	var metadata v2GitMetadata
	if err := v2DecMode.Unmarshal(raw[1], &metadata.RepositoryID); err != nil || len(metadata.RepositoryID) != 16 {
		return nil, errors.New("Git metadata repository ID must be 16 bytes")
	}
	if err := v2DecMode.Unmarshal(raw[2], &metadata.ObjectFormat); err != nil ||
		(metadata.ObjectFormat != 1 && metadata.ObjectFormat != 2) {
		return nil, errors.New("Git metadata object format is unsupported")
	}
	if err := v2DecMode.Unmarshal(raw[3], &metadata.BundleVersion); err != nil ||
		(metadata.BundleVersion != 2 && metadata.BundleVersion != 3) {
		return nil, errors.New("Git metadata bundle version is unsupported")
	}
	if err := v2DecMode.Unmarshal(raw[4], &metadata.Refs); err != nil || len(metadata.Refs) == 0 {
		return nil, errors.New("Git metadata refs are invalid")
	}
	if err := v2DecMode.Unmarshal(raw[5], &metadata.Prerequisites); err != nil {
		return nil, errors.New("Git metadata prerequisites are invalid")
	}
	objectBytes := 20
	if metadata.ObjectFormat == 2 {
		objectBytes = 32
		if metadata.BundleVersion != 3 {
			return nil, errors.New("SHA-256 Git bundles require bundle version 3")
		}
	}
	for name, oid := range metadata.Refs {
		if len(oid) != objectBytes {
			return nil, fmt.Errorf("Git ref %q has an object ID of the wrong length", name)
		}
		if !strings.HasPrefix(name, "refs/heads/") && !strings.HasPrefix(name, "refs/tags/") {
			return nil, fmt.Errorf("Git ref %q is outside the permitted namespaces", name)
		}
	}
	return &metadata, nil
}

// requireCompleteV2GitCheckpoint enforces that a checkpoint carries no
// incremental prerequisites, which is the one capability a later release will
// legitimately add to this metadata.
//
// It is deliberately separate from decodeV2GitMetadata, and deliberately not
// part of descriptor validation. A descriptor that is merely ahead of this
// release must stay parseable, so that the receiver can answer with a signed
// refusal and advance the chain. Rejecting it at parse time instead would leave
// the delivery stuck at the head of the chain with no way to report why —
// which is exactly the deadlock a version-skewed peer would otherwise cause.
// Everything structural about the metadata is still checked before this point.
func requireCompleteV2GitCheckpoint(metadata *v2GitMetadata) error {
	if len(metadata.Prerequisites) != 0 {
		return errors.New("incremental Git prerequisites are unsupported in DUD 2.0")
	}
	return nil
}

func (a *app) runV2Git(ctx context.Context, repository *v2GitRepository, input []byte, args ...string) ([]byte, error) {
	return a.runV2GitWithEnv(ctx, repository, nil, input, args...)
}

// runV2GitWithEnv retains the hardened local Git invocation while allowing a
// caller to expose a verified quarantine object directory read-only through
// Git's alternate-object lookup. It never imports those objects into the
// current repository.
func (a *app) runV2GitWithEnv(ctx context.Context, repository *v2GitRepository, extraEnv []string, input []byte, args ...string) ([]byte, error) {
	hardened := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.allow=never",
		"-c", "protocol.file.allow=always",
		"-c", "fetch.fsckObjects=true",
		"-c", "transfer.fsckObjects=true",
		"-c", "pack.threads=1",
		"-c", fmt.Sprintf("pack.windowMemory=%d", repository.Limits.MemoryBytes*3/8),
		"-c", fmt.Sprintf("pack.deltaCacheSize=%d", repository.Limits.MemoryBytes/8),
		"-c", fmt.Sprintf("core.deltaBaseCacheLimit=%d", repository.Limits.MemoryBytes/8),
	}
	hardened = append(hardened, args...)
	var command *exec.Cmd
	if runtime.GOOS == "linux" {
		limited := append([]string{strconv.FormatUint(repository.Limits.MemoryBytes/1024, 10), a.cfg.GitBin}, hardened...)
		command = exec.CommandContext(
			ctx,
			"/bin/sh",
			append([]string{"-c", `memory_kb=$1; shift; ulimit -v "$memory_kb" || exit 125; exec "$@"`, "dud-git-memory-limit"}, limited...)...,
		)
	} else {
		command = exec.CommandContext(ctx, a.cfg.GitBin, hardened...)
	}
	command.Env = append(os.Environ(),
		"GIT_ALLOW_PROTOCOL=file",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_LFS_SKIP_SMUDGE=1",
	)
	command.Env = append(command.Env, extraEnv...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	stdout := v2GitLimitedBuffer{limit: v2GitMaximumOutputBytes}
	stderr := v2GitLimitedBuffer{limit: 1024 * 1024}
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("Git operation exceeded the %s wall-time limit", repository.Limits.WallTime)
		}
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			message = strconv.QuoteToASCII(message)
		}
		// Carry the status separately from the message. Some callers expect a
		// particular non-zero status as an answer rather than a failure, and
		// Git writes advisories to stderr often enough that classifying on the
		// message text would misread those answers as hard errors.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, &v2GitCommandError{code: exitErr.ExitCode(), message: message}
		}
		if message != "" {
			return nil, fmt.Errorf("Git command failed: %s", message)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

// v2GitCommandError reports a Git invocation that exited non-zero, keeping the
// status separate from the redacted stderr text so callers classify on the
// status alone.
type v2GitCommandError struct {
	code    int
	message string
}

func (e *v2GitCommandError) Error() string {
	if e.message != "" {
		return fmt.Sprintf("Git command failed: %s", e.message)
	}
	return fmt.Sprintf("Git command failed with status %d", e.code)
}

// v2GitExitCode reports the status of a failed Git invocation, and whether the
// error came from one at all.
func v2GitExitCode(err error) (int, bool) {
	var commandErr *v2GitCommandError
	if errors.As(err, &commandErr) {
		return commandErr.code, true
	}
	return 0, false
}

func (a *app) validateV2GitRef(repository *v2GitRepository, ref string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := a.runV2Git(ctx, repository, nil, "check-ref-format", ref); err != nil {
		return fmt.Errorf("invalid advertised Git ref %q: %w", ref, err)
	}
	return nil
}

func parseV2GitBundleHeader(path string, objectBytes int) (uint64, map[string][]byte, [][]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, nil, nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, 1024*1024))
	first, err := reader.ReadString('\n')
	if err != nil {
		return 0, nil, nil, errors.New("Git bundle header is truncated")
	}
	var version uint64
	switch strings.TrimSpace(first) {
	case "# v2 git bundle":
		version = 2
	case "# v3 git bundle":
		version = 3
	default:
		return 0, nil, nil, errors.New("Git bundle has an unsupported signature")
	}
	refs := map[string][]byte{}
	var prerequisites [][]byte
	sawObjectFormat := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, nil, nil, errors.New("Git bundle header is truncated")
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "@") {
			expected := "@object-format=sha1"
			if objectBytes == 32 {
				expected = "@object-format=sha256"
			}
			if version != 3 || sawObjectFormat || line != expected {
				return 0, nil, nil, fmt.Errorf("Git bundle contains unsupported capability %q", line)
			}
			sawObjectFormat = true
			continue
		}
		prerequisite := strings.HasPrefix(line, "-")
		if prerequisite {
			line = strings.TrimPrefix(line, "-")
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, nil, nil, errors.New("Git bundle header contains an invalid reference")
		}
		oid, err := hex.DecodeString(fields[0])
		if err != nil || len(oid) != objectBytes {
			return 0, nil, nil, errors.New("Git bundle header contains an invalid object ID")
		}
		if prerequisite {
			prerequisites = append(prerequisites, oid)
			continue
		}
		name := fields[1]
		if _, exists := refs[name]; exists {
			return 0, nil, nil, fmt.Errorf("Git bundle repeats ref %q", name)
		}
		refs[name] = oid
	}
	if len(refs) == 0 {
		return 0, nil, nil, errors.New("Git bundle advertises no refs")
	}
	if version == 3 && !sawObjectFormat {
		return 0, nil, nil, errors.New("Git bundle version 3 omits its object-format capability")
	}
	return version, refs, prerequisites, nil
}

func equalV2GitRefs(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for name, oid := range left {
		if !bytes.Equal(oid, right[name]) {
			return false
		}
	}
	return true
}

func (a *app) createV2GitBundle(repository *v2GitRepository, opts v2GitPushOptions, repositoryID []byte) (string, *v2GitMetadata, error) {
	branches := append([]string(nil), opts.Branches...)
	if opts.Current {
		output, err := exec.Command(a.cfg.GitBin, "symbolic-ref", "--quiet", "--short", "HEAD").Output()
		if err != nil {
			return "", nil, errors.New("--current requires an attached current branch")
		}
		branches = []string{strings.TrimSpace(string(output))}
	}
	for _, branch := range branches {
		if strings.HasPrefix(branch, "-") {
			return "", nil, fmt.Errorf("invalid branch name %q", branch)
		}
		if err := a.validateV2GitRef(repository, "refs/heads/"+branch); err != nil {
			return "", nil, err
		}
	}
	bundle, err := os.CreateTemp(filepath.Join(repository.DUDDir, "transfers"), ".outgoing-*.bundle")
	if err != nil {
		return "", nil, err
	}
	bundlePath := bundle.Name()
	if err := bundle.Close(); err != nil {
		return "", nil, err
	}
	_ = os.Chmod(bundlePath, 0o600)
	version := uint64(2)
	if repository.ObjectFormat == 2 {
		version = 3
	}
	args := []string{"bundle", "create", "--version=" + strconv.FormatUint(version, 10), bundlePath}
	if len(branches) == 0 {
		args = append(args, "--branches", "--tags")
	} else {
		for _, branch := range branches {
			args = append(args, "refs/heads/"+branch)
		}
		args = append(args, "--tags")
	}
	ctx, cancel := context.WithTimeout(context.Background(), repository.Limits.WallTime)
	defer cancel()
	if _, err := a.runV2Git(ctx, repository, nil, args...); err != nil {
		_ = os.Remove(bundlePath)
		return "", nil, err
	}
	actualVersion, refs, prerequisites, err := parseV2GitBundleHeader(bundlePath, repository.ObjectHexLen/2)
	if err != nil {
		_ = os.Remove(bundlePath)
		return "", nil, err
	}
	if actualVersion != version || len(prerequisites) != 0 {
		_ = os.Remove(bundlePath)
		return "", nil, errors.New("Git did not create the requested complete checkpoint bundle")
	}
	for ref := range refs {
		if err := a.validateV2GitRef(repository, ref); err != nil {
			_ = os.Remove(bundlePath)
			return "", nil, err
		}
	}
	metadata := &v2GitMetadata{
		RepositoryID:  repositoryID,
		ObjectFormat:  repository.ObjectFormat,
		BundleVersion: version,
		Refs:          refs,
		Prerequisites: [][]byte{},
	}
	// Parsing an incremental checkpoint is now deliberately possible, so that a
	// version-skewed peer can be answered rather than left stuck. Sending one
	// is not: this release has no way to produce a bundle a peer could apply.
	if err := requireCompleteV2GitCheckpoint(metadata); err != nil {
		_ = os.Remove(bundlePath)
		return "", nil, err
	}
	return bundlePath, metadata, nil
}

func (runtime *v2PeerRuntime) publishV2PeerPayload(ctx context.Context, plaintext []byte, payloadType uint64, typeMetadata map[int]any, ttl time.Duration) (uint64, string, error) {
	payloadCiphertext, err := encryptV2Payload(plaintext, runtime.recipient)
	if err != nil {
		return 0, "", err
	}
	if len(payloadCiphertext) > v2MaximumObjectBytes {
		return 0, "", errors.New("encrypted peer payload exceeds the server object limit")
	}
	now := uint64(time.Now().Unix())
	policy := v2TransportPolicy{
		ExpiresAt: now + uint64(ttl/time.Second), Consume: 0,
		ClaimLeaseSeconds: 300, AckMode: 1,
	}
	policyMap := v2TransportPolicyMap(policy)
	chain := runtime.state.Chains["out:data"]
	descriptorID, err := newV2DescriptorID()
	if err != nil {
		return 0, "", err
	}
	plainDigest := sha256.Sum256(plaintext)
	cipherDigest := sha256.Sum256(payloadCiphertext)
	plaintextSize := uint64(len(plaintext))
	descriptor := v2Descriptor{
		DescriptorID: descriptorID, PayloadType: payloadType,
		RelationshipID: runtime.relationshipID, Direction: v2OutboundDirection(runtime.state.Role), Chain: 0,
		KeyEpoch: 0, Sequence: chain.SendSequence + 1,
		PreviousDigest: mustDecodeHexV2(chain.SendDigest, 32),
		SenderDeviceID: runtime.localID, RecipientDeviceID: runtime.peerID,
		CanonicalOrigin: runtime.origin, CreatedAt: now, TransportPolicy: policy,
		PayloadHash: plainDigest[:], ChunkHashes: [][]byte{cipherDigest[:]},
		PlaintextSize: &plaintextSize, TypeMetadata: typeMetadata,
	}
	descriptorCiphertext, err := encryptV2Envelope(descriptor, runtime.signingKey, runtime.recipient)
	if err != nil {
		return 0, "", err
	}
	signedMap, err := descriptorMap(descriptor, runtime.signingKey)
	if err != nil {
		return 0, "", err
	}
	signedBytes, err := v2EncMode.Marshal(signedMap)
	if err != nil {
		return 0, "", err
	}
	descriptorDigest := sha256.Sum256(signedBytes)
	secret, err := decodeV2Base64URL(runtime.state.OutboundRelationshipSecret, 32)
	if err != nil {
		return 0, "", err
	}
	slotEpoch := v2SlotEpoch(time.Now())
	slot, err := deriveV2Slot(secret, "data", slotEpoch)
	if err != nil {
		return 0, "", err
	}
	policyBytes, err := v2EncMode.Marshal(policyMap)
	if err != nil {
		return 0, "", err
	}
	key := hex.EncodeToString(descriptorDigest[:])
	operationID, err := randomV2Bytes(16)
	if err != nil {
		return 0, "", err
	}
	runtime.state.PendingGranularDeliveries = append(runtime.state.PendingGranularDeliveries, v2PendingGranularDelivery{
		OperationID:         hex.EncodeToString(operationID),
		EncryptedDescriptor: v2Base64URL(descriptorCiphertext),
		PayloadCiphertext:   v2Base64URL(payloadCiphertext),
		DataSlot:            hex.EncodeToString(slot),
		SlotEpoch:           slotEpoch,
		RequestedPolicy:     v2Base64URL(policyBytes),
		DescriptorDigest:    key,
		Sequence:            descriptor.Sequence,
		CreatedAt:           now,
	})
	metadataBytes, err := v2EncMode.Marshal(typeMetadata)
	if err != nil {
		return 0, "", err
	}
	chain.SendSequence = descriptor.Sequence
	chain.SendDigest = key
	runtime.state.Sent[key] = v2SentDelivery{
		Sequence: descriptor.Sequence, DescriptorDigest: key,
		PayloadType: payloadType, TypeMetadata: v2Base64URL(metadataBytes),
	}
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return 0, "", err
	}
	if err := runtime.flushPendingGranularDeliveries(ctx); err != nil {
		return descriptor.Sequence, key, fmt.Errorf("delivery committed locally and will retry publication: %w", err)
	}
	return descriptor.Sequence, key, nil
}

func (a *app) cmdV2GitPush(args []string) error {
	opts, err := parseV2GitPushOptions(args)
	if err != nil {
		return err
	}
	repository, err := a.resolveV2GitRepository("push")
	if err != nil {
		return err
	}
	repositoryID, err := repository.ensureRepositoryID()
	if err != nil {
		return err
	}
	return a.withV2Peer(opts.Alias, 2*time.Minute, func(runtime *v2PeerRuntime) error {
		if err := runtime.requireGitFeatures(); err != nil {
			return err
		}
		unlock, err := repository.acquirePeerLock(runtime.peer.PeerPseudonymousID)
		if err != nil {
			return err
		}
		defer unlock()
		ctx := context.Background()
		_ = runtime.boundedControlDrain(ctx)
		if runtime.state.Halted {
			return fmt.Errorf("peer relationship is halted: %s", runtime.state.HaltReason)
		}
		if err := runtime.flushPendingCompletions(ctx); err != nil {
			fmt.Fprintf(a.errOut, "WARNING: queued peer completions remain pending: %v\n", err)
		}
		if err := runtime.flushPendingGranularDeliveries(ctx); err != nil {
			return fmt.Errorf("retry pending peer publication: %w", err)
		}
		state, err := repository.loadPeerState(repositoryID, runtime.peer.PeerPseudonymousID)
		if err != nil {
			return err
		}
		if err := reconcileV2GitAcknowledgements(runtime, repository, state); err != nil {
			return err
		}
		bundlePath, metadata, err := a.createV2GitBundle(repository, opts, repositoryID)
		if err != nil {
			return err
		}
		defer os.Remove(bundlePath)
		body, err := os.ReadFile(bundlePath)
		if err != nil {
			return err
		}
		if uint64(len(body)) > repository.Limits.BundleBytes {
			return fmt.Errorf("Git bundle exceeds the local limit of %d bytes", repository.Limits.BundleBytes)
		}
		sequence, digest, err := runtime.publishV2PeerPayload(ctx, body, 4, encodeV2GitMetadata(*metadata), opts.TTL)
		if err != nil {
			return err
		}
		state.Outbound[digest] = v2GitOutboundState{
			Sequence: sequence, DescriptorDigest: digest,
			Refs: stringGitRefs(metadata.Refs), Prerequisites: []string{},
		}
		state.LastFullCheckpointSequence = sequence
		appendV2GitHistory(state, "outbound", sequence, digest, "committed")
		if err := repository.writePeerState(state); err != nil {
			return err
		}
		status := v2DeliveryStatusOf(runtime.state)
		quarantined := quarantinedV2GitDeliveries(state)
		rejected := rejectedV2GitDeliveries(runtime.state)
		refused := refusedV2GitCheckpoints(state)
		if opts.JSON {
			return writeJSON(a.out, status.merge(map[string]any{
				"peer": opts.Alias, "repository_id": hex.EncodeToString(repositoryID),
				"sequence": sequence, "descriptor_digest": digest,
				"refs": state.Outbound[digest].Refs, "acknowledged": false,
				"quarantined_git_deliveries": quarantined,
				"rejected_git_deliveries":    rejected,
				"refused_git_checkpoints":    refused,
			}))
		}
		if err := fprintWrapped(a.out,
			"Sent complete Git checkpoint to %s as data sequence %d.",
			opts.Alias, sequence); err != nil {
			return err
		}
		if err := fprintWrapped(a.out,
			"Not acknowledged yet; 'dud sync %s' collects the acknowledgement.",
			opts.Alias); err != nil {
			return err
		}
		if len(refused) != 0 {
			fmt.Fprintf(a.out, "%d earlier checkpoint(s) were refused by %s; see dud git status %s.\n", len(refused), opts.Alias, opts.Alias)
		}
		return v2GitStatusReport(opts.Verbose, status, quarantined, rejected).write(a.out)
	})
}

func (a *app) validateV2GitMetadata(repository *v2GitRepository, metadata *v2GitMetadata) error {
	if metadata.ObjectFormat != repository.ObjectFormat {
		return errors.New("Git bundle object format does not match the receiving repository")
	}
	for ref := range metadata.Refs {
		if err := a.validateV2GitRef(repository, ref); err != nil {
			return err
		}
	}
	return nil
}

func v2GitAvailableBytes(path string) (uint64, error) {
	var stats unix.Statfs_t
	if err := unix.Statfs(path, &stats); err != nil {
		return 0, err
	}
	return uint64(stats.Bavail) * uint64(stats.Bsize), nil
}

func v2GitDirectoryBytes(root string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

func (a *app) verifyV2GitPackLimits(ctx context.Context, repository *v2GitRepository, scratch string) error {
	indexes, err := filepath.Glob(filepath.Join(scratch, "objects", "pack", "*.idx"))
	if err != nil {
		return err
	}
	count := 0
	for _, index := range indexes {
		output, err := a.runV2Git(ctx, repository, nil, "verify-pack", "-v", index)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || len(fields[0]) != repository.ObjectHexLen {
				continue
			}
			if _, err := hex.DecodeString(fields[0]); err != nil {
				continue
			}
			count++
			if count > repository.Limits.ObjectCount {
				return rejectV2Git(fmt.Errorf("Git bundle contains more than %d objects", repository.Limits.ObjectCount))
			}
			if len(fields) >= 7 {
				depth, err := strconv.ParseUint(fields[5], 10, 64)
				if err == nil && depth > repository.Limits.DeltaDepth {
					return rejectV2Git(fmt.Errorf("Git bundle delta depth %d exceeds the limit of %d", depth, repository.Limits.DeltaDepth))
				}
			}
		}
	}
	return nil
}

func (a *app) verifyV2GitQuarantine(repository *v2GitRepository, bundlePath, digest string, metadata *v2GitMetadata) (string, error) {
	info, err := os.Lstat(bundlePath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || uint64(info.Size()) > repository.Limits.BundleBytes {
		return "", rejectV2Git(fmt.Errorf("Git bundle violates the local limit of %d bytes", repository.Limits.BundleBytes))
	}
	available, err := v2GitAvailableBytes(repository.DUDDir)
	if err != nil {
		return "", err
	}
	required := uint64(info.Size()) * repository.Limits.DiskMultiplier
	if available < required {
		return "", fmt.Errorf("Git quarantine requires %d free bytes but only %d are available", required, available)
	}
	version, refs, prerequisites, err := parseV2GitBundleHeader(bundlePath, repository.ObjectHexLen/2)
	if err != nil {
		return "", err
	}
	if version != metadata.BundleVersion || len(prerequisites) != 0 ||
		!equalV2GitRefs(refs, metadata.Refs) {
		return "", rejectV2Git(errors.New("Git bundle header does not match the signed encrypted metadata"))
	}
	scratch := filepath.Join(repository.DUDDir, "quarantine", digest)
	if filepath.Dir(scratch) != filepath.Join(repository.DUDDir, "quarantine") {
		return "", errors.New("invalid Git quarantine path")
	}
	if err := os.RemoveAll(scratch); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), repository.Limits.WallTime)
	defer cancel()
	objectFormat := "sha1"
	if repository.ObjectFormat == 2 {
		objectFormat = "sha256"
	}
	if _, err := a.runV2Git(ctx, repository, nil, "init", "--bare", "--object-format="+objectFormat, scratch); err != nil {
		return "", err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(scratch)
		}
	}()
	if _, err := a.runV2Git(ctx, repository, nil, "-C", scratch, "bundle", "verify", bundlePath); err != nil {
		return "", err
	}
	if _, err := a.runV2Git(ctx, repository, nil, "-C", scratch, "bundle", "unbundle", bundlePath); err != nil {
		return "", err
	}
	var transaction strings.Builder
	transaction.WriteString("start\n")
	names := make([]string, 0, len(metadata.Refs))
	for name := range metadata.Refs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&transaction, "update %s %s\n", name, hex.EncodeToString(metadata.Refs[name]))
	}
	transaction.WriteString("prepare\ncommit\n")
	if _, err := a.runV2Git(ctx, repository, []byte(transaction.String()), "-C", scratch, "update-ref", "--stdin"); err != nil {
		return "", err
	}
	if _, err := a.runV2Git(ctx, repository, nil, "-C", scratch, "fsck", "--strict", "--full", "--no-reflogs"); err != nil {
		return "", err
	}
	// verify-pack covers every object in the received packs, including valid
	// dangling objects that are deliberately unreachable from advertised refs.
	if err := a.verifyV2GitPackLimits(ctx, repository, scratch); err != nil {
		return "", err
	}
	scratchBytes, err := v2GitDirectoryBytes(filepath.Join(scratch, "objects"))
	if err != nil {
		return "", err
	}
	// Pack indexes and the empty bare-repository scaffolding have a fixed cost
	// that dominates tiny bundles. The one-MiB allowance is metadata overhead,
	// not object expansion; payload-derived storage remains capped at 2x here
	// and at 3x by the preflight free-space reservation above.
	scratchMultiplier := uint64(0)
	if repository.Limits.DiskMultiplier > 0 {
		scratchMultiplier = repository.Limits.DiskMultiplier - 1
	}
	if scratchBytes > uint64(info.Size())*scratchMultiplier+1024*1024 {
		return "", errors.New("Git quarantine exceeds the local 3x bundle disk budget")
	}
	cleanup = false
	return scratch, nil
}

func (a *app) v2GitRefOID(repository *v2GitRepository, ref string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		a.cfg.GitBin,
		"-c", "core.hooksPath=/dev/null",
		"rev-parse", "--verify", "--quiet", ref+"^{object}",
	)
	command.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_OPTIONAL_LOCKS=0",
	)
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", false, nil
		}
		return "", false, err
	}
	value := strings.TrimSpace(string(output))
	if len(value) != repository.ObjectHexLen {
		return "", false, fmt.Errorf("Git ref %q resolved to an invalid object ID", ref)
	}
	return value, true, nil
}

func (a *app) v2GitIsAncestor(repository *v2GitRepository, oldOID, newOID, scratch string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), repository.Limits.WallTime)
	defer cancel()
	_, err := a.runV2GitWithEnv(
		ctx,
		repository,
		[]string{"GIT_ALTERNATE_OBJECT_DIRECTORIES=" + filepath.Join(scratch, "objects")},
		nil,
		"merge-base", "--is-ancestor", oldOID, newOID,
	)
	if err == nil {
		return true, nil
	}
	// `merge-base --is-ancestor` answers "no" with status 1; anything else is a
	// real failure, including the 128 Git uses for an object the quarantine
	// alternate did not make reachable.
	if code, ok := v2GitExitCode(err); ok && code == 1 {
		return false, nil
	}
	return false, err
}

func v2GitRemoteRef(remote, advertised string) (string, error) {
	switch {
	case strings.HasPrefix(advertised, "refs/heads/"):
		return "refs/remotes/" + remote + "/" + strings.TrimPrefix(advertised, "refs/heads/"), nil
	case strings.HasPrefix(advertised, "refs/tags/"):
		return "refs/dud/tags/" + remote + "/" + strings.TrimPrefix(advertised, "refs/tags/"), nil
	default:
		return "", fmt.Errorf("unsupported advertised ref %s", advertised)
	}
}

func (a *app) promoteV2GitQuarantine(repository *v2GitRepository, state *v2GitPeerState, scratch, digest, remote string, metadata *v2GitMetadata, allowRewrite bool) (map[string][]byte, error) {
	if err := validateGitRemoteName(remote); err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	ctx, cancel := context.WithTimeout(context.Background(), repository.Limits.WallTime)
	defer cancel()
	names := make([]string, 0, len(metadata.Refs))
	for name := range metadata.Refs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !strings.HasPrefix(name, "refs/tags/") {
			continue
		}
		target, _ := v2GitRemoteRef(remote, name)
		oldOID, exists, err := a.v2GitRefOID(repository, target)
		if err != nil {
			return nil, err
		}
		newOID := hex.EncodeToString(metadata.Refs[name])
		if exists && oldOID != newOID {
			return nil, fmt.Errorf("incoming tag %s conflicts with the isolated peer tag; tags are never force-updated", name)
		}
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "refs/heads/") {
			continue
		}
		target, _ := v2GitRemoteRef(remote, name)
		oldOID, exists, err := a.v2GitRefOID(repository, target)
		if err != nil || !exists {
			if err != nil {
				return nil, err
			}
			continue
		}
		newOID := hex.EncodeToString(metadata.Refs[name])
		if oldOID == newOID {
			continue
		}
		fastForward, err := a.v2GitIsAncestor(repository, oldOID, newOID, scratch)
		if err != nil {
			return nil, err
		}
		if !fastForward && !allowRewrite {
			return nil, fmt.Errorf("peer branch %s rewrites accepted history; rerun with --allow-rewrite after verifying the peer", name)
		}
	}
	for prior := range state.LastReceivedRefs {
		if !strings.HasPrefix(prior, "refs/heads/") {
			continue
		}
		if _, retained := metadata.Refs[prior]; retained {
			continue
		}
		target, err := v2GitRemoteRef(remote, prior)
		if err != nil {
			return nil, err
		}
		if _, exists, err := a.v2GitRefOID(repository, target); err != nil {
			return nil, err
		} else if exists && !allowRewrite {
			return nil, fmt.Errorf("checkpoint deletes accepted peer branch %s; rerun with --allow-rewrite after verifying the peer", prior)
		}
	}
	importPrefix := "refs/dud/import/" + digest
	fetchArgs := []string{"fetch", "--no-tags", "--no-write-fetch-head", scratch}
	for _, name := range names {
		target := importPrefix + "/" + strings.TrimPrefix(name, "refs/")
		fetchArgs = append(fetchArgs, "+"+name+":"+target)
	}
	if _, err := a.runV2Git(ctx, repository, nil, fetchArgs...); err != nil {
		return nil, err
	}
	defer func() {
		for _, name := range names {
			target := importPrefix + "/" + strings.TrimPrefix(name, "refs/")
			_, _ = a.runV2Git(context.Background(), repository, nil, "update-ref", "-d", target)
		}
	}()
	var transaction strings.Builder
	transaction.WriteString("start\n")
	for _, name := range names {
		target, err := v2GitRemoteRef(remote, name)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&transaction, "update %s %s\n", target, hex.EncodeToString(metadata.Refs[name]))
	}
	for prior := range state.LastReceivedRefs {
		if !strings.HasPrefix(prior, "refs/heads/") {
			continue
		}
		if _, retained := metadata.Refs[prior]; retained {
			continue
		}
		target, err := v2GitRemoteRef(remote, prior)
		if err != nil {
			return nil, err
		}
		if _, exists, err := a.v2GitRefOID(repository, target); err != nil {
			return nil, err
		} else if exists {
			fmt.Fprintf(&transaction, "delete %s\n", target)
		}
	}
	transaction.WriteString("prepare\ncommit\n")
	if _, err := a.runV2Git(ctx, repository, []byte(transaction.String()), "update-ref", "--stdin"); err != nil {
		return nil, err
	}
	managedUpdates := make(map[string]string, len(metadata.Refs))
	for name, oid := range metadata.Refs {
		target, err := v2GitRemoteRef(remote, name)
		if err != nil {
			return nil, err
		}
		managedUpdates[target] = hex.EncodeToString(oid)
	}
	managedDeletes := []string{}
	for prior := range state.LastReceivedRefs {
		if !strings.HasPrefix(prior, "refs/heads/") {
			continue
		}
		if _, retained := metadata.Refs[prior]; retained {
			continue
		}
		target, err := v2GitRemoteRef(remote, prior)
		if err != nil {
			return nil, err
		}
		managedDeletes = append(managedDeletes, target)
	}
	if err := repository.updateManagedRefs(managedUpdates, managedDeletes); err != nil {
		return nil, fmt.Errorf("record managed Git refs after commit: %w", err)
	}
	return metadata.Refs, nil
}

func decodeV2GitResultMetadata(value any) ([]byte, map[string][]byte, [][]byte, error) {
	encoded, err := v2EncMode.Marshal(value)
	if err != nil {
		return nil, nil, nil, err
	}
	var raw map[int]cbor.RawMessage
	if err := v2DecMode.Unmarshal(encoded, &raw); err != nil {
		return nil, nil, nil, errors.New("Git acknowledgement result metadata is invalid")
	}
	keys := make([]int, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	if err := validateV2MetadataKeys(keys, []int{1, 2, 3}, nil); err != nil {
		return nil, nil, nil, fmt.Errorf("Git acknowledgement result metadata is invalid: %w", err)
	}
	var repositoryID []byte
	var refs map[string][]byte
	var prerequisites [][]byte
	if err := v2DecMode.Unmarshal(raw[1], &repositoryID); err != nil || len(repositoryID) != 16 {
		return nil, nil, nil, errors.New("Git acknowledgement repository ID is invalid")
	}
	if err := v2DecMode.Unmarshal(raw[2], &refs); err != nil {
		return nil, nil, nil, errors.New("Git acknowledgement refs are invalid")
	}
	if err := v2DecMode.Unmarshal(raw[3], &prerequisites); err != nil || len(prerequisites) != 0 {
		return nil, nil, nil, errors.New("Git acknowledgement prerequisites are invalid")
	}
	return repositoryID, refs, prerequisites, nil
}

func reconcileV2GitAcknowledgements(runtime *v2PeerRuntime, repository *v2GitRepository, state *v2GitPeerState) error {
	repositoryID, err := repository.loadRepositoryID()
	if err != nil {
		return err
	}
	for digest, sent := range runtime.state.Sent {
		if sent.PayloadType != 4 {
			continue
		}
		outbound, exists := state.Outbound[digest]
		if !exists {
			metadataBytes, err := decodeV2Base64URL(sent.TypeMetadata, -1)
			if err != nil {
				return err
			}
			var raw any
			if err := v2DecMode.Unmarshal(metadataBytes, &raw); err != nil {
				return err
			}
			metadata, err := decodeV2GitMetadata(raw)
			if err != nil {
				return err
			}
			if !bytes.Equal(metadata.RepositoryID, repositoryID) {
				// Delivery-chain state is relationship-wide, while Git state is
				// repository-local. Other repositories paired with this peer
				// are expected to appear in the same durable Sent map.
				continue
			}
			outbound = v2GitOutboundState{
				Sequence: sent.Sequence, DescriptorDigest: digest,
				Refs: stringGitRefs(metadata.Refs), Prerequisites: []string{},
			}
		}
		if sent.Rejected && !outbound.Rejected {
			outbound.Rejected = true
			outbound.RejectedAt = sent.RejectedAt
			appendV2GitHistory(state, "outbound", sent.Sequence, digest, "rejected")
		}
		if sent.Acknowledged && !outbound.Acknowledged {
			resultBytes, err := decodeV2Base64URL(sent.ResultMetadata, -1)
			if err != nil {
				return err
			}
			var result any
			if err := v2DecMode.Unmarshal(resultBytes, &result); err != nil {
				return err
			}
			ackedRepositoryID, fetchedRefs, _, err := decodeV2GitResultMetadata(result)
			if err != nil {
				return err
			}
			if !bytes.Equal(ackedRepositoryID, repositoryID) {
				return errors.New("Git acknowledgement names a different repository")
			}
			expectedRefs, err := byteGitRefs(outbound.Refs, repository.ObjectHexLen/2)
			if err != nil || !equalV2GitRefs(expectedRefs, fetchedRefs) {
				return errors.New("Git acknowledgement fetched refs do not match the sent checkpoint")
			}
			outbound.Acknowledged = true
			outbound.AcknowledgedAt = sent.AcknowledgedAt
			state.LastAcknowledgedSentSequence = sent.Sequence
			state.LastAcknowledgedRefs = stringGitRefs(fetchedRefs)
			appendV2GitHistory(state, "outbound", sent.Sequence, digest, "acknowledged")
		}
		state.Outbound[digest] = outbound
	}
	return repository.writePeerState(state)
}

func (runtime *v2PeerRuntime) receiveAvailableV2Git(ctx context.Context, a *app, repository *v2GitRepository, opts v2GitFetchOptions) (bool, error) {
	now := time.Now()
	dataProofs, err := runtime.granularDataQueryProofs(now)
	if err != nil {
		return false, err
	}
	controlProofs, err := runtime.granularControlQueryProofs(now)
	if err != nil {
		return false, err
	}
	processed, err := decodeV2ControlEventIDs(runtime.state.PendingControlEventIDs)
	if err != nil {
		return false, err
	}
	response, err := queryV2GranularInbox(ctx, runtime.transport, runtime.origin, dataProofs, controlProofs, processed)
	if err != nil {
		return false, err
	}
	rawControls, ok := response.Header[2].([]any)
	if !ok {
		return false, errors.New("granular inbox control events are invalid")
	}
	if err := runtime.applyV2GranularControlResponse(rawControls); err != nil {
		return false, err
	}
	pending, err := validateV2GranularDataSlotResults(response.Header, dataProofs)
	if err != nil {
		return false, err
	}
	delivery, err := decodeV2GranularInboxDelivery(response)
	if err != nil {
		return false, err
	}
	runtime.state.DataScanEpoch = v2SlotEpoch(now)
	runtime.state.PendingDataEpochs = pending
	if delivery == nil {
		return false, writeV2PeerDeliveryState(runtime.paths, runtime.state)
	}
	var sourceEpoch uint64
	for _, proof := range dataProofs {
		if bytes.Equal(proof.Slot, delivery.Slot) {
			sourceEpoch = proof.Epoch
			break
		}
	}
	if sourceEpoch == 0 {
		return false, errors.New("Git inbox delivery slot was not requested")
	}
	return runtime.applyV2GitDelivery(ctx, a, repository, opts, delivery, sourceEpoch)
}

// rejectV2GitDelivery commits a refusal of a delivery this device can never
// apply: it acknowledges with result 1, advances the data-chain watermark, and
// records the reason durably. Advancing the watermark is the whole point.
// Without it the delivery stays at the head of the chain forever, and because
// `dud receive` also refuses to step over a Git payload, one unprocessable
// checkpoint would silence the relationship in both directions.
//
// The refusal is written to state before it is queued, so a crash in between
// leaves the delivery to be re-offered and refused again rather than lost. The
// causes are deterministic, so repeating the refusal reaches the same verdict.
func (runtime *v2PeerRuntime) rejectV2GitDelivery(ctx context.Context, a *app, opts v2GitFetchOptions, envelope *validatedV2Envelope, delivery *v2GranularInboxDelivery, sourceSlotEpoch uint64, policyDigest []byte, sequence uint64, digest string, cause error) (bool, error) {
	now := uint64(time.Now().Unix())
	transfer := runtime.state.InboundTransfers[digest]
	if transfer.Phase == "output-committed" {
		return false, errors.New("refusing to reject a Git delivery that already committed")
	}
	transfer.EntryID = hex.EncodeToString(delivery.ID)
	transfer.Slot = hex.EncodeToString(delivery.Slot)
	transfer.DescriptorDigest = digest
	transfer.Sequence = sequence
	transfer.Phase = "rejected"
	transfer.PolicyDigest = hex.EncodeToString(policyDigest)
	transfer.DescriptorCiphertext = v2Base64URL(delivery.EncryptedDescriptor)
	transfer.RejectionReason = cause.Error()
	transfer.ExpiresAt = now + v2MaximumTTLSeconds
	runtime.state.InboundTransfers[digest] = transfer
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return false, err
	}
	if err := runtime.queueV2GranularRejection(envelope, delivery.ID, delivery.Slot, sourceSlotEpoch, policyDigest); err != nil {
		return false, err
	}
	dataChain := runtime.state.Chains["in:data"]
	dataChain.ReceiveWatermark = sequence
	dataChain.ReceiveDigest = digest
	dataChain.Replay[sequence] = v2ReplayEntry{
		Sequence: sequence, DescriptorDigest: digest,
		ExpiresAt:    now + v2MaximumTTLSeconds,
		OutputDigest: hex.EncodeToString(make([]byte, 32)),
	}
	pruneV2ReplayHistory(runtime.state, now)
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return false, err
	}
	if err := runtime.flushPendingCompletions(ctx); err != nil {
		fmt.Fprintf(a.errOut, "WARNING: Git checkpoint refused; refusal queued for automatic retry: %v\n", err)
	}
	status := v2DeliveryStatusOf(runtime.state)
	if opts.JSON {
		return true, writeJSON(a.out, status.merge(map[string]any{
			"peer": opts.Alias, "received": false, "rejected": true,
			"sequence": sequence, "descriptor_digest": digest,
			"reason":          cause.Error(),
			"acknowledgement": len(runtime.state.PendingCompletions) == 0,
		}))
	}
	fmt.Fprintf(a.out, "Refused Git checkpoint %d: %v\n", sequence, cause)
	fmt.Fprintln(a.out, "The peer was told the checkpoint was refused, and the chain advanced past it.")
	fmt.Fprintln(a.out, "No refs were changed. Ask the peer to push a checkpoint this client can apply.")
	return true, nil
}

func (runtime *v2PeerRuntime) applyV2GitDelivery(ctx context.Context, a *app, repository *v2GitRepository, opts v2GitFetchOptions, delivery *v2GranularInboxDelivery, sourceSlotEpoch uint64) (bool, error) {
	descriptorCiphertext := delivery.EncryptedDescriptor
	expectation, err := runtime.descriptorExpectation()
	if err != nil {
		return false, err
	}
	envelope, err := decryptAndValidateV2Envelope(descriptorCiphertext, runtime.identity, expectation)
	if err != nil {
		return false, err
	}
	chainID, err := descriptorUint(envelope.Descriptor, kChain, "chain")
	if err != nil || chainID != 0 {
		return false, errors.New("data slot contains a non-data descriptor")
	}
	payloadType, err := descriptorUint(envelope.Descriptor, kPayloadType, "payload type")
	if err != nil {
		return false, err
	}
	if payloadType != 4 {
		return false, fmt.Errorf("next delivery is payload type %d; receive it with dud receive %s before fetching Git", payloadType, opts.Alias)
	}
	// Chain position and policy are established before the payload is judged, so
	// that a refusal is only ever issued for a delivery that legitimately sits
	// at the head of this chain, and so that the binding a refusal has to carry
	// is already in hand at every site that can raise one.
	next, err := runtime.validateNextDescriptor(runtime.state.Chains["in:data"], envelope)
	if err != nil {
		_ = writeV2PeerDeliveryState(runtime.paths, runtime.state)
		return false, err
	}
	policy, err := descriptorPolicy(envelope.Descriptor)
	if err != nil {
		return false, err
	}
	if err := validateV2EffectivePolicy(policy, delivery.EffectivePolicy); err != nil {
		return false, err
	}
	// Validated non-zero just above, so the pruner never reads this as the
	// "retain indefinitely" sentinel.
	expiresAt, _ := asV2Uint(delivery.EffectivePolicy[1])
	policyDigest, err := v2PolicyDigest(policy)
	if err != nil {
		return false, err
	}
	if !next {
		return false, errors.New("Git delivery is already committed but lacks a durable completion")
	}
	sequence, _ := descriptorUint(envelope.Descriptor, kSequence, "sequence")
	digest := hex.EncodeToString(envelope.DescriptorDigest[:])
	reject := func(cause error) (bool, error) {
		return runtime.rejectV2GitDelivery(ctx, a, opts, envelope, delivery, sourceSlotEpoch, policyDigest, sequence, digest, cause)
	}
	metadata, err := decodeV2GitMetadata(envelope.Descriptor[kTypeMetadata])
	if err != nil {
		return reject(err)
	}
	if err := requireCompleteV2GitCheckpoint(metadata); err != nil {
		return reject(err)
	}
	if err := a.validateV2GitMetadata(repository, metadata); err != nil {
		return reject(err)
	}
	repositoryID, repositoryIDErr := repository.loadRepositoryID()
	switch {
	case repositoryIDErr == nil && !bytes.Equal(repositoryID, metadata.RepositoryID):
		return false, errors.New("Git delivery belongs to a different repository")
	case errors.Is(repositoryIDErr, os.ErrNotExist) && !opts.Associate:
		return false, errors.New("repository is not associated with this checkpoint; inspect the peer and rerun with --associate")
	case repositoryIDErr != nil && !errors.Is(repositoryIDErr, os.ErrNotExist):
		return false, repositoryIDErr
	}
	if _, exists := runtime.state.InboundTransfers[digest]; !exists {
		runtime.state.InboundTransfers[digest] = v2InboundTransfer{
			EntryID: hex.EncodeToString(delivery.ID), Slot: hex.EncodeToString(delivery.Slot),
			DescriptorDigest: digest, Sequence: sequence, Phase: "descriptor-verified",
			PolicyDigest:         hex.EncodeToString(policyDigest),
			DescriptorCiphertext: v2Base64URL(descriptorCiphertext),
			ExpiresAt:            expiresAt,
		}
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return false, err
		}
	}
	payloadCiphertext := delivery.Payload
	chunks, ok := envelope.Descriptor[kChunkHashes].([]any)
	if !ok || len(chunks) != 1 {
		return false, errors.New("Git descriptor ciphertext hash list is invalid")
	}
	expectedCipherDigest, _ := chunks[0].([]byte)
	actualCipherDigest := sha256.Sum256(payloadCiphertext)
	if !bytes.Equal(expectedCipherDigest, actualCipherDigest[:]) {
		return false, errors.New("Git payload ciphertext does not match the signed descriptor")
	}
	plaintext, err := decryptV2Payload(payloadCiphertext, runtime.identity, v2MaximumObjectBytes)
	if err != nil {
		return false, err
	}
	plainDigest := sha256.Sum256(plaintext)
	expectedPlainDigest, _ := envelope.Descriptor[kPayloadHash].([]byte)
	if !bytes.Equal(expectedPlainDigest, plainDigest[:]) {
		return false, errors.New("Git bundle does not match the signed descriptor")
	}
	if size, exists := envelope.Descriptor[kPlaintextSize]; exists {
		value, ok := asV2Uint(size)
		if !ok || value != uint64(len(plaintext)) {
			return false, errors.New("Git bundle size does not match the signed descriptor")
		}
	}
	bundlePath := filepath.Join(repository.DUDDir, "transfers", digest+".bundle")
	if existing, readErr := os.ReadFile(bundlePath); readErr == nil {
		existingDigest := sha256.Sum256(existing)
		if !bytes.Equal(existingDigest[:], plainDigest[:]) {
			return false, errors.New("durable Git bundle conflicts with the signed delivery")
		}
	} else {
		if !errors.Is(readErr, os.ErrNotExist) {
			return false, readErr
		}
		if err := atomicWriteV2File(bundlePath, plaintext, 0o600); err != nil {
			return false, err
		}
	}
	headerVersion, headerRefs, headerPrerequisites, err := parseV2GitBundleHeader(bundlePath, repository.ObjectHexLen/2)
	if err != nil {
		return false, err
	}
	if headerVersion != metadata.BundleVersion || len(headerPrerequisites) != 0 ||
		!equalV2GitRefs(headerRefs, metadata.Refs) {
		return reject(errors.New("Git bundle header does not match the signed encrypted metadata"))
	}
	globalTransfer := v2InboundTransfer{
		EntryID: hex.EncodeToString(delivery.ID), Slot: hex.EncodeToString(delivery.Slot),
		DescriptorDigest: digest, Sequence: sequence, Phase: "payload-verified",
		TemporaryOutput: bundlePath, OutputDigest: hex.EncodeToString(plainDigest[:]),
		PolicyDigest:         hex.EncodeToString(policyDigest),
		DescriptorCiphertext: v2Base64URL(descriptorCiphertext),
		PlaintextPayload:     bundlePath, ExpiresAt: expiresAt,
	}
	if existing, exists := runtime.state.InboundTransfers[digest]; exists {
		if existing.Sequence != sequence ||
			(existing.OutputDigest != "" && existing.OutputDigest != globalTransfer.OutputDigest) ||
			existing.PolicyDigest != globalTransfer.PolicyDigest {
			return false, errors.New("durable Git transfer state conflicts with the signed descriptor")
		}
		if existing.Phase == "output-committed" {
			globalTransfer = existing
		}
	}
	runtime.state.InboundTransfers[digest] = globalTransfer
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return false, err
	}
	if repositoryIDErr != nil {
		if err := repository.associateRepositoryID(metadata.RepositoryID); err != nil {
			return false, err
		}
		repositoryID = append([]byte(nil), metadata.RepositoryID...)
	}
	state, err := repository.loadPeerState(repositoryID, runtime.peer.PeerPseudonymousID)
	if err != nil {
		return false, err
	}
	inbound := state.Inbound[digest]
	if inbound.Phase != "output-committed" {
		if inbound.Phase == "" {
			inbound = v2GitInboundState{
				Sequence: sequence, DescriptorDigest: digest, Phase: "payload-verified",
				BundlePath: bundlePath, Refs: stringGitRefs(metadata.Refs), Prerequisites: []string{},
			}
			state.Inbound[digest] = inbound
			appendV2GitHistory(state, "inbound", sequence, digest, "payload-verified")
			if err := repository.writePeerState(state); err != nil {
				return false, err
			}
		}
		scratch, err := a.verifyV2GitQuarantine(repository, bundlePath, digest, metadata)
		if err != nil {
			// Only the durable-limit and signed-content failures inside
			// quarantine verification carry a permanent rejection. A full disk,
			// an exceeded wall-time budget, or a failed fsck stays an error so
			// the delivery is offered again.
			if isV2GitPermanentRejection(err) {
				return reject(err)
			}
			return false, err
		}
		inbound.Phase = "verified"
		state.Inbound[digest] = inbound
		appendV2GitHistory(state, "inbound", sequence, digest, "verified")
		if err := repository.writePeerState(state); err != nil {
			_ = os.RemoveAll(scratch)
			return false, err
		}
		remote := runtime.peer.GitRemote
		if remote == "" {
			remote = opts.Alias
		}
		fetchedRefs, err := a.promoteV2GitQuarantine(repository, state, scratch, digest, remote, metadata, opts.AllowRewrite)
		if err != nil {
			return false, err
		}
		resultMetadata := map[int]any{
			1: metadata.RepositoryID,
			2: fetchedRefs,
			3: metadata.Prerequisites,
		}
		resultBytes, err := v2EncMode.Marshal(resultMetadata)
		if err != nil {
			return false, err
		}
		resultDigest := sha256.Sum256(resultBytes)
		inbound.Phase = "output-committed"
		inbound.FetchedRefs = stringGitRefs(fetchedRefs)
		inbound.OutputDigest = hex.EncodeToString(resultDigest[:])
		state.Inbound[digest] = inbound
		state.LastReceivedSequence = sequence
		state.LastReceivedDescriptorDigest = digest
		state.LastReceivedDeliveryID = hex.EncodeToString(delivery.ID)
		state.LastReceivedRefs = stringGitRefs(fetchedRefs)
		appendV2GitHistory(state, "inbound", sequence, digest, "output-committed")
		if err := repository.writePeerState(state); err != nil {
			return false, err
		}
	}
	fetchedRefs, err := byteGitRefs(inbound.FetchedRefs, repository.ObjectHexLen/2)
	if err != nil {
		return false, err
	}
	resultMetadata := map[int]any{
		1: metadata.RepositoryID,
		2: fetchedRefs,
		3: metadata.Prerequisites,
	}
	resultBytes, err := v2EncMode.Marshal(resultMetadata)
	if err != nil {
		return false, err
	}
	resultDigest := sha256.Sum256(resultBytes)
	globalTransfer.Phase = "output-committed"
	globalTransfer.CommittedOutput = repository.CommonDir
	globalTransfer.OutputDigest = hex.EncodeToString(resultDigest[:])
	runtime.state.InboundTransfers[digest] = globalTransfer
	if err := runtime.queueV2GranularCompletion(envelope, delivery.ID, delivery.Slot, sourceSlotEpoch, policyDigest, resultDigest[:], resultMetadata); err != nil {
		return false, err
	}
	dataChain := runtime.state.Chains["in:data"]
	dataChain.ReceiveWatermark = sequence
	dataChain.ReceiveDigest = digest
	dataChain.Replay[sequence] = v2ReplayEntry{
		Sequence: sequence, DescriptorDigest: digest,
		ExpiresAt:    uint64(time.Now().Unix()) + v2MaximumTTLSeconds,
		OutputDigest: hex.EncodeToString(resultDigest[:]),
	}
	pruneV2ReplayHistory(runtime.state, uint64(time.Now().Unix()))
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return false, err
	}
	if err := runtime.flushPendingCompletions(ctx); err != nil {
		fmt.Fprintf(a.errOut, "WARNING: Git refs committed; atomic completion queued for automatic retry: %v\n", err)
	}
	remote := runtime.peer.GitRemote
	if remote == "" {
		remote = opts.Alias
	}
	status := v2DeliveryStatusOf(runtime.state)
	quarantined := quarantinedV2GitDeliveries(state)
	if opts.JSON {
		return true, writeJSON(a.out, status.merge(map[string]any{
			"peer": opts.Alias, "received": true, "repository_id": hex.EncodeToString(repositoryID),
			"sequence": sequence, "descriptor_digest": digest,
			"remote": remote, "refs": stringGitRefs(fetchedRefs),
			"acknowledgement":            len(runtime.state.PendingCompletions) == 0,
			"quarantined_git_deliveries": quarantined,
		}))
	}
	fmt.Fprintf(a.out, "Fetched complete Git checkpoint into refs/remotes/%s/*.\n", remote)
	if err := v2GitStatusReport(opts.Verbose, status, quarantined, rejectedV2GitDeliveries(runtime.state)).write(a.out); err != nil {
		return false, err
	}
	fmt.Fprintln(a.out, "Local branches and the working tree were not changed.")
	fmt.Fprintln(a.out, "Inspect with: git log --oneline --decorate --graph --all")
	branchNames := make([]string, 0, len(fetchedRefs))
	for name := range fetchedRefs {
		if strings.HasPrefix(name, "refs/heads/") {
			branchNames = append(branchNames, strings.TrimPrefix(name, "refs/heads/"))
		}
	}
	sort.Strings(branchNames)
	for _, branch := range branchNames {
		if _, exists, _ := a.v2GitRefOID(repository, "refs/heads/"+branch); exists {
			fmt.Fprintf(a.out, "  git diff %s...%s/%s\n", branch, remote, branch)
			fmt.Fprintf(a.out, "  git merge --ff-only %s/%s\n", remote, branch)
			fmt.Fprintf(a.out, "  git rebase %s/%s  # only after inspection\n", remote, branch)
		}
	}
	return true, nil
}

func (a *app) cmdV2GitFetch(args []string) error {
	opts, err := parseV2GitFetchOptions(args)
	if err != nil {
		return err
	}
	repository, err := a.resolveV2GitRepository("fetch")
	if err != nil {
		return err
	}
	return a.withV2Peer(opts.Alias, 2*time.Minute, func(runtime *v2PeerRuntime) error {
		if err := runtime.requireGitFeatures(); err != nil {
			return err
		}
		unlock, err := repository.acquirePeerLock(runtime.peer.PeerPseudonymousID)
		if err != nil {
			return err
		}
		defer unlock()
		ctx := context.Background()
		_ = runtime.boundedControlDrain(ctx)
		if runtime.state.Halted {
			return fmt.Errorf("peer relationship is halted: %s", runtime.state.HaltReason)
		}
		if err := runtime.flushPendingCompletions(ctx); err != nil {
			fmt.Fprintf(a.errOut, "WARNING: queued peer completions remain pending: %v\n", err)
		}
		received, err := runtime.receiveAvailableV2Git(ctx, a, repository, opts)
		if err != nil {
			return err
		}
		if received {
			return nil
		}
		quarantined := []map[string]any{}
		if repositoryID, idErr := repository.loadRepositoryID(); idErr == nil {
			if state, stateErr := repository.loadPeerState(repositoryID, runtime.peer.PeerPseudonymousID); stateErr == nil {
				quarantined = quarantinedV2GitDeliveries(state)
			}
		}
		status := v2DeliveryStatusOf(runtime.state)
		rejected := rejectedV2GitDeliveries(runtime.state)
		if opts.JSON {
			return writeJSON(a.out, status.merge(map[string]any{
				"peer": opts.Alias, "received": false,
				"quarantined_git_deliveries": quarantined,
				"rejected_git_deliveries":    rejected,
			}))
		}
		fmt.Fprintf(a.out, "No pending Git checkpoint from %s.\n", opts.Alias)
		return v2GitStatusReport(opts.Verbose, status, quarantined, rejected).write(a.out)
	})
}

func (a *app) v2GitDivergence(repository *v2GitRepository, remote string, refs map[string]string) map[string]map[string]uint64 {
	result := map[string]map[string]uint64{}
	for name := range refs {
		if !strings.HasPrefix(name, "refs/heads/") {
			continue
		}
		branch := strings.TrimPrefix(name, "refs/heads/")
		local := "refs/heads/" + branch
		peer := "refs/remotes/" + remote + "/" + branch
		if _, exists, _ := a.v2GitRefOID(repository, local); !exists {
			continue
		}
		command := exec.Command(a.cfg.GitBin, "rev-list", "--left-right", "--count", local+"..."+peer)
		output, err := command.Output()
		if err != nil {
			continue
		}
		fields := strings.Fields(string(output))
		if len(fields) != 2 {
			continue
		}
		ahead, err1 := strconv.ParseUint(fields[0], 10, 64)
		behind, err2 := strconv.ParseUint(fields[1], 10, 64)
		if err1 == nil && err2 == nil {
			result[branch] = map[string]uint64{"local_only": ahead, "peer_only": behind}
		}
	}
	return result
}

func (a *app) v2GitStatusForPeer(repository *v2GitRepository, repositoryID []byte, alias string) (map[string]any, error) {
	var rendered map[string]any
	err := a.withV2Peer(alias, 30*time.Second, func(runtime *v2PeerRuntime) error {
		if err := runtime.requireGitFeatures(); err != nil {
			return err
		}
		unlock, err := repository.acquirePeerLock(runtime.peer.PeerPseudonymousID)
		if err != nil {
			return err
		}
		defer unlock()
		_ = runtime.boundedControlDrain(context.Background())
		state, err := repository.loadPeerState(repositoryID, runtime.peer.PeerPseudonymousID)
		if err != nil {
			return err
		}
		if err := reconcileV2GitAcknowledgements(runtime, repository, state); err != nil {
			return err
		}
		remote := runtime.peer.GitRemote
		if remote == "" {
			remote = alias
		}
		rendered = v2DeliveryStatusOf(runtime.state).merge(map[string]any{
			"peer": alias, "remote": remote,
			"repository_id":                   state.RepositoryID,
			"quarantined_git_deliveries":      quarantinedV2GitDeliveries(state),
			"rejected_git_deliveries":         rejectedV2GitDeliveries(runtime.state),
			"refused_git_checkpoints":         refusedV2GitCheckpoints(state),
			"peer_features":                   runtime.state.PeerFeatures,
			"last_received_sequence":          state.LastReceivedSequence,
			"last_received_descriptor_digest": state.LastReceivedDescriptorDigest,
			"last_received_delivery_id":       state.LastReceivedDeliveryID,
			"last_received_refs":              state.LastReceivedRefs,
			"last_acknowledged_sent_sequence": state.LastAcknowledgedSentSequence,
			"last_acknowledged_refs":          state.LastAcknowledgedRefs,
			"last_full_checkpoint_sequence":   state.LastFullCheckpointSequence,
			"pending_outbound":                countPendingV2GitOutbound(state),
			"divergence":                      a.v2GitDivergence(repository, remote, state.LastReceivedRefs),
		})
		return nil
	})
	return rendered, err
}

// quarantinedV2GitDeliveries lists inbound checkpoints that were accepted and
// verified locally but never promoted into peer refs, for example because the
// checkpoint rewrites accepted history and is waiting for --allow-rewrite.
// They hold local disk and block the chain, so every Git result reports them.
func quarantinedV2GitDeliveries(state *v2GitPeerState) []map[string]any {
	digests := make([]string, 0, len(state.Inbound))
	for digest, inbound := range state.Inbound {
		if inbound.Phase != "output-committed" {
			digests = append(digests, digest)
		}
	}
	sort.Strings(digests)
	quarantined := make([]map[string]any, 0, len(digests))
	for _, digest := range digests {
		inbound := state.Inbound[digest]
		quarantined = append(quarantined, map[string]any{
			"descriptor_digest": digest,
			"sequence":          inbound.Sequence,
			"phase":             inbound.Phase,
		})
	}
	return quarantined
}

// v2GitStatusReport renders the shared delivery counters plus the Git-specific
// quarantine list as one block, so every Git command reports the same rows in
// the same order as send, receive, and sync. Like the peer commands it reports
// on request or on trouble, and the trouble here is wider than the shared
// counters know about: a quarantined or refused Git delivery leaves every
// v2DeliveryStatus counter at zero, so those two lists raise the block on their
// own rather than waiting for a -v that an operator has no reason to pass.
func v2GitStatusReport(verbose bool, status v2DeliveryStatus, quarantined, rejected []map[string]any) *textReport {
	report := &textReport{}
	if !verbose && !status.needsAttention() && len(quarantined) == 0 && len(rejected) == 0 {
		return report
	}
	section := report.section("Status")
	section.addRows(status.rows())
	if len(quarantined) == 0 {
		section.add("quarantined Git deliveries", "none")
	} else {
		entries := make([]string, 0, len(quarantined))
		for _, entry := range quarantined {
			entries = append(entries, fmt.Sprintf("%v (%v)", entry["descriptor_digest"], entry["phase"]))
		}
		section.addList("quarantined Git deliveries", strconv.Itoa(len(entries)), entries)
	}
	if len(rejected) != 0 {
		entries := make([]string, 0, len(rejected))
		for _, entry := range rejected {
			entries = append(entries, fmt.Sprintf("%v (%v)", entry["descriptor_digest"], entry["reason"]))
		}
		section.addList("refused Git deliveries", strconv.Itoa(len(entries)), entries)
	}
	return report
}

func countPendingV2GitOutbound(state *v2GitPeerState) int {
	count := 0
	for _, outbound := range state.Outbound {
		if !outbound.Acknowledged && !outbound.Rejected {
			count++
		}
	}
	return count
}

// refusedV2GitCheckpoints lists checkpoints the peer acknowledged with result 1.
// They are counted apart from pending ones because waiting will not resolve
// them: the peer already answered, and the answer was no.
func refusedV2GitCheckpoints(state *v2GitPeerState) []map[string]any {
	digests := make([]string, 0, len(state.Outbound))
	for digest, outbound := range state.Outbound {
		if outbound.Rejected {
			digests = append(digests, digest)
		}
	}
	sort.Strings(digests)
	refused := make([]map[string]any, 0, len(digests))
	for _, digest := range digests {
		refused = append(refused, map[string]any{
			"descriptor_digest": digest,
			"sequence":          state.Outbound[digest].Sequence,
			"rejected_at":       state.Outbound[digest].RejectedAt,
		})
	}
	return refused
}

// rejectedV2GitDeliveries lists inbound checkpoints this device refused. They
// live in relationship-wide delivery state rather than per-repository Git state
// because a checkpoint can be refused before its repository is ever identified.
func rejectedV2GitDeliveries(state *v2PeerDeliveryState) []map[string]any {
	digests := make([]string, 0, len(state.InboundTransfers))
	for digest, transfer := range state.InboundTransfers {
		if transfer.Phase == "rejected" {
			digests = append(digests, digest)
		}
	}
	sort.Strings(digests)
	rejected := make([]map[string]any, 0, len(digests))
	for _, digest := range digests {
		rejected = append(rejected, map[string]any{
			"descriptor_digest": digest,
			"sequence":          state.InboundTransfers[digest].Sequence,
			"reason":            state.InboundTransfers[digest].RejectionReason,
		})
	}
	return rejected
}

func (a *app) cmdV2GitStatus(args []string) error {
	jsonOutput := false
	var alias string
	for len(args) != 0 {
		switch args[0] {
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
			args = args[1:]
		case "--url", "--doh-url", "--ech-mode":
			return v2PeerNetworkOptionError(args[0])
		default:
			if strings.HasPrefix(args[0], "-") {
				return fatalError("Unknown git status option: " + args[0])
			}
			if alias != "" {
				return errors.New("git status accepts at most one peer alias")
			}
			alias = args[0]
			args = args[1:]
		}
	}
	repository, err := a.resolveV2GitRepository("status")
	if err != nil {
		return err
	}
	repositoryID, err := repository.loadRepositoryID()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("Git repository has no DUD identity; push a checkpoint or explicitly associate an incoming checkpoint first")
		}
		return err
	}
	aliases := []string{alias}
	if alias == "" {
		cfg, _, err := loadV2Config()
		if err != nil {
			return err
		}
		aliases = aliases[:0]
		for name, peer := range cfg.Peers {
			if peer.Status == "active" {
				aliases = append(aliases, name)
			}
		}
		sort.Strings(aliases)
	}
	statuses := make([]map[string]any, 0, len(aliases))
	for _, name := range aliases {
		status, err := a.v2GitStatusForPeer(repository, repositoryID, name)
		if err != nil {
			return err
		}
		statuses = append(statuses, status)
	}
	if jsonOutput {
		return writeJSON(a.out, map[string]any{
			"repository_id": hex.EncodeToString(repositoryID),
			"peers":         statuses,
		})
	}
	report := &textReport{}
	report.section("").add("Repository", hex.EncodeToString(repositoryID))
	for _, status := range statuses {
		section := report.section(fmt.Sprintf("Peer %v", status["peer"]))
		section.addf("remote", "%v", status["remote"])
		section.addf("received sequence", "%v", status["last_received_sequence"])
		section.addf("acknowledged sent sequence", "%v", status["last_acknowledged_sent_sequence"])
		section.addf("pending outbound", "%v", status["pending_outbound"])
		section.addf("queued completions", "%v", status["pending_completions"])
		section.addf("undrained control", "%v", status["undrained_control"])
		section.addf("quarantined chains", "%d", len(status["quarantined_chains"].([]v2QuarantinedChain)))
		section.addf("halted", "%v", status["halted"])
		quarantined, _ := status["quarantined_git_deliveries"].([]map[string]any)
		if len(quarantined) == 0 {
			section.add("quarantined Git deliveries", "none")
		} else {
			entries := make([]string, 0, len(quarantined))
			for _, entry := range quarantined {
				entries = append(entries, fmt.Sprintf("%v (%v)", entry["descriptor_digest"], entry["phase"]))
			}
			section.addList("quarantined Git deliveries", strconv.Itoa(len(entries)), entries)
		}
		if rejected, _ := status["rejected_git_deliveries"].([]map[string]any); len(rejected) != 0 {
			entries := make([]string, 0, len(rejected))
			for _, entry := range rejected {
				entries = append(entries, fmt.Sprintf("%v (%v)", entry["descriptor_digest"], entry["reason"]))
			}
			section.addList("refused incoming checkpoints", strconv.Itoa(len(entries)), entries)
		}
		if refused, _ := status["refused_git_checkpoints"].([]map[string]any); len(refused) != 0 {
			entries := make([]string, 0, len(refused))
			for _, entry := range refused {
				entries = append(entries, fmt.Sprintf("%v (sequence %v)", entry["descriptor_digest"], entry["sequence"]))
			}
			section.addList("checkpoints the peer refused", strconv.Itoa(len(entries)), entries)
		}
		if features, _ := status["peer_features"].([]uint64); len(features) != 0 {
			names := make([]string, 0, len(features))
			for _, id := range features {
				names = append(names, v2FeatureName(id))
			}
			section.add("peer features", strings.Join(names, ", "))
		}
		divergence, _ := status["divergence"].(map[string]map[string]uint64)
		if len(divergence) != 0 {
			branches := section.child("Divergence")
			for _, branch := range sortedKeys(divergence) {
				value := divergence[branch]
				branches.addf(branch, "local-only %d, peer-only %d", value["local_only"], value["peer_only"])
			}
		}
	}
	if err := report.write(a.out); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "\nDUD never merges, rebases, checks out, or moves local branches automatically.")
	return nil
}
