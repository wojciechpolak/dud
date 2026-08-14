// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const v2ManagedRefsVersion = 1

type v2EraseOptions struct {
	Scope       string
	Peer        string
	Yes         bool
	DryRun      bool
	JSON        bool
	IncludeRepo bool
}

type v2EraseResult struct {
	Scope       string   `json:"scope"`
	Erased      bool     `json:"erased"`
	Removed     []string `json:"removed"`
	Retained    []string `json:"retained"`
	Warnings    []string `json:"warnings"`
	WouldRemove []string `json:"would_remove,omitempty"`
}

type v2ManagedGitRefs struct {
	Version int               `json:"version"`
	Refs    map[string]string `json:"refs"`
}

type v2StagedErasePath struct {
	Original string
	Staged   string
}

func parseV2EraseOptions(args []string) (v2EraseOptions, error) {
	if len(args) == 0 {
		return v2EraseOptions{}, fatalError("Usage: dud erase pairings|peer NAME|repo|all ...")
	}
	opts := v2EraseOptions{Scope: args[0]}
	args = args[1:]
	if opts.Scope == "peer" {
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			return opts, fatalError("dud erase peer requires NAME")
		}
		opts.Peer = args[0]
		args = args[1:]
		if err := validateV2PeerAlias(opts.Peer); err != nil {
			return opts, err
		}
	}
	if opts.Scope != "pairings" && opts.Scope != "peer" && opts.Scope != "repo" && opts.Scope != "all" {
		return opts, fatalError("Unknown erase scope: " + opts.Scope)
	}
	for len(args) != 0 {
		switch args[0] {
		case "--yes":
			opts.Yes = true
		case "--dry-run":
			opts.DryRun = true
		case "--json":
			if err := markJSONOption(&opts.JSON); err != nil {
				return opts, err
			}
		case "--repo":
			if opts.Scope != "all" {
				return opts, fatalError("--repo is only valid with 'dud erase all'")
			}
			opts.IncludeRepo = true
		default:
			return opts, fatalError("Unknown erase option: " + args[0])
		}
		args = args[1:]
	}
	if opts.Yes && opts.DryRun {
		return opts, fatalError("--yes and --dry-run cannot be combined")
	}
	if !opts.Yes && !opts.DryRun {
		return opts, fatalError("dud erase is destructive; rerun with --yes or inspect it with --dry-run")
	}
	return opts, nil
}

func newV2EraseResult(scope string) v2EraseResult {
	return v2EraseResult{
		Scope:    scope,
		Removed:  []string{},
		Retained: []string{},
		Warnings: []string{},
	}
}

func (a *app) cmdErase(args []string) error {
	opts, err := parseV2EraseOptions(args)
	if err != nil {
		return err
	}
	result := newV2EraseResult(opts.Scope)
	var eraseErr error
	switch opts.Scope {
	case "pairings":
		result, eraseErr = a.eraseV2Pairings(opts.DryRun)
	case "peer":
		result, eraseErr = a.eraseV2Peer(opts.Peer, opts.DryRun)
	case "repo":
		result, eraseErr = a.eraseV2Repository(opts.DryRun)
	case "all":
		if opts.IncludeRepo {
			var repositoryResult v2EraseResult
			repositoryResult, eraseErr = a.eraseV2Repository(opts.DryRun)
			mergeV2EraseResults(&result, repositoryResult)
		}
		if eraseErr == nil {
			var localResult v2EraseResult
			localResult, eraseErr = a.eraseV2All(opts.DryRun)
			mergeV2EraseResults(&result, localResult)
		}
	}
	result.Scope = opts.Scope
	result.Erased = !opts.DryRun && eraseErr == nil
	result.Removed = sortedUniqueStrings(result.Removed)
	result.Retained = sortedUniqueStrings(result.Retained)
	result.Warnings = sortedUniqueStrings(result.Warnings)
	result.WouldRemove = sortedUniqueStrings(result.WouldRemove)
	if renderErr := a.renderV2EraseResult(result, opts.DryRun, opts.JSON); renderErr != nil {
		return renderErr
	}
	return eraseErr
}

func mergeV2EraseResults(target *v2EraseResult, source v2EraseResult) {
	target.Removed = append(target.Removed, source.Removed...)
	target.Retained = append(target.Retained, source.Retained...)
	target.Warnings = append(target.Warnings, source.Warnings...)
	target.WouldRemove = append(target.WouldRemove, source.WouldRemove...)
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (a *app) renderV2EraseResult(result v2EraseResult, dryRun, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(a.out, result)
	}
	if dryRun {
		if len(result.WouldRemove) == 0 {
			fmt.Fprintln(a.out, "Nothing would be removed.")
		} else {
			fmt.Fprintln(a.out, "Would remove:")
			for _, value := range result.WouldRemove {
				fmt.Fprintf(a.out, "  %s\n", value)
			}
		}
	} else if len(result.Removed) == 0 {
		fmt.Fprintln(a.out, "Nothing needed to be removed.")
	} else {
		fmt.Fprintln(a.out, "Removed:")
		for _, value := range result.Removed {
			fmt.Fprintf(a.out, "  %s\n", value)
		}
	}
	for _, value := range result.Retained {
		fmt.Fprintf(a.errOut, "RETAINED: %s\n", value)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(a.errOut, "WARNING: %s\n", warning)
	}
	return nil
}

func validateV2EraseDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true, fmt.Errorf("refusing to erase symlink %s", path)
	}
	if !info.IsDir() {
		return true, fmt.Errorf("refusing to erase non-directory %s", path)
	}
	return true, nil
}

func validateV2EraseFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return true, fmt.Errorf("refusing to erase non-regular file %s", path)
	}
	return true, nil
}

func v2EraseTombstone(path string) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		random, err := randomV2Bytes(8)
		if err != nil {
			return "", err
		}
		candidate := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".erase-"+hex.EncodeToString(random))
		if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", errors.New("could not allocate a private erase tombstone")
}

func stageV2ErasePath(path string, directory bool) (v2StagedErasePath, bool, error) {
	var exists bool
	var err error
	if directory {
		exists, err = validateV2EraseDirectory(path)
	} else {
		exists, err = validateV2EraseFile(path)
	}
	if err != nil || !exists {
		return v2StagedErasePath{}, exists, err
	}
	tombstone, err := v2EraseTombstone(path)
	if err != nil {
		return v2StagedErasePath{}, true, err
	}
	if err := os.Rename(path, tombstone); err != nil {
		return v2StagedErasePath{}, true, err
	}
	_ = syncV2EraseDirectory(filepath.Dir(path))
	return v2StagedErasePath{Original: path, Staged: tombstone}, true, nil
}

func stageV2EraseMountedDirectory(path string) ([]v2StagedErasePath, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	staged := []v2StagedErasePath{}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		info, err := os.Lstat(child)
		if err != nil {
			_ = rollbackV2ErasePaths(staged)
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			_ = rollbackV2ErasePaths(staged)
			return nil, fmt.Errorf("refusing to erase unexpected bind-mount entry %s", child)
		}
		item, exists, err := stageV2ErasePath(child, info.IsDir())
		if err != nil {
			_ = rollbackV2ErasePaths(staged)
			return nil, err
		}
		if exists {
			staged = append(staged, item)
		}
	}
	return staged, nil
}

// A bind-mounted root cannot be renamed from inside the container, and the
// kernel reports that in two different ways. Renaming the mount point itself
// fails with EBUSY, but the tombstone would have to be created in the mount's
// parent (`/state`, `/config`), which the container runtime creates as root
// while DUD runs unprivileged, so the permission check rejects the rename with
// EACCES or EPERM first. Both mean the same thing here: the root stays, its
// contents are still ours to erase.
func v2EraseRootIsImmovable(err error) bool {
	return errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
}

func v2EraseDirectoryIsEmpty(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

func rollbackV2ErasePaths(paths []v2StagedErasePath) error {
	var failures []string
	for index := len(paths) - 1; index >= 0; index-- {
		item := paths[index]
		if err := os.Rename(item.Staged, item.Original); err != nil {
			failures = append(failures, fmt.Sprintf("restore %s: %v", item.Original, err))
		}
	}
	if len(failures) != 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func removeV2ErasePaths(paths []v2StagedErasePath, result *v2EraseResult) error {
	var failures []string
	for _, item := range paths {
		if err := os.RemoveAll(item.Staged); err != nil {
			result.Retained = append(result.Retained, item.Staged)
			failures = append(failures, fmt.Sprintf("remove %s: %v", item.Staged, err))
			continue
		}
		_ = syncV2EraseDirectory(filepath.Dir(item.Staged))
		result.Removed = append(result.Removed, item.Original)
	}
	if len(failures) != 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func syncV2EraseDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validateV2EraseRoots(paths v2Paths) error {
	for _, path := range sortedUniqueStrings([]string{paths.ConfigDir, paths.StateDir}) {
		if _, err := validateV2EraseDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func readV2ConfigForErase(paths v2Paths) (*v2LocalConfig, error) {
	if err := validatePrivateV2File(paths.Config); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(paths.Config)
	if err != nil {
		return nil, err
	}
	cfg, err := parseV2Config(body)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", paths.Config, err)
	}
	return cfg, nil
}

func (a *app) eraseV2Pairings(dryRun bool) (v2EraseResult, error) {
	result := newV2EraseResult("pairings")
	paths, err := resolveV2Paths()
	if err != nil {
		return result, err
	}
	if err := validateV2EraseRoots(paths); err != nil {
		result.Retained = append(result.Retained, paths.ConfigDir, paths.StateDir)
		return result, err
	}
	pairingsDir := filepath.Join(paths.StateDir, "pairings")
	if _, err := validateV2EraseDirectory(pairingsDir); err != nil {
		result.Retained = append(result.Retained, pairingsDir)
		return result, err
	}
	cfg, err := readV2ConfigForErase(paths)
	if err != nil {
		return result, err
	}
	for alias, peer := range cfg.Peers {
		if peer.Status == "pending" || peer.Status == "unpaired" {
			result.WouldRemove = append(result.WouldRemove, "config peer "+alias)
		}
	}
	if exists, _ := validateV2EraseDirectory(pairingsDir); exists {
		result.WouldRemove = append(result.WouldRemove, pairingsDir)
	}
	if dryRun {
		return result, nil
	}
	unlock, err := acquireV2EraseLock(paths)
	if err != nil {
		return result, err
	}
	defer unlock()
	cfg, err = readV2ConfigForErase(paths)
	if err != nil {
		return result, err
	}
	staged := []v2StagedErasePath{}
	item, exists, err := stageV2ErasePath(pairingsDir, true)
	if err != nil {
		result.Retained = append(result.Retained, pairingsDir)
		return result, err
	}
	if exists {
		staged = append(staged, item)
	}
	removedPeers := []string{}
	for alias, peer := range cfg.Peers {
		if peer.Status == "pending" || peer.Status == "unpaired" {
			delete(cfg.Peers, alias)
			removedPeers = append(removedPeers, alias)
		}
	}
	if err := writeV2Config(paths, cfg); err != nil {
		rollbackErr := rollbackV2ErasePaths(staged)
		if rollbackErr != nil {
			return result, fmt.Errorf("write pairing cleanup: %w; rollback: %v", err, rollbackErr)
		}
		return result, err
	}
	for _, alias := range removedPeers {
		result.Removed = append(result.Removed, "config peer "+alias)
	}
	removeErr := removeV2ErasePaths(staged, &result)
	return result, removeErr
}

func v2PeerEraseTargets(paths v2Paths, alias string, peer v2PeerProfile) []struct {
	Path      string
	Directory bool
} {
	targets := []struct {
		Path      string
		Directory bool
	}{
		{Path: pairingStatePath(paths, alias)},
	}
	if peer.RelationshipID != "" {
		targets = append(targets,
			struct {
				Path      string
				Directory bool
			}{Path: peerDeliveryStatePath(paths, peer.RelationshipID)},
			struct {
				Path      string
				Directory bool
			}{Path: filepath.Join(paths.StateDir, "transfers", peer.RelationshipID), Directory: true},
		)
	}
	return targets
}

func (a *app) eraseV2Peer(alias string, dryRun bool) (v2EraseResult, error) {
	result := newV2EraseResult("peer")
	result.Warnings = append(result.Warnings, "local erasure does not revoke server capabilities or delete the peer's copy of relationship state")
	paths, err := resolveV2Paths()
	if err != nil {
		return result, err
	}
	if err := validateV2EraseRoots(paths); err != nil {
		result.Retained = append(result.Retained, paths.ConfigDir, paths.StateDir)
		return result, err
	}
	cfg, err := readV2ConfigForErase(paths)
	if err != nil {
		return result, err
	}
	peer, exists := cfg.Peers[alias]
	if !exists {
		return result, fmt.Errorf("unknown peer %q; cannot prove that all of its relationship state was found", alias)
	}
	targets := v2PeerEraseTargets(paths, alias, peer)
	result.WouldRemove = append(result.WouldRemove, "config peer "+alias)
	for _, target := range targets {
		var targetExists bool
		if target.Directory {
			targetExists, err = validateV2EraseDirectory(target.Path)
		} else {
			targetExists, err = validateV2EraseFile(target.Path)
		}
		if err != nil {
			result.Retained = append(result.Retained, target.Path)
			return result, err
		}
		if targetExists {
			result.WouldRemove = append(result.WouldRemove, target.Path)
		}
	}
	if dryRun {
		return result, nil
	}
	unlock, err := acquireV2EraseLock(paths)
	if err != nil {
		return result, err
	}
	defer unlock()
	cfg, err = readV2ConfigForErase(paths)
	if err != nil {
		return result, err
	}
	peer, exists = cfg.Peers[alias]
	if !exists {
		return result, fmt.Errorf("peer %q disappeared during local erasure", alias)
	}
	targets = v2PeerEraseTargets(paths, alias, peer)
	staged := []v2StagedErasePath{}
	for _, target := range targets {
		item, targetExists, stageErr := stageV2ErasePath(target.Path, target.Directory)
		if stageErr != nil {
			_ = rollbackV2ErasePaths(staged)
			result.Retained = append(result.Retained, target.Path)
			return result, stageErr
		}
		if targetExists {
			staged = append(staged, item)
		}
	}
	delete(cfg.Peers, alias)
	if err := writeV2Config(paths, cfg); err != nil {
		rollbackErr := rollbackV2ErasePaths(staged)
		if rollbackErr != nil {
			return result, fmt.Errorf("write peer cleanup: %w; rollback: %v", err, rollbackErr)
		}
		return result, err
	}
	result.Removed = append(result.Removed, "config peer "+alias)
	removeErr := removeV2ErasePaths(staged, &result)
	return result, removeErr
}

func acquireV2EraseLock(paths v2Paths) (func(), error) {
	if exists, err := validateV2EraseFile(paths.Lock); err != nil {
		return nil, err
	} else if !exists {
		if exists, dirErr := validateV2EraseDirectory(paths.ConfigDir); dirErr != nil {
			return nil, dirErr
		} else if !exists {
			return func() {}, nil
		}
	}
	file, err := os.OpenFile(paths.Lock, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another DUD process is using local state")
	}
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}

func (a *app) eraseV2All(dryRun bool) (v2EraseResult, error) {
	result := newV2EraseResult("all")
	result.Warnings = append(result.Warnings,
		"local erasure does not revoke server capabilities or delete peer, server, backup, snapshot, or media-remanence copies",
		"logical file deletion is not physical secure erase on SSD or copy-on-write storage",
		"peer state inside Git repositories lives in each repository's own .git/dud; erase it with 'dud erase repo'",
	)
	paths, err := resolveV2Paths()
	if err != nil {
		return result, err
	}
	// Configuration and state are directories inside the world, so the world
	// itself is the single target.
	targets := []string{paths.Root}
	for _, target := range targets {
		exists, targetErr := validateV2EraseDirectory(target)
		if targetErr != nil {
			result.Retained = append(result.Retained, target)
			return result, targetErr
		}
		if exists {
			result.WouldRemove = append(result.WouldRemove, target)
		}
	}
	if dryRun {
		return result, nil
	}
	unlock, err := acquireV2EraseLock(paths)
	if err != nil {
		result.Retained = append(result.Retained, targets...)
		return result, err
	}
	defer unlock()
	staged := []v2StagedErasePath{}
	mountedRoots := []string{}
	for _, target := range targets {
		item, exists, stageErr := stageV2ErasePath(target, true)
		if stageErr != nil && v2EraseRootIsImmovable(stageErr) {
			var mounted []v2StagedErasePath
			mounted, stageErr = stageV2EraseMountedDirectory(target)
			if stageErr == nil {
				staged = append(staged, mounted...)
				mountedRoots = append(mountedRoots, target)
				continue
			}
		}
		if stageErr != nil {
			rollbackErr := rollbackV2ErasePaths(staged)
			result.Retained = append(result.Retained, target)
			if rollbackErr != nil {
				return result, fmt.Errorf("stage local erase: %w; rollback: %v", stageErr, rollbackErr)
			}
			return result, stageErr
		}
		if exists {
			staged = append(staged, item)
		}
	}
	removeErr := removeV2ErasePaths(staged, &result)
	mounted := make(map[string]struct{}, len(mountedRoots))
	for _, root := range mountedRoots {
		mounted[root] = struct{}{}
		// The root itself survives by construction, so emptiness is the only
		// evidence that everything under it went away.
		empty, emptyErr := v2EraseDirectoryIsEmpty(root)
		if emptyErr == nil && empty {
			result.Warnings = append(result.Warnings, root+" is an empty bind-mount root and must be removed by the host wrapper")
			continue
		}
		result.Retained = append(result.Retained, root)
		if emptyErr == nil {
			emptyErr = fmt.Errorf("DUD state remained in %s after erasure", root)
		}
		if removeErr == nil {
			removeErr = emptyErr
		} else {
			removeErr = fmt.Errorf("%v; %w", removeErr, emptyErr)
		}
	}
	for _, target := range targets {
		if _, isMounted := mounted[target]; isMounted {
			continue
		}
		if _, err := os.Lstat(target); err == nil {
			result.Retained = append(result.Retained, target)
			concurrentErr := fmt.Errorf("DUD state reappeared at %s during erasure", target)
			if removeErr == nil {
				removeErr = concurrentErr
			} else {
				removeErr = fmt.Errorf("%v; %w", removeErr, concurrentErr)
			}
		} else if !errors.Is(err, os.ErrNotExist) && removeErr == nil {
			removeErr = err
		}
	}
	return result, removeErr
}

func (repository *v2GitRepository) managedRefsPath() string {
	return filepath.Join(repository.DUDDir, "managed-refs.json")
}

func validV2ManagedRefName(name string) bool {
	return (strings.HasPrefix(name, "refs/remotes/") || strings.HasPrefix(name, "refs/dud/")) &&
		!strings.ContainsAny(name, " \t\r\n")
}

func (repository *v2GitRepository) loadManagedRefs() (*v2ManagedGitRefs, error) {
	path := repository.managedRefsPath()
	if err := validatePrivateV2File(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &v2ManagedGitRefs{Version: v2ManagedRefsVersion, Refs: map[string]string{}}, nil
		}
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var registry v2ManagedGitRefs
	if err := json.Unmarshal(body, &registry); err != nil {
		return nil, fmt.Errorf("parse managed Git refs: %w", err)
	}
	if registry.Version != v2ManagedRefsVersion || registry.Refs == nil {
		return nil, errors.New("managed Git refs registry is invalid")
	}
	for name, oid := range registry.Refs {
		decoded, err := hex.DecodeString(oid)
		if !validV2ManagedRefName(name) || err != nil || (len(decoded) != 20 && len(decoded) != 32) {
			return nil, fmt.Errorf("managed Git ref %q is invalid", name)
		}
	}
	return &registry, nil
}

func (repository *v2GitRepository) updateManagedRefs(updates map[string]string, deleted []string) error {
	registry, err := repository.loadManagedRefs()
	if err != nil {
		return err
	}
	for _, name := range deleted {
		delete(registry.Refs, name)
	}
	for name, oid := range updates {
		if !validV2ManagedRefName(name) {
			return fmt.Errorf("refusing to register invalid managed Git ref %q", name)
		}
		registry.Refs[name] = oid
	}
	body, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteV2File(repository.managedRefsPath(), append(body, '\n'), 0o600)
}

func (a *app) resolveV2GitRepositoryForErase() (*v2GitRepository, error) {
	command := a.localV2GitCommand("rev-parse", "--git-common-dir")
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0")
	output, err := command.Output()
	if err != nil {
		return nil, fatalError("dud erase repo requires a Git repository")
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
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("Git common directory is not a regular directory")
	}
	return &v2GitRepository{CommonDir: common, DUDDir: filepath.Join(common, "dud")}, nil
}

func (a *app) runV2EraseGit(input []byte, args ...string) ([]byte, error) {
	command := a.localV2GitCommand(args...)
	command.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_TERMINAL_PROMPT=0",
	)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("Git command failed: %s", strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (a *app) listV2EraseGitRefs(prefix string) (map[string]string, error) {
	output, err := a.runV2EraseGit(nil, "for-each-ref", "--format=%(refname) %(objectname)", prefix)
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		name, oid, found := strings.Cut(line, " ")
		decoded, decodeErr := hex.DecodeString(oid)
		if !found || !validV2ManagedRefName(name) || decodeErr != nil || (len(decoded) != 20 && len(decoded) != 32) {
			return nil, errors.New("Git returned an invalid ref while planning local erasure")
		}
		refs[name] = oid
	}
	return refs, nil
}

func (a *app) currentV2EraseGitRef(name string) (string, bool, error) {
	command := a.localV2GitCommand("show-ref", "--verify", "--hash", name)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0")
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimSpace(string(output)), true, nil
}

func (a *app) v2EraseGitRemoteNames() (map[string]struct{}, error) {
	output, err := a.runV2EraseGit(nil, "remote")
	if err != nil {
		return nil, err
	}
	result := map[string]struct{}{}
	for _, name := range strings.Fields(string(output)) {
		result[name] = struct{}{}
	}
	return result, nil
}

func v2ManagedRefRemote(name string) string {
	const prefix = "refs/remotes/"
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	remainder := strings.TrimPrefix(name, prefix)
	remote, _, _ := strings.Cut(remainder, "/")
	return remote
}

func (a *app) v2EraseGitHasDUDConfig() (bool, error) {
	command := a.localV2GitCommand("config", "--local", "--get-regexp", `^dud\.`)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0")
	if err := command.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func acquireV2EraseRepositoryLocks(repository *v2GitRepository) (func(), error) {
	paths, err := filepath.Glob(filepath.Join(repository.DUDDir, "peers", "*.lock"))
	if err != nil {
		return nil, err
	}
	files := []*os.File{}
	unlock := func() {
		for _, file := range files {
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			_ = file.Close()
		}
	}
	for _, path := range paths {
		if _, err := validateV2EraseFile(path); err != nil {
			unlock()
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			unlock()
			return nil, err
		}
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = file.Close()
			unlock()
			return nil, errors.New("another DUD Git operation is using repository state")
		}
		files = append(files, file)
	}
	return unlock, nil
}

func (a *app) eraseV2Repository(dryRun bool) (v2EraseResult, error) {
	result := newV2EraseResult("repo")
	result.Warnings = append(result.Warnings, "unreachable Git objects are retained until ordinary Git garbage collection")
	repository, err := a.resolveV2GitRepositoryForErase()
	if err != nil {
		return result, err
	}
	dudDirExists, err := validateV2EraseDirectory(repository.DUDDir)
	if err != nil {
		result.Retained = append(result.Retained, repository.DUDDir)
		return result, err
	}
	ownedRefs, err := a.listV2EraseGitRefs("refs/dud/")
	if err != nil {
		return result, err
	}
	managed := &v2ManagedGitRefs{Version: v2ManagedRefsVersion, Refs: map[string]string{}}
	if dudDirExists {
		managed, err = repository.loadManagedRefs()
		if err != nil {
			result.Retained = append(result.Retained, repository.managedRefsPath())
			result.Warnings = append(result.Warnings, err.Error())
			managed = &v2ManagedGitRefs{Version: v2ManagedRefsVersion, Refs: map[string]string{}}
		}
	}
	remotes, err := a.v2EraseGitRemoteNames()
	if err != nil {
		return result, err
	}
	for name, recordedOID := range managed.Refs {
		if _, alreadyOwned := ownedRefs[name]; alreadyOwned {
			continue
		}
		if remote := v2ManagedRefRemote(name); remote != "" {
			if _, collision := remotes[remote]; collision {
				result.Retained = append(result.Retained, name)
				result.Warnings = append(result.Warnings, fmt.Sprintf("managed ref %s overlaps configured Git remote %s", name, remote))
				continue
			}
		}
		currentOID, exists, refErr := a.currentV2EraseGitRef(name)
		if refErr != nil {
			return result, refErr
		}
		if !exists {
			continue
		}
		if currentOID != recordedOID {
			result.Retained = append(result.Retained, name)
			result.Warnings = append(result.Warnings, fmt.Sprintf("managed ref %s changed after DUD last wrote it", name))
			continue
		}
		ownedRefs[name] = currentOID
	}
	hasConfig, err := a.v2EraseGitHasDUDConfig()
	if err != nil {
		return result, err
	}
	for name := range ownedRefs {
		result.WouldRemove = append(result.WouldRemove, name)
	}
	if hasConfig {
		result.WouldRemove = append(result.WouldRemove, filepath.Join(repository.CommonDir, "config")+" [dud]")
	}
	if dudDirExists {
		result.WouldRemove = append(result.WouldRemove, repository.DUDDir)
	}
	if dryRun {
		return result, nil
	}
	unlock, err := acquireV2EraseRepositoryLocks(repository)
	if err != nil {
		result.Retained = append(result.Retained, repository.DUDDir)
		return result, err
	}
	defer unlock()
	if len(ownedRefs) != 0 {
		names := make([]string, 0, len(ownedRefs))
		for name := range ownedRefs {
			names = append(names, name)
		}
		sort.Strings(names)
		var transaction strings.Builder
		transaction.WriteString("start\n")
		for _, name := range names {
			fmt.Fprintf(&transaction, "delete %s %s\n", name, ownedRefs[name])
		}
		transaction.WriteString("prepare\ncommit\n")
		if _, err := a.runV2EraseGit([]byte(transaction.String()), "update-ref", "--stdin"); err != nil {
			result.Retained = append(result.Retained, names...)
			return result, err
		}
		result.Removed = append(result.Removed, names...)
	}
	var failures []string
	if hasConfig {
		if _, configErr := a.runV2EraseGit(nil, "config", "--local", "--remove-section", "dud"); configErr != nil {
			result.Retained = append(result.Retained, filepath.Join(repository.CommonDir, "config")+" [dud]")
			failures = append(failures, configErr.Error())
		} else {
			result.Removed = append(result.Removed, filepath.Join(repository.CommonDir, "config")+" [dud]")
		}
	}
	if dudDirExists {
		removedDUDDir := false
		if err := os.RemoveAll(repository.DUDDir); err != nil {
			result.Retained = append(result.Retained, repository.DUDDir)
			failures = append(failures, err.Error())
		} else {
			result.Removed = append(result.Removed, repository.DUDDir)
			_ = syncV2EraseDirectory(repository.CommonDir)
			removedDUDDir = true
		}
		if _, err := os.Lstat(repository.DUDDir); removedDUDDir && err == nil {
			result.Retained = append(result.Retained, repository.DUDDir)
			failures = append(failures, "DUD repository state reappeared during erasure")
		} else if removedDUDDir && !errors.Is(err, os.ErrNotExist) {
			result.Retained = append(result.Retained, repository.DUDDir)
			failures = append(failures, err.Error())
		}
	}
	if len(failures) != 0 {
		return result, errors.New(strings.Join(failures, "; "))
	}
	return result, nil
}
