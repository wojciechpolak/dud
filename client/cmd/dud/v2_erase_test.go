// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newV2EraseTestApp(t *testing.T) (*app, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	a := newApp(strings.NewReader(""), stdout, stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return nil, errors.New("erase unexpectedly attempted a network operation")
	}
	return a, stdout, stderr
}

func initializeV2EraseTestDevice(t *testing.T) (*v2LocalConfig, v2Paths) {
	t.Helper()
	cfg, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	return cfg, paths
}

func TestV2ErasePairingsIsLogicalAndDryRunIsReadOnly(t *testing.T) {
	setTestV2Homes(t)
	_, paths := initializeV2EraseTestDevice(t)
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers["pending"] = v2PeerProfile{Status: "pending", BaseURL: cfg.BaseURL}
		cfg.Peers["unpaired"] = v2PeerProfile{Status: "unpaired", BaseURL: cfg.BaseURL}
		cfg.Peers["active"] = v2PeerProfile{Status: "active", RelationshipID: strings.Repeat("11", 16), BaseURL: cfg.BaseURL}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pairingsDir := filepath.Join(paths.StateDir, "pairings")
	if err := os.MkdirAll(pairingsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pairingsDir, "pending.json"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, stdout, stderr := newV2EraseTestApp(t)
	if code := a.main([]string{"erase", "pairings"}); code != 1 {
		t.Fatalf("unconfirmed erase code = %d", code)
	}
	if _, err := os.Stat(pairingsDir); err != nil {
		t.Fatalf("unconfirmed erase changed pairing directory: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := a.main([]string{"erase", "pairings", "--dry-run", "--json"}); code != 0 {
		t.Fatalf("dry-run code = %d, stderr = %s", code, stderr.String())
	}
	var dry v2EraseResult
	if err := json.Unmarshal(stdout.Bytes(), &dry); err != nil {
		t.Fatal(err)
	}
	if dry.Erased || len(dry.WouldRemove) != 3 || len(dry.Removed) != 0 {
		t.Fatalf("dry-run result = %#v", dry)
	}
	if _, err := os.Stat(pairingsDir); err != nil {
		t.Fatalf("dry-run changed pairing directory: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := a.main([]string{"erase", "pairings", "--yes", "--json"}); code != 0 {
		t.Fatalf("erase code = %d, stderr = %s", code, stderr.String())
	}
	loaded, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["pending"]; exists {
		t.Fatal("pending profile survived pairing erasure")
	}
	if _, exists := loaded.Peers["unpaired"]; exists {
		t.Fatal("unpaired profile survived pairing erasure")
	}
	if _, exists := loaded.Peers["active"]; !exists {
		t.Fatal("active profile was removed by pairing erasure")
	}
	if _, err := os.Stat(pairingsDir); !os.IsNotExist(err) {
		t.Fatalf("pairing directory survived: %v", err)
	}
}

func TestV2ErasePeerRemovesOnlyTargetRelationship(t *testing.T) {
	setTestV2Homes(t)
	_, paths := initializeV2EraseTestDevice(t)
	targetRelationship := strings.Repeat("12", 16)
	otherRelationship := strings.Repeat("34", 16)
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers["target"] = v2PeerProfile{Status: "active", RelationshipID: targetRelationship, BaseURL: cfg.BaseURL}
		cfg.Peers["other"] = v2PeerProfile{Status: "active", RelationshipID: otherRelationship, BaseURL: cfg.BaseURL}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	targets := []string{
		pairingStatePath(paths, "target"),
		peerDeliveryStatePath(paths, targetRelationship),
		filepath.Join(paths.StateDir, "transfers", targetRelationship, "payload"),
	}
	otherDelivery := peerDeliveryStatePath(paths, otherRelationship)
	for _, path := range append(targets, otherDelivery) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, stdout, stderr := newV2EraseTestApp(t)
	if code := a.main([]string{"erase", "peer", "target", "--yes", "--json"}); code != 0 {
		t.Fatalf("erase code = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	loaded, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := loaded.Peers["target"]; exists {
		t.Fatal("target profile survived")
	}
	if _, exists := loaded.Peers["other"]; !exists {
		t.Fatal("other profile was removed")
	}
	for _, path := range targets {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("target artifact %s survived: %v", path, err)
		}
	}
	if _, err := os.Stat(otherDelivery); err != nil {
		t.Fatalf("other peer artifact changed: %v", err)
	}
	var result v2EraseResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Erased || len(result.Warnings) == 0 {
		t.Fatalf("peer erase result = %#v", result)
	}
}

func TestStageMountedDirectoryRollsBackAndRemovesChildren(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"file", "dir"} {
		path := filepath.Join(root, name)
		if name == "dir" {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	staged, err := stageV2EraseMountedDirectory(root)
	if err != nil || len(staged) != 2 {
		t.Fatalf("staged = %#v, %v", staged, err)
	}
	if err := rollbackV2ErasePaths(staged); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "file")); err != nil {
		t.Fatal(err)
	}
	staged, err = stageV2EraseMountedDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	result := newV2EraseResult("peer")
	if err := removeV2ErasePaths(staged, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 2 {
		t.Fatalf("erase result = %#v", result)
	}
}

func TestV2EraseAllIsLockedIdempotentAndDoesNotRecreateState(t *testing.T) {
	setTestV2Homes(t)
	_, paths := initializeV2EraseTestDevice(t)
	a, stdout, stderr := newV2EraseTestApp(t)
	unlock, err := acquireV2ConfigLock(paths)
	if err != nil {
		t.Fatal(err)
	}
	if code := a.main([]string{"erase", "all", "--yes"}); code != 1 {
		unlock()
		t.Fatalf("erase while locked code = %d", code)
	}
	unlock()
	if _, err := os.Stat(paths.Config); err != nil {
		t.Fatalf("locked erase changed config: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := a.main([]string{"erase", "all", "--dry-run", "--json"}); code != 0 {
		t.Fatalf("dry-run code = %d, stderr = %s", code, stderr.String())
	}
	if _, err := os.Stat(paths.Config); err != nil {
		t.Fatalf("dry-run changed config: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := a.main([]string{"erase", "all", "--yes", "--json"}); code != 0 {
		t.Fatalf("erase code = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{paths.Root, paths.ConfigDir, paths.StateDir} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("DUD world directory %s survived: %v", path, err)
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := a.main([]string{"erase", "all", "--yes", "--json"}); code != 0 {
		t.Fatalf("idempotent erase code = %d, stderr = %s", code, stderr.String())
	}
	for _, path := range []string{paths.ConfigDir, paths.StateDir} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("idempotent erase recreated %s: %v", path, err)
		}
	}
}

// In the shipped image the world directory is a bind mount whose parent the
// container runtime creates as root while DUD runs unprivileged, so staging the
// world itself is refused with EACCES rather than the EBUSY a mount point alone
// would report. The contents must still be erased.
func TestV2EraseAllErasesContentsWhenTheRootCannotBeStaged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permission check under test")
	}
	root := t.TempDir()
	setV2TestHomes(t, root)
	_, paths := initializeV2EraseTestDevice(t)
	stateSecret := filepath.Join(paths.StateDir, "delivery.json")
	if err := os.WriteFile(stateSecret, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(paths.Root)
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(parent, 0o700)
	})
	a, stdout, stderr := newV2EraseTestApp(t)
	if code := a.main([]string{"erase", "all", "--yes", "--json"}); code != 0 {
		t.Fatalf("erase code = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{paths.Config, stateSecret} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("DUD state %s survived: %v", path, err)
		}
	}
	entries, err := os.ReadDir(paths.Root)
	if err != nil {
		t.Fatalf("read retained root %s: %v", paths.Root, err)
	}
	if len(entries) != 0 {
		t.Fatalf("retained root %s still holds %d entries", paths.Root, len(entries))
	}
	var result v2EraseResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Erased {
		t.Fatalf("erase result = %#v", result)
	}
	found := false
	for _, warning := range result.Warnings {
		if strings.HasPrefix(warning, paths.Root+" is an empty bind-mount root") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no host-removal warning for %s: %#v", paths.Root, result.Warnings)
	}
}

func TestV2EraseAllRejectsASymlinkedWorld(t *testing.T) {
	root := t.TempDir()
	setV2TestHomes(t, root)
	dudHome := os.Getenv("DUD_HOME")
	if err := os.MkdirAll(dudHome, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "real-world")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "marker")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dudHome, "default")); err != nil {
		t.Fatal(err)
	}
	a, _, stderr := newV2EraseTestApp(t)
	if code := a.main([]string{"erase", "all", "--yes"}); code != 1 {
		t.Fatalf("symlink erase code = %d", code)
	}
	if !strings.Contains(stderr.String(), "symlink") {
		t.Fatalf("symlink error = %s", stderr.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("symlink target was changed: %v", err)
	}
}

func TestV2EraseRepoRefusesActiveDUDGitOperation(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	a, _, stderr := newV2EraseTestApp(t)
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("test")
		if err != nil {
			t.Fatal(err)
		}
		unlock, err := repository.acquirePeerLock(strings.Repeat("a", 32))
		if err != nil {
			t.Fatal(err)
		}
		if code := a.main([]string{"erase", "repo", "--yes"}); code != 1 {
			unlock()
			t.Fatalf("erase while Git state locked code = %d", code)
		}
		unlock()
		if !strings.Contains(stderr.String(), "another DUD Git operation") {
			t.Fatalf("lock error = %s", stderr.String())
		}
		if _, err := os.Stat(repository.DUDDir); err != nil {
			t.Fatalf("locked repository state changed: %v", err)
		}
	})
}

func TestV2EraseRepoDeletesOnlyCertainOwnedRefs(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	firstOID := commitGitTestFile(t, repositoryPath, "one", "one", "one")
	secondOID := commitGitTestFile(t, repositoryPath, "two", "two", "two")
	a, stdout, stderr := newV2EraseTestApp(t)
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("test")
		if err != nil {
			t.Fatal(err)
		}
		runGitTestCommand(t, repositoryPath, "update-ref", "refs/dud/tags/peer/v1", firstOID)
		runGitTestCommand(t, repositoryPath, "update-ref", "refs/remotes/peer/main", firstOID)
		runGitTestCommand(t, repositoryPath, "update-ref", "refs/remotes/changed/main", secondOID)
		runGitTestCommand(t, repositoryPath, "remote", "add", "collision", "https://example.invalid/repo.git")
		runGitTestCommand(t, repositoryPath, "update-ref", "refs/remotes/collision/main", firstOID)
		if err := repository.updateManagedRefs(map[string]string{
			"refs/remotes/peer/main":      firstOID,
			"refs/remotes/changed/main":   firstOID,
			"refs/remotes/collision/main": firstOID,
		}, nil); err != nil {
			t.Fatal(err)
		}
		runGitTestCommand(t, repositoryPath, "config", "--local", "dud.gitObjectCount", "123")
		stdout.Reset()
		stderr.Reset()
		if code := a.main([]string{"erase", "repo", "--dry-run", "--json"}); code != 0 {
			t.Fatalf("dry-run code = %d, stderr = %s", code, stderr.String())
		}
		if got := runGitTestCommand(t, repositoryPath, "rev-parse", "refs/remotes/peer/main"); got != firstOID {
			t.Fatal("dry-run changed managed ref")
		}
		stdout.Reset()
		stderr.Reset()
		if code := a.main([]string{"erase", "repo", "--yes", "--json"}); code != 0 {
			t.Fatalf("erase code = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
		}
		for _, ref := range []string{"refs/dud/tags/peer/v1", "refs/remotes/peer/main"} {
			command := execGitTestCommand(repositoryPath, "show-ref", "--verify", "--quiet", ref)
			if err := command.Run(); err == nil {
				t.Fatalf("owned ref %s survived", ref)
			}
		}
		for _, ref := range []string{"refs/remotes/changed/main", "refs/remotes/collision/main"} {
			if got := runGitTestCommand(t, repositoryPath, "rev-parse", ref); got == "" {
				t.Fatalf("ambiguous ref %s was removed", ref)
			}
		}
		if _, err := os.Stat(repository.DUDDir); !os.IsNotExist(err) {
			t.Fatalf("DUD Git directory survived: %v", err)
		}
		command := execGitTestCommand(repositoryPath, "config", "--local", "--get", "dud.gitObjectCount")
		if err := command.Run(); err == nil {
			t.Fatal("DUD Git config survived")
		}
		var result v2EraseResult
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if !result.Erased || len(result.Retained) != 2 {
			t.Fatalf("repository erase result = %#v", result)
		}
	})
}

func execGitTestCommand(directory string, args ...string) *exec.Cmd {
	return exec.Command("git", append([]string{"-C", directory}, args...)...)
}
