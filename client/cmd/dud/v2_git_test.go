// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func runGitTestCommand(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func initializeGitTestRepository(t *testing.T, directory string) {
	t.Helper()
	runGitTestCommand(t, directory, "init", "-b", "main")
	runGitTestCommand(t, directory, "config", "user.name", "DUD Test")
	runGitTestCommand(t, directory, "config", "user.email", "dud@example.test")
}

func commitGitTestFile(t *testing.T, directory, name, body, message string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTestCommand(t, directory, "add", name)
	runGitTestCommand(t, directory, "commit", "-m", message)
	return runGitTestCommand(t, directory, "rev-parse", "HEAD")
}

func withGitTestDirectory(t *testing.T, directory string, operation func()) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()
	operation()
}

func TestParseV2GitPeerOptions(t *testing.T) {
	push, err := parseV2GitPushOptions([]string{"laptop", "--branch", "main", "--branch", "release", "--ttl", "1h", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if push.Alias != "laptop" || len(push.Branches) != 2 || push.TTL.Hours() != 1 || !push.JSON {
		t.Fatalf("unexpected push options: %#v", push)
	}
	if _, err := parseV2GitPushOptions([]string{"laptop", "--incremental"}); err == nil {
		t.Fatal("DUD 2.0 accepted an incremental Git push")
	}
	fetch, err := parseV2GitFetchOptions([]string{"desktop", "--associate", "--allow-rewrite", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if fetch.Alias != "desktop" || !fetch.Associate || !fetch.AllowRewrite || !fetch.JSON {
		t.Fatalf("unexpected fetch options: %#v", fetch)
	}
}

func TestV2GitAliasesHaveIdenticalDispatch(t *testing.T) {
	repository := t.TempDir()
	initializeGitTestRepository(t, repository)
	setV2TestHomes(t, t.TempDir())
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, repository, func() {
		pushErr := a.cmdGit([]string{"push", "peer", "--branch", "main"})
		sendErr := a.cmdGit([]string{"send", "peer", "--branch", "main"})
		if pushErr == nil || sendErr == nil || pushErr.Error() != sendErr.Error() {
			t.Fatalf("push/send dispatch differs: %v / %v", pushErr, sendErr)
		}
		fetchErr := a.cmdGit([]string{"fetch", "peer", "--associate"})
		receiveErr := a.cmdGit([]string{"receive", "peer", "--associate"})
		if fetchErr == nil || receiveErr == nil || fetchErr.Error() != receiveErr.Error() {
			t.Fatalf("fetch/receive dispatch differs: %v / %v", fetchErr, receiveErr)
		}
	})
}

// TestV2GitMetadataParsesButRefusesIncrementalPrerequisites fixes the division
// of labour that makes version skew survivable: an incremental checkpoint is
// structurally valid and therefore parses, and is then refused by the Git layer
// where the receiver can answer the peer and advance its chain. Refusing it
// during descriptor validation instead would leave it stuck with no reply.
func TestV2GitMetadataParsesButRefusesIncrementalPrerequisites(t *testing.T) {
	encoded := encodeV2GitMetadata(v2GitMetadata{
		RepositoryID:  bytes.Repeat([]byte{1}, 16),
		ObjectFormat:  1,
		BundleVersion: 2,
		Refs:          map[string][]byte{"refs/heads/main": bytes.Repeat([]byte{2}, 20)},
		Prerequisites: [][]byte{bytes.Repeat([]byte{3}, 20)},
	})
	metadata, err := decodeV2GitMetadata(encoded)
	if err != nil {
		t.Fatalf("incremental metadata did not parse: %v", err)
	}
	if err := requireCompleteV2GitCheckpoint(metadata); err == nil ||
		!strings.Contains(err.Error(), "incremental Git prerequisites") {
		t.Fatalf("unexpected checkpoint error: %v", err)
	}
}

func TestV2GitSignedAcknowledgementAdvancesRepositoryState(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("status")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err := repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		peerID := strings.Repeat("4", 32)
		state := newV2GitPeerState(repositoryID, peerID)
		refs := map[string][]byte{"refs/heads/main": bytes.Repeat([]byte{0x56}, 20)}
		metadataBytes, err := v2EncMode.Marshal(encodeV2GitMetadata(v2GitMetadata{
			RepositoryID: repositoryID, ObjectFormat: 1, BundleVersion: 2,
			Refs: refs, Prerequisites: [][]byte{},
		}))
		if err != nil {
			t.Fatal(err)
		}
		resultBytes, err := v2EncMode.Marshal(map[int]any{
			1: repositoryID,
			2: refs,
			3: [][]byte{},
		})
		if err != nil {
			t.Fatal(err)
		}
		digest := strings.Repeat("5", 64)
		runtime := &v2PeerRuntime{state: &v2PeerDeliveryState{
			Sent: map[string]v2SentDelivery{
				digest: {
					Sequence: 7, DescriptorDigest: digest, PayloadType: 4,
					TypeMetadata: v2Base64URL(metadataBytes), Acknowledged: true,
					AcknowledgedAt: 42, ResultMetadata: v2Base64URL(resultBytes),
				},
			},
		}}
		if err := reconcileV2GitAcknowledgements(runtime, repository, state); err != nil {
			t.Fatal(err)
		}
		if state.LastAcknowledgedSentSequence != 7 ||
			state.LastAcknowledgedRefs["refs/heads/main"] != hexOID(refs["refs/heads/main"]) ||
			!state.Outbound[digest].Acknowledged {
			t.Fatalf("acknowledgement did not advance Git state: %#v", state)
		}
	})
}

func TestV2GitQuarantinePromotesOnlyRemoteTrackingRefs(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGitTestRepository(t, source)
	wantOID := commitGitTestFile(t, source, "README.md", "first\n", "initial")
	initializeGitTestRepository(t, destination)

	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var bundlePath string
	var metadata *v2GitMetadata
	var sourceID []byte
	withGitTestDirectory(t, source, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		sourceID, err = repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		bundlePath, metadata, err = a.createV2GitBundle(repository, v2GitPushOptions{}, sourceID)
		if err != nil {
			t.Fatal(err)
		}
	})
	defer os.Remove(bundlePath)

	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.associateRepositoryID(sourceID); err != nil {
			t.Fatal(err)
		}
		state := newV2GitPeerState(sourceID, strings.Repeat("a", 32))
		scratch, err := a.verifyV2GitQuarantine(repository, bundlePath, strings.Repeat("b", 64), metadata)
		if err != nil {
			t.Fatal(err)
		}
		refs, err := a.promoteV2GitQuarantine(repository, state, scratch, strings.Repeat("b", 64), "peer", metadata, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := hexOID(refs["refs/heads/main"]); got != wantOID {
			t.Fatalf("promoted ref = %s, want %s", got, wantOID)
		}
		if got := runGitTestCommand(t, destination, "rev-parse", "refs/remotes/peer/main"); got != wantOID {
			t.Fatalf("remote-tracking ref = %s, want %s", got, wantOID)
		}
		registry, err := repository.loadManagedRefs()
		if err != nil {
			t.Fatal(err)
		}
		if got := registry.Refs["refs/remotes/peer/main"]; got != wantOID {
			t.Fatalf("managed ref OID = %s, want %s", got, wantOID)
		}
		command := exec.Command("git", "-C", destination, "show-ref", "--verify", "--quiet", "refs/heads/main")
		if err := command.Run(); err == nil {
			t.Fatal("quarantine promotion created or moved a local branch")
		}
	})
}

func TestV2GitQuarantineRejectsMetadataMismatchBeforePromotion(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGitTestRepository(t, source)
	commitGitTestFile(t, source, "file.txt", "content\n", "initial")
	initializeGitTestRepository(t, destination)
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var bundlePath string
	var metadata *v2GitMetadata
	withGitTestDirectory(t, source, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err := repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		bundlePath, metadata, err = a.createV2GitBundle(repository, v2GitPushOptions{}, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
	})
	defer os.Remove(bundlePath)
	metadata.Refs["refs/heads/main"][0] ^= 0xff

	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.verifyV2GitQuarantine(repository, bundlePath, strings.Repeat("c", 64), metadata); err == nil ||
			!strings.Contains(err.Error(), "does not match") {
			t.Fatalf("unexpected quarantine result: %v", err)
		}
		if _, err := os.Stat(filepath.Join(repository.DUDDir, "quarantine", strings.Repeat("c", 64))); !os.IsNotExist(err) {
			t.Fatalf("failed quarantine was retained: %v", err)
		}
	})
}

func TestV2GitQuarantineRejectsMalformedPackWithoutContamination(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	oid := bytes.Repeat([]byte{0x12}, 20)
	ref := "refs/heads/main"
	bundlePath := filepath.Join(t.TempDir(), "malformed.bundle")
	body := []byte("# v2 git bundle\n" + hexOID(oid) + " " + ref + "\n\nnot-a-pack")
	if err := os.WriteFile(bundlePath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := &v2GitMetadata{
		RepositoryID:  bytes.Repeat([]byte{0x34}, 16),
		ObjectFormat:  1,
		BundleVersion: 2,
		Refs:          map[string][]byte{ref: oid},
		Prerequisites: [][]byte{},
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		digest := strings.Repeat("3", 64)
		if _, err := a.verifyV2GitQuarantine(repository, bundlePath, digest, metadata); err == nil {
			t.Fatal("malformed pack passed quarantine")
		}
		if _, err := os.Stat(filepath.Join(repository.DUDDir, "quarantine", digest)); !os.IsNotExist(err) {
			t.Fatalf("malformed quarantine was retained: %v", err)
		}
		command := exec.Command("git", "-C", repositoryPath, "cat-file", "-e", hexOID(oid))
		if err := command.Run(); err == nil {
			t.Fatal("malformed quarantine contaminated the real object database")
		}
	})
}

func TestV2GitBranchSelectionAndLinkedWorktreeShareIdentity(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	worktree := filepath.Join(root, "worktree")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGitTestRepository(t, source)
	commitGitTestFile(t, source, "main.txt", "main\n", "main")
	runGitTestCommand(t, source, "branch", "feature")
	runGitTestCommand(t, source, "worktree", "add", worktree, "feature")

	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var mainCommon string
	var repositoryID []byte
	withGitTestDirectory(t, source, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		mainCommon = repository.CommonDir
		repositoryID, err = repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		bundle, metadata, err := a.createV2GitBundle(repository, v2GitPushOptions{Branches: []string{"main"}}, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(bundle)
		if _, exists := metadata.Refs["refs/heads/main"]; !exists {
			t.Fatal("selected main branch is absent from the bundle")
		}
		if _, exists := metadata.Refs["refs/heads/feature"]; exists {
			t.Fatal("unselected feature branch was included in the bundle")
		}
	})
	withGitTestDirectory(t, worktree, func() {
		repository, err := a.resolveV2GitRepository("status")
		if err != nil {
			t.Fatal(err)
		}
		if repository.CommonDir != mainCommon {
			t.Fatalf("linked worktree common dir = %s, want %s", repository.CommonDir, mainCommon)
		}
		got, err := repository.loadRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, repositoryID) {
			t.Fatal("linked worktree did not share the repository identity")
		}
	})
}

func TestV2GitLocalLimitsMayOnlyTightenDefaults(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	runGitTestCommand(t, repositoryPath, "config", "dud.gitObjectCount", "123")
	runGitTestCommand(t, repositoryPath, "config", "dud.gitWallSeconds", "30")
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if repository.Limits.ObjectCount != 123 || repository.Limits.WallTime.Seconds() != 30 {
			t.Fatalf("local limits were not applied: %#v", repository.Limits)
		}
		runGitTestCommand(t, repositoryPath, "config", "dud.gitObjectCount", "500001")
		if _, err := a.resolveV2GitRepository("fetch"); err == nil {
			t.Fatal("local Git limit weakened the fixed maximum")
		}
	})
}

// `merge-base --is-ancestor` answers "no" by exiting 1, and runV2Git replaces
// the raw exit error with the command's stderr whenever Git writes any. So the
// answer has to be read from the status rather than the message: a Git that
// emits an advisory alongside its exit 1 would otherwise turn an ordinary
// non-fast-forward into a hard failure the operator cannot resolve with
// --allow-rewrite.
func TestV2GitExitCodeSurvivesCommandOutput(t *testing.T) {
	repository := t.TempDir()
	initializeGitTestRepository(t, repository)
	for _, failure := range []struct {
		name   string
		stderr string
		code   int
	}{
		{"silent exit 1", "", 1},
		{"exit 1 with an advisory on stderr", "hint: advisory text\n", 1},
		{"a real failure keeps its own status", "fatal: bad object\n", 128},
	} {
		t.Run(failure.name, func(t *testing.T) {
			stub := filepath.Join(t.TempDir(), "git-stub.sh")
			script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' %q >&2\nexit %d\n", failure.stderr, failure.code)
			if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
			var handle *v2GitRepository
			withGitTestDirectory(t, repository, func() {
				resolved, err := a.resolveV2GitRepository("fetch")
				if err != nil {
					t.Fatal(err)
				}
				handle = resolved
				a.cfg.GitBin = stub
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_, runErr := a.runV2Git(ctx, handle, nil, "merge-base", "--is-ancestor", "a", "b")
				code, ok := v2GitExitCode(runErr)
				if !ok || code != failure.code {
					t.Fatalf("exit code = %d, %v (error %v)", code, ok, runErr)
				}
				if strings.Contains(runErr.Error(), "exit status") {
					t.Fatalf("error text leaks Go subprocess wording: %q", runErr.Error())
				}
			})
		})
	}
	if _, ok := v2GitExitCode(errors.New("unrelated")); ok {
		t.Fatal("a non-Git error reported an exit code")
	}
}

// The same property end to end: a real non-fast-forward has to come back as a
// clean "no", not an error, through the quarantine alternate.
func TestV2GitIsAncestorAnswersWithoutImporting(t *testing.T) {
	root := t.TempDir()
	repository := filepath.Join(root, "repository")
	if err := os.MkdirAll(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGitTestRepository(t, repository)
	first := commitGitTestFile(t, repository, "history.txt", "one\n", "one")
	second := commitGitTestFile(t, repository, "history.txt", "two\n", "two")
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, repository, func() {
		handle, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		// The quarantine alternate is the repository itself here: the point is
		// the answer's classification, not where the objects came from.
		ancestor, err := a.v2GitIsAncestor(handle, first, second, handle.CommonDir)
		if err != nil || !ancestor {
			t.Fatalf("ancestor = %v, %v", ancestor, err)
		}
		ancestor, err = a.v2GitIsAncestor(handle, second, first, handle.CommonDir)
		if err != nil {
			t.Fatalf("non-fast-forward reported an error rather than an answer: %v", err)
		}
		if ancestor {
			t.Fatal("a non-fast-forward was reported as a fast-forward")
		}

		// The same "no", from a Git that also wrote an advisory to stderr.
		// runV2Git replaces the exit error's text whenever that happens, so
		// a message-based classification gets this case wrong. It turns a
		// non-fast-forward into a failure that --allow-rewrite cannot fix.
		stub := filepath.Join(t.TempDir(), "git-stub.sh")
		if err := os.WriteFile(stub, []byte("#!/bin/sh\necho 'hint: advisory' >&2\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		a.cfg.GitBin = stub
		ancestor, err = a.v2GitIsAncestor(handle, second, first, handle.CommonDir)
		if err != nil {
			t.Fatalf("a chatty Git turned a non-fast-forward into a failure: %v", err)
		}
		if ancestor {
			t.Fatal("a non-fast-forward was reported as a fast-forward")
		}
	})
}

func TestV2GitRewriteRequiresExplicitPermission(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGitTestRepository(t, source)
	initialOID := commitGitTestFile(t, source, "history.txt", "one\n", "one")
	secondOID := commitGitTestFile(t, source, "history.txt", "two\n", "two")
	initializeGitTestRepository(t, destination)
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var repositoryID []byte
	var secondBundle string
	var secondMetadata *v2GitMetadata
	withGitTestDirectory(t, source, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err = repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		secondBundle, secondMetadata, err = a.createV2GitBundle(repository, v2GitPushOptions{}, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
	})
	defer os.Remove(secondBundle)
	state := newV2GitPeerState(repositoryID, strings.Repeat("d", 32))
	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.associateRepositoryID(repositoryID); err != nil {
			t.Fatal(err)
		}
		scratch, err := a.verifyV2GitQuarantine(repository, secondBundle, strings.Repeat("e", 64), secondMetadata)
		if err != nil {
			t.Fatal(err)
		}
		refs, err := a.promoteV2GitQuarantine(repository, state, scratch, strings.Repeat("e", 64), "peer", secondMetadata, false)
		if err != nil {
			t.Fatal(err)
		}
		state.LastReceivedRefs = stringGitRefs(refs)
		runGitTestCommand(t, destination, "update-ref", "refs/remotes/peer/removed", secondOID)
		state.LastReceivedRefs["refs/heads/removed"] = secondOID
	})

	runGitTestCommand(t, source, "reset", "--hard", initialOID)
	rewrittenOID := commitGitTestFile(t, source, "history.txt", "rewritten\n", "rewrite")
	var rewrittenBundle string
	var rewrittenMetadata *v2GitMetadata
	withGitTestDirectory(t, source, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		rewrittenBundle, rewrittenMetadata, err = a.createV2GitBundle(repository, v2GitPushOptions{}, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
	})
	defer os.Remove(rewrittenBundle)
	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		scratch, err := a.verifyV2GitQuarantine(repository, rewrittenBundle, strings.Repeat("f", 64), rewrittenMetadata)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.promoteV2GitQuarantine(repository, state, scratch, strings.Repeat("f", 64), "peer", rewrittenMetadata, false); err == nil ||
			!strings.Contains(err.Error(), "--allow-rewrite") {
			t.Fatalf("unexpected rewrite result: %v", err)
		}
		if got := runGitTestCommand(t, destination, "rev-parse", "refs/remotes/peer/main"); got != secondOID {
			t.Fatalf("rejected rewrite moved peer ref to %s", got)
		}
		command := exec.Command("git", "-C", destination, "cat-file", "-e", rewrittenOID+"^{object}")
		if err := command.Run(); err == nil {
			t.Fatal("rejected rewrite copied quarantine objects into the real repository")
		}
		scratch, err = a.verifyV2GitQuarantine(repository, rewrittenBundle, strings.Repeat("0", 64), rewrittenMetadata)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.promoteV2GitQuarantine(repository, state, scratch, strings.Repeat("0", 64), "peer", rewrittenMetadata, true); err != nil {
			t.Fatal(err)
		}
		if got := runGitTestCommand(t, destination, "rev-parse", "refs/remotes/peer/main"); got != rewrittenOID {
			t.Fatalf("approved rewrite left peer ref at %s", got)
		}
		command = exec.Command("git", "-C", destination, "show-ref", "--verify", "--quiet", "refs/remotes/peer/removed")
		if err := command.Run(); err == nil {
			t.Fatal("approved complete checkpoint retained a deleted peer branch")
		}
	})
}

func TestV2GitSHA256CheckpointUsesBundleVersionThree(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("git", "-C", source, "init", "--object-format=sha256", "-b", "main")
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("installed Git does not support SHA-256 repositories: %v\n%s", err, output)
	}
	runGitTestCommand(t, source, "config", "user.name", "DUD Test")
	runGitTestCommand(t, source, "config", "user.email", "dud@example.test")
	wantOID := commitGitTestFile(t, source, "sha256.txt", "sha256\n", "sha256")
	runGitTestCommand(t, destination, "init", "--object-format=sha256", "-b", "main")
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var repositoryID []byte
	var bundlePath string
	var metadata *v2GitMetadata
	withGitTestDirectory(t, source, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err = repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		bundlePath, metadata, err = a.createV2GitBundle(repository, v2GitPushOptions{}, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
		if metadata.ObjectFormat != 2 || metadata.BundleVersion != 3 {
			t.Fatalf("unexpected SHA-256 metadata: %#v", metadata)
		}
	})
	defer os.Remove(bundlePath)
	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.associateRepositoryID(repositoryID); err != nil {
			t.Fatal(err)
		}
		state := newV2GitPeerState(repositoryID, strings.Repeat("1", 32))
		scratch, err := a.verifyV2GitQuarantine(repository, bundlePath, strings.Repeat("2", 64), metadata)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.promoteV2GitQuarantine(repository, state, scratch, strings.Repeat("2", 64), "peer", metadata, false); err != nil {
			t.Fatal(err)
		}
		if got := runGitTestCommand(t, destination, "rev-parse", "refs/remotes/peer/main"); got != wantOID {
			t.Fatalf("SHA-256 remote-tracking ref = %s, want %s", got, wantOID)
		}
	})
}

// writeDanglingGitBlob stores a loose object that no advertised ref reaches, so
// a hostile sender can smuggle it into an otherwise honest pack.
func writeDanglingGitBlob(t *testing.T, directory, content string) string {
	t.Helper()
	command := exec.Command("git", "-C", directory, "hash-object", "-w", "--stdin")
	command.Stdin = strings.NewReader(content)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git hash-object failed: %v", err)
	}
	return strings.TrimSpace(string(output))
}

// writeHostileGitBundle assembles a bundle by hand so the pack may carry objects
// beyond the advertised history, which `git bundle create` would never emit.
func writeHostileGitBundle(t *testing.T, source, path string, extra []string) *v2GitMetadata {
	t.Helper()
	head := runGitTestCommand(t, source, "rev-parse", "refs/heads/main")
	names := []string{}
	for _, line := range strings.Split(runGitTestCommand(t, source, "rev-list", "--objects", "main"), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			names = append(names, fields[0])
		}
	}
	names = append(names, extra...)
	pack := exec.Command("git", "-C", source, "pack-objects", "--stdout")
	pack.Stdin = strings.NewReader(strings.Join(names, "\n") + "\n")
	var packed bytes.Buffer
	pack.Stdout = &packed
	if err := pack.Run(); err != nil {
		t.Fatalf("git pack-objects failed: %v", err)
	}
	body := append([]byte("# v2 git bundle\n"+head+" refs/heads/main\n\n"), packed.Bytes()...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	oid, err := hex.DecodeString(head)
	if err != nil {
		t.Fatal(err)
	}
	return &v2GitMetadata{
		RepositoryID:  bytes.Repeat([]byte{0x7a}, 16),
		ObjectFormat:  1,
		BundleVersion: 2,
		Refs:          map[string][]byte{"refs/heads/main": oid},
		Prerequisites: [][]byte{},
	}
}

func TestV2GitQuarantineCountsUnreachableBundleObjects(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	for _, directory := range []string{source, destination} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		initializeGitTestRepository(t, directory)
	}
	commitGitTestFile(t, source, "README.md", "first\n", "initial")
	var dangling []string
	for index := 0; index < 8; index++ {
		dangling = append(dangling, writeDanglingGitBlob(t, source, fmt.Sprintf("unreachable-%d\n", index)))
	}
	bundlePath := filepath.Join(root, "hostile.bundle")
	metadata := writeHostileGitBundle(t, source, bundlePath, dangling)

	// The advertised history is a commit, a tree, and a blob. Anything above
	// three objects in the pack is unreachable padding from the sender.
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	runGitTestCommand(t, destination, "config", "dud.gitObjectCount", "5")
	rejected := strings.Repeat("7", 64)
	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.verifyV2GitQuarantine(repository, bundlePath, rejected, metadata); err == nil ||
			!strings.Contains(err.Error(), "more than 5 objects") {
			t.Fatalf("unreachable object flood passed quarantine: %v", err)
		}
		if _, err := os.Stat(filepath.Join(repository.DUDDir, "quarantine", rejected)); !os.IsNotExist(err) {
			t.Fatalf("rejected quarantine was retained: %v", err)
		}
		for _, oid := range dangling {
			command := exec.Command("git", "-C", destination, "cat-file", "-e", oid)
			if err := command.Run(); err == nil {
				t.Fatal("unreachable object reached the real object database")
			}
		}
	})

	// Raising the local ceiling above the smuggled total accepts the identical
	// bundle, so the rejection above is the object count and not the payload.
	runGitTestCommand(t, destination, "config", "dud.gitObjectCount", "64")
	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		scratch, err := a.verifyV2GitQuarantine(repository, bundlePath, strings.Repeat("8", 64), metadata)
		if err != nil {
			t.Fatalf("bundle rejected under a sufficient object limit: %v", err)
		}
		if err := os.RemoveAll(scratch); err != nil {
			t.Fatal(err)
		}
	})
}

// commitDeltaChainHistory rewrites one large file many times so that repacking
// produces a long delta chain rather than a fan of independent deltas.
func commitDeltaChainHistory(t *testing.T, directory string) {
	t.Helper()
	lines := make([]string, 1500)
	for index := range lines {
		lines[index] = fmt.Sprintf("%08d %s", index, strings.Repeat("x", 40))
	}
	path := filepath.Join(directory, "history.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTestCommand(t, directory, "add", "history.txt")
	runGitTestCommand(t, directory, "commit", "-m", "base")
	generator := rand.New(rand.NewSource(7))
	for revision := 1; revision <= 24; revision++ {
		for edit := 0; edit < 4; edit++ {
			chosen := generator.Intn(len(lines))
			lines[chosen] = fmt.Sprintf("revision %d %s", revision, lines[chosen])
		}
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
			t.Fatal(err)
		}
		runGitTestCommand(t, directory, "add", "history.txt")
		runGitTestCommand(t, directory, "commit", "-m", fmt.Sprintf("revision %d", revision))
	}
	runGitTestCommand(t, directory, "repack", "-a", "-d", "-f", "--depth=50", "--window=250")
}

// deepestGitPackDelta reports the longest delta chain the local Git actually
// produced, so the delta-depth test can skip rather than fail on a Git whose
// packing heuristics changed.
func deepestGitPackDelta(t *testing.T, directory string) uint64 {
	t.Helper()
	indexes, err := filepath.Glob(filepath.Join(directory, ".git", "objects", "pack", "*.idx"))
	if err != nil || len(indexes) == 0 {
		t.Fatalf("no pack index in %s: %v", directory, err)
	}
	var deepest uint64
	for _, index := range indexes {
		for _, line := range strings.Split(runGitTestCommand(t, directory, "verify-pack", "-v", index), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 7 {
				continue
			}
			if depth, err := strconv.ParseUint(fields[5], 10, 64); err == nil && depth > deepest {
				deepest = depth
			}
		}
	}
	return deepest
}

func TestV2GitQuarantineRejectsExcessiveDeltaDepth(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	for _, directory := range []string{source, destination} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		initializeGitTestRepository(t, directory)
	}
	commitDeltaChainHistory(t, source)
	const permitted = 4
	if deepest := deepestGitPackDelta(t, source); deepest <= permitted {
		t.Skipf("installed Git packed a maximum delta depth of %d", deepest)
	}

	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var repositoryID []byte
	var bundlePath string
	var metadata *v2GitMetadata
	withGitTestDirectory(t, source, func() {
		repository, err := a.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err = repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		bundlePath, metadata, err = a.createV2GitBundle(repository, v2GitPushOptions{}, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
	})
	defer os.Remove(bundlePath)

	runGitTestCommand(t, destination, "config", "dud.gitDeltaDepth", strconv.Itoa(permitted))
	digest := strings.Repeat("9", 64)
	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.associateRepositoryID(repositoryID); err != nil {
			t.Fatal(err)
		}
		if _, err := a.verifyV2GitQuarantine(repository, bundlePath, digest, metadata); err == nil ||
			!strings.Contains(err.Error(), "delta depth") {
			t.Fatalf("deep delta chain passed quarantine: %v", err)
		}
		if _, err := os.Stat(filepath.Join(repository.DUDDir, "quarantine", digest)); !os.IsNotExist(err) {
			t.Fatalf("rejected quarantine was retained: %v", err)
		}
	})

	// The same bundle is acceptable once the local ceiling covers the chain.
	runGitTestCommand(t, destination, "config", "dud.gitDeltaDepth", strconv.Itoa(v2GitMaximumDeltaDepth))
	withGitTestDirectory(t, destination, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		scratch, err := a.verifyV2GitQuarantine(repository, bundlePath, strings.Repeat("a", 64), metadata)
		if err != nil {
			t.Fatalf("bundle rejected under the default delta depth: %v", err)
		}
		if err := os.RemoveAll(scratch); err != nil {
			t.Fatal(err)
		}
	})
}

func TestV2GitLimitedBufferBoundsCommandOutput(t *testing.T) {
	writer := v2GitLimitedBuffer{limit: 8}
	if written, err := writer.Write([]byte("0123")); written != 4 || err != nil {
		t.Fatalf("short write = %d, %v", written, err)
	}
	written, err := writer.Write([]byte("456789"))
	if written != 4 || err == nil || !strings.Contains(err.Error(), "exceeded the local limit") {
		t.Fatalf("overflowing write = %d, %v", written, err)
	}
	if written, err := writer.Write([]byte("x")); written != 0 || err == nil {
		t.Fatalf("write past the limit = %d, %v", written, err)
	}
	if writer.String() != "01234567" || len(writer.Bytes()) != 8 {
		t.Fatalf("buffer grew past the limit: %q", writer.String())
	}
}

// TestV2GitFetchAppliesACompleteCheckpoint drives the public git fetch command
// through a complete signed granular delivery.  It exercises the durable
// delivery state, quarantine checks, remote-tracking ref promotion, and the
// acknowledgement that retires the inbox entry together.
func TestV2GitFetchAppliesACompleteCheckpoint(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	initializeGitTestRepository(t, source)
	wantOID := commitGitTestFile(t, source, "README.md", "checkpoint\n", "checkpoint")
	initializeGitTestRepository(t, destination)

	var bundlePath string
	var metadata *v2GitMetadata
	sourceApp := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, source, func() {
		repository, err := sourceApp.resolveV2GitRepository("push")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err := repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		bundlePath, metadata, err = sourceApp.createV2GitBundle(repository, v2GitPushOptions{}, repositoryID)
		if err != nil {
			t.Fatal(err)
		}
	})
	defer os.Remove(bundlePath)
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}

	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	delivery := buildInboundV2GitDelivery(t, crypto, *metadata, bundle)
	transport := &drainingInboxTransport{queue: []stubbedV2Delivery{delivery}}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	withGitTestDirectory(t, destination, func() {
		if err := a.run([]string{"git", "fetch", "laptop", "--associate"}); err != nil {
			t.Fatal(err)
		}
	})
	if transport.completions != 1 {
		t.Fatalf("completions = %d, want 1", transport.completions)
	}
	if got := runGitTestCommand(t, destination, "rev-parse", "refs/remotes/laptop/main"); got != wantOID {
		t.Fatalf("remote-tracking ref = %s, want %s", got, wantOID)
	}
	if !strings.Contains(stdout.String(), "Fetched complete Git checkpoint") {
		t.Fatalf("fetch output = %s", stdout.String())
	}
}

func TestV2GitStatusReportsActivePeerState(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	commitGitTestFile(t, repositoryPath, "README.md", "status\n", "status")
	paths, deliveryState := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, deliveryState); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, &emptySlotTransport{}, &stdout, &stderr)
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("status")
		if err != nil {
			t.Fatal(err)
		}
		repositoryID, err := repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		state := newV2GitPeerState(repositoryID, strings.Repeat("32", 16))
		state.LastReceivedSequence = 3
		state.Outbound["pending"] = v2GitOutboundState{Sequence: 4}
		if err := repository.writePeerState(state); err != nil {
			t.Fatal(err)
		}
		if err := a.run([]string{"git", "status", "laptop", "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	peers, ok := result["peers"].([]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("git status peers = %#v", result)
	}
	peer := peers[0].(map[string]any)
	if peer["last_received_sequence"] != float64(3) || peer["pending_outbound"] != float64(1) {
		t.Fatalf("git status peer = %#v", peer)
	}
}

func TestV2GitFetchReportsAnEmptyPeerInbox(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, &emptySlotTransport{}, &stdout, &stderr)
	withGitTestDirectory(t, repositoryPath, func() {
		if err := a.run([]string{"git", "fetch", "laptop", "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["peer"] != "laptop" || result["received"] != false {
		t.Fatalf("empty fetch result = %#v", result)
	}
}

func TestV2GitStatusReportsDivergenceForTrackedBranch(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	base := commitGitTestFile(t, repositoryPath, "README.md", "base\n", "base")
	commitGitTestFile(t, repositoryPath, "README.md", "local\n", "local")
	runGitTestCommand(t, repositoryPath, "update-ref", "refs/remotes/laptop/main", base)
	paths, deliveryState := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, deliveryState); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, &emptySlotTransport{}, &stdout, &stderr)
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("status")
		if err != nil {
			t.Fatal(err)
		}
		id, err := repository.ensureRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		state := newV2GitPeerState(id, strings.Repeat("32", 16))
		state.LastReceivedRefs["refs/heads/main"] = base
		if err := repository.writePeerState(state); err != nil {
			t.Fatal(err)
		}
		if err := a.run([]string{"git", "status", "laptop"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(stdout.String(), "local-only 1, peer-only 0") {
		t.Fatalf("Git divergence report = %s", stdout.String())
	}
}

func TestV2GitPushPublishesACompleteCheckpoint(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	commitGitTestFile(t, repositoryPath, "README.md", "push\n", "push")
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	policy := v2TransportPolicyMap(v2TransportPolicy{ExpiresAt: uint64(time.Now().Add(time.Hour).Unix()), Consume: 0, ClaimLeaseSeconds: 300, AckMode: 1})
	response, err := v2EncMode.Marshal(map[int]any{1: bytesRepeatV2(0x81, 16), 2: policy, 3: false, 4: []any{}, 5: []any{}})
	if err != nil {
		t.Fatal(err)
	}
	transport := &gitPushTransport{deliveryResponse: response}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	withGitTestDirectory(t, repositoryPath, func() {
		if err := a.run([]string{"git", "push", "laptop", "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	if transport.deliveries != 1 {
		t.Fatalf("published deliveries = %d, want 1", transport.deliveries)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["peer"] != "laptop" || result["sequence"] != float64(1) {
		t.Fatalf("push result = %#v", result)
	}
}

type gitPushTransport struct {
	emptySlotTransport
	deliveryResponse []byte
	deliveries       int
}

func (transport *gitPushTransport) Do(ctx context.Context, request v2Request) (*v2Response, error) {
	if request.Path == "/v2/inbox" {
		return transport.emptySlotTransport.Do(ctx, request)
	}
	if request.Method == "POST" && request.Path == "/v2/deliveries" {
		transport.deliveries++
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: transport.deliveryResponse}, nil
	}
	return nil, fmt.Errorf("unexpected Git push request: %s %s", request.Method, request.Path)
}

// buildInboundV2GitDelivery is the Git counterpart to buildInboundV2Delivery.
// The production metadata comes from a real bundle, so the receiver validates
// the same signed ref map and repository identity that a peer would publish.
func buildInboundV2GitDelivery(t *testing.T, crypto v2TestPeerCrypto, metadata v2GitMetadata, plaintext []byte) stubbedV2Delivery {
	t.Helper()
	return buildInboundV2GitDeliveryAt(t, crypto, metadata, plaintext, 1, strings.Repeat("00", 32), nil)
}

// buildInboundV2GitDeliveryAt places a Git checkpoint at an explicit position on
// the inbound data chain, so a test can queue one delivery behind another and
// observe whether the second is ever reached. mutate, when set, rewrites the
// signed type_meta map after it is built from the real bundle, which is how a
// checkpoint that no receiver can apply is produced without hand-rolling a
// descriptor.
func buildInboundV2GitDeliveryAt(t *testing.T, crypto v2TestPeerCrypto, metadata v2GitMetadata, plaintext []byte, sequence uint64, previousDigest string, mutate func(map[int]any)) stubbedV2Delivery {
	t.Helper()
	now := uint64(time.Now().Unix())
	policy := v2TransportPolicy{ExpiresAt: now + 86_400, Consume: 0, ClaimLeaseSeconds: 300, AckMode: 1}
	payloadCiphertext, err := encryptV2Payload(plaintext, crypto.recipient)
	if err != nil {
		t.Fatal(err)
	}
	descriptorID, err := newV2DescriptorID()
	if err != nil {
		t.Fatal(err)
	}
	plainDigest := sha256.Sum256(plaintext)
	cipherDigest := sha256.Sum256(payloadCiphertext)
	plaintextSize := uint64(len(plaintext))
	typeMetadata := encodeV2GitMetadata(metadata)
	if mutate != nil {
		mutate(typeMetadata)
	}
	descriptor := v2Descriptor{
		DescriptorID: descriptorID, PayloadType: 4, RelationshipID: crypto.relationshipID,
		Direction: v2InboundDirection(crypto.role), Chain: 0, KeyEpoch: 0, Sequence: sequence,
		PreviousDigest: mustDecodeHexV2(previousDigest, 32), SenderDeviceID: crypto.peerID,
		RecipientDeviceID: crypto.localID, CanonicalOrigin: crypto.origin, CreatedAt: now,
		TransportPolicy: policy, PayloadHash: plainDigest[:], ChunkHashes: [][]byte{cipherDigest[:]},
		DisplayName: "checkpoint.bundle", PlaintextSize: &plaintextSize, TypeMetadata: typeMetadata,
	}
	descriptorCiphertext, err := encryptV2Envelope(descriptor, crypto.signingKey, crypto.recipient)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := descriptorMap(descriptor, crypto.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := v2EncMode.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(signedBytes)
	epoch := v2SlotEpoch(time.Now())
	slot, err := deriveV2Slot(crypto.inboundSecret, "data", epoch)
	if err != nil {
		t.Fatal(err)
	}
	id := bytesRepeatV2(0x9a, 16)
	id[0] = byte(sequence)
	return stubbedV2Delivery{id: id, slot: slot, epoch: epoch, descriptor: descriptorCiphertext, payload: payloadCiphertext, policy: v2TransportPolicyMap(policy), digest: hex.EncodeToString(digest[:])}
}

func TestV2GitCommandFailuresAreSanitized(t *testing.T) {
	repositoryPath := t.TempDir()
	initializeGitTestRepository(t, repositoryPath)
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	withGitTestDirectory(t, repositoryPath, func() {
		repository, err := a.resolveV2GitRepository("fetch")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		hostile := "\x1b[31m\x07nonexistent\ndud-injected"
		if _, err := a.runV2Git(ctx, repository, nil, "cat-file", "-e", hostile); err == nil {
			t.Fatal("invalid object name succeeded")
		} else {
			message := err.Error()
			if strings.ContainsAny(message, "\x00\x07\x1b\n\r") {
				t.Fatalf("Git failure leaked control characters: %q", message)
			}
			// Git replaces some control bytes itself, so only demand the escape
			// once the reported failure has echoed the whole hostile argument.
			if strings.Contains(message, "dud-injected") && !strings.Contains(message, `\n`) {
				t.Fatalf("Git failure was not ASCII-quoted: %s", message)
			}
		}
	})
}

func hexOID(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&15]
	}
	return string(result)
}
