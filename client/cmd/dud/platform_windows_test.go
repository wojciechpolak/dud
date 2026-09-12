// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//go:build windows

package main

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateACLAllowsOnlyTheCurrentUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setPrivatePathPermissions(path, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivatePathPermissions(path, info); err != nil {
		t.Fatal(err)
	}

	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;;GA;;;" + everyone.String() + ")",
	)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivatePathPermissions(path, info); err == nil {
		t.Fatal("an ACL granting access to Everyone was accepted as private")
	}
}

func TestWindowsFileLockRejectsASecondWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := lockLocalFile(first); err != nil {
		t.Fatal(err)
	}
	if err := lockLocalFile(second); !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("second lock error = %v", err)
	}
	if err := unlockLocalFile(first); err != nil {
		t.Fatal(err)
	}
	if err := lockLocalFile(second); err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := unlockLocalFile(second); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsAtomicReplacementOverwritesTheDestination(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "config.toml")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteV2File(target, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new" {
		t.Fatalf("replacement body = %q", body)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivatePathPermissions(target, info); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsAtomicCopyOverwritesTheDestination(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicCopyV2File(target, source); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new" {
		t.Fatalf("copied body = %q", body)
	}
}

func TestWindowsAvailableBytesUsesTheContainingVolume(t *testing.T) {
	available, err := availableLocalBytes(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if available == 0 {
		t.Fatal("volume reported no available space")
	}
}

func TestWindowsPeerConfigurationRoundTrip(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dud")
	t.Setenv("DUD_HOME", home)
	t.Setenv("DUD_PROFILE", "")
	cfg, _, err := initializeV2Config(
		"windows-device",
		"https://dud.example.com",
		"https://cloudflare-dns.com/dns-query",
		"hard",
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Device != "windows-device" {
		t.Fatalf("device = %q", cfg.Device)
	}
	if _, err := updateV2Config(func(next *v2LocalConfig) error {
		next.Device = "renamed-device"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Device != "renamed-device" {
		t.Fatalf("updated device = %q", loaded.Device)
	}
}

func TestWindowsDevNullIsNotATerminal(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if isTerminal(file.Fd()) {
		t.Fatal("NUL was detected as an interactive console")
	}
}

func TestWindowsCollectionExtractionUsesARootedHandle(t *testing.T) {
	body := buildV2HostileArchive(
		t,
		[]*tar.Header{
			{Typeflag: tar.TypeDir, Name: "docs", Mode: 0o755},
			regularV2Entry("docs/readme.txt", 7, 0o644),
		},
		[][]byte{nil, []byte("windows")},
	)
	destination := filepath.Join(t.TempDir(), "received")
	if _, err := extractV2CollectionArchive(body, destination, uint64(len(body))); err != nil {
		t.Fatal(err)
	}
	if err := verifyV2ExtractedCollection(body, destination, uint64(len(body))); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsProcessCleanupUsesConsoleInterruptSemantics(t *testing.T) {
	setProcessPrivateFileMask()
	signals := processCleanupSignals()
	if len(signals) != 1 || signals[0] != os.Interrupt {
		t.Fatalf("cleanup signals = %#v", signals)
	}
	if code := processSignalExitCode(os.Interrupt); code != 130 {
		t.Fatalf("interrupt exit code = %d", code)
	}
}
