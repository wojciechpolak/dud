//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpticalArchiveCancellationStopsPreparationAndCleansStaging(t *testing.T) {
	parent, renderer, _, _ := newOpticalTestApp(t, "")
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	ready, release := filepath.Join(tools, "ready"), filepath.Join(tools, "release")
	script := "#!/bin/sh\n: > \"$DUD_TEST_TAR_READY\"\nwhile [ ! -e \"$DUD_TEST_TAR_RELEASE\" ]; do sleep 0.01; done\nexit 7\n"
	if err := os.WriteFile(filepath.Join(tools, "tar"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DUD_TEST_TAR_READY", ready)
	t.Setenv("DUD_TEST_TAR_RELEASE", release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	parent.commandCtx = ctx
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		result = parent.run([]string{"optical", "send", "--file", source, "--passphrase"})
	}()
	defer func() {
		_ = os.WriteFile(release, nil, 0o600)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("archive process did not exit during cleanup")
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("archive process did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled optical operation is waiting for tar")
	}
	if result == nil || renderer.called || !renderer.closed {
		t.Fatalf("cancellation reached display or skipped cleanup: %v", result)
	}
	assertOpticalCleanup(t)
}
