//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpticalKeysDistinguishEscapeSequencesFromQuitKeys(t *testing.T) {
	for _, quit := range []string{"q", "Q", "\x1b"} {
		t.Run(quit, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			input, output := io.Pipe()
			defer func() { _ = output.Close() }()
			defer func() { _ = input.Close() }()
			stop := context.AfterFunc(ctx, func() { _ = input.CloseWithError(ctx.Err()) })
			defer stop()
			done := make(chan struct{})
			go func() {
				defer close(done)
				readOpticalKeys(ctx, input, cancel)
			}()
			// SS3 keypad keys and terminal responses can contain literal q/Q.
			for _, sequence := range []string{"\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D", "\x1b[5~", "\x1bOP", "\x1bOq", "\x1b[1 q", "\x1b_Gi=1;OK\x1b\\", "\x1b]11;Qq\x07", "\x1bq"} {
				for _, value := range []byte(sequence) {
					// Each pipe write supplies a separate read to the decoder.
					if _, err := output.Write([]byte{value}); err != nil {
						t.Fatalf("sequence %q stopped the display: %v", sequence, err)
					}
				}
			}
			select {
			case <-done:
				t.Fatal("a navigation key or terminal response stopped the display")
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := io.WriteString(output, quit); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
				if ctx.Err() != context.Canceled {
					t.Fatal("reader finished without recognizing the quit key")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("quit key did not finish the reader")
			}
		})
	}
}

func TestOpticalKeyInputStopsOnCancellationAndEOF(t *testing.T) {
	for _, cancelInput := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		input, output := io.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			readOpticalKeys(ctx, input, cancel)
		}()
		if cancelInput {
			cancel()
		}
		_ = output.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("key reader did not release input")
		}
		_ = input.Close()
		cancel()
	}
}

func TestOpticalPollingInputReleasesIdleDescriptor(t *testing.T) {
	for _, reason := range []string{"cancellation", "deadline", "eof"} {
		t.Run(reason, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(fds[0]) }()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if reason == "cancellation" {
				cancel()
			}
			if reason == "eof" {
				_ = unix.Close(fds[1])
			} else {
				defer func() { _ = unix.Close(fds[1]) }()
			}
			done := make(chan error, 1)
			go func() {
				_, err := (opticalKeyInput{ctx: ctx, fd: fds[0]}).Read(make([]byte, 1))
				done <- err
			}()
			select {
			case err := <-done:
				if reason == "eof" && err != io.EOF || reason != "eof" && err != ctx.Err() {
					t.Fatalf("%s: %v", reason, err)
				}
			case <-time.After(time.Second):
				t.Fatal("polling input did not release its descriptor")
			}
		})
	}
}
