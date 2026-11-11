//go:build darwin || linux

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpticalTerminalCLIProcess(t *testing.T) {
	if os.Getenv("DUD_TEST_OPTICAL_TERMINAL_CLI") != "1" {
		return
	}
	if err := os.Setenv("DUD_AGE_BIN", os.Getenv("DUD_TEST_OPTICAL_TERMINAL_AGE")); err != nil {
		t.Fatal(err)
	}
	for index, argument := range os.Args {
		if argument == "--" {
			original, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), uint(ioctlReadTermios))
			if err != nil {
				t.Fatal(err)
			}
			if os.Getenv("DUD_TEST_OPTICAL_TERMINAL_SUPERVISOR") == "1" {
				runOpticalTerminalSignalSupervisor(t, os.Args[index+1:])
			} else {
				os.Args = append([]string{os.Args[0]}, os.Args[index+1:]...)
				main()
			}
			restored, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), uint(ioctlReadTermios))
			if err != nil || restored.Lflag != original.Lflag {
				t.Fatalf("quit did not restore terminal input: %v", err)
			}
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI arguments")
}

// Retain the controlling terminal after the sender exits so its input mode
// remains inspectable when signal cleanup bypasses the sender's defers.
func runOpticalTerminalSignalSupervisor(t *testing.T, args []string) {
	t.Helper()
	signal.Ignore(os.Interrupt)
	if err := os.Unsetenv("DUD_TEST_OPTICAL_TERMINAL_SUPERVISOR"); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], append([]string{"-test.run=^TestOpticalTerminalCLIProcess$", "--"}, args...)...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	var exit *exec.ExitError
	if err := command.Run(); !errors.As(err, &exit) || exit.ExitCode() != 130 {
		t.Fatalf("SIGINT sender exit: %v", err)
	}
	fmt.Println("DUD-OPTICAL-SIGNAL-CLEANUP-OK")
}

func TestOpticalTerminalCLIKeysRestoreTerminalAndReportStatus(t *testing.T) {
	for _, renderer := range []string{"kitty", "terminal"} {
		for _, size := range []struct {
			name  string
			bytes int
		}{{"single-block", 8}, {"multiple-blocks", 8192}} {
			for _, key := range []string{"q", "\x1b", "\x03"} {
				t.Run(renderer+"/"+size.name+"/"+key, func(t *testing.T) {
					runOpticalTerminalCLITest(t, renderer, size.bytes, key)
				})
			}
		}
	}
}

func runOpticalTerminalCLITest(t *testing.T, renderer string, bytes int, key string) {
	t.Helper()
	t.Setenv("TERM", "xterm-kitty")
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("DUD_TEST_OPTICAL_TERMINAL_CLI", "1")
	t.Setenv("DUD_TEST_OPTICAL_TERMINAL_AGE", writePassthroughAge(t))
	if key == "\x03" {
		t.Setenv("DUD_TEST_OPTICAL_TERMINAL_SUPERVISOR", "1")
	}
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte(strings.Repeat("x", bytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close() }()
	name, err := tuiOpticalTestPTYName(master)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = terminal.Close() }()
	if err := unix.IoctlSetWinsize(int(terminal.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: 512, Row: 256, Xpixel: 1740, Ypixel: 960}); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestOpticalTerminalCLIProcess$", "--", "optical", "send", "--file", source, "--passphrase", "--json", "--optical-renderer", renderer, "--optical-profile", "balanced", "--optical-scale", "1")
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() {
		cancel()
		_ = master.Close()
		_ = terminal.Close()
	}()
	transcript, err := exerciseOpticalCLIKeys(ctx, master, done, key)
	if err != nil {
		t.Fatalf("%s CLI key %q: %v\n%s", renderer, key, err, transcript[max(0, len(transcript)-1000):])
	}
	expected := `"status": "display-ended"`
	if key == "\x03" {
		expected = "DUD-OPTICAL-SIGNAL-CLEANUP-OK"
	}
	if !strings.Contains(transcript, expected) || !strings.Contains(transcript, "\x1b[?25h\x1b[?1049l") {
		t.Fatal("termination did not restore display and report its status")
	}
	assertOpticalCleanup(t)
}

func exerciseOpticalCLIKeys(ctx context.Context, master *os.File, done <-chan error, key string) (string, error) {
	var transcript strings.Builder
	var navigationAt time.Time
	queried, quit := false, false
	var buffer [65536]byte
	for ctx.Err() == nil {
		n, err := readOpticalKitty(ctx, int(master.Fd()), buffer[:], time.Now().Add(100*time.Millisecond))
		transcript.Write(buffer[:n])
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return transcript.String(), err
		}
		text := transcript.String()
		if !queried && strings.Contains(text, "\x1b[c") {
			queried = true
			if _, err := master.Write([]byte("\x1b_Gi=31;OK\x1b\\\x1b[4;960;1740t\x1b[6;16;10t\x1b[?62;c")); err != nil {
				return text, err
			}
		}
		if navigationAt.IsZero() && strings.Contains(text, "\x1b[H") {
			if _, err := master.Write([]byte("\x1b[A\x1bOP")); err != nil {
				return text, err
			}
			navigationAt = time.Now()
		}
		select {
		case err := <-done:
			if !quit {
				return text, errors.New("navigation ended display before quit key")
			}
			return text, err
		default:
		}
		if !quit && !navigationAt.IsZero() && time.Since(navigationAt) >= 150*time.Millisecond {
			quit = true
			if _, err := master.Write([]byte(key)); err != nil {
				return text, err
			}
		}
	}
	return transcript.String(), ctx.Err()
}
