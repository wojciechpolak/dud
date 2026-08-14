// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

// Injected at build time from package.json via
// -ldflags "-X main.version=...". The "dev" fallback makes a build
// that skipped injection visible instead of reporting a stale number.
var version = "dev"

type config struct {
	BaseURL      string
	DOHURL       string
	ECHMode      string
	SecretToken  string
	V2Secret     string
	CABundle     string
	ConnectTo    string
	AgeBin       string
	AgeKeygenBin string
	GitBin       string
	QREncodeBin  string
	Image        string
}

type app struct {
	cfg            config
	in             io.Reader
	out            io.Writer
	errOut         io.Writer
	exe            string
	newV2Transport func(v2TransportOptions) (v2Transport, error)
}

type fatalError string

func (e fatalError) Error() string { return string(e) }

func main() {
	syscall.Umask(0o077)
	cleanupTempFilesOnSignal()
	a := newApp(os.Stdin, os.Stdout, os.Stderr)
	if code := a.main(os.Args[1:]); code != 0 {
		os.Exit(code)
	}
}

// Deferred cleanup never runs when a signal kills the process, so an
// interrupted upload or download would leave decrypted plaintext in the
// temp directory.
func cleanupTempFilesOnSignal() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		sig := <-signals
		removeAllTempFiles()
		os.Exit(128 + int(sig.(syscall.Signal)))
	}()
}

func newApp(in io.Reader, out io.Writer, errOut io.Writer) *app {
	exe, _ := os.Executable()
	return &app{
		cfg:    loadConfig(),
		in:     in,
		out:    out,
		errOut: errOut,
		exe:    exe,
		newV2Transport: func(options v2TransportOptions) (v2Transport, error) {
			return newProductionV2Transport(options)
		},
	}
}

func (a *app) main(args []string) int {
	err := a.run(args)
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// The subprocess already reported the failure on its own stderr.
		if code := exitErr.ExitCode(); code > 0 {
			return code
		}
		return 1
	}
	// An HTTP status of 400 or more leaves the shell with exit code 22, which
	// scripts wrapping the CLI branch on.
	var statusErr *dropStatusError
	if errors.As(err, &statusErr) {
		fmt.Fprintln(a.errOut, statusErr.Error())
		return statusErr.ExitCode()
	}
	if msg := err.Error(); msg != "" {
		fmt.Fprintln(a.errOut, msg)
	}
	return 1
}

func (a *app) run(args []string) error {
	if len(args) == 0 {
		if stdinIsTTY() {
			return a.interactiveMenu()
		}
		a.usage()
		return fatalError("")
	}

	command := args[0]
	rest := args[1:]

	switch command {
	case "--version", "version":
		fmt.Fprintln(a.out, envDefault("DUD_VERSION", version))
	case "test":
		return a.cmdTest(rest)
	case "init":
		return a.cmdInit(rest)
	case "config":
		return a.cmdConfig(rest)
	case "doctor":
		return a.cmdDoctor(rest)
	case "capabilities":
		return a.cmdCapabilities(rest)
	case "migrate":
		return a.cmdMigrate(rest)
	case "erase":
		return a.cmdErase(rest)
	case "peer":
		return a.cmdPeer(rest)
	case "sync":
		return a.cmdSync(rest)
	case "inbox":
		return a.cmdInbox(rest)
	case "upload", "send":
		if len(rest) != 0 && !strings.HasPrefix(rest[0], "-") {
			return a.cmdPeerSend(rest)
		}
		return a.cmdUpload(rest, "dud receive")
	case "download", "receive":
		if len(rest) != 0 && !strings.HasPrefix(rest[0], "-") {
			return a.cmdPeerReceive(rest)
		}
		return a.cmdDownload(rest)
	case "git":
		return a.cmdGit(rest)
	case "flush":
		return a.cmdFlush(rest)
	case "keygen":
		return a.cmdKeygen(rest)
	case "install":
		fmt.Fprint(a.out, installScript(a.cfg.Image))
	case "shell-init":
		fmt.Fprint(a.out, shellInitScript(a.cfg.Image))
	case "help", "-h", "--help":
		a.usage()
	default:
		return fatalError("Unknown command: " + command)
	}
	return nil
}
