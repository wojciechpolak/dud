// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

func loadConfig() config {
	return config{
		BaseURL:      envDefault("DUD_BASE_URL", v2DefaultBaseURL),
		DOHURL:       envDefault("DUD_DOH_URL", v2DefaultDOHURL),
		ECHMode:      envDefault("DUD_ECH_MODE", v2DefaultECHMode),
		SecretToken:  os.Getenv("DUD_DROP_SECRET"),
		V2Secret:     os.Getenv("DUD_PEER_SECRET"),
		CABundle:     os.Getenv("DUD_CA_BUNDLE"),
		ConnectTo:    os.Getenv("DUD_CONNECT_TO"),
		AgeBin:       envDefault("DUD_AGE_BIN", "age"),
		AgeKeygenBin: envDefault("DUD_AGE_KEYGEN_BIN", "age-keygen"),
		GitBin:       envDefault("DUD_GIT_BIN", "git"),
		QREncodeBin:  envDefault("DUD_QRENCODE_BIN", "qrencode"),
		Image:        envDefault("DUD_IMAGE", "ghcr.io/wojciechpolak/dud/dud-client:latest"),
	}
}

func envDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func needValue(args []string, name string) error {
	if len(args) < 2 {
		return fatalError("Missing value for " + name)
	}
	return nil
}

func (a *app) validateECHMode() error {
	switch a.cfg.ECHMode {
	case "hard", "off":
		return nil
	default:
		return fatalError("DUD_ECH_MODE must be either 'hard' or 'off'")
	}
}

func stdinIsTTY() bool {
	if os.Getenv("DUD_TEST_STDIN_TTY") == "1" {
		return true
	}
	return isTerminal(os.Stdin.Fd())
}

func (a *app) runCommand(name string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func (a *app) runAge(args ...string) error {
	stdin := a.in
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close()
		stdin = tty
	}
	return a.runCommand(a.cfg.AgeBin, args, stdin, a.out, a.errOut)
}

// Every temp file is registered so the signal handler can remove
// sensitive intermediates (plaintext, bundles) if the process is
// interrupted before its deferred cleanup runs.
var (
	tempFilesMu sync.Mutex
	tempFiles   = map[string]struct{}{}
)

func tempFile(pattern string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	tempFilesMu.Lock()
	tempFiles[name] = struct{}{}
	tempFilesMu.Unlock()
	return name, nil
}

func removeTempFile(path string) {
	tempFilesMu.Lock()
	delete(tempFiles, path)
	tempFilesMu.Unlock()
	os.Remove(path)
}

func removeAllTempFiles() {
	tempFilesMu.Lock()
	defer tempFilesMu.Unlock()
	for path := range tempFiles {
		os.Remove(path)
	}
	tempFiles = map[string]struct{}{}
}

func copyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func validateBundleListing(data []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		entry := scanner.Text()
		if entry == "" {
			continue
		}
		if strings.HasPrefix(entry, "/") {
			return fatalError("Bundle contains an absolute path: " + entry)
		}
		parts := strings.Split(entry, "/")
		for _, part := range parts {
			if part == ".." {
				return fatalError("Bundle contains an unsafe path: " + entry)
			}
		}
	}
	return scanner.Err()
}

func absPathIfRelative(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	wd, err := os.Getwd()
	if err != nil {
		return path
	}
	return filepath.Join(wd, path)
}
