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

const (
	dudBaseURLEnvironment     = "DUD_BASE_URL"
	dudDropBaseURLEnvironment = "DUD_DROP_BASE_URL"
	dudPeerBaseURLEnvironment = "DUD_PEER_BASE_URL"
)

func loadConfig() config {
	return config{
		DropBaseURL:  envDefaultChain(v2DefaultBaseURL, dudDropBaseURLEnvironment, dudBaseURLEnvironment),
		PeerBaseURL:  envDefaultChain(v2DefaultBaseURL, dudPeerBaseURLEnvironment, dudBaseURLEnvironment),
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

		GitTrustedDir: absolutePathEnvironment("DUD_GIT_TRUSTED_DIR"),
	}
}

// absolutePathEnvironment reads a variable that names one directory. Git reads
// the value as a path to compare against, so a relative path names nothing it
// can match and the wildcard "*" would trust every repository the caller ever
// runs dud in. Rejecting both leaves the caller with Git's own ownership error,
// which names the directory and the setting that would accept it.
func absolutePathEnvironment(name string) string {
	value := os.Getenv(name)
	if !filepath.IsAbs(value) {
		return ""
	}
	return filepath.Clean(value)
}

func envDefaultChain(fallback string, names ...string) string {
	if value, _ := firstEnvironment(names...); value != "" {
		return value
	}
	return fallback
}

func firstEnvironment(names ...string) (string, string) {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value, name
		}
	}
	return "", ""
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
	if tty, err := openInteractiveInput(); err == nil {
		defer func() { _ = tty.Close() }()
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
	if err := setPrivatePathPermissions(name, false); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
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
	_ = os.Remove(path)
}

func removeAllTempFiles() {
	tempFilesMu.Lock()
	defer tempFilesMu.Unlock()
	for path := range tempFiles {
		_ = os.Remove(path)
	}
	tempFiles = map[string]struct{}{}
}

func copyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
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
