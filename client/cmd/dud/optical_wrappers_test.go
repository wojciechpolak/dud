// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func wrapperTestApp(in *os.File, out, stderr *bytes.Buffer) *app {
	a := newApp(in, out, stderr)
	a.newOpticalRenderer = func(context.Context, display.Options) (display.Renderer, error) {
		return nil, errors.New("headless container")
	}
	return a
}

func TestOpticalWrapperDockerProcess(t *testing.T) {
	if os.Getenv("DUD_TEST_WRAPPER_CHILD") != "1" {
		return
	}
	index := slices.Index(os.Args, "dud-wrapper-regression")
	if index < 0 {
		t.Fatal("missing Docker image")
	}
	encoded, err := json.Marshal(os.Args[1:index])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("DUD_TEST_WRAPPER_ARGS"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := wrapperTestApp(os.Stdin, &out, &stderr).main(os.Args[index+1:])
	_, _ = os.Stdout.Write(out.Bytes())
	_, _ = os.Stderr.Write(stderr.Bytes())
	os.Exit(code)
}

func TestOpticalWrappersPreserveHelpAndFailureReportsWithoutReadingStdin(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DUD_HOME", filepath.Join(root, "home"))
	t.Setenv("DUD_PROFILE", "")
	t.Setenv("DUD_IMAGE", "dud-wrapper-regression")
	t.Setenv("DUD_TEST_WRAPPER_CHILD", "1")
	t.Setenv("DUD_TEST_WRAPPER_ARGS", filepath.Join(root, "args.json"))
	t.Setenv("DUD_TEST_HOST_TTY", "1")
	t.Setenv("DUD_TEST_STDOUT_TTY", "1")
	t.Setenv("DUD_TEST_TTY_INPUT_PATH", "/dev/null")
	if err := os.WriteFile(filepath.Join(root, "docker"), []byte("#!/bin/sh\nexec "+cliShellArg(executable)+" -test.run=^TestOpticalWrapperDockerProcess$ -- \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	cases := [][]string{
		{"upload", "--optical", "--help"},
		{"send", "--optical", "-h"},
		{"optical", "send", "--help"},
		{"optical", "send", "--json", "-m", "private message"},
		{"optical", "send", "--optical-renderer", "kitty", "--json", "-m", "private message"},
		{"optical", "decrypt", "--help"},
		{"optical", "decrypt", "-h"},
		{"send", "peer", "--optical", "--help"},
		{"upload", "--optical", "--optical-renderer", "terminal", "--help"},
		{"upload", "--optical", "--optical-renderer", "kitty", "--help"},
		{"upload", "--optical", "--optical-renderer", "kitty", "--json", "-m", "message"},
		{"send", "--optical", "--json"},
		{"upload", "--optical", "--json", "--ttl", "1h"},
		{"upload", "--optical", "-m", "--help", "--json"},
		{"send", "--optical", "--file", "--help", "--json"},
		{"upload", "--optical", "--recipient", "--help", "--json"},
		{"upload", "--optical", "-m", "--json"},
		{"upload", "--optical", "--optical-profile", "--help", "--json"},
		{"upload", "--optical", "--optical-renderer", "--help", "--json"},
		{"upload", "--optical", "--optical-scale", "--help", "--json"},
		{"upload", "--optical", "--optical-quiet-zone", "--help", "--json"},
		{"upload", "--optical", "--optical-renderer", "terminal", "-m", "--help", "--json"},
	}
	for _, shell := range []string{"sh", "bash", "zsh"} {
		binary, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		for name, source := range map[string]string{
			"install":    installScript("dud-wrapper-regression"),
			"shell-init": shellInitScript("dud-wrapper-regression") + "\ndud \"$@\"\n",
		} {
			wrapper := filepath.Join(root, name+".sh")
			if err := os.WriteFile(wrapper, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, args := range cases {
				t.Run(shell+"/"+name+"/"+strings.Join(args, " "), func(t *testing.T) {
					var expected, expectedError bytes.Buffer
					wantCode := wrapperTestApp(os.Stdin, &expected, &expectedError).main(args)
					input, writer, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						_ = input.Close()
						_ = writer.Close()
					}()
					// An open, empty pipe never supplies EOF to accidental stdin staging.
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, binary, append([]string{wrapper}, args...)...)
					command.WaitDelay = 500 * time.Millisecond
					command.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0")
					command.Dir = root
					command.Stdin = input
					var output, stderr bytes.Buffer
					command.Stdout, command.Stderr = &output, &stderr
					err = command.Run()
					if command.ProcessState == nil {
						t.Fatalf("wrapper did not start: %v", err)
					}
					code := command.ProcessState.ExitCode()
					if ctx.Err() != nil || code != wantCode || output.String() != expected.String() || stderr.String() != expectedError.String() {
						t.Fatalf("wrapper changed CLI result: code=%d want=%d err=%v\nstdout: %s\nstderr: %s", code, wantCode, err, output.String(), stderr.String())
					}
					if hasJSONFlag(args[1:]) && !strings.Contains(output.String(), "Usage") {
						opticalJSON(t, &output)
					}
					encoded, err := os.ReadFile(os.Getenv("DUD_TEST_WRAPPER_ARGS"))
					if err != nil {
						t.Fatal(err)
					}
					var dockerArgs []string
					if err := json.Unmarshal(encoded, &dockerArgs); err != nil {
						t.Fatal(err)
					}
					preflight := (args[0] == "upload" || args[0] == "send" || args[0] == "optical" && args[1] == "send") &&
						(strings.Contains(expected.String(), "Usage") || !slices.Contains(args, "terminal") && !slices.Contains(args, "kitty"))
					if preflight && (slices.Contains(dockerArgs, "-i") || slices.Contains(dockerArgs, "-it")) {
						t.Fatalf("preflight connected interactive stdin: %v", dockerArgs)
					}
				})
			}
		}
	}
}
