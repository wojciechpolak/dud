// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

type opticalCommandError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *opticalCommandError) Error() string    { return e.Message }
func opticalFailure(code, message string) error { return &opticalCommandError{code, message} }
func hasOpticalUploadFlag(args []string) bool   { return uploadFlagPresent(args, "--optical") }
func hasJSONFlag(args []string) bool            { return uploadFlagPresent(args, "--json") }
func uploadFlagPresent(args []string, name string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == name {
			return true
		}
		switch args[i] {
		case "--file", "-m", "--ttl", "--recipient", "-r", "--recipient-file", "-R", "--url", "--doh-url", "--optical-profile", "--optical-renderer", "--optical-scale", "--optical-quiet-zone":
			i++
		}
	}
	return false
}

func validateOpticalUploadOptions(opts uploadOptions) error {
	for _, flag := range []string{"--ttl", "--delete-after-read", "--url", "--doh-url", "--no-qr", "--id"} {
		if opts.explicitFlags[flag] {
			return opticalFailure("usage", "Optical upload rejects explicit network options")
		}
	}
	if opts.sourceCount() > 1 || (opts.explicitFlags["-m"] && opts.message == "") {
		return opticalFailure("usage", "Optical upload accepts one source: files, a nonempty message, or stdin")
	}
	if opts.passphraseRequested && opts.recipientMode() {
		return opticalFailure("usage", "Optical upload accepts either passphrase or recipients")
	}
	if opts.recipientsFile != "" {
		info, err := os.Stat(opts.recipientsFile)
		if err != nil || !info.Mode().IsRegular() {
			return opticalFailure("input", "Optical recipient file is unavailable")
		}
	}
	if opts.opticalProfile != "high-rate" && opts.opticalProfile != "balanced" {
		return opticalFailure("usage", "Optical profile must be high-rate or balanced")
	}
	if opts.opticalRenderer != "window" && opts.opticalRenderer != "terminal" && opts.opticalRenderer != "kitty" {
		return opticalFailure("usage", "Optical renderer must be window, terminal or kitty")
	}
	if opts.opticalQuietZone < 4 || opts.opticalQuietZone > 16 || opts.opticalScale < 1 || opts.opticalScale > 16 {
		return opticalFailure("usage", "Optical quiet zone must be 4..16 and scale must be 1..16")
	}
	for _, file := range opts.files {
		if file == "" {
			return opticalFailure("input", "Optical input path is empty")
		}
	}
	return nil
}
func opticalDisplayOptions(opts uploadOptions) display.Options {
	result := display.Options{Settings: display.QRSettings{Version: 40, ErrorCorrection: display.QRLow, QuietZone: opts.opticalQuietZone, Scale: opts.opticalScale}, BlockSize: optical.HighDensityBlockSize, FPS: 60}
	if opts.opticalProfile == "balanced" {
		result.Settings.Version = 30
		result.BlockSize = optical.BlockSize
		result.FPS = 30
	}
	return result
}
func opticalReport() map[string]any {
	return map[string]any{"mode": "optical", "format": "dud/optical/1", "operation": "upload"}
}
func (a *app) reportOpticalFailure(jsonOutput bool, err error) error {
	var failure *opticalCommandError
	if !errors.As(err, &failure) {
		failure = &opticalCommandError{"renderer", "Optical display failed"}
	}
	if jsonOutput {
		report := opticalReport()
		report["status"] = "failed"
		report["error"] = failure
		if outputErr := writeJSON(a.out, report); outputErr != nil {
			return opticalFailure("output", "Optical report could not be written")
		}
	}
	return failure
}

var opticalOperations = struct {
	sync.Mutex
	next    uint64
	cleanup map[uint64]func()
}{cleanup: make(map[uint64]func())}

func registerOpticalOperation(cleanup func()) func() {
	opticalOperations.Lock()
	id := opticalOperations.next
	opticalOperations.next++
	opticalOperations.cleanup[id] = cleanup
	opticalOperations.Unlock()
	return func() { opticalOperations.Lock(); delete(opticalOperations.cleanup, id); opticalOperations.Unlock() }
}
func closeOpticalOperations() {
	opticalOperations.Lock()
	callbacks := make([]func(), 0, len(opticalOperations.cleanup))
	for _, callback := range opticalOperations.cleanup {
		callbacks = append(callbacks, callback)
	}
	opticalOperations.Unlock()
	for _, callback := range callbacks {
		callback()
	}
}

func (a *app) cmdOpticalUpload(opts uploadOptions) error {
	ctx, cancel := context.WithCancel(a.commandContext())
	defer cancel()
	unregister := registerOpticalOperation(cancel)
	defer unregister()
	settings := opticalDisplayOptions(opts)
	factory := a.newOpticalRenderer
	if factory == nil {
		factory = func(ctx context.Context, options display.Options) (display.Renderer, error) {
			return a.openOpticalRenderer(ctx, opts.opticalRenderer, options)
		}
	}
	renderer, err := factory(ctx, settings)
	if err != nil {
		var failure *opticalCommandError
		if errors.As(err, &failure) {
			return a.reportOpticalFailure(opts.outputJSON, failure)
		}
		return a.reportOpticalFailure(opts.outputJSON, opticalFailure("renderer-unavailable", fmt.Sprintf("Optical %s renderer unavailable; use a capable display and binary or select terminal explicitly", opts.opticalRenderer)))
	}
	defer func() { _ = renderer.Close() }()
	unregisterRenderer := registerOpticalOperation(func() { _ = renderer.Close() })
	defer unregisterRenderer()
	size, err := a.prepareOpticalUpload(ctx, opts, renderer)
	if err != nil {
		return a.reportOpticalFailure(opts.outputJSON, err)
	}
	if err := renderer.Close(); err != nil {
		return a.reportOpticalFailure(opts.outputJSON, opticalFailure("renderer", "Optical display cleanup failed"))
	}
	report := opticalReport()
	report["status"] = "display-ended"
	report["profile"] = opts.opticalProfile
	report["renderer"] = opts.opticalRenderer
	report["ciphertextBytes"] = size
	if opts.outputJSON {
		if err := writeJSON(a.out, report); err != nil {
			return opticalFailure("output", "Optical report could not be written")
		}
		return nil
	}
	if _, err := fmt.Fprintln(a.out, "Optical transfer display ended. Remote receipt is unconfirmed."); err != nil {
		return opticalFailure("output", "Optical report could not be written")
	}
	return nil
}

func (a *app) openOpticalRenderer(ctx context.Context, renderer string, options display.Options) (display.Renderer, error) {
	var terminal display.Renderer
	var err error
	switch renderer {
	case "window":
		return display.OpenWindow(ctx, filepath.Dir(a.exe), options)
	case "kitty":
		terminal, err = a.openOpticalKitty(ctx, options)
	default:
		terminal, err = a.openOpticalTerminal(options)
	}
	if err != nil {
		return nil, err
	}
	return &opticalTerminalRenderer{Renderer: terminal}, nil
}
func (a *app) prepareOpticalUpload(ctx context.Context, opts uploadOptions, renderer display.Renderer) (int64, error) {
	paths := make([]string, 0, 3)
	defer func() {
		for _, path := range paths {
			removeTempFile(path)
		}
	}()
	for _, prefix := range []string{"dud-optical-input-", "dud-optical-container-", "dud-optical-age-"} {
		path, err := tempFile(prefix)
		if err != nil {
			return 0, opticalFailure("input", "Optical staging file could not be created")
		}
		paths = append(paths, path)
	}
	if len(opts.files) == 0 && opts.message == "" && stdinIsTTY() {
		if _, err := fmt.Fprintln(a.errOut, "Enter plaintext, then press Ctrl-D when finished."); err != nil {
			return 0, opticalFailure("output", "Optical input prompt could not be written")
		}
	}
	input, err := drop.PrepareInput(paths[0], drop.InputOptions{Files: opts.files, Message: opts.message}, drop.InputEnvironment{Context: ctx, Stdin: a.in, Stderr: io.Discard, CommandOutput: io.Discard, StdinIsTTY: stdinIsTTY(), MaxBytes: capsule.MaxPayloadSize, OmitMacMetadata: true})
	if errors.Is(err, drop.ErrInputLimit) {
		return 0, opticalFailure("ciphertext-limit", "Optical source exceeds the ciphertext budget")
	}
	if err != nil {
		return 0, opticalFailure("input", "Optical source preparation failed")
	}
	if info, err := os.Stat(input.Path); err != nil {
		return 0, opticalFailure("input", "Optical source could not be read")
	} else if info.Size() > capsule.MaxPayloadSize {
		return 0, opticalFailure("ciphertext-limit", "Optical plaintext exceeds the ciphertext budget")
	}
	if err := capsule.WriteFile(paths[1], input); err != nil {
		if errors.Is(err, drop.ErrInputLimit) {
			return 0, opticalFailure("ciphertext-limit", "Optical collection exceeds the ciphertext budget")
		}
		if input.Type == drop.PayloadCollection {
			return 0, opticalFailure("archive", "Optical collection validation failed")
		}
		return 0, opticalFailure("input", "Optical private container validation failed")
	}
	// Encryption consumes only the validated private container. Its stderr and
	// stdout cannot become report fields or reveal input metadata.
	run := func(args ...string) error { return a.runOpticalAge(ctx, args...) }
	encryptionOptions, err := opticalRecipients(opts)
	if err != nil {
		return 0, err
	}
	if err := drop.EncryptFile(paths[1], paths[2], encryptionOptions, run, tempFile, removeTempFile); err != nil {
		return 0, opticalFailure("encryption", "Optical capsule encryption failed")
	}
	info, err := os.Stat(paths[2])
	if err != nil || !info.Mode().IsRegular() {
		return 0, opticalFailure("encryption", "Optical encryption produced no readable ciphertext")
	}
	if info.Size() < 1 || info.Size() > optical.MaxCapsuleSize {
		return 0, opticalFailure("ciphertext-limit", "Optical ciphertext must contain 1..64 MiB including encryption overhead")
	}
	if err := renderer.Display(ctx, paths[2]); err != nil {
		return 0, opticalFailure("renderer", "Optical display failed")
	}
	return info.Size(), nil
}
func (a *app) runOpticalAge(ctx context.Context, args ...string) error {
	return a.runOpticalAgeOutput(ctx, io.Discard, args...)
}

func (a *app) runOpticalAgeOutput(ctx context.Context, output io.Writer, args ...string) error {
	stdin := a.in
	if tty, err := openInteractiveInput(); err == nil {
		defer func() { _ = tty.Close() }()
		stdin = tty
	}
	ageContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(ageContext, a.cfg.AgeBin, args...)
	command.WaitDelay = 2 * time.Second
	done := make(chan struct{})
	unregister := registerOpticalOperation(func() {
		cancel()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
		}
	})
	defer unregister()
	defer close(done)
	command.Stdin = stdin
	command.Stdout = output
	command.Stderr = io.Discard
	return command.Run()
}
