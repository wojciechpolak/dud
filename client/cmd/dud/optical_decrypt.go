// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
)

func opticalDecryptFlagPresent(args []string, name string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == name {
			return true
		}
		switch args[i] {
		case "--file", "--id", "--out", "--out-dir", "--identity", "-i", "--url", "--doh-url":
			i++
		}
	}
	return false
}

func validateOpticalDecryptOptions(opts downloadOptions) error {
	if opts.explicitFlags["--id"] || opts.explicitFlags["--url"] || opts.explicitFlags["--doh-url"] {
		return opticalFailure("usage", "Optical decrypt rejects explicit network options")
	}
	if opts.file == "" {
		return opticalFailure("usage", "Optical decrypt requires one local --file")
	}
	targets := 0
	for _, selected := range []bool{opts.out != "", opts.outputStdout, opts.extract} {
		if selected {
			targets++
		}
	}
	if targets != 1 || (opts.outDir != "" && !opts.extract) || (opts.outputJSON && opts.outputStdout) ||
		(opts.explicitFlags["--out"] && opts.out == "") || (opts.explicitFlags["--out-dir"] && opts.outDir == "") ||
		((opts.explicitFlags["--identity"] || opts.explicitFlags["-i"]) && opts.identity == "") {
		return opticalFailure("usage", "Optical decrypt requires one output: --out, --stdout, or --extract with optional --out-dir; JSON cannot accompany stdout")
	}
	return nil
}

func opticalDecryptReport() map[string]any {
	report := opticalReport()
	report["operation"] = "decrypt"
	return report
}

func (a *app) reportOpticalDecryptFailure(jsonOutput bool, err error) error {
	var failure *opticalCommandError
	if !errors.As(err, &failure) {
		failure = &opticalCommandError{"capsule", "Optical capsule validation failed"}
	}
	if jsonOutput {
		report := opticalDecryptReport()
		report["status"] = "failed"
		report["error"] = failure
		if err := writeJSON(a.out, report); err != nil {
			return opticalFailure("output", "Optical report could not be written")
		}
	}
	return failure
}

func (a *app) cmdOpticalDecrypt(opts downloadOptions) error {
	ctx, cancel := context.WithCancel(a.commandContext())
	defer cancel()
	unregister := registerOpticalOperation(cancel)
	defer unregister()
	output, err := a.decryptOpticalCapsule(ctx, opts)
	if err != nil {
		return a.reportOpticalDecryptFailure(opts.outputJSON, err)
	}
	if opts.outputStdout {
		return nil
	}
	if opts.outputJSON {
		report := opticalDecryptReport()
		report["status"] = "recovered"
		report["output"] = output
		err = writeJSON(a.out, report)
	} else {
		_, err = fmt.Fprintf(a.out, "Optical transfer validated and recovered to %s\n", output)
	}
	if err != nil {
		return opticalFailure("output", "Optical report could not be written")
	}
	return nil
}

func readOpticalFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, opticalFailure("input", "Optical input must be a readable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, opticalFailure("input", "Optical local file is unavailable")
	}
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, opticalFailure("input", "Optical input must be a readable regular file")
	}
	if info.Size() < 1 || info.Size() > maximum {
		return nil, opticalFailure("ciphertext-limit", "Optical local file exceeds its size bounds")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, opticalFailure("input", "Optical local file could not be read")
	}
	if len(body) < 1 || int64(len(body)) > maximum {
		return nil, opticalFailure("ciphertext-limit", "Optical local file exceeds its size bounds")
	}
	return body, nil
}

// Native identity snapshots prevent age plugins from running during local recovery.
func snapshotOpticalIdentity(path, snapshot string) error {
	body, err := readOpticalFile(path, optical.MaxCapsuleSize)
	if err != nil {
		return opticalFailure("input", "Optical identity file is unavailable or exceeds its size bound")
	}
	identities, err := age.ParseIdentities(bytes.NewReader(body))
	if err != nil || len(identities) == 0 {
		return opticalFailure("decryption", "Optical recovery requires native X25519 or hybrid identities")
	}
	for _, identity := range identities {
		switch identity.(type) {
		case *age.X25519Identity, *age.HybridIdentity:
		default:
			return opticalFailure("decryption", "Optical recovery requires native X25519 or hybrid identities")
		}
	}
	if err := os.WriteFile(snapshot, body, 0o600); err != nil {
		return opticalFailure("input", "Optical identity snapshot could not be written")
	}
	return nil
}

func (a *app) decryptOpticalCapsule(ctx context.Context, opts downloadOptions) (string, error) {
	body, err := readOpticalFile(opts.file, optical.MaxCapsuleSize)
	if err != nil {
		return "", err
	}
	paths := make([]string, 0, 3)
	defer func() {
		for _, path := range paths {
			removeTempFile(path)
		}
	}()
	for _, prefix := range []string{"dud-optical-recover-age-", "dud-optical-recover-plain-", "dud-optical-recover-identity-"} {
		path, err := tempFile(prefix)
		if err != nil {
			return "", opticalFailure("input", "Optical staging file could not be created")
		}
		paths = append(paths, path)
	}
	if err := os.WriteFile(paths[0], body, 0o600); err != nil {
		return "", opticalFailure("input", "Optical ciphertext snapshot could not be written")
	}
	args := []string{"--decrypt"}
	if opts.identity != "" {
		if err := snapshotOpticalIdentity(opts.identity, paths[2]); err != nil {
			return "", err
		}
		args = append(args, "-i", paths[2])
	}
	args = append(args, paths[0])
	file, err := os.OpenFile(paths[1], os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", opticalFailure("input", "Optical plaintext staging file is unavailable")
	}
	bounded := &opticalPlaintextWriter{writer: file, remaining: capsule.MaxPayloadSize + capsule.HeaderSize + capsule.MaxDisplayNameBytes}
	decryptErr := a.runOpticalAgeOutput(ctx, bounded, args...)
	closeErr := file.Close()
	if decryptErr != nil {
		return "", opticalFailure("decryption", "Optical capsule decryption failed")
	}
	if closeErr != nil {
		return "", opticalFailure("input", "Optical plaintext staging failed")
	}
	encoded, err := readOpticalFile(paths[1], capsule.MaxPayloadSize+capsule.HeaderSize+capsule.MaxDisplayNameBytes)
	if err != nil {
		return "", opticalFailure("capsule", "Optical private container is invalid")
	}
	metadata, payload, err := capsule.Decode(encoded)
	if err != nil {
		return "", opticalCapsuleFailure(err)
	}
	return a.writeOpticalPayload(opts, metadata, payload)
}

func opticalCapsuleFailure(err error) error {
	if errors.Is(err, capsule.ErrUnsupportedFormat) {
		return opticalFailure("unsupported-format", "Unsupported optical capsule; expected dud/optical/1")
	}
	if errors.Is(err, capsule.ErrArchive) {
		return opticalFailure("archive", "Optical collection validation failed")
	}
	return opticalFailure("capsule", "Optical private container validation failed")
}

type opticalPlaintextWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *opticalPlaintextWriter) Write(body []byte) (int, error) {
	if int64(len(body)) > w.remaining {
		return 0, errors.New("optical plaintext exceeds its container bound")
	}
	n, err := w.writer.Write(body)
	w.remaining -= int64(n)
	return n, err
}

func (a *app) writeOpticalPayload(opts downloadOptions, metadata capsule.Metadata, payload []byte) (string, error) {
	if opts.extract {
		if metadata.Type != drop.PayloadCollection {
			return "", opticalFailure("archive", "Optical extraction requires a collection")
		}
		destination := opts.outDir
		if destination == "" {
			destination = "."
		}
		output, err := filepath.Abs(destination)
		if err == nil {
			err = extractOpticalCollection(payload, output)
		}
		if err != nil {
			return "", opticalFailure("output", "Optical collection output failed or collides with an existing path")
		}
		return output, nil
	}
	if opts.outputStdout {
		if _, err := io.Copy(a.out, bytes.NewReader(payload)); err != nil {
			return "", opticalFailure("output", "Optical stdout output failed")
		}
		return "", nil
	}
	output, err := filepath.Abs(opts.out)
	if err == nil {
		err = writeOpticalFile(output, payload)
	}
	if err != nil {
		return "", opticalFailure("output", "Optical output failed or destination already exists")
	}
	return output, nil
}

func writeOpticalFile(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := setPrivatePathPermissions(path, false); err != nil {
		return errors.Join(err, file.Close())
	}
	_, writeErr := io.Copy(file, bytes.NewReader(payload))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}
