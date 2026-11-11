// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package drop contains the input preparation and encryption steps shared by
// dead drop and optical transfers. It does not select or contact a transport.
package drop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type PayloadType uint8

const (
	PayloadMessage    PayloadType = 1
	PayloadStream     PayloadType = 2
	PayloadFile       PayloadType = 3
	PayloadCollection PayloadType = 4
)

type ArchiveFormat uint8

const (
	ArchiveNone ArchiveFormat = 0
	ArchiveTar  ArchiveFormat = 1
)

type InputOptions struct {
	Files   []string
	Message string
}

type InputEnvironment struct {
	Context       context.Context
	Stdin         io.Reader
	Stderr        io.Writer
	CommandOutput io.Writer
	StdinIsTTY    bool
	MaxBytes      int64
	// OmitMacMetadata suppresses automatic AppleDouble files from native tar.
	OmitMacMetadata bool
}

type PreparedInput struct {
	Path          string
	Type          PayloadType
	DisplayName   string
	ArchiveFormat ArchiveFormat
	Bundle        bool
}

// ErrInputLimit identifies a prepared input that exceeds its explicit byte limit.
var ErrInputLimit = errors.New("prepared input exceeds its byte limit")

func PrepareInput(target string, opts InputOptions, env InputEnvironment) (PreparedInput, error) {
	if len(opts.Files) == 0 {
		payloadType := PayloadStream
		displayName := "stdin.bin"
		if opts.Message != "" {
			if env.MaxBytes > 0 && int64(len(opts.Message)) > env.MaxBytes {
				return PreparedInput{}, ErrInputLimit
			}
			payloadType = PayloadMessage
			displayName = "message.txt"
			if err := os.WriteFile(target, []byte(opts.Message), 0o600); err != nil {
				return PreparedInput{}, err
			}
			return PreparedInput{Path: target, Type: payloadType, DisplayName: displayName}, nil
		}
		if env.StdinIsTTY {
			fmt.Fprintln(env.Stderr, "Enter plaintext, then press Ctrl-D when finished.")
		}
		if err := copyReaderLimit(target, env.Stdin, env.MaxBytes); err != nil {
			return PreparedInput{}, err
		}
		return PreparedInput{Path: target, Type: payloadType, DisplayName: displayName}, nil
	}

	bundle := false
	pathCount := 0
	for _, source := range opts.Files {
		if source == "" {
			continue
		}
		info, err := os.Stat(source)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return PreparedInput{}, fmt.Errorf("Path not found: %s", source)
			}
			return PreparedInput{}, err
		}
		if env.MaxBytes > 0 && !info.IsDir() && (!info.Mode().IsRegular() || info.Size() > env.MaxBytes) {
			return PreparedInput{}, ErrInputLimit
		}
		pathCount++
		if info.IsDir() || pathCount > 1 {
			bundle = true
		}
	}
	if bundle {
		if err := createBundleArchive(target, opts.Files, env); err != nil {
			return PreparedInput{}, err
		}
		return PreparedInput{
			Path:          target,
			Type:          PayloadCollection,
			DisplayName:   "dud-collection.tar",
			ArchiveFormat: ArchiveTar,
			Bundle:        true,
		}, nil
	}
	if err := copyFileLimit(target, opts.Files[0], env.MaxBytes); err != nil {
		return PreparedInput{}, err
	}
	return PreparedInput{
		Path:        target,
		Type:        PayloadFile,
		DisplayName: filepath.Base(opts.Files[0]),
	}, nil
}

func createBundleArchive(archivePath string, sources []string, env InputEnvironment) error {
	ctx := env.Context
	if ctx == nil {
		ctx = context.Background()
	}
	args := []string{"-cf", archivePath}
	seen := map[string]bool{}

	for _, source := range sources {
		if source == "" {
			continue
		}
		info, err := os.Lstat(source)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("Path not found: %s", source)
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Bundle sources cannot include symlinks: %s", source)
		}
		if err := filepath.WalkDir(source, func(_ string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("Bundle sources cannot include symlinks: %s", source)
			}
			return nil
		}); err != nil {
			return err
		}

		archiveName := filepath.Base(source)
		if archiveName == "" || archiveName == "." || archiveName == ".." {
			return fmt.Errorf("Bundle source has an invalid top-level name: %s", source)
		}
		if seen[archiveName] {
			return fmt.Errorf("Bundle sources must have unique top-level names: %s", archiveName)
		}
		seen[archiveName] = true
		// Source names must not select options, stdin, or BSD tar's @archive import.
		if strings.HasPrefix(archiveName, "-") || strings.HasPrefix(archiveName, "@") {
			archiveName = "./" + archiveName
		}
		args = append(args, "-C", filepath.Dir(source), archiveName)
	}

	if env.MaxBytes > 0 {
		args[1] = "-"
	}
	cmd := exec.CommandContext(ctx, "tar", args...)
	cmd.Stderr = env.Stderr
	if env.OmitMacMetadata {
		// Archive options from the environment cannot add metadata or transform
		// the selected source files during portable input preparation.
		cmd.Env = append(os.Environ(), "COPYFILE_DISABLE=1", "TAR_OPTIONS=", "TAR_READER_OPTIONS=", "TAR_WRITER_OPTIONS=")
	}
	if env.MaxBytes > 0 {
		output, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer func() { _ = output.Close() }()
		bounded := &boundedInputWriter{writer: output, remaining: env.MaxBytes}
		cmd.Stdout = bounded
		err = cmd.Run()
		if bounded.exceeded {
			return ErrInputLimit
		}
		return err
	}
	cmd.Stdout = env.CommandOutput
	return cmd.Run()
}

func copyFileLimit(target, source string, limit int64) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	return copyReaderLimit(target, input, limit)
}

func copyReaderLimit(target string, input io.Reader, limit int64) error {
	output, err := os.Create(target)
	if err != nil {
		return err
	}
	var writer io.Writer = output
	if limit > 0 {
		writer = &boundedInputWriter{writer: output, remaining: limit}
	}
	_, copyErr := io.Copy(writer, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// boundedInputWriter stops staging before an input can consume unbounded disk.
type boundedInputWriter struct {
	writer    io.Writer
	remaining int64
	exceeded  bool
}

func (w *boundedInputWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		w.exceeded = true
		return 0, ErrInputLimit
	}
	n, err := w.writer.Write(data)
	w.remaining -= int64(n)
	return n, err
}
