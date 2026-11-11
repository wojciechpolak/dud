// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

func extractOpticalCollection(body []byte, destination string) error {
	entries, err := capsule.InspectCollection(body)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("extraction root is not a directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := preflightOpticalCollection(root, entries); err != nil {
		return err
	}
	reader := tar.NewReader(bytes.NewReader(body))
	createdDirs := map[string]bool{}
	for _, entry := range entries {
		header, err := reader.Next()
		if err != nil {
			return err
		}
		if header.Name != entry.Name {
			return errors.New("collection changed during extraction")
		}
		if err := extractOpticalEntry(root, reader, entry, createdDirs); err != nil {
			return err
		}
	}
	return nil
}

// Every top-level archive path must be unused, including implicit parents.
// Preflight checks all collisions before any archive entry is created.
func preflightOpticalCollection(root *os.Root, entries []drop.CollectionEntry) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	existing, readErr := directory.ReadDir(drop.MaximumCollectionEntries + 1)
	closeErr := directory.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if len(existing) > drop.MaximumCollectionEntries {
		return errors.New("extraction root exceeds its entry bound")
	}
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	occupied := map[string]bool{}
	for _, entry := range existing {
		occupied[cases.Fold().String(norm.NFC.String(entry.Name()))] = true
	}
	for _, entry := range entries {
		top, _, _ := strings.Cut(entry.Name, "/")
		if occupied[cases.Fold().String(norm.NFC.String(top))] {
			return errors.New("collection collides with an existing path")
		}
	}
	return nil
}

func extractOpticalEntry(root *os.Root, reader *tar.Reader, entry drop.CollectionEntry, createdDirs map[string]bool) error {
	components := strings.Split(entry.Name, "/")
	count := len(components) - 1
	if entry.Directory {
		count++
	}
	for index := 1; index <= count; index++ {
		directory := strings.Join(components[:index], "/")
		if createdDirs[directory] {
			continue
		}
		if err := root.Mkdir(directory, 0o755); err != nil {
			return err
		}
		if err := root.Chmod(directory, 0o755); err != nil {
			return err
		}
		createdDirs[directory] = true
	}
	if entry.Directory {
		return nil
	}
	file, err := root.OpenFile(entry.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(entry.Mode))
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(file, reader, entry.Size)
	if copyErr == nil {
		copyErr = file.Chmod(os.FileMode(entry.Mode))
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	return errors.Join(copyErr, file.Close())
}
