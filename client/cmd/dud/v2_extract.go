// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wojciechpolak/dud/client/drop"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	v2MaximumCollectionEntries = drop.MaximumCollectionEntries
	v2MaximumCollectionDepth   = drop.MaximumCollectionDepth
	v2MaximumExtractedBytes    = drop.MaximumExtractedBytes
)

type v2CollectionEntry struct {
	name  string
	mode  int64
	size  int64
	mtime time.Time
	dir   bool
}

func createV2CollectionArchive(paths []string) ([]byte, []string, error) {
	if len(paths) == 0 {
		return nil, nil, errors.New("collection requires at least one path")
	}
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	topNames := make([]string, 0, len(paths))
	seenTop := map[string]bool{}
	entryCount := 0
	for _, raw := range paths {
		source := absPathIfRelative(raw)
		info, err := os.Lstat(source)
		if err != nil {
			return nil, nil, err
		}
		name := filepath.Base(filepath.Clean(source))
		if name == "." || name == string(filepath.Separator) {
			return nil, nil, fmt.Errorf("cannot archive collection root %s", source)
		}
		collision := cases.Fold().String(norm.NFC.String(name))
		if seenTop[collision] {
			return nil, nil, fmt.Errorf("collection top-level name %q collides after normalization", name)
		}
		seenTop[collision] = true
		topNames = append(topNames, name)
		err = filepath.Walk(source, func(path string, current os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if current.Mode()&os.ModeSymlink != 0 || (!current.Mode().IsRegular() && !current.IsDir()) {
				return fmt.Errorf("collection entry %s is not a regular file or directory", path)
			}
			relative, err := filepath.Rel(filepath.Dir(source), path)
			if err != nil {
				return err
			}
			archiveName := filepath.ToSlash(relative)
			if err := validateV2ArchivePath(archiveName); err != nil {
				return err
			}
			entryCount++
			if entryCount > v2MaximumCollectionEntries {
				return errors.New("collection exceeds 100000 entries")
			}
			header, err := tar.FileInfoHeader(current, "")
			if err != nil {
				return err
			}
			header.Name = archiveName
			// USTAR cannot encode a non-ASCII name, so those entries need PAX
			// with a single `path` record. Everything else is normalized away
			// first, which keeps the emitted record set to exactly that one.
			header.Format = tar.FormatUSTAR
			if !isASCIIV2ArchiveName(archiveName) {
				header.Format = tar.FormatPAX
			}
			header.Uid = 0
			header.Gid = 0
			header.Uname = ""
			header.Gname = ""
			header.AccessTime = time.Time{}
			header.ChangeTime = time.Time{}
			// Sub-second precision would add an `mtime` PAX record the receiver
			// does not accept.
			header.ModTime = header.ModTime.Truncate(time.Second)
			header.PAXRecords = nil
			if current.IsDir() {
				header.Mode = 0o755
			} else if current.Mode().Perm()&0o100 != 0 {
				header.Mode = 0o755
			} else {
				header.Mode = 0o644
			}
			if err := writer.WriteHeader(header); err != nil {
				return err
			}
			if current.Mode().IsRegular() {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				_, copyErr := io.Copy(writer, io.LimitReader(file, current.Size()+1))
				closeErr := file.Close()
				if copyErr != nil {
					return copyErr
				}
				if closeErr != nil {
					return closeErr
				}
			}
			if output.Len() > v2MaximumObjectBytes {
				return errors.New("collection archive exceeds the 100 MiB object limit")
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		_ = info
	}
	if err := writer.Close(); err != nil {
		return nil, nil, err
	}
	if output.Len() > v2MaximumObjectBytes {
		return nil, nil, errors.New("collection archive exceeds the 100 MiB object limit")
	}
	return output.Bytes(), topNames, nil
}

// isASCIIV2ArchiveName reports whether USTAR can carry this name verbatim.
func isASCIIV2ArchiveName(name string) bool {
	for index := 0; index < len(name); index++ {
		if name[index] >= 0x80 {
			return false
		}
	}
	return true
}

func validateV2ArchivePath(name string) error {
	return drop.ValidateArchivePath(name)
}

func validPortableV2ArchiveComponent(component string) bool {
	return drop.ValidPortableArchiveComponent(component)
}

func inspectV2CollectionArchive(body []byte, signedPlaintextSize uint64) ([]v2CollectionEntry, error) {
	validated, err := drop.InspectCollectionArchive(body, signedPlaintextSize, drop.CollectionArchivePolicy{})
	if err != nil {
		return nil, err
	}
	entries := make([]v2CollectionEntry, len(validated))
	for index, entry := range validated {
		entries[index] = v2CollectionEntry{
			name:  entry.Name,
			mode:  entry.Mode,
			size:  entry.Size,
			mtime: entry.ModTime,
			dir:   entry.Directory,
		}
	}
	return entries, nil
}

func validateV2CollectionNames(entries []v2CollectionEntry, rawNames []any) error {
	expected := map[string]bool{}
	for _, raw := range rawNames {
		name, ok := raw.(string)
		if !ok || validateV2ArchivePath(name) != nil || strings.Contains(name, "/") {
			return errors.New("collection top-level name metadata is invalid")
		}
		key := cases.Fold().String(norm.NFC.String(name))
		if expected[key] {
			return errors.New("collection top-level names collide")
		}
		expected[key] = true
	}
	actual := map[string]bool{}
	for _, entry := range entries {
		top := strings.Split(entry.name, "/")[0]
		actual[cases.Fold().String(norm.NFC.String(top))] = true
	}
	if len(actual) != len(expected) {
		return errors.New("collection top-level names do not match signed metadata")
	}
	for key := range actual {
		if !expected[key] {
			return errors.New("collection top-level names do not match signed metadata")
		}
	}
	return nil
}

func extractV2ArchiveEntry(root *os.Root, reader *tar.Reader, entry v2CollectionEntry) error {
	components := strings.Split(entry.name, "/")
	parent := strings.Join(components[:len(components)-1], "/")
	if parent != "" {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("securely create collection directory %q: %w", parent, err)
		}
	}
	if entry.dir {
		if err := root.MkdirAll(entry.name, 0o755); err != nil {
			return err
		}
		return nil
	}
	file, err := root.OpenFile(entry.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(entry.mode))
	if err != nil {
		return fmt.Errorf("securely create collection file %q: %w", entry.name, err)
	}
	written, copyErr := io.CopyN(file, reader, entry.size)
	if copyErr == nil && written != entry.size {
		copyErr = io.ErrUnexpectedEOF
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func extractV2CollectionArchive(body []byte, destination string, signedPlaintextSize uint64) ([]string, error) {
	entries, err := inspectV2CollectionArchive(body, signedPlaintextSize)
	if err != nil {
		return nil, err
	}
	destination = filepath.Clean(destination)
	if _, err := os.Lstat(destination); err == nil {
		return nil, fmt.Errorf("refusing to overwrite existing collection destination %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	stage, err := os.MkdirTemp(parent, ".dud-collection-")
	if err != nil {
		return nil, err
	}
	if err := setPrivatePathPermissions(stage, true); err != nil {
		_ = os.RemoveAll(stage)
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()
	root, err := os.OpenRoot(stage)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	reader := tar.NewReader(bytes.NewReader(body))
	for _, entry := range entries {
		header, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if header.Name != entry.name {
			return nil, errors.New("collection changed between validation and extraction")
		}
		if err := extractV2ArchiveEntry(root, reader, entry); err != nil {
			return nil, err
		}
	}
	if err := syncDirectory(stage); err != nil {
		return nil, err
	}
	if err := root.Close(); err != nil {
		return nil, err
	}
	for _, entry := range entries {
		path := filepath.Join(stage, filepath.FromSlash(entry.name))
		_ = os.Chtimes(path, entry.mtime, entry.mtime)
	}
	if err := os.Rename(stage, destination); err != nil {
		return nil, err
	}
	_ = syncDirectory(parent)
	committed = true
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names, nil
}

func verifyV2ExtractedCollection(body []byte, destination string, signedPlaintextSize uint64) error {
	entries, err := inspectV2CollectionArchive(body, signedPlaintextSize)
	if err != nil {
		return err
	}
	reader := tar.NewReader(bytes.NewReader(body))
	expected := map[string]bool{}
	for _, entry := range entries {
		header, err := reader.Next()
		if err != nil || header.Name != entry.name {
			return errors.New("collection verification archive changed")
		}
		path := filepath.Join(destination, filepath.FromSlash(entry.name))
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 ||
			(entry.dir && !info.IsDir()) ||
			(!entry.dir && !info.Mode().IsRegular()) {
			return fmt.Errorf("committed collection entry %q does not match", entry.name)
		}
		if !entry.dir {
			bodyOnDisk, err := os.ReadFile(path)
			if err != nil || int64(len(bodyOnDisk)) != entry.size {
				return fmt.Errorf("committed collection file %q does not match", entry.name)
			}
			archived, err := io.ReadAll(io.LimitReader(reader, entry.size+1))
			if err != nil || !bytes.Equal(archived, bodyOnDisk) {
				return fmt.Errorf("committed collection file %q does not match", entry.name)
			}
		}
		expected[filepath.Clean(path)] = true
	}
	err = filepath.Walk(destination, func(path string, _ os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == destination {
			return nil
		}
		if !expected[filepath.Clean(path)] {
			return fmt.Errorf("committed collection contains unexpected path %q", path)
		}
		return nil
	})
	return err
}
