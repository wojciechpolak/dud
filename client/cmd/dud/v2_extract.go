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

	"golang.org/x/sys/unix"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	v2MaximumCollectionEntries = 100_000
	v2MaximumCollectionDepth   = 64
	v2MaximumExtractedBytes    = int64(1 << 30)
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
	if name == "" || strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return errors.New("collection contains an unsafe path")
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	if cleaned != name || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("collection path %q is not canonical and relative", name)
	}
	if len(strings.Split(name, "/")) > v2MaximumCollectionDepth {
		return fmt.Errorf("collection path %q exceeds depth %d", name, v2MaximumCollectionDepth)
	}
	return nil
}

func inspectV2CollectionArchive(body []byte, signedPlaintextSize uint64) ([]v2CollectionEntry, error) {
	if uint64(len(body)) != signedPlaintextSize || int64(len(body)) > v2MaximumExtractedBytes {
		return nil, errors.New("collection archive violates its signed size bound")
	}
	reader := tar.NewReader(bytes.NewReader(body))
	entries := []v2CollectionEntry{}
	collisions := map[string]string{}
	var extracted int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("inspect collection: %w", err)
		}
		if len(entries) >= v2MaximumCollectionEntries {
			return nil, errors.New("collection exceeds 100000 entries")
		}
		if err := validateV2ArchivePath(header.Name); err != nil {
			return nil, err
		}
		// GNU adds sparse maps and long-name members whose bodies do not match
		// their declared size. PAX is accepted only for the one record a
		// non-ASCII name needs. Xattrs, ownership, and sparse maps are extensions
		// this format does not carry.
		if header.Format == tar.FormatGNU || header.Xattrs != nil {
			return nil, fmt.Errorf("collection entry %q uses unsupported extensions", header.Name)
		}
		for key := range header.PAXRecords {
			if key != "path" {
				return nil, fmt.Errorf(
					"collection entry %q uses unsupported extension record %q", header.Name, key)
			}
		}
		if header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
			return nil, fmt.Errorf("collection entry %q requests ownership metadata", header.Name)
		}
		entry := v2CollectionEntry{name: header.Name, mtime: header.ModTime}
		switch header.Typeflag {
		case tar.TypeDir:
			entry.dir = true
			entry.mode = 0o755
			if header.Size != 0 {
				return nil, fmt.Errorf("collection directory %q has a body", header.Name)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > v2MaximumObjectBytes {
				return nil, fmt.Errorf("collection file %q exceeds the single-file limit", header.Name)
			}
			entry.size = header.Size
			if header.Mode&0o100 != 0 {
				entry.mode = 0o755
			} else {
				entry.mode = 0o644
			}
			extracted += header.Size
			if extracted > int64(signedPlaintextSize) || extracted > v2MaximumExtractedBytes {
				return nil, errors.New("collection exceeds the signed extraction budget")
			}
		default:
			return nil, fmt.Errorf("collection entry %q is a link or special file", header.Name)
		}
		collision := cases.Fold().String(norm.NFC.String(header.Name))
		if prior, exists := collisions[collision]; exists {
			return nil, fmt.Errorf("collection paths %q and %q collide after normalization", prior, header.Name)
		}
		collisions[collision] = header.Name
		entries = append(entries, entry)
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

func openV2DirectoryAt(parent int, name string) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func ensureV2DirectoryAt(parent int, name string) (int, error) {
	if err := unix.Mkdirat(parent, name, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	return openV2DirectoryAt(parent, name)
}

func extractV2ArchiveEntry(rootFD int, reader *tar.Reader, entry v2CollectionEntry) error {
	components := strings.Split(entry.name, "/")
	parentFD := rootFD
	opened := []int{}
	defer func() {
		for _, fd := range opened {
			_ = unix.Close(fd)
		}
	}()
	for _, component := range components[:len(components)-1] {
		next, err := ensureV2DirectoryAt(parentFD, component)
		if err != nil {
			return fmt.Errorf("securely open collection directory %q: %w", component, err)
		}
		opened = append(opened, next)
		parentFD = next
	}
	name := components[len(components)-1]
	if entry.dir {
		fd, err := ensureV2DirectoryAt(parentFD, name)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	}
	fd, err := unix.Openat(
		parentFD,
		name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		uint32(entry.mode),
	)
	if err != nil {
		return fmt.Errorf("securely create collection file %q: %w", entry.name, err)
	}
	file := os.NewFile(uintptr(fd), entry.name)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("create collection file handle")
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
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = os.RemoveAll(stage)
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()
	rootFD, err := unix.Open(stage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	reader := tar.NewReader(bytes.NewReader(body))
	for index, entry := range entries {
		header, err := reader.Next()
		if err != nil {
			_ = unix.Close(rootFD)
			return nil, err
		}
		if header.Name != entry.name {
			_ = unix.Close(rootFD)
			return nil, errors.New("collection changed between validation and extraction")
		}
		if err := extractV2ArchiveEntry(rootFD, reader, entry); err != nil {
			_ = unix.Close(rootFD)
			return nil, err
		}
		_ = index
	}
	if err := unix.Fsync(rootFD); err != nil {
		_ = unix.Close(rootFD)
		return nil, err
	}
	if err := unix.Close(rootFD); err != nil {
		return nil, err
	}
	for _, entry := range entries {
		path := filepath.Join(stage, filepath.FromSlash(entry.name))
		_ = os.Chtimes(path, entry.mtime, entry.mtime)
	}
	if err := os.Rename(stage, destination); err != nil {
		return nil, err
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Fsync(parentFD)
		_ = unix.Close(parentFD)
	}
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
