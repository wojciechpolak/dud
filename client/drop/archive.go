// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package drop

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	// MaximumCollectionEntries bounds metadata work before extraction.
	MaximumCollectionEntries = 100_000
	// MaximumCollectionDepth bounds path traversal during validation and extraction.
	MaximumCollectionDepth = 64
	// MaximumExtractedBytes bounds the total regular-file content in a collection.
	MaximumExtractedBytes = int64(1 << 30)
	// MaximumCollectionFile bounds one regular file in a collection.
	MaximumCollectionFile = int64(100 * 1024 * 1024)
)

// CollectionArchivePolicy selects inert tar metadata accepted from a producer.
type CollectionArchivePolicy struct {
	// AllowOwnershipMetadata accepts ownership fields without returning or applying them.
	AllowOwnershipMetadata bool
	// AllowGNUFormat accepts GNU headers while retaining entry-type and extension checks.
	AllowGNUFormat bool
}

// CollectionEntry is a validated regular file or directory from a tar stream.
type CollectionEntry struct {
	Name      string
	Mode      int64
	Size      int64
	ModTime   time.Time
	Directory bool
}

// ValidateArchivePath rejects paths that cannot be extracted portably beneath a root.
func ValidateArchivePath(name string) error {
	if name == "" || strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return errors.New("collection contains an unsafe path")
	}
	for _, component := range strings.Split(name, "/") {
		if !ValidPortableArchiveComponent(component) {
			return fmt.Errorf("collection path %q is not portable to Windows", name)
		}
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	if cleaned != name || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("collection path %q is not canonical and relative", name)
	}
	if len(strings.Split(name, "/")) > MaximumCollectionDepth {
		return fmt.Errorf("collection path %q exceeds depth %d", name, MaximumCollectionDepth)
	}
	return nil
}

// ValidPortableArchiveComponent reports whether a path component is portable to Windows.
func ValidPortableArchiveComponent(component string) bool {
	if component == "" || strings.TrimRight(component, " .") != component ||
		strings.ContainsAny(component, `<>:"|?*`) {
		return false
	}
	for _, character := range component {
		if character < 32 {
			return false
		}
	}
	base, _, _ := strings.Cut(component, ".")
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"COM¹", "COM²", "COM³",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		"LPT¹", "LPT²", "LPT³":
		return false
	default:
		return true
	}
}

// InspectCollectionArchive validates a complete tar stream without extracting it.
func InspectCollectionArchive(body []byte, signedPlaintextSize uint64, policy CollectionArchivePolicy) ([]CollectionEntry, error) {
	if uint64(len(body)) != signedPlaintextSize || int64(len(body)) > MaximumExtractedBytes {
		return nil, errors.New("collection archive violates its signed size bound")
	}
	reader := tar.NewReader(bytes.NewReader(body))
	entries := []CollectionEntry{}
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
		if len(entries) >= MaximumCollectionEntries {
			return nil, errors.New("collection exceeds 100000 entries")
		}
		if err := ValidateArchivePath(header.Name); err != nil {
			return nil, err
		}
		if header.Format == tar.FormatGNU && !policy.AllowGNUFormat {
			return nil, fmt.Errorf("collection entry %q uses unsupported extensions", header.Name)
		}
		for key := range header.PAXRecords {
			if key != "path" {
				return nil, fmt.Errorf(
					"collection entry %q uses unsupported extension record %q", header.Name, key)
			}
		}
		if !policy.AllowOwnershipMetadata &&
			(header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "") {
			return nil, fmt.Errorf("collection entry %q requests ownership metadata", header.Name)
		}
		entry := CollectionEntry{Name: header.Name, ModTime: header.ModTime}
		switch header.Typeflag {
		case tar.TypeDir:
			entry.Directory = true
			entry.Mode = 0o755
			if header.Size != 0 {
				return nil, fmt.Errorf("collection directory %q has a body", header.Name)
			}
		case tar.TypeReg:
			if header.Size < 0 || header.Size > MaximumCollectionFile {
				return nil, fmt.Errorf("collection file %q exceeds the single-file limit", header.Name)
			}
			entry.Size = header.Size
			if header.Mode&0o100 != 0 {
				entry.Mode = 0o755
			} else {
				entry.Mode = 0o644
			}
			extracted += header.Size
			if extracted > int64(signedPlaintextSize) || extracted > MaximumExtractedBytes {
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
