// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package capsule

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/wojciechpolak/dud/client/drop"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	// maximumCollectionHierarchyComponents permits every collection entry to
	// contribute one implicit parent while bounding namespace and map growth.
	maximumCollectionHierarchyComponents = 200_000
	// maximumCollectionHierarchyPrefixBytes bounds repeated prefix construction
	// and Unicode normalization independently of archive byte length.
	maximumCollectionHierarchyPrefixBytes = 64 * 1024 * 1024
)

// InspectCollection applies the shared archive policy and verifies the complete
// optical tar stream, including end markers and implicit directory collisions.
func InspectCollection(body []byte) ([]drop.CollectionEntry, error) {
	entries, err := drop.InspectCollectionArchive(body, uint64(len(body)), drop.CollectionArchivePolicy{AllowOwnershipMetadata: true, AllowGNUFormat: true})
	if err != nil {
		return nil, err
	}
	if err := inspectCollectionHierarchy(entries); err != nil {
		return nil, err
	}
	stream := bytes.NewReader(body)
	reader := tar.NewReader(stream)
	for range entries {
		if _, err := reader.Next(); err != nil {
			return nil, err
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			return nil, err
		}
	}
	// tar.Reader accepts EOF without end markers and ignores bytes after them.
	// Optical collections require two zero blocks and only zero record padding.
	offset := len(body) - stream.Len()
	offset = (offset + 511) / 512 * 512
	if offset > len(body) || len(body)-offset < 1024 || len(body)%512 != 0 {
		return nil, errors.New("collection tar end markers are truncated")
	}
	for _, value := range body[offset:] {
		if value != 0 {
			return nil, errors.New("collection contains trailing archive data")
		}
	}
	return entries, nil
}

func inspectCollectionHierarchy(entries []drop.CollectionEntry) error {
	if err := validateCollectionHierarchyBudget(entries); err != nil {
		return err
	}
	paths := map[string]string{}
	directories := map[string]bool{}
	for _, entry := range entries {
		components := strings.Split(entry.Name, "/")
		for index := range components {
			name := strings.Join(components[:index+1], "/")
			key := cases.Fold().String(norm.NFC.String(name))
			directory := index < len(components)-1 || entry.Directory
			if previous, exists := paths[key]; exists {
				if previous != name || directories[key] != directory {
					return errors.New("collection contains conflicting parent paths")
				}
			} else {
				paths[key] = name
				directories[key] = directory
			}
		}
	}
	return nil
}

func validateCollectionHierarchyBudget(entries []drop.CollectionEntry) error {
	components := 0
	prefixBytes := 0
	for _, entry := range entries {
		for index := range entry.Name {
			if entry.Name[index] != '/' {
				continue
			}
			if components >= maximumCollectionHierarchyComponents {
				return errors.New("collection hierarchy exceeds 200000 path components")
			}
			if index > maximumCollectionHierarchyPrefixBytes-prefixBytes {
				return errors.New("collection hierarchy exceeds its prefix byte budget")
			}
			components++
			prefixBytes += index
		}
		if components >= maximumCollectionHierarchyComponents {
			return errors.New("collection hierarchy exceeds 200000 path components")
		}
		if len(entry.Name) > maximumCollectionHierarchyPrefixBytes-prefixBytes {
			return errors.New("collection hierarchy exceeds its prefix byte budget")
		}
		components++
		prefixBytes += len(entry.Name)
	}
	return nil
}
