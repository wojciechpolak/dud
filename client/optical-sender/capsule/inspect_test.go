// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package capsule

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wojciechpolak/dud/client/drop"
)

func TestCollectionHierarchyRejectsAggregateWorkBeforeAllocation(t *testing.T) {
	t.Run("components", func(t *testing.T) {
		prefix := strings.Repeat("d/", drop.MaximumCollectionDepth-1)
		entries := make([]drop.CollectionEntry, maximumCollectionHierarchyComponents/drop.MaximumCollectionDepth+1)
		for index := range entries {
			entries[index].Name = prefix + fmt.Sprintf("file-%04d", index)
		}
		err := inspectCollectionHierarchy(entries)
		if err == nil || err.Error() != "collection hierarchy exceeds 200000 path components" {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("prefix bytes", func(t *testing.T) {
		prefix := strings.Repeat("abcdefghijklmno/", drop.MaximumCollectionDepth-1)
		entries := make([]drop.CollectionEntry, maximumCollectionHierarchyPrefixBytes/32_000+1)
		for index := range entries {
			entries[index].Name = prefix + fmt.Sprintf("file-%015d", index)
		}
		err := inspectCollectionHierarchy(entries)
		if err == nil || err.Error() != "collection hierarchy exceeds its prefix byte budget" {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCollectionHierarchyAcceptsOrdinaryNestedPaths(t *testing.T) {
	entries := []drop.CollectionEntry{
		{Name: "docs", Directory: true},
		{Name: "docs/readme.txt"},
		{Name: "docs/examples", Directory: true},
		{Name: "docs/examples/demo.txt"},
	}
	if err := inspectCollectionHierarchy(entries); err != nil {
		t.Fatal(err)
	}
}

func TestCollectionCapsuleRejectsHierarchyComponentBudget(t *testing.T) {
	prefix := strings.Repeat("d/", drop.MaximumCollectionDepth-1)
	headers := make([]*tar.Header, maximumCollectionHierarchyComponents/drop.MaximumCollectionDepth+1)
	for index := range headers {
		headers[index] = &tar.Header{
			Name:     prefix + fmt.Sprintf("file-%04d", index),
			Typeflag: tar.TypeReg,
		}
	}
	body := collectionFixture(t, headers)
	encoded, err := Encode(body, Metadata{
		Type:          drop.PayloadCollection,
		ArchiveFormat: drop.ArchiveTar,
		DisplayName:   "collection.tar",
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata, payload, err := Decode(encoded)
	if !errors.Is(err, ErrArchive) || metadata != (Metadata{}) || payload != nil {
		t.Fatalf("decoded over-budget hierarchy: metadata=%#v payload=%d error=%v", metadata, len(payload), err)
	}
}

func TestCollectionRejectsTruncatedEndMarkersTrailingDataAndParentConflicts(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers []tar.Header
		mutate  func([]byte) []byte
	}{
		{name: "truncated markers", headers: []tar.Header{{Name: "file", Typeflag: tar.TypeReg}}, mutate: func(body []byte) []byte { return body[:len(body)-512] }},
		{name: "no markers", headers: []tar.Header{{Name: "file", Typeflag: tar.TypeReg}}, mutate: func(body []byte) []byte { return body[:len(body)-1024] }},
		{name: "trailing data", headers: []tar.Header{{Name: "file", Typeflag: tar.TypeReg}}, mutate: func(body []byte) []byte { return append(body, bytes.Repeat([]byte{1}, 512)...) }},
		{name: "partial padding", headers: []tar.Header{{Name: "file", Typeflag: tar.TypeReg}}, mutate: func(body []byte) []byte { return append(body, 0) }},
		{name: "file parent", headers: []tar.Header{{Name: "file", Typeflag: tar.TypeReg}, {Name: "file/child", Typeflag: tar.TypeReg}}},
		{name: "parent after child", headers: []tar.Header{{Name: "file/child", Typeflag: tar.TypeReg}, {Name: "file", Typeflag: tar.TypeReg}}},
		{name: "parent spelling", headers: []tar.Header{{Name: "Dir/one", Typeflag: tar.TypeReg}, {Name: "dir/two", Typeflag: tar.TypeReg}}},
		{name: "Unicode parent", headers: []tar.Header{{Name: "é/one", Typeflag: tar.TypeReg}, {Name: "e\u0301/two", Typeflag: tar.TypeReg}}},
		{name: "noncanonical", headers: []tar.Header{{Name: "a/../b", Typeflag: tar.TypeReg}}},
		{name: "symlink", headers: []tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "file"}}},
		{name: "hardlink", headers: []tar.Header{{Name: "link", Typeflag: tar.TypeLink, Linkname: "file"}}},
		{name: "fifo", headers: []tar.Header{{Name: "fifo", Typeflag: tar.TypeFifo}}},
		{name: "normalized collision", headers: []tar.Header{{Name: "File", Typeflag: tar.TypeReg}, {Name: "file", Typeflag: tar.TypeReg}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			for _, header := range test.headers {
				if err := writer.WriteHeader(&header); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			body := archive.Bytes()
			if test.mutate != nil {
				body = test.mutate(body)
			}
			encoded, err := Encode(body, Metadata{Type: drop.PayloadCollection, ArchiveFormat: drop.ArchiveTar, DisplayName: "collection.tar"})
			if err != nil {
				t.Fatal(err)
			}
			metadata, payload, err := Decode(encoded)
			if !errors.Is(err, ErrArchive) || payload != nil || metadata != (Metadata{}) {
				t.Fatal("invalid archive accepted", err)
			}
		})
	}
}
