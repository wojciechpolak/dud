// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package drop

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func collectionArchive(t *testing.T, headers ...*tar.Header) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			if _, err := writer.Write(bytes.Repeat([]byte{'x'}, int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestCollectionArchiveOwnershipPolicy(t *testing.T) {
	body := collectionArchive(t, &tar.Header{
		Name: "file.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1,
		Uid: 501, Gid: 20, Uname: "user", Gname: "staff",
	})
	if _, err := InspectCollectionArchive(body, uint64(len(body)), CollectionArchivePolicy{}); err == nil {
		t.Fatal("strict archive policy accepted ownership metadata")
	}
	entries, err := InspectCollectionArchive(body, uint64(len(body)), CollectionArchivePolicy{
		AllowOwnershipMetadata: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "file.txt" || entries[0].Size != 1 {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestCollectionArchiveGNUFormatPolicy(t *testing.T) {
	body := collectionArchive(t, &tar.Header{
		Name: "file.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, Format: tar.FormatGNU,
	})
	if _, err := InspectCollectionArchive(body, uint64(len(body)), CollectionArchivePolicy{}); err == nil {
		t.Fatal("strict archive policy accepted GNU format")
	}
	if _, err := InspectCollectionArchive(body, uint64(len(body)), CollectionArchivePolicy{
		AllowGNUFormat: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCollectionArchiveRejectsUnsafeEntries(t *testing.T) {
	tests := map[string][]*tar.Header{
		"traversal": {{Name: "../escape", Typeflag: tar.TypeReg}},
		"link":      {{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "target"}},
		"collision": {
			{Name: "Readme", Typeflag: tar.TypeReg},
			{Name: "README", Typeflag: tar.TypeReg},
		},
	}
	for name, headers := range tests {
		t.Run(name, func(t *testing.T) {
			body := collectionArchive(t, headers...)
			if _, err := InspectCollectionArchive(body, uint64(len(body)), CollectionArchivePolicy{
				AllowOwnershipMetadata: true,
			}); err == nil {
				t.Fatal("unsafe collection archive was accepted")
			}
		})
	}
}

func TestCollectionArchiveRejectsSingleFileAndDepthLimits(t *testing.T) {
	var oversized bytes.Buffer
	writer := tar.NewWriter(&oversized)
	if err := writer.WriteHeader(&tar.Header{
		Name: "large.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: MaximumCollectionFile + 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCollectionArchive(oversized.Bytes(), uint64(oversized.Len()), CollectionArchivePolicy{}); err == nil {
		t.Fatal("oversized collection file was accepted")
	}

	deepName := strings.Repeat("d/", MaximumCollectionDepth) + "file"
	body := collectionArchive(t, &tar.Header{Name: deepName, Typeflag: tar.TypeReg, Mode: 0o644})
	if _, err := InspectCollectionArchive(body, uint64(len(body)), CollectionArchivePolicy{}); err == nil {
		t.Fatal("overly deep collection path was accepted")
	}
}
