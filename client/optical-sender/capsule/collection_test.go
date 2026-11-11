// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package capsule

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dud/client/drop"
)

func collectionFixture(t *testing.T, headers []*tar.Header) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := tar.NewWriter(&body)
	for _, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write(bytes.Repeat([]byte{'a'}, int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}
func TestPreparedCollectionCanonicalizesDirectoryHeadersAndRetainsFileBytes(t *testing.T) {
	body := collectionFixture(t, []*tar.Header{{Name: "docs/", Typeflag: tar.TypeDir, Mode: 0755}, {Name: "docs/file", Typeflag: tar.TypeReg, Mode: 0644, Size: 5}})
	root := t.TempDir()
	input := filepath.Join(root, "tar")
	output := filepath.Join(root, "container")
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(output, drop.PreparedInput{Path: input, Type: drop.PayloadCollection, DisplayName: "dud-collection.tar", ArchiveFormat: drop.ArchiveTar}); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	metadata, payload, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := drop.InspectCollectionArchive(payload, metadata.PlaintextSize, drop.CollectionArchivePolicy{AllowOwnershipMetadata: true, AllowGNUFormat: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "docs" || !entries[0].Directory || entries[1].Name != "docs/file" {
		t.Fatalf("entries %+v", entries)
	}
	reader := tar.NewReader(bytes.NewReader(payload))
	_, _ = reader.Next()
	_, _ = reader.Next()
	var contents bytes.Buffer
	if _, err := contents.ReadFrom(reader); err != nil {
		t.Fatal(err)
	}
	if contents.String() != "aaaaa" {
		t.Fatal("file bytes differ")
	}
}
func TestPreparedCollectionRejectsUnsafeTypesPathsAndCollisionsBeforeWriting(t *testing.T) {
	for _, headers := range [][]*tar.Header{
		{{Name: "../", Typeflag: tar.TypeDir}},
		{{Name: "docs//", Typeflag: tar.TypeDir}},
		{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "outside"}},
		{{Name: "File", Typeflag: tar.TypeReg}, {Name: "file", Typeflag: tar.TypeReg}},
	} {
		root := t.TempDir()
		input := filepath.Join(root, "tar")
		output := filepath.Join(root, "container")
		if err := os.WriteFile(input, collectionFixture(t, headers), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(output, drop.PreparedInput{Path: input, Type: drop.PayloadCollection, DisplayName: "dud-collection.tar", ArchiveFormat: drop.ArchiveTar}); err == nil {
			t.Fatal("invalid collection accepted")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("invalid container was written")
		}
	}
}

func TestNativeCollectionMetadataIsRemovedDuringPreparationAndRejectedInReceivedCapsules(t *testing.T) {
	name := "folder/" + strings.Repeat("long", 40)
	stamp := time.Unix(1_700_000_000, 123_456_789)
	body := collectionFixture(t, []*tar.Header{{
		Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 5, Format: tar.FormatPAX,
		ModTime: stamp, AccessTime: stamp, ChangeTime: stamp,
		Uid: 501, Gid: 20, Uname: strings.Repeat("owner", 10), Gname: strings.Repeat("group", 10),
		PAXRecords: map[string]string{
			"LIBARCHIVE.creationtime": "1700000000.123", "SCHILY.fflags": "hidden",
			"SCHILY.acl.ace": "local ACL", "SCHILY.xattr.com.dud.test": "local attribute",
			"LIBARCHIVE.xattr.com.dud.test": "bG9jYWw=",
		},
	}})
	input, output := filepath.Join(t.TempDir(), "native.tar"), filepath.Join(t.TempDir(), "capsule")
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(output, drop.PreparedInput{Path: input, Type: drop.PayloadCollection, DisplayName: "collection.tar", ArchiveFormat: drop.ArchiveTar}); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(bytes.NewReader(payload))
	header, err := reader.Next()
	if err != nil || header.Name != name {
		t.Fatalf("canonical path changed: %+v, %v", header, err)
	}
	for key := range header.PAXRecords {
		if key != "path" {
			t.Fatalf("local metadata reached capsule: %s", key)
		}
	}
	if header.ModTime.Unix() != 0 || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
		t.Fatalf("local attributes or timestamps reached capsule: %+v", header)
	}
	var recovered bytes.Buffer
	if _, err := recovered.ReadFrom(reader); err != nil || recovered.String() != "aaaaa" {
		t.Fatalf("file data changed: %q, %v", recovered.String(), err)
	}
	received, err := Encode(body, Metadata{Type: drop.PayloadCollection, DisplayName: "collection.tar", ArchiveFormat: drop.ArchiveTar})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(received); !errors.Is(err, ErrArchive) {
		t.Fatalf("received noncanonical metadata was accepted: %v", err)
	}
}

func TestPreparedCollectionRejectsUnknownNativeExtensions(t *testing.T) {
	body := collectionFixture(t, []*tar.Header{{
		Name: "file", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5, Format: tar.FormatPAX,
		PAXRecords: map[string]string{"DUD.unsupported": "value"},
	}})
	if _, err := normalizeCollection(body); err == nil {
		t.Fatal("unknown native extension was accepted")
	}
}
