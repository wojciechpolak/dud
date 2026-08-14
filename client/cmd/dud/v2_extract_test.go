// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestV2CollectionRoundTripUsesAtomicNoFollowExtraction(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_700_000_000, 0)
	script := filepath.Join(source, "nested", "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(script, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	archive, names, err := createV2CollectionArchive([]string{source})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := inspectV2CollectionArchive(archive, uint64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	rawNames := make([]any, len(names))
	for index := range names {
		rawNames[index] = names[index]
	}
	if err := validateV2CollectionNames(entries, rawNames); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "received")
	if _, err := extractV2CollectionArchive(archive, destination, uint64(len(archive))); err != nil {
		t.Fatal(err)
	}
	if err := verifyV2ExtractedCollection(archive, destination, uint64(len(archive))); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(destination, "source", "nested", "run.sh")
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "#!/bin/sh\n" {
		t.Fatalf("output = %q", body)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("normalized mode = %o", info.Mode().Perm())
	}
	if _, err := extractV2CollectionArchive(archive, destination, uint64(len(archive))); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("second extraction error = %v", err)
	}
}

func TestV2CollectionCreationAndMetadataRejectInvalidInputs(t *testing.T) {
	if _, _, err := createV2CollectionArchive(nil); err == nil {
		t.Fatal("empty collection accepted")
	}
	if _, _, err := createV2CollectionArchive([]string{filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing collection path accepted")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := createV2CollectionArchive([]string{link}); err == nil {
		t.Fatal("symlink collection entry accepted")
	}
	entries := []v2CollectionEntry{{name: "one/file"}, {name: "two/file"}}
	for _, names := range [][]any{{"one", 1}, {"one", "ONE"}, {"one"}, {"one", "two", "three"}} {
		if err := validateV2CollectionNames(entries, names); err == nil {
			t.Fatalf("collection names accepted: %#v", names)
		}
	}
	if _, err := inspectV2CollectionArchive([]byte("not a tar"), 9); err == nil {
		t.Fatal("invalid archive accepted")
	}
	if _, err := inspectV2CollectionArchive([]byte{}, 1); err == nil {
		t.Fatal("wrong signed size accepted")
	}
}

func TestV2CollectionRejectsLinksSpecialPathsExtensionsAndCollisionsBeforeExtraction(t *testing.T) {
	tests := []struct {
		name    string
		headers []*tar.Header
		bodies  [][]byte
	}{
		{
			name: "traversal",
			headers: []*tar.Header{{
				Name: "../escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644,
			}},
			bodies: [][]byte{[]byte("x")},
		},
		{
			name: "absolute",
			headers: []*tar.Header{{
				Name: "/escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644,
			}},
			bodies: [][]byte{[]byte("x")},
		},
		{
			name: "symlink",
			headers: []*tar.Header{{
				Name: "link", Typeflag: tar.TypeSymlink, Linkname: "target",
			}},
			bodies: [][]byte{nil},
		},
		{
			name: "hardlink",
			headers: []*tar.Header{{
				Name: "link", Typeflag: tar.TypeLink, Linkname: "target",
			}},
			bodies: [][]byte{nil},
		},
		{
			name: "fifo",
			headers: []*tar.Header{{
				Name: "pipe", Typeflag: tar.TypeFifo,
			}},
			bodies: [][]byte{nil},
		},
		{
			name: "case collision",
			headers: []*tar.Header{
				{Name: "Readme", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
				{Name: "README", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
			},
			bodies: [][]byte{[]byte("a"), []byte("b")},
		},
		{
			name: "pax xattr",
			headers: []*tar.Header{{
				Name:       "file",
				Typeflag:   tar.TypeReg,
				Size:       1,
				Mode:       0o644,
				Format:     tar.FormatPAX,
				PAXRecords: map[string]string{"SCHILY.xattr.user.test": "x"},
			}},
			bodies: [][]byte{[]byte("x")},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			body := buildV2HostileArchive(t, testCase.headers, testCase.bodies)
			destination := filepath.Join(t.TempDir(), "output")
			if _, err := extractV2CollectionArchive(body, destination, uint64(len(body))); err == nil {
				t.Fatal("hostile archive was accepted")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("destination exists after preflight rejection: %v", err)
			}
		})
	}
}

func TestV2CollectionSenderRejectsSourceSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := createV2CollectionArchive([]string{link, target}); err == nil {
		t.Fatal("collection sender followed a symlink")
	}
}

func buildV2HostileArchive(t *testing.T, headers []*tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for index, header := range headers {
		if header.Format == tar.FormatUnknown {
			header.Format = tar.FormatUSTAR
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(bodies[index]) != 0 {
			if _, err := writer.Write(bodies[index]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
