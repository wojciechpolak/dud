// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func regularV2Entry(name string, size int64, mode int64) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: size, Mode: mode}
}

// TestV2CollectionRefusesArchiveBombs covers the three shapes a decompression
// bomb takes here: more bytes than the signed plaintext size promised, more
// entries than the format allows, and a single file over the object limit.
func TestV2CollectionRefusesArchiveBombs(t *testing.T) {
	t.Run("more bytes than the signed size", func(t *testing.T) {
		body := buildV2HostileArchive(t,
			[]*tar.Header{regularV2Entry("big", 4096, 0o644)},
			[][]byte{make([]byte, 4096)})
		// The receiver is told the plaintext is tiny; the archive says otherwise.
		if _, err := inspectV2CollectionArchive(body, 64); err == nil {
			t.Fatal("an archive larger than its signed size was accepted")
		}
		// And the honest size still has to bound the sum of the entries.
		if _, err := inspectV2CollectionArchive(body, uint64(len(body))); err != nil {
			t.Fatalf("an honest archive was rejected: %v", err)
		}
	})

	t.Run("more entries than the format allows", func(t *testing.T) {
		headers := make([]*tar.Header, 0, v2MaximumCollectionEntries+1)
		bodies := make([][]byte, 0, v2MaximumCollectionEntries+1)
		for index := 0; index <= v2MaximumCollectionEntries; index++ {
			headers = append(headers, regularV2Entry(fmt.Sprintf("f%06d", index), 0, 0o644))
			bodies = append(bodies, nil)
		}
		body := buildV2HostileArchive(t, headers, bodies)
		_, err := inspectV2CollectionArchive(body, uint64(len(body)))
		if err == nil || !strings.Contains(err.Error(), "entries") {
			t.Fatalf("entry-count error = %v", err)
		}
	})

	t.Run("one file over the object limit", func(t *testing.T) {
		// The declared size alone must be refused, before any body is read, so
		// the header is emitted without the body it claims.
		var output bytes.Buffer
		writer := tar.NewWriter(&output)
		if err := writer.WriteHeader(regularV2Entry("huge", v2MaximumObjectBytes+1, 0o644)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Flush(); err == nil {
			t.Fatal("the writer accepted a body-less oversized entry")
		}
		body := output.Bytes()
		if _, err := inspectV2CollectionArchive(body, uint64(v2MaximumObjectBytes+1)); err == nil {
			t.Fatal("a file over the single-object limit was accepted")
		}
	})

	t.Run("deeper than the path depth limit", func(t *testing.T) {
		name := strings.Repeat("d/", v2MaximumCollectionDepth+1) + "file"
		body := buildV2HostileArchive(t,
			[]*tar.Header{regularV2Entry(name, 1, 0o644)},
			[][]byte{[]byte("x")})
		if _, err := inspectV2CollectionArchive(body, uint64(len(body))); err == nil {
			t.Fatal("an over-deep path was accepted")
		}
	})
}

// TestV2CollectionNormalizesUnsafeModes proves the extractor derives a mode
// rather than trusting one: setuid, setgid and sticky bits cannot survive a
// transfer even when the sender sets them.
func TestV2CollectionNormalizesUnsafeModes(t *testing.T) {
	for name, mode := range map[string]int64{
		"setuid":                0o4755,
		"setgid":                0o2755,
		"sticky":                0o1777,
		"world writable":        0o666,
		"setuid non-executable": 0o4644,
	} {
		t.Run(name, func(t *testing.T) {
			body := buildV2HostileArchive(t,
				[]*tar.Header{regularV2Entry("file", 1, mode)},
				[][]byte{[]byte("x")})
			entries, err := inspectV2CollectionArchive(body, uint64(len(body)))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("entries = %d", len(entries))
			}
			if entries[0].mode != 0o644 && entries[0].mode != 0o755 {
				t.Fatalf("mode %o survived inspection as %o", mode, entries[0].mode)
			}

			destination := filepath.Join(t.TempDir(), "out")
			if _, err := extractV2CollectionArchive(body, destination, uint64(len(body))); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(filepath.Join(destination, "file"))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
				t.Fatalf("extracted mode = %v", info.Mode())
			}
			if info.Mode().Perm()&0o022 != 0 {
				t.Fatalf("extracted file is group or world writable: %v", info.Mode())
			}
		})
	}
}

// TestV2CollectionRefusesSparseAndExtendedFormats covers the tar variants whose
// bodies do not equal their declared size, which is how a sparse archive smuggles
// more bytes past a length check.
func TestV2CollectionRefusesSparseAndExtendedFormats(t *testing.T) {
	for name, header := range map[string]*tar.Header{
		"GNU sparse": {
			Name: "sparse", Typeflag: tar.TypeGNUSparse, Size: 1, Mode: 0o644,
			Format: tar.FormatGNU,
		},
		"GNU long name": {
			Name: strings.Repeat("a", 200), Typeflag: tar.TypeReg, Size: 1, Mode: 0o644,
			Format: tar.FormatGNU,
		},
		"PAX record other than path": {
			Name: "file", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644,
			Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "x"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				// A writer may refuse to encode some of these itself, which is an
				// equally acceptable outcome for a shape we never emit.
				_ = recover()
			}()
			body := buildV2HostileArchive(t, []*tar.Header{header}, [][]byte{[]byte("x")})
			if _, err := inspectV2CollectionArchive(body, uint64(len(body))); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

// TestV2CollectionRefusesUnicodeCollisions proves normalization happens before
// extraction, so two names that differ only in Unicode form or case cannot
// race to occupy one path on a case-folding or normalizing filesystem.
func TestV2CollectionRefusesUnicodeCollisions(t *testing.T) {
	for name, pair := range map[string][2]string{
		// U+00E9 versus "e" + U+0301.
		"NFC against NFD":        {"café.txt", "café.txt"},
		"case only":              {"Report.txt", "report.txt"},
		"case and Unicode":       {"CAFÉ.txt", "café.txt"},
		"nested NFC against NFD": {"dir/å.txt", "dir/å.txt"},
	} {
		t.Run(name, func(t *testing.T) {
			first := regularV2Entry(pair[0], 1, 0o644)
			second := regularV2Entry(pair[1], 1, 0o644)
			for _, header := range []*tar.Header{first, second} {
				if !isASCIIV2ArchiveName(header.Name) {
					header.Format = tar.FormatPAX
				}
			}
			body := buildV2HostileArchive(t, []*tar.Header{first, second},
				[][]byte{[]byte("a"), []byte("b")})
			_, err := inspectV2CollectionArchive(body, uint64(len(body)))
			if err == nil || !strings.Contains(err.Error(), "collide") {
				t.Fatalf("collision error = %v", err)
			}
			destination := filepath.Join(t.TempDir(), "out")
			if _, err := extractV2CollectionArchive(body, destination, uint64(len(body))); err == nil {
				t.Fatal("a colliding archive was extracted")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("destination exists after a rejected collision: %v", err)
			}
		})
	}
}

// TestV2CollectionExtractionRefusesToFollowAPlantedSymlink is the symlink race:
// an attacker who can write into the destination between validation and
// extraction plants a link where a directory is about to be created.
func TestV2CollectionExtractionRefusesToFollowAPlantedSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "out")
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	// The archive wants out/dir/file; "dir" already exists as a link elsewhere.
	if err := os.Symlink(outside, filepath.Join(destination, "dir")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	body := buildV2HostileArchive(t,
		[]*tar.Header{regularV2Entry("dir/file", 1, 0o644)},
		[][]byte{[]byte("x")})
	if _, err := extractV2CollectionArchive(body, destination, uint64(len(body))); err == nil {
		t.Fatal("extraction followed a planted symlink")
	}
	if _, err := os.Lstat(filepath.Join(outside, "file")); !os.IsNotExist(err) {
		t.Fatal("extraction wrote through a planted symlink")
	}
}

// TestV2CollectionExtractionRefusesToOverwrite fixes the non-destructive policy:
// an existing file at a target path stops the whole extraction rather than
// being replaced, and the file keeps its original contents.
func TestV2CollectionExtractionRefusesToOverwrite(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(destination, "file")
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := buildV2HostileArchive(t,
		[]*tar.Header{regularV2Entry("file", 1, 0o644)},
		[][]byte{[]byte("x")})
	_, err := extractV2CollectionArchive(body, destination, uint64(len(body)))
	if err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("overwrite error = %v", err)
	}
	contents, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "original" {
		t.Fatalf("existing file was modified: %q", contents)
	}
}

// TestV2CollectionCarriesNonASCIINames is the positive side of the PAX rule: a
// name USTAR cannot encode still has to survive a round trip, because refusing
// it would make the collection format unusable outside ASCII filenames.
func TestV2CollectionCarriesNonASCIINames(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "docs")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	names := []string{"caf\u00e9.txt", "\u65e5\u672c\u8a9e.md", "\u00dcnicode Ordner.txt"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(source, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive, topNames, err := createV2CollectionArchive([]string{source})
	if err != nil {
		t.Fatalf("a collection with non-ASCII names could not be created: %v", err)
	}
	entries, err := inspectV2CollectionArchive(archive, uint64(len(archive)))
	if err != nil {
		t.Fatalf("a collection with non-ASCII names was rejected: %v", err)
	}
	raw := make([]any, len(topNames))
	for index := range topNames {
		raw[index] = topNames[index]
	}
	if err := validateV2CollectionNames(entries, raw); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "out")
	if _, err := extractV2CollectionArchive(archive, destination, uint64(len(archive))); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(destination, "docs", name)); err != nil {
			t.Fatalf("extracted name %q: %v", name, err)
		}
	}
}
