// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
	"golang.org/x/sys/unix"
)

func TestOpticalCollectionWithSystemBSDTarPreservesFilesWithoutNativeMetadata(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "files", true: "directory"}[directory], func(t *testing.T) {
			root := t.TempDir()
			contents := map[string]string{
				"--exclude=foo": "literal filename", "foo": "selected payload", "._keep": "selected AppleDouble-like name",
			}
			if directory {
				contents["nested/-"+strings.Repeat("é", 60)] = "long Unicode filename"
			}
			for name, body := range contents {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := unix.Setxattr(path, "com.dud.optical-test", []byte("local metadata"), 0); err != nil {
					t.Fatal(err)
				}
				if err := unix.Chflags(path, unix.UF_HIDDEN); err != nil {
					t.Fatal(err)
				}
				stamp := time.Unix(1_700_000_000, 123_456_789)
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}
			tools := t.TempDir()
			log := filepath.Join(tools, "tar.log")
			script := "#!/bin/sh\nprintf 'copyfile=%s\\n' \"$COPYFILE_DISABLE\" > \"$DUD_TEST_BSD_TAR_LOG\"\nexec /usr/bin/tar \"$@\"\n"
			if err := os.WriteFile(filepath.Join(tools, "tar"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("DUD_TEST_BSD_TAR_LOG", log)
			a, renderer, _, _ := newOpticalTestApp(t, "")
			args := []string{"optical", "send", "--passphrase"}
			if directory {
				args = append(args, "--file", root)
			} else {
				for _, name := range []string{"--exclude=foo", "foo", "._keep"} {
					args = append(args, "--file", filepath.Join(root, name))
				}
			}
			if err := a.run(args); err != nil {
				t.Fatal(err)
			}
			_, payload, err := capsule.Decode(renderer.ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			destination := t.TempDir()
			if err := extractOpticalCollection(payload, destination); err != nil {
				t.Fatal(err)
			}
			extractedRoot := destination
			if directory {
				extractedRoot = filepath.Join(destination, filepath.Base(root))
			}
			for name, want := range contents {
				path := filepath.Join(extractedRoot, name)
				body, err := os.ReadFile(path)
				if err != nil || string(body) != want {
					t.Fatalf("changed source %q: %q, %v", name, body, err)
				}
				size, err := unix.Listxattr(path, nil)
				if err != nil {
					t.Fatal(err)
				}
				attributes := make([]byte, size)
				if _, err := unix.Listxattr(path, attributes); err != nil || bytes.Contains(attributes, []byte("com.dud.optical-test")) {
					t.Fatalf("source metadata reached extracted file: %q, %v", attributes, err)
				}
			}
			entries, err := capsule.InspectCollection(payload)
			if err != nil {
				t.Fatal(err)
			}
			files := 0
			for _, entry := range entries {
				if !entry.Directory {
					files++
				}
			}
			if files != len(contents) {
				t.Fatalf("BSD tar added sidecars or omitted files: %d, want %d", files, len(contents))
			}
			invocation, err := os.ReadFile(log)
			if err != nil || string(invocation) != "copyfile=1\n" {
				t.Fatalf("system BSD tar did not disable AppleDouble: %q, %v", invocation, err)
			}
			assertOpticalCleanup(t)
		})
	}
}
