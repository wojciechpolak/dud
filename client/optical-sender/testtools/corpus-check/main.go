// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// corpus-check verifies generated fixture bytes and their complete optical recovery.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wojciechpolak/dud/client/optical-sender"
)

type corpusEntry struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: corpus-check MANIFEST CORPUS_DIRECTORY")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var manifest struct {
		Files []corpusEntry `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	if len(manifest.Files) == 0 {
		return fmt.Errorf("corpus manifest contains no files")
	}
	for _, entry := range manifest.Files {
		if err := checkEntry(entry, args[1]); err != nil {
			return fmt.Errorf("%s: %w", entry.Name, err)
		}
		fmt.Println(entry.Name)
	}
	return nil
}

func checkEntry(entry corpusEntry, directory string) error {
	capsule, err := os.ReadFile(filepath.Join(directory, entry.Name))
	if err != nil {
		return err
	}
	if len(capsule) != entry.Size {
		return fmt.Errorf("size=%d, want %d", len(capsule), entry.Size)
	}
	digest := sha256.Sum256(capsule)
	if hex.EncodeToString(digest[:]) != entry.SHA256 {
		return fmt.Errorf("generated corpus digest does not match manifest")
	}
	var sessionID [optical.SessionIDSize]byte
	copy(sessionID[:], digest[:optical.SessionIDSize])
	encoder, err := optical.NewEncoder(capsule, sessionID)
	if err != nil {
		return err
	}
	decoder := optical.NewDecoder()
	for stripe := 0; stripe < encoder.StripeCount(); stripe++ {
		count, err := encoder.SourceCount(stripe)
		if err != nil {
			return err
		}
		for sequence := range count {
			frame, err := encoder.Frame(stripe, uint32(sequence))
			if err != nil {
				return err
			}
			if _, err := decoder.Add(frame); err != nil {
				return err
			}
		}
	}
	result, err := decoder.Result()
	if err != nil {
		return err
	}
	if !bytes.Equal(result, capsule) {
		return fmt.Errorf("round trip changed corpus bytes")
	}
	return nil
}
