// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

type v2FailingReader struct {
	remaining int
}

func (reader *v2FailingReader) Read(value []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, errors.New("source interrupted")
	}
	if len(value) > reader.remaining {
		value = value[:reader.remaining]
	}
	for index := range value {
		value[index] = byte(index)
	}
	reader.remaining -= len(value)
	return len(value), nil
}

func v2ChunkTestIdentity(t *testing.T) *age.HybridIdentity {
	t.Helper()
	identity, err := age.ParseHybridIdentity("AGE-SECRET-KEY-PQ-1TNKN5N7GU6X7H46D69HMCT89GWQ5P3MVC2YA8RA0EXFWCYQ6L3QQELH8KS")
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestV2ChunkSpoolEncryptsIndependentVerifiedFiles(t *testing.T) {
	identity := v2ChunkTestIdentity(t)
	chunkSize := uint64(1024 * 1024)
	plaintext := append(bytes.Repeat([]byte{0x31}, int(chunkSize)), []byte("tail")...)
	directory := t.TempDir()
	spool, err := spoolV2ChunkedPayload(bytes.NewReader(plaintext), directory, identity.Recipient(), chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if spool.PlaintextLength != uint64(len(plaintext)) || len(spool.Chunks) != 2 {
		t.Fatalf("spool size = %d in %d chunks", spool.PlaintextLength, len(spool.Chunks))
	}
	if spool.Chunks[0].CiphertextLength != 1050475 || spool.Chunks[1].CiphertextLength != 1663 {
		t.Fatalf("hybrid age ciphertext lengths = %d, %d", spool.Chunks[0].CiphertextLength, spool.Chunks[1].CiphertextLength)
	}
	wantPlaintextHash := sha256.Sum256(plaintext)
	if !bytes.Equal(spool.PlaintextHash, wantPlaintextHash[:]) {
		t.Fatal("whole plaintext hash does not match")
	}
	var restored bytes.Buffer
	for index, chunk := range spool.Chunks {
		body, err := os.ReadFile(chunk.Path)
		if err != nil {
			t.Fatal(err)
		}
		wantCiphertextHash := sha256.Sum256(body)
		if chunk.CiphertextLength != uint64(len(body)) || !bytes.Equal(chunk.CiphertextHash, wantCiphertextHash[:]) {
			t.Fatalf("chunk %d ciphertext declaration does not match", index)
		}
		decrypted, err := age.Decrypt(bytes.NewReader(body), identity)
		if err != nil {
			t.Fatal(err)
		}
		part, err := io.ReadAll(decrypted)
		if err != nil {
			t.Fatal(err)
		}
		if uint64(len(part)) != chunk.PlaintextLength {
			t.Fatalf("chunk %d plaintext length = %d", index, len(part))
		}
		restored.Write(part)
	}
	if !bytes.Equal(restored.Bytes(), plaintext) {
		t.Fatal("decrypted chunks do not reassemble the source")
	}
}

func TestV2ChunkSpoolRemovesFilesAfterSourceFailure(t *testing.T) {
	directory := t.TempDir()
	_, err := spoolV2ChunkedPayload(
		&v2FailingReader{remaining: 1024*1024 + 32},
		directory,
		v2ChunkTestIdentity(t).Recipient(),
		1024*1024,
	)
	if err == nil || !strings.Contains(err.Error(), "source interrupted") {
		t.Fatalf("source failure error = %v", err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for index, entry := range entries {
			names[index] = entry.Name()
		}
		t.Fatalf("failed spool retained files: %v", names)
	}
}

func TestV2ChunkSpoolRejectsSingleChunkAndUnregisteredSize(t *testing.T) {
	directory := t.TempDir()
	identity := v2ChunkTestIdentity(t)
	if _, err := spoolV2ChunkedPayload(bytes.NewReader([]byte("small")), directory, identity.Recipient(), 1024*1024); err == nil {
		t.Fatal("single chunk was accepted")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("single-chunk refusal retained a file")
	}
	if _, err := spoolV2ChunkedPayload(bytes.NewReader(nil), filepath.Join(directory, "invalid"), identity.Recipient(), 2*1024*1024); err == nil {
		t.Fatal("unregistered chunk size was accepted")
	}
}
