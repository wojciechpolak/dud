// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

type v2SpooledChunk struct {
	ID               []byte
	Path             string
	PlaintextLength  uint64
	CiphertextLength uint64
	CiphertextHash   []byte
}

type v2ChunkSpool struct {
	PlaintextLength uint64
	PlaintextHash   []byte
	Chunks          []v2SpooledChunk
}

type v2CountingWriter struct {
	written uint64
	writer  io.Writer
}

func (writer *v2CountingWriter) Write(value []byte) (int, error) {
	written, err := writer.writer.Write(value)
	writer.written += uint64(written)
	return written, err
}

func newV2ChunkID() ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return id, nil
}

func removeV2SpooledChunks(chunks []v2SpooledChunk) error {
	var result error
	for _, chunk := range chunks {
		if err := os.Remove(chunk.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func removeV2TemporaryChunk(path string, cause error) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, err)
	}
	return cause
}

func spoolV2ChunkedPayload(source io.Reader, spoolDir string, recipient age.Recipient, chunkSize uint64) (_ *v2ChunkSpool, resultErr error) {
	return spoolV2ChunkedPayloadObserved(source, spoolDir, recipient, chunkSize, 0, nil)
}

func spoolV2ChunkedPayloadObserved(source io.Reader, spoolDir string, recipient age.Recipient, chunkSize, plaintextTotal uint64, observe func(int64, int64)) (_ *v2ChunkSpool, resultErr error) {
	if source == nil || recipient == nil {
		return nil, errors.New("chunk spool source and recipient are required")
	}
	if !validV2ChunkSize(chunkSize) {
		return nil, errors.New("chunk spool size is not registered")
	}
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(spoolDir, 0o700); err != nil {
		return nil, err
	}

	spool := &v2ChunkSpool{Chunks: []v2SpooledChunk{}}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, removeV2SpooledChunks(spool.Chunks))
		}
	}()
	observedSource := source
	if observe != nil {
		observe(0, int64(plaintextTotal))
		observedSource = &v2ObservedReader{reader: source, total: int64(plaintextTotal), observe: observe}
	}
	buffered := bufio.NewReaderSize(observedSource, 64*1024)
	plaintextHash := sha256.New()
	copyBuffer := make([]byte, 64*1024)
	for {
		if _, err := buffered.Peek(1); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read chunk source: %w", err)
		}
		if len(spool.Chunks) >= v2MaximumChunkCount {
			return nil, errors.New("chunk spool exceeds the maximum chunk count")
		}
		if spool.PlaintextLength >= v2MaximumChunkedBytes {
			return nil, errors.New("chunk spool exceeds the maximum plaintext size")
		}
		id, err := newV2ChunkID()
		if err != nil {
			return nil, err
		}
		name := hex.EncodeToString(id) + ".age"
		finalPath := filepath.Join(spoolDir, name)
		temporaryPath := filepath.Join(spoolDir, "."+name+".tmp")
		file, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		ciphertextHash := sha256.New()
		ciphertext := &v2CountingWriter{writer: io.MultiWriter(file, ciphertextHash)}
		encrypted, err := age.Encrypt(ciphertext, recipient)
		if err != nil {
			return nil, removeV2TemporaryChunk(temporaryPath, errors.Join(err, file.Close()))
		}
		limited := &io.LimitedReader{R: buffered, N: int64(chunkSize)}
		plaintextLength, copyErr := io.CopyBuffer(io.MultiWriter(encrypted, plaintextHash), limited, copyBuffer)
		closeErr := encrypted.Close()
		syncErr := file.Sync()
		fileErr := file.Close()
		if copyErr != nil || closeErr != nil || syncErr != nil || fileErr != nil {
			return nil, removeV2TemporaryChunk(temporaryPath, errors.Join(copyErr, closeErr, syncErr, fileErr))
		}
		if plaintextLength <= 0 {
			return nil, removeV2TemporaryChunk(temporaryPath, errors.New("chunk spool produced an empty part"))
		}
		if spool.PlaintextLength+uint64(plaintextLength) > v2MaximumChunkedBytes {
			return nil, removeV2TemporaryChunk(temporaryPath, errors.New("chunk spool exceeds the maximum plaintext size"))
		}
		if err := os.Rename(temporaryPath, finalPath); err != nil {
			return nil, removeV2TemporaryChunk(temporaryPath, err)
		}
		spool.PlaintextLength += uint64(plaintextLength)
		spool.Chunks = append(spool.Chunks, v2SpooledChunk{
			ID:               id,
			Path:             finalPath,
			PlaintextLength:  uint64(plaintextLength),
			CiphertextLength: ciphertext.written,
			CiphertextHash:   ciphertextHash.Sum(nil),
		})
	}
	if len(spool.Chunks) < 2 {
		return nil, errors.New("chunked transfer requires at least two chunks")
	}
	spool.PlaintextHash = plaintextHash.Sum(nil)
	return spool, nil
}
