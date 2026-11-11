// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package capsule

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/wojciechpolak/dud/client/drop"
)

func TestEncodingIsDeterministic(t *testing.T) {
	metadata := Metadata{Type: drop.PayloadFile, DisplayName: "note.txt"}
	first, err := Encode([]byte("hello"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encode([]byte("hello"), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("equal inputs produced different capsules")
	}
	want := "4455444341503100010300000040000800000000000000050000000000000005" +
		"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" +
		"6e6f74652e74787468656c6c6f"
	if hex.EncodeToString(first) != want {
		t.Fatalf("capsule = %x, want %s", first, want)
	}

	decodedMetadata, payload, err := Decode(first)
	if err != nil {
		t.Fatal(err)
	}
	if decodedMetadata.Type != drop.PayloadFile || decodedMetadata.DisplayName != "note.txt" ||
		decodedMetadata.ArchiveFormat != drop.ArchiveNone || decodedMetadata.PlaintextSize != 5 ||
		decodedMetadata.PlaintextSHA != sha256.Sum256([]byte("hello")) || string(payload) != "hello" {
		t.Fatalf("decoded capsule = %#v, %q", decodedMetadata, payload)
	}
}

func TestEncodingEnforcesMetadataBounds(t *testing.T) {
	tests := []Metadata{
		{Type: drop.PayloadFile, DisplayName: ""},
		{Type: drop.PayloadFile, DisplayName: strings.Repeat("a", MaxDisplayNameBytes+1)},
		{Type: drop.PayloadFile, DisplayName: "../file"},
		{Type: drop.PayloadFile, DisplayName: "bad\nname"},
		{Type: drop.PayloadType(99), DisplayName: "file"},
		{Type: drop.PayloadFile, DisplayName: "file", ArchiveFormat: drop.ArchiveTar},
		{Type: drop.PayloadCollection, DisplayName: "files.tar", ArchiveFormat: drop.ArchiveNone},
	}
	for _, metadata := range tests {
		if _, err := Encode([]byte("x"), metadata); err == nil {
			t.Fatalf("invalid metadata was accepted: %#v", metadata)
		}
	}
}

func TestDecoderRejectsMalformedMetadataBeforePayloadUse(t *testing.T) {
	valid, err := Encode([]byte("payload"), Metadata{Type: drop.PayloadFile, DisplayName: "file.bin"})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]byte) []byte{
		"short header":      func(input []byte) []byte { return input[:HeaderSize-1] },
		"magic":             func(input []byte) []byte { input[0] ^= 1; return input },
		"version":           func(input []byte) []byte { input[8]++; return input },
		"reserved":          func(input []byte) []byte { input[11] = 1; return input },
		"header length":     func(input []byte) []byte { input[13]--; return input },
		"empty name":        func(input []byte) []byte { binary.BigEndian.PutUint16(input[14:16], 0); return input },
		"payload type":      func(input []byte) []byte { input[9] = 99; return input },
		"archive format":    func(input []byte) []byte { input[10] = byte(drop.ArchiveTar); return input },
		"plaintext size":    func(input []byte) []byte { binary.BigEndian.PutUint64(input[16:24], 1); return input },
		"payload length":    func(input []byte) []byte { binary.BigEndian.PutUint64(input[24:32], 1); return input },
		"oversized payload": func(input []byte) []byte { binary.BigEndian.PutUint64(input[24:32], MaxPayloadSize+1); return input },
		"trailing byte":     func(input []byte) []byte { return append(input, 0) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(append([]byte(nil), valid...))
			if _, _, err := Decode(candidate); err == nil {
				t.Fatal("malformed capsule was accepted")
			}
		})
	}
}

func TestDecoderValidatesPlaintextDigest(t *testing.T) {
	encoded, err := Encode([]byte("payload"), Metadata{Type: drop.PayloadMessage, DisplayName: "message.txt"})
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)-1] ^= 1
	if _, _, err := Decode(encoded); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("error = %v, want digest mismatch", err)
	}
}

func TestFileRejectsOversizedPlaintextBeforeReadingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxPayloadSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	err = WriteFile(filepath.Join(t.TempDir(), "capsule"), drop.PreparedInput{
		Path: path, Type: drop.PayloadFile, DisplayName: "large.bin",
	})
	if err == nil || err.Error() != "capsule plaintext exceeds 64 MiB" {
		t.Fatalf("error = %v", err)
	}
}

func TestSavedCiphertextDecryptsWithOriginalPassphraseOrIdentity(t *testing.T) {
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.ParseHybridIdentity("AGE-SECRET-KEY-PQ-1TNKN5N7GU6X7H46D69HMCT89GWQ5P3MVC2YA8RA0EXFWCYQ6L3QQELH8KS")
	if err != nil {
		t.Fatal(err)
	}
	passphraseRecipient, err := age.NewScryptRecipient("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	passphraseIdentity, err := age.NewScryptIdentity("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		recipient age.Recipient
		identity  age.Identity
	}{
		{name: "passphrase", recipient: passphraseRecipient, identity: passphraseIdentity},
		{name: "X25519", recipient: x25519.Recipient(), identity: x25519},
		{name: "hybrid post-quantum", recipient: hybrid.Recipient(), identity: hybrid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("private optical payload")
			encoded, err := Encode(payload, Metadata{Type: drop.PayloadMessage, DisplayName: "message.txt"})
			if err != nil {
				t.Fatal(err)
			}
			ciphertext := encryptAge(t, encoded, test.recipient)
			if bytes.Contains(ciphertext, payload) || bytes.Contains(ciphertext, []byte("message.txt")) {
				t.Fatal("ciphertext disclosed private capsule content")
			}

			saved := filepath.Join(t.TempDir(), "dud-encrypted-capsule.age")
			if err := os.WriteFile(saved, ciphertext, 0o600); err != nil {
				t.Fatal(err)
			}
			plaintext := decryptSavedAge(t, saved, test.identity)
			metadata, decoded, err := Decode(plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Type != drop.PayloadMessage || metadata.DisplayName != "message.txt" ||
				metadata.PlaintextSize != uint64(len(payload)) || metadata.PlaintextSHA != sha256.Sum256(payload) ||
				!bytes.Equal(decoded, payload) {
				t.Fatalf("decoded handoff = %#v, %q", metadata, decoded)
			}
		})
	}
}

func TestSavedCiphertextRejectsCorruption(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode([]byte("payload"), Metadata{Type: drop.PayloadFile, DisplayName: "file.bin"})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := encryptAge(t, encoded, identity.Recipient())
	ciphertext[len(ciphertext)-1] ^= 1
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	if err == nil {
		t.Fatal("corrupted saved ciphertext decrypted successfully")
	}
}

func TestCollectionCapsuleValidatesPreparedArchive(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.txt")
	second := filepath.Join(root, "second.txt")
	if err := os.WriteFile(first, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, err := drop.PrepareInput(filepath.Join(t.TempDir(), "collection.tar"), drop.InputOptions{
		Files: []string{first, second},
	}, drop.InputEnvironment{CommandOutput: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(prepared.Path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(payload, Metadata{
		Type: prepared.Type, DisplayName: prepared.DisplayName, ArchiveFormat: prepared.ArchiveFormat,
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata, decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Type != drop.PayloadCollection || metadata.ArchiveFormat != drop.ArchiveTar ||
		!bytes.Equal(decoded, payload) {
		t.Fatalf("decoded collection = %#v, %d bytes", metadata, len(decoded))
	}
}

func TestCollectionCapsuleRejectsUnsafeArchive(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(archive.Bytes(), Metadata{
		Type: drop.PayloadCollection, DisplayName: "dud-collection.tar", ArchiveFormat: drop.ArchiveTar,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(encoded); err == nil {
		t.Fatal("collection capsule accepted an unsafe archive path")
	}
}

func encryptAge(t *testing.T, plaintext []byte, recipient age.Recipient) []byte {
	t.Helper()
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return ciphertext.Bytes()
}

func decryptSavedAge(t *testing.T, path string, identity age.Identity) []byte {
	t.Helper()
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func TestFormatZeroCapsuleIsRejected(t *testing.T) {
	encoded, err := hex.DecodeString("4455444341503000000300000040000800000000000000050000000000000005" +
		"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" +
		"6e6f74652e74787468656c6c6f")
	if err != nil {
		t.Fatal(err)
	}
	metadata, payload, err := Decode(encoded)
	if err == nil || err.Error() != "unsupported optical capsule; expected dud/optical/1, received format 0" || payload != nil || metadata != (Metadata{}) {
		t.Fatalf("format-0 result = %#v, %x, %v", metadata, payload, err)
	}
}

func TestFormatOnePrivateContainerVectors(t *testing.T) {
	data, err := os.ReadFile("../testdata/format1/typescript-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		PrivateContainers []struct {
			Name          string
			PayloadType   uint8
			ArchiveFormat uint8
			DisplayName   string
			Payload       string
			Bytes         string
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.PrivateContainers) != 4 {
		t.Fatal("private container vector set is incomplete")
	}
	for _, vector := range vectors.PrivateContainers {
		t.Run(vector.Name, func(t *testing.T) {
			encoded, err := hex.DecodeString(vector.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			metadata, payload, err := Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Type != drop.PayloadType(vector.PayloadType) || metadata.ArchiveFormat != drop.ArchiveFormat(vector.ArchiveFormat) || metadata.DisplayName != vector.DisplayName || hex.EncodeToString(payload) != vector.Payload {
				t.Fatalf("vector differs: %#v, %x", metadata, payload)
			}
			actual, err := Encode(payload, metadata)
			if err != nil || !bytes.Equal(actual, encoded) {
				t.Fatalf("encode differs: %x, %v", actual, err)
			}
		})
	}
}

func TestBinaryAgeOverheadMatchesContainerLength(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 65536 - 72, 65537 - 72, MaxPayloadSize} {
		encoded, err := Encode(make([]byte, size), Metadata{Type: drop.PayloadFile, DisplayName: "note.txt"})
		if err != nil {
			t.Fatal(err)
		}
		var encrypted bytes.Buffer
		writer, err := age.Encrypt(&encrypted, identity.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(encoded); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		ciphertext := encrypted.Bytes()
		macStart := bytes.Index(ciphertext, []byte("\n--- ")) + 1
		if macStart < 1 {
			t.Fatal("missing age header MAC")
		}
		headerSize := macStart + bytes.IndexByte(ciphertext[macStart:], '\n') + 1
		chunks := (len(encoded) + 65535) / 65536
		expected := headerSize + 16 + len(encoded) + 16*chunks
		if len(ciphertext) != expected {
			t.Fatalf("ciphertext length %d, want %d", len(ciphertext), expected)
		}
		if size == MaxPayloadSize && len(ciphertext) <= MaxPayloadSize {
			t.Fatal("64 MiB plaintext must exceed the optical ciphertext limit")
		}
	}
}
