// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package capsule

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/wojciechpolak/dud/client/drop"
)

func FuzzPrivateCapsuleDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("DUDCAP0\x00"))
	for _, payloadType := range []drop.PayloadType{drop.PayloadMessage, drop.PayloadStream, drop.PayloadFile} {
		encoded, err := Encode([]byte{0, 1, 127, 128, 255}, Metadata{Type: payloadType, DisplayName: "zażółć.bin"})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
		for _, offset := range []int{8, 9, 10, 11, 12, 14, 16, 24, 32} {
			malformed := append([]byte(nil), encoded...)
			malformed[offset] = 255
			f.Add(malformed)
		}
	}
	var collection bytes.Buffer
	writer := tar.NewWriter(&collection)
	if err := writer.WriteHeader(&tar.Header{Name: "file.bin", Mode: 0o600, Size: 3, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		f.Fatal(err)
	}
	if _, err := writer.Write([]byte{0, 128, 255}); err != nil {
		f.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		f.Fatal(err)
	}
	encoded, err := Encode(collection.Bytes(), Metadata{Type: drop.PayloadCollection, DisplayName: "files.tar", ArchiveFormat: drop.ArchiveTar})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, data []byte) {
		// Fuzz input bounds limit harness work; the decoder enforces the capsule limit.
		if len(data) > 1024*1024 {
			t.Skip()
		}
		metadata, payload, err := Decode(data)
		if err != nil {
			return
		}
		if uint64(len(payload)) != metadata.PlaintextSize || sha256.Sum256(payload) != metadata.PlaintextSHA {
			t.Fatal("accepted capsule has inconsistent payload metadata")
		}
		rebuilt, err := Encode(payload, metadata)
		if err != nil || !bytes.Equal(data, rebuilt) {
			t.Fatal("accepted capsule cannot reproduce its exact input")
		}
		if len(payload) > 0 {
			original := append([]byte(nil), data...)
			payload[len(payload)-1] ^= 255
			if !bytes.Equal(data, original) {
				t.Fatal("decoded payload aliases the encoded input")
			}
		}
	})
}

func FuzzPrivateCapsuleFileNameAndPayload(f *testing.F) {
	for _, name := range []string{"file.bin", "zażółć.bin", "", "..", "../file", "bad\x00name", "bad\nname", "bad\\name", "\xff"} {
		f.Add(name, []byte{0, 127, 128, 255})
	}
	f.Fuzz(func(t *testing.T, name string, payload []byte) {
		if len(name) > 1024 || len(payload) > 64*1024 {
			t.Skip()
		}
		encoded, err := Encode(payload, Metadata{Type: drop.PayloadFile, DisplayName: name})
		if err != nil {
			return
		}
		metadata, recovered, err := Decode(encoded)
		if err != nil || metadata.DisplayName != name || metadata.Type != drop.PayloadFile || metadata.ArchiveFormat != drop.ArchiveNone || !bytes.Equal(recovered, payload) {
			t.Fatal("accepted file metadata or bytes fail round trip")
		}
	})
}
