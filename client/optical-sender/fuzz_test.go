// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package optical

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func FuzzParseFrame(f *testing.F) {
	data, err := os.ReadFile("testdata/format1/typescript-vectors.json")
	if err != nil {
		f.Fatal(err)
	}
	var vectors testVectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		f.Fatal(err)
	}
	add := func(encoded string) {
		seed, decodeErr := hex.DecodeString(encoded)
		if decodeErr != nil {
			f.Fatal(decodeErr)
		}
		f.Add(seed)
	}
	for _, vector := range vectors.Cases {
		for _, frame := range vector.Frames {
			add(frame.Bytes)
		}
	}
	for _, vector := range vectors.Invalid {
		add(vector.Bytes)
	}
	for _, vector := range vectors.Hostile {
		for _, frame := range vector.Frames {
			add(frame)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1024*1024 {
			return
		}
		frame, parseErr := ParseFrame(data)
		if parseErr != nil {
			var codecError *CodecError
			if !errors.As(parseErr, &codecError) {
				t.Fatalf("parser returned %T instead of CodecError", parseErr)
			}
			return
		}
		if len(frame.Payload) != int(frame.BlockSize) {
			t.Fatalf("payload length=%d, block size=%d", len(frame.Payload), frame.BlockSize)
		}
		if frame.SourceCount < 1 || frame.SourceCount > MaxSourceBlocks {
			t.Fatalf("accepted source count %d", frame.SourceCount)
		}
		if frame.Degree < 1 || frame.Degree > maximumRepairDegree {
			t.Fatalf("accepted fountain degree %d", frame.Degree)
		}
		if len(frame.Payload) > 0 {
			first := frame.Payload[0]
			data[HeaderSize] ^= 0xff
			if frame.Payload[0] != first {
				t.Fatal("parsed payload aliases the input frame")
			}
		}
	})
}
