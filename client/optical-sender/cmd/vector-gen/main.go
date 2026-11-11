// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
)

type selectionVector struct {
	Stripe      int    `json:"stripe"`
	Sequence    uint32 `json:"sequence"`
	SourceCount int    `json:"sourceCount"`
	Selected    []int  `json:"selected"`
}

type frameVector struct {
	Stripe   int    `json:"stripe"`
	Sequence uint32 `json:"sequence"`
	Selected []int  `json:"selected"`
	Bytes    string `json:"bytes"`
}

type caseVector struct {
	Name          string        `json:"name"`
	Recipe        string        `json:"recipe"`
	CapsuleLength int           `json:"capsuleLength"`
	BlockSize     int           `json:"blockSize"`
	Digest        string        `json:"digest"`
	Frames        []frameVector `json:"frames"`
}

type invalidVector struct {
	Name  string `json:"name"`
	Code  string `json:"code"`
	Bytes string `json:"bytes"`
}

type hostileStreamVector struct {
	Name            string   `json:"name"`
	Frames          []string `json:"frames"`
	Repeat          int      `json:"repeat"`
	Code            string   `json:"code,omitempty"`
	IndependentRows int      `json:"independentRows"`
}

type privateContainerVector struct {
	Name          string `json:"name"`
	PayloadType   uint8  `json:"payloadType"`
	ArchiveFormat uint8  `json:"archiveFormat"`
	DisplayName   string `json:"displayName"`
	Payload       string `json:"payload"`
	Bytes         string `json:"bytes"`
}

func privateContainers() []privateContainerVector {
	entries := []privateContainerVector{
		{Name: "hello-file", PayloadType: 3, DisplayName: "note.txt", Payload: "68656c6c6f"},
		{Name: "empty-stream", PayloadType: 2, DisplayName: "stdin.bin", Payload: ""},
		{Name: "binary-utf8-name", PayloadType: 1, DisplayName: "wiadomość.txt", Payload: "00ff0a7f"},
		{Name: "empty-collection", PayloadType: 4, ArchiveFormat: 1, DisplayName: "dud-collection.tar", Payload: hex.EncodeToString(make([]byte, 1024))},
	}
	for i := range entries {
		payload, err := hex.DecodeString(entries[i].Payload)
		if err != nil {
			panic(err)
		}
		encoded, err := capsule.Encode(payload, capsule.Metadata{Type: drop.PayloadType(entries[i].PayloadType), ArchiveFormat: drop.ArchiveFormat(entries[i].ArchiveFormat), DisplayName: entries[i].DisplayName})
		if err != nil {
			panic(err)
		}
		entries[i].Bytes = hex.EncodeToString(encoded)
	}
	return entries
}

type vectorFile struct {
	Format            int                      `json:"format"`
	GeneratedBy       string                   `json:"generatedBy"`
	SessionID         string                   `json:"sessionId"`
	Selection         []selectionVector        `json:"selection"`
	Cases             []caseVector             `json:"cases"`
	Invalid           []invalidVector          `json:"invalid"`
	Hostile           []hostileStreamVector    `json:"hostile"`
	PrivateContainers []privateContainerVector `json:"privateContainers"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: vector-gen OUTPUT.json")
		os.Exit(2)
	}
	var sessionID [optical.SessionIDSize]byte
	for index := range sessionID {
		sessionID[index] = byte(index * 17)
	}
	complete := buildCase("complete-capsule", 2401, optical.BlockSize, sessionID, [][2]uint32{
		{0, 0}, {0, 1}, {0, 2}, {0, 3}, {0, 4}, {0, 17},
	})
	boundary := buildCase("stripe-boundary", optical.MaxStripeSize+1, optical.BlockSize, sessionID, [][2]uint32{
		{0, 0}, {0, 1024}, {0, 1030}, {1, 0}, {1, 1},
	})
	highDensity := buildCase("high-density-complete", optical.HighDensityBlockSize*2+1, optical.HighDensityBlockSize, sessionID, [][2]uint32{
		{0, 0}, {0, 1}, {0, 2}, {0, 17},
	})
	base, err := hex.DecodeString(complete.Frames[0].Bytes)
	if err != nil {
		panic(err)
	}
	vectors := vectorFile{
		Format:      optical.FormatVersion,
		GeneratedBy: "go",
		SessionID:   hex.EncodeToString(sessionID[:]),
		Selection: []selectionVector{
			selection(sessionID, 0, 0, 4),
			selection(sessionID, 0, 4, 4),
			selection(sessionID, 0, 1121, 1024),
			selection(sessionID, 7, 1007, 1000),
			selection(sessionID, 85, 0xfffffffe, 1024),
		},
		Cases:             []caseVector{complete, boundary, highDensity},
		Invalid:           invalidVectors(base),
		Hostile:           hostileStreams(base),
		PrivateContainers: privateContainers(),
	}
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(os.Args[1], data, 0o644); err != nil {
		panic(err)
	}
}

func vectorCapsule(length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = byte(index*73 + (index>>8)*19 + 41)
	}
	return result
}

func selection(sessionID [optical.SessionIDSize]byte, stripe int, sequence uint32, count int) selectionVector {
	return selectionVector{
		Stripe:      stripe,
		Sequence:    sequence,
		SourceCount: count,
		Selected:    optical.SelectBlocks(sessionID, uint16(stripe), sequence, count),
	}
}

func buildCase(name string, length, blockSize int, sessionID [optical.SessionIDSize]byte, requested [][2]uint32) caseVector {
	capsule := vectorCapsule(length)
	encoder, err := optical.NewEncoderWithBlockSize(capsule, sessionID, blockSize)
	if err != nil {
		panic(err)
	}
	frames := make([]frameVector, 0, len(requested))
	for _, request := range requested {
		stripe := int(request[0])
		sequence := request[1]
		frame, err := encoder.Frame(stripe, sequence)
		if err != nil {
			panic(err)
		}
		count, err := encoder.SourceCount(stripe)
		if err != nil {
			panic(err)
		}
		frames = append(frames, frameVector{
			Stripe:   stripe,
			Sequence: sequence,
			Selected: optical.SelectBlocks(sessionID, uint16(stripe), sequence, count),
			Bytes:    hex.EncodeToString(frame),
		})
	}
	if name == "complete-capsule" || name == "high-density-complete" {
		decoder := optical.NewDecoder()
		count, _ := encoder.SourceCount(0)
		for sequence := range count {
			frame, _ := encoder.Frame(0, uint32(sequence))
			if _, err := decoder.Add(frame); err != nil {
				panic(err)
			}
		}
		if _, err := decoder.Result(); err != nil {
			panic(err)
		}
	}
	digest := sha256.Sum256(capsule)
	return caseVector{
		Name:          name,
		Recipe:        "index-73-page-19-plus-41",
		CapsuleLength: length,
		BlockSize:     blockSize,
		Digest:        hex.EncodeToString(digest[:]),
		Frames:        frames,
	}
}

func invalidVectors(base []byte) []invalidVector {
	return []invalidVector{
		{Name: "empty", Code: "frame-length", Bytes: ""},
		{Name: "truncated-header", Code: "frame-length", Bytes: hex.EncodeToString(base[:optical.HeaderSize])},
		{Name: "truncated-qr-payload", Code: "frame-length", Bytes: hex.EncodeToString(base[:len(base)-1])},
		{Name: "magic", Code: "magic", Bytes: hex.EncodeToString(mutate(base, 0, 0xff))},
		{Name: "version", Code: "version", Bytes: hex.EncodeToString(mutate(base, 8, 1))},
		{Name: "features", Code: "features", Bytes: hex.EncodeToString(mutate(base, 9, 1))},
		{Name: "header-length", Code: "header-length", Bytes: hex.EncodeToString(mutate(base, 11, 87))},
		{Name: "block-size", Code: "block-size", Bytes: hex.EncodeToString(mutate(base, 39, 1))},
		{Name: "payload-length", Code: "payload-length", Bytes: hex.EncodeToString(mutate(base, 53, 1))},
		{Name: "payload-length-maximum", Code: "payload-length", Bytes: hex.EncodeToString(setUint16(base, 52, 0xffff))},
		{Name: "crc", Code: "crc", Bytes: hex.EncodeToString(mutate(base, 100, 0x80))},
		{Name: "capsule-length-over-limit", Code: "capsule-length", Bytes: hex.EncodeToString(setUint32(base, 40, optical.MaxCapsuleSize+1))},
		{Name: "capsule-length-uint32-maximum", Code: "capsule-length", Bytes: hex.EncodeToString(setUint32(base, 40, 0xffffffff))},
		{Name: "stripe-count", Code: "stripe-count", Bytes: hex.EncodeToString(setUint16(base, 34, 2))},
		{Name: "stripe-count-maximum", Code: "stripe-count", Bytes: hex.EncodeToString(setUint16(base, 34, 0xffff))},
		{Name: "stripe-index-maximum", Code: "stripe-index", Bytes: hex.EncodeToString(setUint16(base, 32, 0xffff))},
		{Name: "stripe-offset", Code: "stripe-offset", Bytes: hex.EncodeToString(setUint32(base, 44, 1))},
		{Name: "stripe-offset-uint32-maximum", Code: "stripe-offset", Bytes: hex.EncodeToString(setUint32(base, 44, 0xffffffff))},
		{Name: "stripe-length", Code: "stripe-length", Bytes: hex.EncodeToString(setUint32(base, 48, 2400))},
		{Name: "stripe-length-uint32-maximum", Code: "stripe-length", Bytes: hex.EncodeToString(setUint32(base, 48, 0xffffffff))},
		{Name: "source-count", Code: "source-count", Bytes: hex.EncodeToString(setUint16(base, 36, 3))},
		{Name: "source-count-maximum", Code: "source-count", Bytes: hex.EncodeToString(setUint16(base, 36, 0xffff))},
		{Name: "impossible-fountain-degree", Code: "degree", Bytes: hex.EncodeToString(setUint16(base, 54, 0xffff))},
		{Name: "sequence-uint32-maximum", Code: "degree", Bytes: hex.EncodeToString(setUint32(base, 28, 0xffffffff))},
	}
}

func hostileStreams(base []byte) []hostileStreamVector {
	collidingSession := mutateWithCRC(base, 12, 0xff)
	digestSubstitution := mutateWithCRC(base, 56, 0xff)
	inconsistentMetadata := setUint32(base, 40, 2402)
	inconsistentMetadata = setUint32(inconsistentMetadata, 48, 2402)
	encodedBase := hex.EncodeToString(base)
	return []hostileStreamVector{
		{Name: "duplicate-equation", Frames: []string{encodedBase}, Repeat: 2, IndependentRows: 1},
		{Name: "endless-duplicate-stream", Frames: []string{encodedBase}, Repeat: 16384, IndependentRows: 1},
		{Name: "colliding-session", Frames: []string{encodedBase, hex.EncodeToString(collidingSession)}, Repeat: 1, Code: "session", IndependentRows: 1},
		{Name: "digest-substitution", Frames: []string{encodedBase, hex.EncodeToString(digestSubstitution)}, Repeat: 1, Code: "session", IndependentRows: 1},
		{Name: "inconsistent-session-metadata", Frames: []string{encodedBase, hex.EncodeToString(inconsistentMetadata)}, Repeat: 1, Code: "session", IndependentRows: 1},
	}
}

func mutate(value []byte, offset int, xor byte) []byte {
	copyOfValue := append([]byte(nil), value...)
	copyOfValue[offset] ^= xor
	return copyOfValue
}

func mutateWithCRC(value []byte, offset int, xor byte) []byte {
	copyOfValue := mutate(value, offset, xor)
	optical.RecomputeCRC(copyOfValue)
	return copyOfValue
}

func setUint32(value []byte, offset int, replacement uint32) []byte {
	copyOfValue := append([]byte(nil), value...)
	binary.BigEndian.PutUint32(copyOfValue[offset:offset+4], replacement)
	optical.RecomputeCRC(copyOfValue)
	return copyOfValue
}

func setUint16(value []byte, offset, replacement int) []byte {
	copyOfValue := append([]byte(nil), value...)
	binary.BigEndian.PutUint16(copyOfValue[offset:offset+2], uint16(replacement))
	optical.RecomputeCRC(copyOfValue)
	return copyOfValue
}
