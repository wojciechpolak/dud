// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package optical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type testVectorFile struct {
	Format      int    `json:"format"`
	GeneratedBy string `json:"generatedBy"`
	SessionID   string `json:"sessionId"`
	Selection   []struct {
		Stripe      int    `json:"stripe"`
		Sequence    uint32 `json:"sequence"`
		SourceCount int    `json:"sourceCount"`
		Selected    []int  `json:"selected"`
	} `json:"selection"`
	Cases []struct {
		Name          string `json:"name"`
		Recipe        string `json:"recipe"`
		CapsuleLength int    `json:"capsuleLength"`
		BlockSize     int    `json:"blockSize"`
		Digest        string `json:"digest"`
		Frames        []struct {
			Stripe   int    `json:"stripe"`
			Sequence uint32 `json:"sequence"`
			Selected []int  `json:"selected"`
			Bytes    string `json:"bytes"`
		} `json:"frames"`
	} `json:"cases"`
	Invalid []struct {
		Name  string `json:"name"`
		Code  string `json:"code"`
		Bytes string `json:"bytes"`
	} `json:"invalid"`
	Hostile []struct {
		Name            string   `json:"name"`
		Frames          []string `json:"frames"`
		Repeat          int      `json:"repeat"`
		Code            string   `json:"code"`
		IndependentRows int      `json:"independentRows"`
	} `json:"hostile"`
}

func TestTypeScriptVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/format1/typescript-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors testVectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Format != 1 || vectors.GeneratedBy != "typescript" {
		t.Fatalf("unexpected vector source: format=%d generator=%q", vectors.Format, vectors.GeneratedBy)
	}
	var sessionID [SessionIDSize]byte
	decodedSession, err := hex.DecodeString(vectors.SessionID)
	if err != nil || len(decodedSession) != len(sessionID) {
		t.Fatalf("invalid session ID: %v", err)
	}
	copy(sessionID[:], decodedSession)
	for _, vector := range vectors.Selection {
		got := SelectBlocks(sessionID, uint16(vector.Stripe), vector.Sequence, vector.SourceCount)
		if !equalInts(got, vector.Selected) {
			t.Fatalf("selection stripe=%d sequence=%d: got %v, want %v", vector.Stripe, vector.Sequence, got, vector.Selected)
		}
	}
	for _, vector := range vectors.Cases {
		if vector.Recipe != "index-73-page-19-plus-41" {
			t.Fatalf("unsupported vector recipe %q", vector.Recipe)
		}
		capsule := vectorTestCapsule(vector.CapsuleLength)
		digest := sha256.Sum256(capsule)
		if hex.EncodeToString(digest[:]) != vector.Digest {
			t.Fatalf("%s: capsule digest does not match recipe", vector.Name)
		}
		encoder, err := NewEncoderWithBlockSize(capsule, sessionID, vector.BlockSize)
		if err != nil {
			t.Fatal(err)
		}
		decoder := NewDecoder()
		for _, expected := range vector.Frames {
			got, err := encoder.Frame(expected.Stripe, expected.Sequence)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != expected.Bytes {
				t.Fatalf("%s stripe=%d sequence=%d: frame differs", vector.Name, expected.Stripe, expected.Sequence)
			}
			count, _ := encoder.SourceCount(expected.Stripe)
			selected := SelectBlocks(sessionID, uint16(expected.Stripe), expected.Sequence, count)
			if !equalInts(selected, expected.Selected) {
				t.Fatalf("%s stripe=%d sequence=%d: selected blocks differ", vector.Name, expected.Stripe, expected.Sequence)
			}
			if vector.Name == "complete-capsule" || vector.Name == "high-density-complete" {
				if _, err := decoder.Add(mustDecodeHex(t, expected.Bytes)); err != nil {
					t.Fatal(err)
				}
			}
		}
		if vector.Name == "complete-capsule" || vector.Name == "high-density-complete" {
			result, err := decoder.Result()
			if err != nil {
				t.Fatal(err)
			}
			if !equalBytes(result, capsule) {
				t.Fatal("TypeScript frames recovered different capsule bytes")
			}
		}
	}
	assertInvalidTypeScriptVectors(t, vectors)
	assertHostileTypeScriptVectors(t, vectors)
}

func assertInvalidTypeScriptVectors(t *testing.T, vectors testVectorFile) {
	t.Helper()
	for _, vector := range vectors.Invalid {
		_, err := ParseFrame(mustDecodeHex(t, vector.Bytes))
		var codecError *CodecError
		if !errors.As(err, &codecError) || codecError.Code != vector.Code {
			t.Fatalf("invalid %s (%s): got %v", vector.Name, vector.Code, err)
		}
	}
}

func assertHostileTypeScriptVectors(t *testing.T, vectors testVectorFile) {
	t.Helper()
	for _, vector := range vectors.Hostile {
		t.Run(vector.Name, func(t *testing.T) {
			decoder := NewDecoder()
			var progress Progress
			var gotErr error
			for range vector.Repeat {
				for _, encoded := range vector.Frames {
					next, addErr := decoder.Add(mustDecodeHex(t, encoded))
					if addErr != nil {
						gotErr = addErr
						break
					}
					progress = next
				}
				if gotErr != nil {
					break
				}
			}
			if vector.Code == "" {
				if gotErr != nil {
					t.Fatal(gotErr)
				}
			} else {
				var codecError *CodecError
				if !errors.As(gotErr, &codecError) || codecError.Code != vector.Code {
					t.Fatalf("got %v, want %s", gotErr, vector.Code)
				}
			}
			if progress.IndependentRows != vector.IndependentRows {
				t.Fatalf("independent rows=%d, want %d", progress.IndependentRows, vector.IndependentRows)
			}
		})
	}
}

func TestRoundTripAcrossStripeBoundary(t *testing.T) {
	capsule := vectorTestCapsule(MaxStripeSize + BlockSize + 7)
	var sessionID [SessionIDSize]byte
	for index := range sessionID {
		sessionID[index] = byte(255 - index)
	}
	encoder, err := NewEncoder(capsule, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	decoder := NewDecoder()
	for stripe := 0; stripe < encoder.StripeCount(); stripe++ {
		count, _ := encoder.SourceCount(stripe)
		for sequence := range count {
			frame, _ := encoder.Frame(stripe, uint32(sequence))
			if _, err := decoder.Add(frame); err != nil {
				t.Fatal(err)
			}
		}
	}
	result, err := decoder.Result()
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(result, capsule) {
		t.Fatal("round trip changed capsule bytes")
	}
}

func TestHighDensityProfileRoundTripsAcrossStripeBoundary(t *testing.T) {
	capsule := vectorTestCapsule(HighDensityBlockSize*MaxSourceBlocks + HighDensityBlockSize + 7)
	var sessionID [SessionIDSize]byte
	for index := range sessionID {
		sessionID[index] = byte(index*11 + 3)
	}
	encoder, err := NewEncoderWithBlockSize(capsule, sessionID, HighDensityBlockSize)
	if err != nil {
		t.Fatal(err)
	}
	if encoder.StripeCount() != 2 {
		t.Fatalf("stripe count=%d, want 2", encoder.StripeCount())
	}
	decoder := NewDecoder()
	for stripe := 0; stripe < encoder.StripeCount(); stripe++ {
		count, _ := encoder.SourceCount(stripe)
		for sequence := range count {
			frame, frameErr := encoder.Frame(stripe, uint32(sequence))
			if frameErr != nil {
				t.Fatal(frameErr)
			}
			if len(frame) != HighDensityFrameSize {
				t.Fatalf("frame size=%d, want %d", len(frame), HighDensityFrameSize)
			}
			parsed, parseErr := ParseFrame(frame)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if parsed.BlockSize != HighDensityBlockSize {
				t.Fatalf("block size=%d, want %d", parsed.BlockSize, HighDensityBlockSize)
			}
			if _, addErr := decoder.Add(frame); addErr != nil {
				t.Fatal(addErr)
			}
		}
	}
	result, err := decoder.Result()
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(result, capsule) {
		t.Fatal("high-density round trip changed capsule bytes")
	}
}

func TestRepairFramesRecoverFiftyPercentUniformLoss(t *testing.T) {
	capsule := vectorTestCapsule(48 * BlockSize)
	var sessionID [SessionIDSize]byte
	encoder, _ := NewEncoder(capsule, sessionID)
	decoder := NewDecoder()
	for sequence := uint32(0); sequence < 4000 && !decoder.Complete(); sequence++ {
		if sequence%2 == 0 {
			continue
		}
		frame, _ := encoder.Frame(0, sequence)
		if _, err := decoder.Add(frame); err != nil {
			t.Fatal(err)
		}
	}
	result, err := decoder.Result()
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(result, capsule) {
		t.Fatal("repair recovery changed capsule bytes")
	}
}

func TestMaximumDegreeRepairSequencesCoverEverySourceBlock(t *testing.T) {
	const sourceCount = MaxStripeSize / BlockSize
	var sessionID [SessionIDSize]byte
	for index := range sessionID {
		sessionID[index] = byte(index*19 + 7)
	}
	encoder, err := NewEncoder(make([]byte, MaxStripeSize), sessionID)
	if err != nil {
		t.Fatal(err)
	}

	covered := make([]bool, sourceCount)
	remaining := sourceCount
	nextSequence := uint64(sourceCount + sourceCount/2)
	for range 1600 {
		sequence, err := encoder.NextMaximumDegreeRepairSequence(0, nextSequence)
		if err != nil {
			t.Fatal(err)
		}
		indexes := SelectBlocks(sessionID, 0, sequence, sourceCount)
		if len(indexes) != maximumRepairDegree {
			t.Fatalf("sequence %d degree=%d, want %d", sequence, len(indexes), maximumRepairDegree)
		}
		for _, index := range indexes {
			if !covered[index] {
				covered[index] = true
				remaining--
			}
		}
		if remaining == 0 {
			return
		}
		nextSequence = uint64(sequence) + 1
	}
	t.Fatalf("maximum-degree recovery left %d of %d source blocks untouched", remaining, sourceCount)
}

func TestMaximumDegreeRepairSequenceRejectsExhaustedSpace(t *testing.T) {
	encoder, err := NewEncoder(make([]byte, BlockSize), [SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = encoder.NextMaximumDegreeRepairSequence(0, uint64(^uint32(0))+1)
	assertCodecError(t, err, "repair-sequence")
}

func TestDecoderRejectsContradictoryDuplicate(t *testing.T) {
	capsule := vectorTestCapsule(2 * BlockSize)
	var sessionID [SessionIDSize]byte
	encoder, _ := NewEncoder(capsule, sessionID)
	frame, _ := encoder.Frame(0, 0)
	decoder := NewDecoder()
	if _, err := decoder.Add(frame); err != nil {
		t.Fatal(err)
	}
	contradiction := append([]byte(nil), frame...)
	contradiction[HeaderSize] ^= 1
	RecomputeCRC(contradiction)
	_, err := decoder.Add(contradiction)
	assertCodecError(t, err, "contradiction")
}

func TestDecoderBudgetCoversEveryBoundedCapsuleStripe(t *testing.T) {
	if MaxActiveStripes != MaxStripeCount {
		t.Fatalf("active stripe limit=%d, want maximum stripe count %d", MaxActiveStripes, MaxStripeCount)
	}
	capsule := vectorTestCapsule(16 * 1024 * 1024)
	var sessionID [SessionIDSize]byte
	encoder, _ := NewEncoder(capsule, sessionID)
	decoder := NewDecoder()
	for stripe := 0; stripe < encoder.StripeCount(); stripe++ {
		frame, _ := encoder.Frame(stripe, 0)
		progress, err := decoder.Add(frame)
		if err != nil {
			t.Fatal(err)
		}
		if progress.IndependentRows != 1 {
			t.Fatalf("stripe %d rows=%d, want 1", stripe, progress.IndependentRows)
		}
	}
	if encoder.StripeCount() != 11 || len(decoder.active) != 11 {
		t.Fatalf("encoder stripes=%d active decoder stripes=%d, want 11", encoder.StripeCount(), len(decoder.active))
	}
}

func vectorTestCapsule(length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = byte(index*73 + (index>>8)*19 + 41)
	}
	return result
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertCodecError(t *testing.T, err error, code string) {
	t.Helper()
	var codecError *CodecError
	if !errors.As(err, &codecError) || codecError.Code != code {
		t.Fatalf("got %v, want codec error %q", err, code)
	}
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestFormatZeroFramesAreRejectedBeforeSessionAllocation(t *testing.T) {
	data, err := os.ReadFile("testdata/format0/typescript-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var archived struct {
		Cases []struct{ Frames []struct{ Bytes string } }
	}
	if err := json.Unmarshal(data, &archived); err != nil {
		t.Fatal(err)
	}
	for _, item := range archived.Cases {
		for _, vector := range item.Frames {
			decoder := NewDecoder()
			_, err := decoder.Add(mustDecodeHex(t, vector.Bytes))
			var codecErr *CodecError
			if !errors.As(err, &codecErr) || codecErr.Code != "version" || codecErr.Message != "unsupported optical sender; expected dud/optical/1, received format 0" || decoder.initialized || len(decoder.active) != 0 {
				t.Fatalf("format-0 result = %v, %#v", err, decoder)
			}
		}
	}
}
