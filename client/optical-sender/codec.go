// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package optical implements the Go codec for dud/optical/1.
package optical

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const (
	FormatVersion        = 1
	HeaderSize           = 88
	BlockSize            = 1600
	HighDensityBlockSize = 2860
	FrameSize            = HeaderSize + BlockSize + 4
	HighDensityFrameSize = HeaderSize + HighDensityBlockSize + 4
	MaxSourceBlocks      = 1024
	MaxStripeSize        = BlockSize * MaxSourceBlocks
	MaxCapsuleSize       = 64 * 1024 * 1024
	MaxStripeCount       = (MaxCapsuleSize + MaxStripeSize - 1) / MaxStripeSize
	MaxActiveStripes     = MaxStripeCount
	SessionIDSize        = 16
	CapsuleDigestSize    = 32
	reservedFeatures     = 0
	maximumRepairDegree  = 31
	maximumRepairSearch  = 4096
)

var frameMagic = [8]byte{'D', 'U', 'D', 'O', 'P', 'T', '1', 0}

// CodecError identifies a stable rejection category shared with the TypeScript
// implementation. The message may give more detail without becoming a wire
// contract.
type CodecError struct {
	Code    string
	Message string
}

func (e *CodecError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func reject(code, format string, args ...any) error {
	return &CodecError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Frame is a validated optical equation.
type Frame struct {
	SessionID   [SessionIDSize]byte
	Sequence    uint32
	StripeIndex uint16
	StripeCount uint16
	SourceCount uint16
	BlockSize   uint16
	CapsuleLen  uint32
	StripeLen   uint32
	Degree      uint16
	Digest      [CapsuleDigestSize]byte
	Payload     []byte
}

// Encoder holds an immutable capsule and its public reconstruction metadata.
type Encoder struct {
	capsule    []byte
	sessionID  [SessionIDSize]byte
	digest     [CapsuleDigestSize]byte
	stripes    int
	blockSize  int
	stripeSize int
}

// NewEncoder validates and copies a capsule before any frames are produced.
func NewEncoder(capsule []byte, sessionID [SessionIDSize]byte) (*Encoder, error) {
	return NewEncoderWithBlockSize(capsule, sessionID, BlockSize)
}

// NewEncoderWithBlockSize selects one of the bounded optical profiles.
func NewEncoderWithBlockSize(capsule []byte, sessionID [SessionIDSize]byte, blockSize int) (*Encoder, error) {
	if len(capsule) == 0 || len(capsule) > MaxCapsuleSize {
		return nil, reject("capsule-length", "capsule length %d is outside 1..%d", len(capsule), MaxCapsuleSize)
	}
	if !validBlockSize(blockSize) {
		return nil, reject("block-size", "source block size %d is unsupported", blockSize)
	}
	copyOfCapsule := append([]byte(nil), capsule...)
	stripeSize := blockSize * MaxSourceBlocks
	return &Encoder{
		capsule:    copyOfCapsule,
		sessionID:  sessionID,
		digest:     sha256.Sum256(copyOfCapsule),
		stripes:    stripeCount(len(copyOfCapsule), stripeSize),
		blockSize:  blockSize,
		stripeSize: stripeSize,
	}, nil
}

// BlockSize returns the source-block size carried by every frame in the session.
func (e *Encoder) BlockSize() int {
	return e.blockSize
}

// StripeCount returns the number of independently recoverable stripes.
func (e *Encoder) StripeCount() int {
	return e.stripes
}

// SourceCount returns the number of source blocks in a stripe.
func (e *Encoder) SourceCount(stripeIndex int) (int, error) {
	_, length, err := e.stripeBounds(stripeIndex)
	if err != nil {
		return 0, err
	}
	return sourceCount(length, e.blockSize), nil
}

// NextMaximumDegreeRepairSequence returns the first fresh sequence whose
// equation has the format's highest degree for this stripe. The bounded search
// keeps display-frame generation finite even at the end of the sequence space.
func (e *Encoder) NextMaximumDegreeRepairSequence(stripeIndex int, start uint64) (uint32, error) {
	_, length, err := e.stripeBounds(stripeIndex)
	if err != nil {
		return 0, err
	}
	k := sourceCount(length, e.blockSize)
	if start < uint64(k) {
		start = uint64(k)
	}
	sequenceLimit := uint64(^uint32(0)) + 1
	if start >= sequenceLimit {
		return 0, reject("repair-sequence", "repair sequence space is exhausted")
	}
	searchLimit := min(start+maximumRepairSearch, sequenceLimit)
	wantDegree := min(maximumRepairDegree, k)
	for candidate := start; candidate < searchLimit; candidate++ {
		sequence := uint32(candidate)
		if len(SelectBlocks(e.sessionID, uint16(stripeIndex), sequence, k)) == wantDegree {
			return sequence, nil
		}
	}
	return 0, reject("repair-sequence", "no maximum-degree repair sequence in the bounded search from %d", start)
}

func (e *Encoder) stripeBounds(stripeIndex int) (int, int, error) {
	if stripeIndex < 0 || stripeIndex >= e.stripes {
		return 0, 0, reject("stripe-index", "stripe index %d is outside 0..%d", stripeIndex, e.stripes-1)
	}
	offset := stripeIndex * e.stripeSize
	length := min(e.stripeSize, len(e.capsule)-offset)
	return offset, length, nil
}

// Frame encodes one systematic or repair equation for a stripe.
func (e *Encoder) Frame(stripeIndex int, sequence uint32) ([]byte, error) {
	offset, length, err := e.stripeBounds(stripeIndex)
	if err != nil {
		return nil, err
	}
	k := sourceCount(length, e.blockSize)
	indexes := SelectBlocks(e.sessionID, uint16(stripeIndex), sequence, k)
	payload := make([]byte, e.blockSize)
	for _, index := range indexes {
		blockStart := offset + index*e.blockSize
		blockEnd := min(blockStart+e.blockSize, offset+length)
		for sourceOffset := blockStart; sourceOffset < blockEnd; sourceOffset++ {
			payload[sourceOffset-blockStart] ^= e.capsule[sourceOffset]
		}
	}

	frameSize := HeaderSize + e.blockSize + 4
	frame := make([]byte, frameSize)
	copy(frame[0:8], frameMagic[:])
	frame[8] = FormatVersion
	frame[9] = reservedFeatures
	binary.BigEndian.PutUint16(frame[10:12], HeaderSize)
	copy(frame[12:28], e.sessionID[:])
	binary.BigEndian.PutUint32(frame[28:32], sequence)
	binary.BigEndian.PutUint16(frame[32:34], uint16(stripeIndex))
	binary.BigEndian.PutUint16(frame[34:36], uint16(e.stripes))
	binary.BigEndian.PutUint16(frame[36:38], uint16(k))
	binary.BigEndian.PutUint16(frame[38:40], uint16(e.blockSize))
	binary.BigEndian.PutUint32(frame[40:44], uint32(len(e.capsule)))
	binary.BigEndian.PutUint32(frame[44:48], uint32(offset))
	binary.BigEndian.PutUint32(frame[48:52], uint32(length))
	binary.BigEndian.PutUint16(frame[52:54], uint16(e.blockSize))
	binary.BigEndian.PutUint16(frame[54:56], uint16(len(indexes)))
	copy(frame[56:88], e.digest[:])
	copy(frame[HeaderSize:HeaderSize+e.blockSize], payload)
	binary.BigEndian.PutUint32(frame[frameSize-4:], crc32.ChecksumIEEE(frame[:frameSize-4]))
	return frame, nil
}

// ParseFrame validates all fixed and derived fields before copying the payload.
func ParseFrame(data []byte) (Frame, error) {
	var frame Frame
	if len(data) < HeaderSize+4 {
		return frame, reject("frame-length", "frame length %d is shorter than the fixed framing", len(data))
	}
	if string(data[0:8]) == "DUDOPT0\x00" {
		return frame, reject("version", "unsupported optical sender; expected dud/optical/1, received format 0")
	}
	if string(data[0:8]) != string(frameMagic[:]) {
		return frame, reject("magic", "frame magic is invalid")
	}
	if data[8] != FormatVersion {
		return frame, reject("version", "unsupported optical sender; expected dud/optical/1, received format %d", data[8])
	}
	if data[9] != reservedFeatures {
		return frame, reject("features", "must-understand feature bits are set")
	}
	if binary.BigEndian.Uint16(data[10:12]) != HeaderSize {
		return frame, reject("header-length", "header length is invalid")
	}
	blockSize := int(binary.BigEndian.Uint16(data[38:40]))
	if !validBlockSize(blockSize) {
		return frame, reject("block-size", "source block size is invalid")
	}
	frameSize := HeaderSize + blockSize + 4
	if len(data) != frameSize {
		return frame, reject("frame-length", "frame length %d does not equal %d", len(data), frameSize)
	}
	if int(binary.BigEndian.Uint16(data[52:54])) != blockSize {
		return frame, reject("payload-length", "QR payload length is invalid")
	}
	wantCRC := binary.BigEndian.Uint32(data[frameSize-4:])
	if got := crc32.ChecksumIEEE(data[:frameSize-4]); got != wantCRC {
		return frame, reject("crc", "frame CRC-32 is invalid")
	}

	copy(frame.SessionID[:], data[12:28])
	frame.Sequence = binary.BigEndian.Uint32(data[28:32])
	frame.StripeIndex = binary.BigEndian.Uint16(data[32:34])
	frame.StripeCount = binary.BigEndian.Uint16(data[34:36])
	frame.SourceCount = binary.BigEndian.Uint16(data[36:38])
	frame.BlockSize = uint16(blockSize)
	frame.CapsuleLen = binary.BigEndian.Uint32(data[40:44])
	stripeOffset := binary.BigEndian.Uint32(data[44:48])
	frame.StripeLen = binary.BigEndian.Uint32(data[48:52])
	frame.Degree = binary.BigEndian.Uint16(data[54:56])
	copy(frame.Digest[:], data[56:88])

	if frame.CapsuleLen == 0 || frame.CapsuleLen > MaxCapsuleSize {
		return Frame{}, reject("capsule-length", "declared capsule length %d is outside the optical bound", frame.CapsuleLen)
	}
	stripeSize := blockSize * MaxSourceBlocks
	expectedStripes := stripeCount(int(frame.CapsuleLen), stripeSize)
	if int(frame.StripeCount) != expectedStripes || expectedStripes > MaxStripeCount {
		return Frame{}, reject("stripe-count", "stripe count is inconsistent with capsule length")
	}
	if int(frame.StripeIndex) >= expectedStripes {
		return Frame{}, reject("stripe-index", "stripe index is outside the capsule")
	}
	expectedOffset := int(frame.StripeIndex) * stripeSize
	expectedLength := min(stripeSize, int(frame.CapsuleLen)-expectedOffset)
	if int(stripeOffset) != expectedOffset {
		return Frame{}, reject("stripe-offset", "stripe offset is inconsistent with stripe index")
	}
	if int(frame.StripeLen) != expectedLength {
		return Frame{}, reject("stripe-length", "stripe length is inconsistent with capsule length")
	}
	expectedSources := sourceCount(expectedLength, blockSize)
	if int(frame.SourceCount) != expectedSources {
		return Frame{}, reject("source-count", "source-block count is inconsistent with stripe length")
	}
	indexes := SelectBlocks(frame.SessionID, frame.StripeIndex, frame.Sequence, expectedSources)
	if int(frame.Degree) != len(indexes) {
		return Frame{}, reject("degree", "fountain degree is inconsistent with frame sequence")
	}
	frame.Payload = append([]byte(nil), data[HeaderSize:HeaderSize+blockSize]...)
	return frame, nil
}

func validBlockSize(blockSize int) bool {
	return blockSize == BlockSize || blockSize == HighDensityBlockSize
}

func stripeCount(capsuleLength, stripeSize int) int {
	return (capsuleLength + stripeSize - 1) / stripeSize
}

func sourceCount(stripeLength, blockSize int) int {
	return (stripeLength + blockSize - 1) / blockSize
}

// SelectBlocks implements the integer-only selection algorithm from docs/protocol-optical.md.
func SelectBlocks(sessionID [SessionIDSize]byte, stripeIndex uint16, sequence uint32, k int) []int {
	if k < 1 || k > MaxSourceBlocks {
		panic("optical source-block count outside 1..1024")
	}
	if uint64(sequence) < uint64(k) {
		return []int{int(sequence)}
	}
	state := uint32(0x6d2b79f5)
	for _, value := range sessionID {
		state = mix32(state ^ uint32(value))
	}
	state = mix32(state ^ uint32(stripeIndex))
	state = mix32(state ^ sequence)
	next := func() uint32 {
		state += 0x9e3779b9
		state = mix32(state)
		return state
	}
	draw := next() % 1000
	degree := maximumRepairDegree
	switch {
	case draw < 500:
		degree = 2
	case draw < 750:
		degree = 3
	case draw < 875:
		degree = 4
	case draw < 938:
		degree = 5
	case draw < 969:
		degree = 6
	case draw < 985:
		degree = 7
	}
	degree = min(degree, k)
	selected := make([]int, 0, degree)
	for len(selected) < degree {
		candidate := int(next() % uint32(k))
		position := 0
		for position < len(selected) && selected[position] < candidate {
			position++
		}
		if position < len(selected) && selected[position] == candidate {
			continue
		}
		selected = append(selected, 0)
		copy(selected[position+1:], selected[position:])
		selected[position] = candidate
	}
	return selected
}

func mix32(value uint32) uint32 {
	value ^= value >> 16
	value *= 0x21f0aaad
	value ^= value >> 15
	value *= 0x735a2d97
	value ^= value >> 15
	return value
}
