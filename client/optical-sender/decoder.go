// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package optical

import (
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"math/bits"
	"slices"
)

type equation struct {
	coefficients []uint64
	payload      []byte
}

type stripeDecoder struct {
	sourceCount int
	stripeLen   int
	blockSize   int
	basis       map[int]*equation
}

// Decoder reconstructs one optical session. The fixed capsule and stripe
// limits bound its unfinished equation state.
type Decoder struct {
	initialized bool
	sessionID   [SessionIDSize]byte
	digest      [CapsuleDigestSize]byte
	capsuleLen  int
	stripeCount int
	blockSize   int
	active      map[int]*stripeDecoder
	recovered   map[int][]byte
}

// Progress reports independent equations and completed stripes.
type Progress struct {
	StripeIndex      int
	IndependentRows  int
	SourceCount      int
	RecoveredStripes int
	StripeCount      int
}

// NewDecoder creates an empty, session-specific decoder.
func NewDecoder() *Decoder {
	return &Decoder{
		active:    make(map[int]*stripeDecoder),
		recovered: make(map[int][]byte),
	}
}

// Add parses one frame and adds its equation when it belongs to this session.
func (d *Decoder) Add(data []byte) (Progress, error) {
	frame, err := ParseFrame(data)
	if err != nil {
		return Progress{}, err
	}
	if !d.initialized {
		d.initialized = true
		d.sessionID = frame.SessionID
		d.digest = frame.Digest
		d.capsuleLen = int(frame.CapsuleLen)
		d.stripeCount = int(frame.StripeCount)
		d.blockSize = int(frame.BlockSize)
	} else if frame.SessionID != d.sessionID || frame.Digest != d.digest || int(frame.CapsuleLen) != d.capsuleLen || int(frame.StripeCount) != d.stripeCount || int(frame.BlockSize) != d.blockSize {
		return Progress{}, reject("session", "frame belongs to a different or inconsistent session")
	}

	stripeIndex := int(frame.StripeIndex)
	if _, complete := d.recovered[stripeIndex]; complete {
		return d.progress(stripeIndex, int(frame.SourceCount), int(frame.SourceCount)), nil
	}
	stripe := d.active[stripeIndex]
	if stripe == nil {
		if len(d.active) >= MaxActiveStripes {
			return Progress{}, reject("active-stripes", "unfinished stripe count exceeds %d", MaxActiveStripes)
		}
		stripe = &stripeDecoder{
			sourceCount: int(frame.SourceCount),
			stripeLen:   int(frame.StripeLen),
			blockSize:   int(frame.BlockSize),
			basis:       make(map[int]*equation),
		}
		d.active[stripeIndex] = stripe
	}
	row := &equation{coefficients: make([]uint64, (stripe.sourceCount+63)/64), payload: frame.Payload}
	for _, index := range SelectBlocks(frame.SessionID, frame.StripeIndex, frame.Sequence, stripe.sourceCount) {
		row.coefficients[index/64] |= uint64(1) << (index % 64)
	}
	independent, err := stripe.add(row)
	if err != nil {
		return Progress{}, err
	}
	if independent && len(stripe.basis) == stripe.sourceCount {
		decoded := stripe.solve()
		d.recovered[stripeIndex] = decoded
		delete(d.active, stripeIndex)
	}
	return d.progress(stripeIndex, len(stripe.basis), stripe.sourceCount), nil
}

func (d *Decoder) progress(stripeIndex, rows, sources int) Progress {
	return Progress{
		StripeIndex:      stripeIndex,
		IndependentRows:  rows,
		SourceCount:      sources,
		RecoveredStripes: len(d.recovered),
		StripeCount:      d.stripeCount,
	}
}

// Complete reports whether every stripe has been recovered.
func (d *Decoder) Complete() bool {
	return d.initialized && len(d.recovered) == d.stripeCount
}

// Result joins recovered stripes and verifies the complete capsule digest.
func (d *Decoder) Result() ([]byte, error) {
	if !d.Complete() {
		return nil, reject("incomplete", "not every stripe has been recovered")
	}
	result := make([]byte, 0, d.capsuleLen)
	for index := 0; index < d.stripeCount; index++ {
		stripe, ok := d.recovered[index]
		if !ok {
			return nil, reject("incomplete", "stripe %d has not been recovered", index)
		}
		result = append(result, stripe...)
	}
	result = result[:d.capsuleLen]
	digest := sha256.Sum256(result)
	if digest != d.digest {
		return nil, reject("digest", "reconstructed capsule digest does not match")
	}
	return result, nil
}

func (s *stripeDecoder) add(row *equation) (bool, error) {
	for {
		pivot := firstSet(row.coefficients)
		if pivot < 0 {
			if slices.ContainsFunc(row.payload[:], func(value byte) bool { return value != 0 }) {
				return false, reject("contradiction", "dependent equation has a nonzero payload")
			}
			return false, nil
		}
		existing := s.basis[pivot]
		if existing == nil {
			s.basis[pivot] = row
			return true, nil
		}
		xorEquation(row, existing)
	}
}

func (s *stripeDecoder) solve() []byte {
	blocks := make([][]byte, s.sourceCount)
	for index := range blocks {
		blocks[index] = make([]byte, s.blockSize)
	}
	for pivot := s.sourceCount - 1; pivot >= 0; pivot-- {
		row := s.basis[pivot]
		copy(blocks[pivot], row.payload)
		for index := pivot + 1; index < s.sourceCount; index++ {
			if row.coefficients[index/64]&(uint64(1)<<(index%64)) != 0 {
				for offset := range blocks[pivot] {
					blocks[pivot][offset] ^= blocks[index][offset]
				}
			}
		}
	}
	result := make([]byte, 0, s.stripeLen)
	for index := range blocks {
		result = append(result, blocks[index]...)
	}
	return result[:s.stripeLen]
}

func xorEquation(target, source *equation) {
	for index := range target.coefficients {
		target.coefficients[index] ^= source.coefficients[index]
	}
	for index := range target.payload {
		target.payload[index] ^= source.payload[index]
	}
}

func firstSet(coefficients []uint64) int {
	for wordIndex, word := range coefficients {
		if word != 0 {
			return wordIndex*64 + bits.TrailingZeros64(word)
		}
	}
	return -1
}

// RecomputeCRC updates a mutated fixture so parsers reach field validation.
func RecomputeCRC(frame []byte) {
	if len(frame) >= HeaderSize+4 {
		binary.BigEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
	}
}
