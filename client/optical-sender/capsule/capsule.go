// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package capsule encodes the private metadata and payload that an optical
// transfer encrypts before fountain encoding.
package capsule

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/wojciechpolak/dud/client/drop"
)

const (
	Version             = 1
	HeaderSize          = 64
	MaxDisplayNameBytes = 255
	MaxPayloadSize      = 64 * 1024 * 1024
)

var (
	magic                = [8]byte{'D', 'U', 'D', 'C', 'A', 'P', '1', 0}
	ErrUnsupportedFormat = errors.New("unsupported optical capsule")
	ErrArchive           = errors.New("validate capsule collection")
	ErrDigestMismatch    = errors.New("capsule plaintext digest does not match its payload")
)

type Metadata struct {
	Type          drop.PayloadType
	DisplayName   string
	PlaintextSize uint64
	PlaintextSHA  [sha256.Size]byte
	ArchiveFormat drop.ArchiveFormat
}

func Encode(payload []byte, metadata Metadata) ([]byte, error) {
	metadata.PlaintextSize = uint64(len(payload))
	metadata.PlaintextSHA = sha256.Sum256(payload)
	if err := validateMetadata(metadata); err != nil {
		return nil, err
	}
	result := make([]byte, HeaderSize+len(metadata.DisplayName)+len(payload))
	copy(result[0:8], magic[:])
	result[8] = Version
	result[9] = byte(metadata.Type)
	result[10] = byte(metadata.ArchiveFormat)
	binary.BigEndian.PutUint16(result[12:14], HeaderSize)
	binary.BigEndian.PutUint16(result[14:16], uint16(len(metadata.DisplayName)))
	binary.BigEndian.PutUint64(result[16:24], metadata.PlaintextSize)
	binary.BigEndian.PutUint64(result[24:32], uint64(len(payload)))
	copy(result[32:64], metadata.PlaintextSHA[:])
	copy(result[64:], metadata.DisplayName)
	copy(result[64+len(metadata.DisplayName):], payload)
	return result, nil
}

func WriteFile(outputPath string, input drop.PreparedInput) error {
	info, err := os.Stat(input.Path)
	if err != nil {
		return err
	}
	if info.Size() < 0 || info.Size() > MaxPayloadSize {
		return errors.New("capsule plaintext exceeds 64 MiB")
	}
	payload, err := os.ReadFile(input.Path)
	if err != nil {
		return err
	}
	if input.Type == drop.PayloadCollection {
		payload, err = normalizeCollection(payload)
		if err != nil {
			return err
		}
	}
	encoded, err := Encode(payload, Metadata{
		Type:          input.Type,
		DisplayName:   input.DisplayName,
		ArchiveFormat: input.ArchiveFormat,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, encoded, 0o600)
}

func Decode(encoded []byte) (Metadata, []byte, error) {
	if len(encoded) < HeaderSize {
		return Metadata{}, nil, errors.New("capsule is shorter than its fixed header")
	}
	if string(encoded[0:8]) == "DUDCAP0\x00" {
		return Metadata{}, nil, fmt.Errorf("%w; expected dud/optical/1, received format 0", ErrUnsupportedFormat)
	}
	if string(encoded[0:8]) != string(magic[:]) {
		return Metadata{}, nil, fmt.Errorf("%w: capsule magic is invalid", ErrUnsupportedFormat)
	}
	if encoded[8] != Version {
		return Metadata{}, nil, fmt.Errorf("%w; expected dud/optical/1, received format %d", ErrUnsupportedFormat, encoded[8])
	}
	if encoded[11] != 0 {
		return Metadata{}, nil, errors.New("capsule reserved byte is nonzero")
	}
	if binary.BigEndian.Uint16(encoded[12:14]) != HeaderSize {
		return Metadata{}, nil, errors.New("capsule header length is invalid")
	}
	nameLength := int(binary.BigEndian.Uint16(encoded[14:16]))
	payloadLength := binary.BigEndian.Uint64(encoded[24:32])
	if nameLength < 1 || nameLength > MaxDisplayNameBytes {
		return Metadata{}, nil, errors.New("capsule display name length is invalid")
	}
	if payloadLength > MaxPayloadSize {
		return Metadata{}, nil, errors.New("capsule payload exceeds 64 MiB")
	}
	expectedLength := uint64(HeaderSize) + uint64(nameLength) + payloadLength
	if expectedLength != uint64(len(encoded)) {
		return Metadata{}, nil, errors.New("capsule length does not match its metadata")
	}
	metadata := Metadata{
		Type:          drop.PayloadType(encoded[9]),
		ArchiveFormat: drop.ArchiveFormat(encoded[10]),
		DisplayName:   string(encoded[64 : 64+nameLength]),
		PlaintextSize: binary.BigEndian.Uint64(encoded[16:24]),
	}
	copy(metadata.PlaintextSHA[:], encoded[32:64])
	if err := validateMetadata(metadata); err != nil {
		return Metadata{}, nil, err
	}
	if metadata.PlaintextSize != payloadLength {
		return Metadata{}, nil, errors.New("capsule plaintext size does not match its payload length")
	}
	payload := encoded[64+nameLength:]
	digest := sha256.Sum256(payload)
	if digest != metadata.PlaintextSHA {
		return Metadata{}, nil, ErrDigestMismatch
	}
	if metadata.Type == drop.PayloadCollection {
		_, err := InspectCollection(payload)
		if err != nil {
			return Metadata{}, nil, fmt.Errorf("%w: %w", ErrArchive, err)
		}
	}
	result := append([]byte(nil), payload...)
	return metadata, result, nil
}

func validateMetadata(metadata Metadata) error {
	if metadata.PlaintextSize > MaxPayloadSize {
		return errors.New("capsule plaintext exceeds 64 MiB")
	}
	if len(metadata.DisplayName) < 1 || len(metadata.DisplayName) > MaxDisplayNameBytes {
		return fmt.Errorf("capsule display name must contain 1 through %d bytes", MaxDisplayNameBytes)
	}
	if !utf8.ValidString(metadata.DisplayName) {
		return errors.New("capsule display name is not valid UTF-8")
	}
	if metadata.DisplayName == "." || metadata.DisplayName == ".." || strings.ContainsAny(metadata.DisplayName, "/\\") {
		return errors.New("capsule display name must be one path component")
	}
	for _, character := range metadata.DisplayName {
		if character < 0x20 || character == 0x7f {
			return errors.New("capsule display name contains a control character")
		}
	}
	switch metadata.Type {
	case drop.PayloadMessage, drop.PayloadStream, drop.PayloadFile:
		if metadata.ArchiveFormat != drop.ArchiveNone {
			return errors.New("capsule archive format conflicts with its payload type")
		}
	case drop.PayloadCollection:
		if metadata.ArchiveFormat != drop.ArchiveTar {
			return errors.New("capsule collection must use the tar archive format")
		}
	default:
		return fmt.Errorf("capsule payload type %d is invalid", metadata.Type)
	}
	return nil
}
