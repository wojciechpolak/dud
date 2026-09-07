// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

func descriptorV2ChunkManifest(descriptor map[int]any, manifest []v2ChunkManifestPart) (uint64, uint64, []byte, error) {
	chunkSize, sizeOK := asV2Uint(descriptor[kChunkSize])
	plaintextLength, lengthOK := asV2Uint(descriptor[kPlaintextSize])
	chunkIDs, idsOK := v2ByteArray(descriptor[kChunkIDs])
	chunkHashes, hashesOK := v2ByteArray(descriptor[kChunkHashes])
	plaintextHash, hashOK := descriptor[kPayloadHash].([]byte)
	if !sizeOK || !lengthOK || !idsOK || !hashesOK || !hashOK || len(plaintextHash) != 32 || len(chunkIDs) != len(manifest) || len(chunkHashes) != len(manifest) {
		return 0, 0, nil, errors.New("signed chunk layout does not match the inbox manifest")
	}
	for index, part := range manifest {
		if !bytes.Equal(part.ID, chunkIDs[index]) || !bytes.Equal(part.Digest, chunkHashes[index]) {
			return 0, 0, nil, errors.New("signed chunk layout does not match the inbox manifest")
		}
	}
	return chunkSize, plaintextLength, append([]byte(nil), plaintextHash...), nil
}

func inboundV2ChunkParts(directory string, manifest []v2ChunkManifestPart) []v2InboundChunkPart {
	parts := make([]v2InboundChunkPart, len(manifest))
	for index, part := range manifest {
		id := hex.EncodeToString(part.ID)
		parts[index] = v2InboundChunkPart{
			ID:               id,
			Path:             filepath.Join(directory, id+".age"),
			CiphertextLength: part.Length,
			CiphertextHash:   hex.EncodeToString(part.Digest),
		}
	}
	return parts
}

func matchesV2InboundChunkState(transfer v2InboundTransfer, delivery *v2GranularInboxDelivery, descriptorDigest string, sequence, chunkSize, plaintextLength uint64, plaintextHash, policyDigest []byte, parts []v2InboundChunkPart) bool {
	if transfer.EntryID != hex.EncodeToString(delivery.ID) || transfer.Slot != hex.EncodeToString(delivery.Slot) || transfer.DescriptorDigest != descriptorDigest || transfer.Sequence != sequence || transfer.ChunkSize != chunkSize || transfer.PlaintextLength != plaintextLength || transfer.OutputDigest != hex.EncodeToString(plaintextHash) || transfer.PolicyDigest != hex.EncodeToString(policyDigest) {
		return false
	}
	if (transfer.Phase == "payload-verified" || transfer.Phase == "output-committed") && len(transfer.Chunks) == 0 {
		return true
	}
	if len(transfer.Chunks) != len(parts) {
		return false
	}
	for index, part := range parts {
		stored := transfer.Chunks[index]
		if stored.ID != part.ID || stored.Path != part.Path || stored.CiphertextLength != part.CiphertextLength || stored.CiphertextHash != part.CiphertextHash {
			return false
		}
	}
	return true
}

func discardV2InboundChunks(transfer v2InboundTransfer) error {
	var result error
	directories := map[string]bool{}
	for _, part := range transfer.Chunks {
		for _, path := range []string{part.Path, part.Path + ".tmp"} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
		}
		directories[filepath.Dir(part.Path)] = true
	}
	for directory := range directories {
		if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func verifyV2ChunkFile(path string, length uint64, digest []byte) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, int64(length)+1))
	return err == nil && written == int64(length) && bytes.Equal(hasher.Sum(nil), digest)
}

func writeV2DownloadedChunk(path string, stream *v2ChunkStream) error {
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(stream.Body, int64(stream.Length)+1))
	closeStreamErr := stream.Body.Close()
	if copyErr != nil || closeStreamErr != nil || written != int64(stream.Length) || !bytes.Equal(hasher.Sum(nil), stream.Digest) {
		return errors.Join(copyErr, closeStreamErr, errors.New("downloaded chunk does not match the signed manifest"))
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func assembleV2ChunkedPlaintext(target string, parts []v2InboundChunkPart, chunkSize, plaintextLength uint64, plaintextHash []byte, identity age.Identity) error {
	temporary := target + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	plaintextHasher := sha256.New()
	var total uint64
	for index, part := range parts {
		ciphertext, err := os.Open(part.Path)
		if err != nil {
			return err
		}
		decrypted, decryptErr := age.Decrypt(ciphertext, identity)
		if decryptErr != nil {
			_ = ciphertext.Close()
			return fmt.Errorf("decrypt peer chunk %d: %w", index+1, decryptErr)
		}
		expected := chunkSize
		if index == len(parts)-1 {
			expected = plaintextLength - total
		}
		written, copyErr := io.Copy(io.MultiWriter(file, plaintextHasher), io.LimitReader(decrypted, int64(expected)+1))
		closeErr := ciphertext.Close()
		if copyErr != nil || closeErr != nil || written != int64(expected) {
			return errors.Join(copyErr, closeErr, errors.New("decrypted chunk length does not match the signed descriptor"))
		}
		total += uint64(written)
	}
	if total != plaintextLength || !bytes.Equal(plaintextHasher.Sum(nil), plaintextHash) {
		return errors.New("assembled plaintext does not match the signed descriptor")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func atomicCopyV2File(target, source string) error {
	directory := filepath.Dir(target)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(target)+".tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		_ = temporary.Close()
		return err
	}
	_, copyErr := io.Copy(temporary, input)
	inputErr := input.Close()
	if copyErr != nil || inputErr != nil {
		_ = temporary.Close()
		return errors.Join(copyErr, inputErr)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, target)
}

func (runtime *v2PeerRuntime) receiveV2ChunkedPayload(ctx context.Context, delivery *v2GranularInboxDelivery, envelope *validatedV2Envelope, sourceSlotEpoch uint64, policyDigest []byte, sequence, expiresAt uint64) (string, [32]byte, v2InboundTransfer, bool, error) {
	var resultDigest [32]byte
	descriptorDigest := hex.EncodeToString(envelope.DescriptorDigest[:])
	chunkSize, plaintextLength, plaintextHash, err := descriptorV2ChunkManifest(envelope.Descriptor, delivery.Chunks)
	if err != nil {
		return "", resultDigest, v2InboundTransfer{}, false, err
	}
	copy(resultDigest[:], plaintextHash)
	transferDirectory := filepath.Join(runtime.paths.StateDir, "transfers", runtime.state.RelationshipID)
	chunkDirectory := filepath.Join(transferDirectory, descriptorDigest+".chunks")
	if err := os.MkdirAll(chunkDirectory, 0o700); err != nil {
		return "", resultDigest, v2InboundTransfer{}, false, err
	}
	parts := inboundV2ChunkParts(chunkDirectory, delivery.Chunks)
	durableOutput := filepath.Join(transferDirectory, descriptorDigest)
	transfer, resume := runtime.state.InboundTransfers[descriptorDigest]
	if resume {
		if !matchesV2InboundChunkState(transfer, delivery, descriptorDigest, sequence, chunkSize, plaintextLength, plaintextHash, policyDigest, parts) {
			if err := discardV2InboundChunks(transfer); err != nil {
				return "", resultDigest, v2InboundTransfer{}, true, fmt.Errorf("discard conflicting inbound chunk state: %w", err)
			}
			delete(runtime.state.InboundTransfers, descriptorDigest)
			if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
				return "", resultDigest, v2InboundTransfer{}, true, err
			}
			resume = false
		}
	}
	if !resume {
		if err := os.MkdirAll(chunkDirectory, 0o700); err != nil {
			return "", resultDigest, v2InboundTransfer{}, false, err
		}
		transfer = v2InboundTransfer{
			EntryID:              hex.EncodeToString(delivery.ID),
			Slot:                 hex.EncodeToString(delivery.Slot),
			DescriptorDigest:     descriptorDigest,
			Sequence:             sequence,
			Phase:                "chunks-downloading",
			TemporaryOutput:      durableOutput,
			OutputDigest:         hex.EncodeToString(plaintextHash),
			PolicyDigest:         hex.EncodeToString(policyDigest),
			DescriptorCiphertext: v2Base64URL(delivery.EncryptedDescriptor),
			ChunkSize:            chunkSize,
			PlaintextLength:      plaintextLength,
			Chunks:               parts,
			ExpiresAt:            expiresAt,
		}
		runtime.state.InboundTransfers[descriptorDigest] = transfer
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return "", resultDigest, v2InboundTransfer{}, false, err
		}
	}
	if transfer.Phase == "payload-verified" || transfer.Phase == "output-committed" {
		if !verifyV2ChunkFile(durableOutput, plaintextLength, plaintextHash) {
			return "", resultDigest, v2InboundTransfer{}, resume, errors.New("durable peer output conflicts with the signed delivery")
		}
		return durableOutput, resultDigest, transfer, resume, nil
	}
	available, err := v2AvailableBytes(chunkDirectory)
	if err != nil {
		return "", resultDigest, v2InboundTransfer{}, resume, err
	}
	needed := plaintextLength
	for _, part := range transfer.Chunks {
		if !part.Downloaded {
			needed += part.CiphertextLength
		}
	}
	if available < needed {
		return "", resultDigest, v2InboundTransfer{}, resume, fmt.Errorf("resumable receive needs %d bytes but only %d bytes are free", needed, available)
	}
	readSecret, err := v2CapabilitySecret(runtime.state, v2InboundDirection(runtime.state.Role), "read")
	if err != nil {
		return "", resultDigest, v2InboundTransfer{}, resume, err
	}
	var downloadTotal int64
	reusable := make([]bool, len(transfer.Chunks))
	var downloadedBase int64
	for index, part := range transfer.Chunks {
		downloadTotal += int64(part.CiphertextLength)
		digest, _ := hex.DecodeString(part.CiphertextHash)
		if verifyV2ChunkFile(part.Path, part.CiphertextLength, digest) {
			reusable[index] = true
			downloadedBase += int64(part.CiphertextLength)
		}
	}
	if runtime.progress != nil {
		runtime.progress.PhaseResumed("downloading", downloadedBase, downloadTotal)
	}
	for index := range transfer.Chunks {
		part := &transfer.Chunks[index]
		if reusable[index] {
			if !part.Downloaded {
				part.Downloaded = true
				runtime.state.InboundTransfers[descriptorDigest] = transfer
				if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
					return "", resultDigest, v2InboundTransfer{}, resume, err
				}
			}
			continue
		}
		part.Downloaded = false
		_ = os.Remove(part.Path)
		_ = os.Remove(part.Path + ".tmp")
		proof, err := newV2GranularSlotProofInput(readSecret, v2DirectionName(v2InboundDirection(runtime.state.Role)), "read", v2GranularDataChain, delivery.Slot, sourceSlotEpoch, time.Now())
		if err != nil {
			return "", resultDigest, v2InboundTransfer{}, resume, err
		}
		base := downloadedBase
		stream, err := getV2DeliveryChunkObserved(ctx, runtime.transport, runtime.origin, delivery.ID, delivery.Chunks[index], proof, func(transferred, _ int64) {
			if runtime.progress != nil {
				runtime.progress.Set(base+transferred, downloadTotal)
			}
		})
		if err != nil {
			return "", resultDigest, v2InboundTransfer{}, resume, err
		}
		if err := writeV2DownloadedChunk(part.Path, stream); err != nil {
			return "", resultDigest, v2InboundTransfer{}, resume, err
		}
		part.Downloaded = true
		downloadedBase += int64(part.CiphertextLength)
		if runtime.progress != nil {
			runtime.progress.Set(downloadedBase, downloadTotal)
		}
		runtime.state.InboundTransfers[descriptorDigest] = transfer
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return "", resultDigest, v2InboundTransfer{}, resume, err
		}
	}
	if runtime.progress != nil {
		runtime.progress.Phase("verification and completion", 0)
	}
	if verifyV2ChunkFile(durableOutput, plaintextLength, plaintextHash) {
		transfer.Phase = "payload-verified"
	} else {
		_ = os.Remove(durableOutput + ".tmp")
		if err := assembleV2ChunkedPlaintext(durableOutput, transfer.Chunks, chunkSize, plaintextLength, plaintextHash, runtime.identity); err != nil {
			return "", resultDigest, v2InboundTransfer{}, resume, err
		}
		transfer.Phase = "payload-verified"
	}
	transfer.PlaintextPayload = durableOutput
	transfer.TemporaryOutput = durableOutput
	runtime.state.InboundTransfers[descriptorDigest] = transfer
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return "", resultDigest, v2InboundTransfer{}, resume, err
	}
	for _, part := range transfer.Chunks {
		_ = os.Remove(part.Path)
	}
	_ = os.Remove(chunkDirectory)
	transfer.Chunks = nil
	runtime.state.InboundTransfers[descriptorDigest] = transfer
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return "", resultDigest, v2InboundTransfer{}, resume, err
	}
	return durableOutput, resultDigest, transfer, resume, nil
}
