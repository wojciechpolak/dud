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
	defer func() { _ = file.Close() }()
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
	if err := setPrivatePathPermissions(temporary, false); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
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
	if err := setPrivatePathPermissions(temporary, false); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
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
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := setPrivatePathPermissions(temporary.Name(), false); err != nil {
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
	return replaceLocalFile(temporaryPath, target)
}

// openV2InboundChunkTransfer finds or creates the record that tracks a chunked
// delivery across runs, and reports whether an earlier run had already started
// it. A record that does not agree with the signed descriptor on every field
// describes a different delivery under the same digest, so its parts are
// discarded and the transfer starts again rather than mixing the two.
func (runtime *v2PeerRuntime) openV2InboundChunkTransfer(delivery *v2GranularInboxDelivery, descriptorDigest, chunkDirectory, durableOutput string, manifest v2InboundChunkManifest, parts []v2InboundChunkPart, policyDigest []byte, sequence, expiresAt uint64) (v2InboundTransfer, bool, error) {
	transfer, resume := runtime.state.InboundTransfers[descriptorDigest]
	if resume && !matchesV2InboundChunkState(transfer, delivery, descriptorDigest, sequence, manifest.chunkSize, manifest.plaintextLength, manifest.plaintextHash, policyDigest, parts) {
		if err := discardV2InboundChunks(transfer); err != nil {
			return v2InboundTransfer{}, true, fmt.Errorf("discard conflicting inbound chunk state: %w", err)
		}
		delete(runtime.state.InboundTransfers, descriptorDigest)
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return v2InboundTransfer{}, true, err
		}
		resume = false
	}
	if resume {
		return transfer, true, nil
	}
	if err := os.MkdirAll(chunkDirectory, 0o700); err != nil {
		return v2InboundTransfer{}, false, err
	}
	transfer = v2InboundTransfer{
		EntryID:              hex.EncodeToString(delivery.ID),
		Slot:                 hex.EncodeToString(delivery.Slot),
		DescriptorDigest:     descriptorDigest,
		Sequence:             sequence,
		Phase:                "chunks-downloading",
		TemporaryOutput:      durableOutput,
		OutputDigest:         hex.EncodeToString(manifest.plaintextHash),
		PolicyDigest:         hex.EncodeToString(policyDigest),
		DescriptorCiphertext: v2Base64URL(delivery.EncryptedDescriptor),
		ChunkSize:            manifest.chunkSize,
		PlaintextLength:      manifest.plaintextLength,
		Chunks:               parts,
		ExpiresAt:            expiresAt,
	}
	runtime.state.InboundTransfers[descriptorDigest] = transfer
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return v2InboundTransfer{}, false, err
	}
	return transfer, false, nil
}

// checkV2InboundChunkSpace refuses a transfer that cannot finish on this disk.
// The reservation covers the parts still to download plus the assembled
// plaintext, because both exist at once until the parts are removed.
func checkV2InboundChunkSpace(chunkDirectory string, transfer v2InboundTransfer, plaintextLength uint64) error {
	available, err := v2AvailableBytes(chunkDirectory)
	if err != nil {
		return err
	}
	needed := plaintextLength
	for _, part := range transfer.Chunks {
		if !part.Downloaded {
			needed += part.CiphertextLength
		}
	}
	if available < needed {
		return fmt.Errorf("resumable receive needs %d bytes but only %d bytes are free", needed, available)
	}
	return nil
}

// downloadV2InboundChunks fetches the parts this device does not already hold.
// A part already on disk whose contents hash to what the descriptor signed is
// kept, so an interrupted receive re-downloads only what is missing. The
// file's digest decides that, not the record, so a part truncated by a crash is
// detected and fetched again.
func (runtime *v2PeerRuntime) downloadV2InboundChunks(ctx context.Context, delivery *v2GranularInboxDelivery, descriptorDigest string, transfer *v2InboundTransfer, sourceSlotEpoch uint64) error {
	readSecret, err := v2CapabilitySecret(runtime.state, v2InboundDirection(runtime.state.Role), "read")
	if err != nil {
		return err
	}
	var downloadTotal, downloadedBase int64
	reusable := make([]bool, len(transfer.Chunks))
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
				runtime.state.InboundTransfers[descriptorDigest] = *transfer
				if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
					return err
				}
			}
			continue
		}
		part.Downloaded = false
		_ = os.Remove(part.Path)
		_ = os.Remove(part.Path + ".tmp")
		proof, err := newV2GranularSlotProofInput(readSecret, v2DirectionName(v2InboundDirection(runtime.state.Role)), "read", v2GranularDataChain, delivery.Slot, sourceSlotEpoch, time.Now())
		if err != nil {
			return err
		}
		base := downloadedBase
		stream, err := getV2DeliveryChunkObserved(ctx, runtime.transport, runtime.origin, delivery.ID, delivery.Chunks[index], proof, func(transferred, _ int64) {
			if runtime.progress != nil {
				runtime.progress.Set(base+transferred, downloadTotal)
			}
		})
		if err != nil {
			return err
		}
		if err := writeV2DownloadedChunk(part.Path, stream); err != nil {
			return err
		}
		part.Downloaded = true
		downloadedBase += int64(part.CiphertextLength)
		if runtime.progress != nil {
			runtime.progress.Set(downloadedBase, downloadTotal)
		}
		runtime.state.InboundTransfers[descriptorDigest] = *transfer
		if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
			return err
		}
	}
	return nil
}

// assembleV2InboundPayload decrypts the downloaded parts into the single
// plaintext the descriptor signed and drops the parts. The assembled file is
// recorded before the parts are removed, so an interrupted assembly leaves
// either the parts to retry from or a verified payload, never neither.
func (runtime *v2PeerRuntime) assembleV2InboundPayload(descriptorDigest, durableOutput, chunkDirectory string, transfer *v2InboundTransfer, manifest v2InboundChunkManifest) error {
	if runtime.progress != nil {
		runtime.progress.Phase("verification and completion", 0)
	}
	if !verifyV2ChunkFile(durableOutput, manifest.plaintextLength, manifest.plaintextHash) {
		_ = os.Remove(durableOutput + ".tmp")
		if err := assembleV2ChunkedPlaintext(durableOutput, transfer.Chunks, manifest.chunkSize, manifest.plaintextLength, manifest.plaintextHash, runtime.identity); err != nil {
			return err
		}
	}
	transfer.Phase = "payload-verified"
	transfer.PlaintextPayload = durableOutput
	transfer.TemporaryOutput = durableOutput
	runtime.state.InboundTransfers[descriptorDigest] = *transfer
	if err := writeV2PeerDeliveryState(runtime.paths, runtime.state); err != nil {
		return err
	}
	for _, part := range transfer.Chunks {
		_ = os.Remove(part.Path)
	}
	_ = os.Remove(chunkDirectory)
	transfer.Chunks = nil
	runtime.state.InboundTransfers[descriptorDigest] = *transfer
	return writeV2PeerDeliveryState(runtime.paths, runtime.state)
}

// v2InboundChunkManifest holds what a chunked descriptor commits to about the
// payload as a whole: the size each part covers, the total plaintext length,
// and the digest the assembled plaintext must have.
type v2InboundChunkManifest struct {
	chunkSize       uint64
	plaintextLength uint64
	plaintextHash   []byte
}

// receiveV2ChunkedPayload downloads and reassembles a delivery that arrived as
// separate parts, and reports the path of the assembled plaintext together with
// its digest and whether the work resumed an earlier run. Every step records
// its progress before the next begins, so an interrupted receive continues from
// where it stopped rather than re-downloading the payload.
func (runtime *v2PeerRuntime) receiveV2ChunkedPayload(ctx context.Context, delivery *v2GranularInboxDelivery, envelope *validatedV2Envelope, sourceSlotEpoch uint64, policyDigest []byte, sequence, expiresAt uint64) (string, [32]byte, v2InboundTransfer, bool, error) {
	var resultDigest [32]byte
	descriptorDigest := hex.EncodeToString(envelope.DescriptorDigest[:])
	chunkSize, plaintextLength, plaintextHash, err := descriptorV2ChunkManifest(envelope.Descriptor, delivery.Chunks)
	if err != nil {
		return "", resultDigest, v2InboundTransfer{}, false, err
	}
	manifest := v2InboundChunkManifest{chunkSize: chunkSize, plaintextLength: plaintextLength, plaintextHash: plaintextHash}
	copy(resultDigest[:], plaintextHash)
	transferDirectory := filepath.Join(runtime.paths.StateDir, "transfers", runtime.state.RelationshipID)
	chunkDirectory := filepath.Join(transferDirectory, descriptorDigest+".chunks")
	if err := os.MkdirAll(chunkDirectory, 0o700); err != nil {
		return "", resultDigest, v2InboundTransfer{}, false, err
	}
	parts := inboundV2ChunkParts(chunkDirectory, delivery.Chunks)
	durableOutput := filepath.Join(transferDirectory, descriptorDigest)
	transfer, resume, err := runtime.openV2InboundChunkTransfer(delivery, descriptorDigest, chunkDirectory, durableOutput, manifest, parts, policyDigest, sequence, expiresAt)
	if err != nil {
		return "", resultDigest, v2InboundTransfer{}, resume, err
	}
	// A transfer that already reached its payload still has to prove the
	// assembled file is the one the descriptor signed: nothing else guards a
	// durable output that was replaced between runs.
	if transfer.Phase == "payload-verified" || transfer.Phase == "output-committed" {
		if !verifyV2ChunkFile(durableOutput, plaintextLength, plaintextHash) {
			return "", resultDigest, v2InboundTransfer{}, resume, errors.New("durable peer output conflicts with the signed delivery")
		}
		return durableOutput, resultDigest, transfer, resume, nil
	}
	if err := checkV2InboundChunkSpace(chunkDirectory, transfer, plaintextLength); err != nil {
		return "", resultDigest, v2InboundTransfer{}, resume, err
	}
	if err := runtime.downloadV2InboundChunks(ctx, delivery, descriptorDigest, &transfer, sourceSlotEpoch); err != nil {
		return "", resultDigest, v2InboundTransfer{}, resume, err
	}
	if err := runtime.assembleV2InboundPayload(descriptorDigest, durableOutput, chunkDirectory, &transfer, manifest); err != nil {
		return "", resultDigest, v2InboundTransfer{}, resume, err
	}
	return durableOutput, resultDigest, transfer, resume, nil
}
