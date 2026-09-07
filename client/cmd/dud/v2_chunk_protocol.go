// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
)

type v2ChunkManifestPart struct {
	ID     []byte
	Length uint64
	Digest []byte
}

type v2ChunkUploadResponse struct {
	UploadID        []byte
	ExpiresAt       uint64
	MissingChunkIDs [][]byte
	Idempotent      bool
}

type v2ChunkCommitResponse struct {
	DeliveryID []byte
	Idempotent bool
}

type v2ChunkStream struct {
	Body   io.ReadCloser
	Length uint64
	Digest []byte
}

func validateV2ChunkManifestPart(part v2ChunkManifestPart) error {
	if len(part.ID) != 16 || part.Length == 0 || part.Length > v2MaximumChunkCiphertextBytes || len(part.Digest) != sha256.Size {
		return errors.New("chunk manifest part is invalid")
	}
	return nil
}

func validateV2ChunkManifest(parts []v2ChunkManifestPart) (uint64, error) {
	if len(parts) < 2 || len(parts) > v2MaximumChunkCount {
		return 0, errors.New("chunk manifest has an invalid part count")
	}
	seen := map[string]bool{}
	var total uint64
	for _, part := range parts {
		if err := validateV2ChunkManifestPart(part); err != nil {
			return 0, err
		}
		key := string(part.ID)
		if seen[key] || total > math.MaxUint64-part.Length {
			return 0, errors.New("chunk manifest is invalid")
		}
		seen[key] = true
		total += part.Length
		if total > v2MaximumChunkedCiphertextBytes {
			return 0, errors.New("chunk manifest exceeds the maximum ciphertext size")
		}
	}
	return total, nil
}

func v2ChunkAuthorization(input v2GranularSlotProofInput, method, origin, path string, digest []byte) (string, error) {
	wrapper, err := encodeV2GranularSlotProof(input, method, origin, path, digest, 0, false)
	if err != nil {
		return "", err
	}
	proof, ok := wrapper[4].([]byte)
	if !ok || len(proof) == 0 {
		return "", errors.New("chunk authorization proof is invalid")
	}
	return "DUD2 " + base64.RawURLEncoding.EncodeToString(proof), nil
}

func v2ChunkHeaders(input v2GranularSlotProofInput, method, origin, path string, digest []byte) (http.Header, error) {
	authorization, err := v2ChunkAuthorization(input, method, origin, path, digest)
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Set("DUD-Authorization", authorization)
	return headers, nil
}

func createV2ChunkUpload(ctx context.Context, transport v2Transport, origin string, operationID []byte, chain uint64, slot []byte, epoch uint64, parts []v2ChunkManifestPart, proof v2GranularSlotProofInput) (*v2ChunkUploadResponse, error) {
	if len(operationID) != 16 || len(slot) != 16 || epoch == 0 {
		return nil, errors.New("chunk upload request is invalid")
	}
	total, err := validateV2ChunkManifest(parts)
	if err != nil {
		return nil, err
	}
	wireParts := make([]any, len(parts))
	for index, part := range parts {
		wireParts[index] = map[int]any{1: part.ID, 2: part.Length, 3: part.Digest}
	}
	body, err := v2EncMode.Marshal(map[int]any{1: operationID, 2: chain, 3: slot, 4: epoch, 5: wireParts, 6: total})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	headers, err := v2ChunkHeaders(proof, "POST", origin, "/v2/deliveries/uploads", digest[:])
	if err != nil {
		return nil, err
	}
	headers.Set("Accept", v2CBORContentType)
	headers.Set("Content-Type", v2CBORContentType)
	headers.Set("Content-Length", strconv.Itoa(len(body)))
	response, err := transport.Do(ctx, v2Request{Method: "POST", Origin: origin, Path: "/v2/deliveries/uploads", Headers: headers, Body: body, MaxResponseBytes: v2MaxDescriptorBytes})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, decodeV2HTTPError(response)
	}
	if (response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK) || response.ContentType != v2CBORContentType {
		return nil, fmt.Errorf("chunk upload creation returned HTTP %d and Content-Type %q", response.StatusCode, response.ContentType)
	}
	var value map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &value); err != nil {
		return nil, err
	}
	canonical, err := v2EncMode.Marshal(value)
	uploadID, uploadOK := value[1].([]byte)
	expiresAt, expiryOK := asV2Uint(value[2])
	missing, missingOK := value[3].([]any)
	idempotent, idempotentOK := value[4].(bool)
	if err != nil || !bytes.Equal(canonical, response.Body) || len(value) != 4 || !uploadOK || len(uploadID) != 16 || !expiryOK || expiresAt == 0 || !missingOK || len(missing) > len(parts) || !idempotentOK {
		return nil, errors.New("chunk upload creation response is invalid")
	}
	missingIDs := make([][]byte, len(missing))
	allowed := map[string]bool{}
	for _, part := range parts {
		allowed[string(part.ID)] = true
	}
	for index, raw := range missing {
		id, ok := raw.([]byte)
		if !ok || len(id) != 16 || !allowed[string(id)] {
			return nil, errors.New("chunk upload creation response is invalid")
		}
		missingIDs[index] = append([]byte(nil), id...)
	}
	return &v2ChunkUploadResponse{UploadID: append([]byte(nil), uploadID...), ExpiresAt: expiresAt, MissingChunkIDs: missingIDs, Idempotent: idempotent}, nil
}

func putV2ChunkUploadPart(ctx context.Context, transport v2Transport, origin string, uploadID []byte, part v2ChunkManifestPart, body io.Reader, proof v2GranularSlotProofInput) error {
	return putV2ChunkUploadPartObserved(ctx, transport, origin, uploadID, part, body, proof, nil)
}

func putV2ChunkUploadPartObserved(ctx context.Context, transport v2Transport, origin string, uploadID []byte, part v2ChunkManifestPart, body io.Reader, proof v2GranularSlotProofInput, observe func(int64, int64)) error {
	if len(uploadID) != 16 || body == nil {
		return errors.New("chunk upload part is invalid")
	}
	if err := validateV2ChunkManifestPart(part); err != nil {
		return err
	}
	path := "/v2/deliveries/uploads/" + hex.EncodeToString(uploadID) + "/chunks/" + hex.EncodeToString(part.ID)
	headers, err := v2ChunkHeaders(proof, "PUT", origin, path, part.Digest)
	if err != nil {
		return err
	}
	headers.Set("Content-Type", "application/octet-stream")
	headers.Set("Content-Length", strconv.FormatUint(part.Length, 10))
	headers.Set("DUD-Content-SHA256", hex.EncodeToString(part.Digest))
	response, err := transport.Do(ctx, v2Request{Method: "PUT", Origin: origin, Path: path, Headers: headers, BodyStream: body, ContentLength: int64(part.Length), MaxResponseBytes: v2MaxDescriptorBytes, ObserveUpload: observe})
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return decodeV2HTTPError(response)
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("chunk upload part returned HTTP %d", response.StatusCode)
	}
	return nil
}

func headV2ChunkUploadPart(ctx context.Context, transport v2Transport, origin string, uploadID []byte, part v2ChunkManifestPart, proof v2GranularSlotProofInput) (bool, error) {
	if len(uploadID) != 16 {
		return false, errors.New("chunk upload is invalid")
	}
	if err := validateV2ChunkManifestPart(part); err != nil {
		return false, err
	}
	path := "/v2/deliveries/uploads/" + hex.EncodeToString(uploadID) + "/chunks/" + hex.EncodeToString(part.ID)
	headers, err := v2ChunkHeaders(proof, "HEAD", origin, path, make([]byte, 32))
	if err != nil {
		return false, err
	}
	response, err := transport.Do(ctx, v2Request{Method: "HEAD", Origin: origin, Path: path, Headers: headers, MaxResponseBytes: v2MaxDescriptorBytes})
	if err != nil {
		return false, err
	}
	if response.StatusCode >= 400 {
		if protocolErr := decodeV2HTTPError(response); protocolErr != nil {
			var unavailable *v2ProtocolError
			if errors.As(protocolErr, &unavailable) && unavailable.Code == 4 {
				return false, nil
			}
			return false, protocolErr
		}
	}
	length, lengthErr := strconv.ParseUint(response.Headers.Get("Content-Length"), 10, 64)
	digest, digestErr := hex.DecodeString(response.Headers.Get("DUD-Content-SHA256"))
	if response.StatusCode != http.StatusOK || response.ContentType != "application/octet-stream" || lengthErr != nil || length != part.Length || digestErr != nil || !bytes.Equal(digest, part.Digest) {
		return false, errors.New("chunk upload status does not match its manifest")
	}
	return true, nil
}

func renewV2ChunkUpload(ctx context.Context, transport v2Transport, origin string, uploadID, operationID []byte, proof v2GranularSlotProofInput) (uint64, bool, error) {
	if len(uploadID) != 16 || len(operationID) != 16 {
		return 0, false, errors.New("chunk upload renewal is invalid")
	}
	body, err := v2EncMode.Marshal(map[int]any{1: operationID})
	if err != nil {
		return 0, false, err
	}
	path := "/v2/deliveries/uploads/" + hex.EncodeToString(uploadID) + "/renew"
	digest := sha256.Sum256(body)
	headers, err := v2ChunkHeaders(proof, "POST", origin, path, digest[:])
	if err != nil {
		return 0, false, err
	}
	headers.Set("Accept", v2CBORContentType)
	headers.Set("Content-Type", v2CBORContentType)
	headers.Set("Content-Length", strconv.Itoa(len(body)))
	response, err := transport.Do(ctx, v2Request{Method: "POST", Origin: origin, Path: path, Headers: headers, Body: body, MaxResponseBytes: v2MaxDescriptorBytes})
	if err != nil {
		return 0, false, err
	}
	if response.StatusCode >= 400 {
		return 0, false, decodeV2HTTPError(response)
	}
	if response.StatusCode != http.StatusOK || response.ContentType != v2CBORContentType {
		return 0, false, fmt.Errorf("chunk upload renewal returned HTTP %d and Content-Type %q", response.StatusCode, response.ContentType)
	}
	var value map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &value); err != nil {
		return 0, false, err
	}
	canonical, err := v2EncMode.Marshal(value)
	expiresAt, expiryOK := asV2Uint(value[1])
	idempotent, idempotentOK := value[2].(bool)
	if err != nil || !bytes.Equal(canonical, response.Body) || len(value) != 2 || !expiryOK || expiresAt == 0 || !idempotentOK {
		return 0, false, errors.New("chunk upload renewal response is invalid")
	}
	return expiresAt, idempotent, nil
}

func abandonV2ChunkUpload(ctx context.Context, transport v2Transport, origin string, uploadID []byte, proof v2GranularSlotProofInput) error {
	if len(uploadID) != 16 {
		return errors.New("chunk upload is invalid")
	}
	path := "/v2/deliveries/uploads/" + hex.EncodeToString(uploadID)
	headers, err := v2ChunkHeaders(proof, "DELETE", origin, path, make([]byte, 32))
	if err != nil {
		return err
	}
	response, err := transport.Do(ctx, v2Request{Method: "DELETE", Origin: origin, Path: path, Headers: headers, MaxResponseBytes: v2MaxDescriptorBytes})
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return decodeV2HTTPError(response)
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("chunk upload abandonment returned HTTP %d", response.StatusCode)
	}
	return nil
}

func commitV2ChunkUpload(ctx context.Context, transport v2Transport, origin string, uploadID, operationID, descriptor []byte, policy map[int]any, proof v2GranularSlotProofInput) (*v2ChunkCommitResponse, error) {
	if len(uploadID) != 16 || len(operationID) != 16 || len(descriptor) == 0 || len(descriptor) > v2MaxDescriptorBytes || policy == nil {
		return nil, errors.New("chunk upload commit is invalid")
	}
	body, err := v2EncMode.Marshal(map[int]any{1: operationID, 2: descriptor, 3: policy})
	if err != nil {
		return nil, err
	}
	path := "/v2/deliveries/uploads/" + hex.EncodeToString(uploadID) + "/commit"
	digest := sha256.Sum256(body)
	headers, err := v2ChunkHeaders(proof, "POST", origin, path, digest[:])
	if err != nil {
		return nil, err
	}
	headers.Set("Accept", v2CBORContentType)
	headers.Set("Content-Type", v2CBORContentType)
	headers.Set("Content-Length", strconv.Itoa(len(body)))
	response, err := transport.Do(ctx, v2Request{Method: "POST", Origin: origin, Path: path, Headers: headers, Body: body, MaxResponseBytes: v2MaxDescriptorBytes})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, decodeV2HTTPError(response)
	}
	if response.StatusCode != http.StatusOK || response.ContentType != v2CBORContentType {
		return nil, fmt.Errorf("chunk upload commit returned HTTP %d and Content-Type %q", response.StatusCode, response.ContentType)
	}
	var value map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &value); err != nil {
		return nil, err
	}
	canonical, err := v2EncMode.Marshal(value)
	deliveryID, deliveryOK := value[1].([]byte)
	idempotent, idempotentOK := value[2].(bool)
	if err != nil || !bytes.Equal(canonical, response.Body) || len(value) != 2 || !deliveryOK || len(deliveryID) != 16 || !idempotentOK {
		return nil, errors.New("chunk upload commit response is invalid")
	}
	return &v2ChunkCommitResponse{DeliveryID: append([]byte(nil), deliveryID...), Idempotent: idempotent}, nil
}

func getV2DeliveryChunk(ctx context.Context, transport v2Transport, origin string, deliveryID []byte, part v2ChunkManifestPart, proof v2GranularSlotProofInput) (*v2ChunkStream, error) {
	return getV2DeliveryChunkObserved(ctx, transport, origin, deliveryID, part, proof, nil)
}

func getV2DeliveryChunkObserved(ctx context.Context, transport v2Transport, origin string, deliveryID []byte, part v2ChunkManifestPart, proof v2GranularSlotProofInput, observe func(int64, int64)) (*v2ChunkStream, error) {
	if len(deliveryID) != 16 || len(part.ID) != 16 || part.Length == 0 || len(part.Digest) != 32 {
		return nil, errors.New("delivery chunk request is invalid")
	}
	path := "/v2/deliveries/" + hex.EncodeToString(deliveryID) + "/chunks/" + hex.EncodeToString(part.ID)
	headers, err := v2ChunkHeaders(proof, "GET", origin, path, make([]byte, 32))
	if err != nil {
		return nil, err
	}
	response, err := transport.Do(ctx, v2Request{Method: "GET", Origin: origin, Path: path, Headers: headers, StreamResponse: true, ObserveDownload: observe})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		if response.Stream != nil {
			_ = response.Stream.Close()
		}
		return nil, fmt.Errorf("delivery chunk returned HTTP %d", response.StatusCode)
	}
	length, lengthErr := strconv.ParseUint(response.Headers.Get("Content-Length"), 10, 64)
	digest, digestErr := hex.DecodeString(response.Headers.Get("DUD-Content-SHA256"))
	if response.ContentType != "application/octet-stream" || response.Stream == nil || lengthErr != nil || length != part.Length || digestErr != nil || !bytes.Equal(digest, part.Digest) {
		if response.Stream != nil {
			_ = response.Stream.Close()
		}
		return nil, errors.New("delivery chunk response does not match the signed manifest")
	}
	return &v2ChunkStream{Body: response.Stream, Length: length, Digest: digest}, nil
}
