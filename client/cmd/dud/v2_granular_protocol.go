// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	v2GranularFrameMagic       = "DUD2"
	v2GranularFramePrefixBytes = 8
	v2GranularMaxHeaderBytes   = 262_144
	v2GranularMaxPayloadBytes  = 100 * 1024 * 1024
	v2GranularMaxSlotProofs    = 31
	v2GranularWireProtocol     = uint64(2)
)

const (
	v2GranularDataChain    = uint64(0)
	v2GranularControlChain = uint64(1)
)

type v2GranularSlotProofInput struct {
	TokenSecret []byte
	Direction   string
	Scope       string
	Chain       uint64
	Slot        []byte
	Epoch       uint64
	Nonce       []byte
	ExpiresAt   uint64
}

type v2GranularInboxResponse struct {
	Header  map[int]any
	Payload []byte
}

type v2GranularInboxDelivery struct {
	ID                  []byte
	Slot                []byte
	EncryptedDescriptor []byte
	EffectivePolicy     map[int]any
	Payload             []byte
}

type v2GranularControlEventResponse struct {
	EventID    []byte
	Idempotent bool
}

type v2GranularDeliveryResponse struct {
	DeliveryID      []byte
	EffectivePolicy map[int]any
	Idempotent      bool
	ControlResults  []any
	ControlEvents   []any
}

type v2GranularCompletionResponse struct {
	DeliveryID     []byte
	ControlEventID []byte
	Idempotent     bool
}

func v2GranularUint64(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}

func v2GranularCapabilityContext(input v2GranularSlotProofInput) ([]byte, error) {
	if len(input.Slot) != 16 || (input.Scope != "write" && input.Scope != "read" && input.Scope != "ack") ||
		(input.Direction != "inviter->invitee" && input.Direction != "invitee->inviter") {
		return nil, errors.New("granular delivery authorization context is invalid")
	}
	return bytes.Join([][]byte{
		[]byte(input.Direction),
		[]byte(input.Scope),
		v2GranularUint64(input.Chain),
		input.Slot,
		v2GranularUint64(input.Epoch),
	}, []byte("|")), nil
}

func deriveV2DailyCapabilityLookupIDClient(tokenSecret []byte, epoch uint64) ([]byte, error) {
	if len(tokenSecret) != 32 {
		return nil, errors.New("capability secret is invalid")
	}
	mac := hmac.New(sha256.New, tokenSecret)
	mac.Write([]byte("dud/v2/capability-lookup|"))
	mac.Write(v2GranularUint64(epoch))
	return mac.Sum(nil)[:16], nil
}

func encodeV2GranularSlotProof(input v2GranularSlotProofInput, method, origin, path string, requestDigest []byte, operationIndex uint64, redacted bool) (map[int]any, error) {
	if method == "" || origin == "" || path == "" || len(input.Nonce) != 16 || input.ExpiresAt == 0 {
		return nil, errors.New("granular delivery proof input is invalid")
	}
	lookupID, err := deriveV2DailyCapabilityLookupIDClient(input.TokenSecret, input.Epoch)
	if err != nil {
		return nil, err
	}
	mac := make([]byte, 32)
	if !redacted {
		mac, err = deriveV2GranularAuthorizationMACWithRequest(
			input,
			lookupID,
			method,
			origin,
			path,
			requestDigest,
			operationIndex,
		)
		if err != nil {
			return nil, err
		}
	}
	proof, err := v2EncMode.Marshal(map[int]any{
		1: lookupID,
		2: input.Nonce,
		3: input.ExpiresAt,
		4: operationIndex,
		5: mac,
	})
	if err != nil {
		return nil, err
	}
	return map[int]any{
		1: input.Slot,
		2: input.Epoch,
		3: input.Chain,
		4: proof,
	}, nil
}

func deriveV2GranularAuthorizationMACWithRequest(input v2GranularSlotProofInput, lookupID []byte, method, origin, path string, requestDigest []byte, operationIndex uint64) ([]byte, error) {
	if len(input.TokenSecret) != 32 || len(lookupID) != 16 || len(requestDigest) != 32 || len(input.Nonce) != 16 {
		return nil, errors.New("granular delivery authorization proof is invalid")
	}
	contextBytes, err := v2GranularCapabilityContext(input)
	if err != nil {
		return nil, err
	}
	authKey, err := hkdf.Key(sha256.New, input.TokenSecret, nil, string(append([]byte("dud/v2/delivery-authkey|"), contextBytes...)), 32)
	if err != nil {
		return nil, err
	}
	fields := [][]byte{
		[]byte("dud/v2/delivery-auth"), v2GranularUint64(v2GranularWireProtocol), lookupID,
		[]byte(input.Direction), []byte(input.Scope), v2GranularUint64(input.Chain), input.Slot,
		v2GranularUint64(input.Epoch), []byte(method), []byte(origin), []byte(path),
		v2GranularUint64(operationIndex), requestDigest, input.Nonce, v2GranularUint64(input.ExpiresAt),
	}
	mac := hmac.New(sha256.New, authKey)
	mac.Write(fields[0])
	for _, field := range fields[1:] {
		mac.Write([]byte{0})
		mac.Write(field)
	}
	return mac.Sum(nil), nil
}

func newV2GranularSlotProofInput(tokenSecret []byte, direction, scope string, chain uint64, slot []byte, epoch uint64, now time.Time) (v2GranularSlotProofInput, error) {
	nonce, err := randomV2Bytes(16)
	if err != nil {
		return v2GranularSlotProofInput{}, err
	}
	expiresAt := uint64(now.Unix()) + 60
	// Clamping to the end of the slot epoch is only meaningful while that
	// epoch is still running. Protocol §8 has a receiver poll the current slot
	// plus a recovery window of roughly 30 past slots, and a proof for one of
	// those would otherwise be born already expired. The server rejects anything
	// whose expiry is behind its clock. The epoch is a separate
	// signed field in the proof, so a past-epoch query is still bound to the
	// epoch it names; only the authorization lifetime lives here.
	epochEnd := (epoch + 1) * v2SlotEpochSeconds
	if expiresAt >= epochEnd && epochEnd > uint64(now.Unix()) {
		expiresAt = epochEnd - 1
	}
	return v2GranularSlotProofInput{TokenSecret: tokenSecret, Direction: direction, Scope: scope, Chain: chain, Slot: slot, Epoch: epoch, Nonce: nonce, ExpiresAt: expiresAt}, nil
}

func encodeV2GranularInboxRequest(origin string, dataProofs, controlProofs []v2GranularSlotProofInput, processedControlIDs [][]byte) ([]byte, error) {
	if origin == "" || len(dataProofs)+len(controlProofs) == 0 || len(dataProofs) > v2GranularMaxSlotProofs || len(controlProofs) > v2GranularMaxSlotProofs || len(processedControlIDs) > v2GranularMaxSlotProofs {
		return nil, errors.New("granular inbox request is invalid")
	}
	for _, id := range processedControlIDs {
		if len(id) != 16 {
			return nil, errors.New("processed control event ID is invalid")
		}
	}
	redactedData := make([]any, len(dataProofs))
	redactedControl := make([]any, len(controlProofs))
	for index, input := range dataProofs {
		proof, err := encodeV2GranularSlotProof(input, "POST", origin, "/v2/inbox", make([]byte, 32), uint64(index), true)
		if err != nil {
			return nil, err
		}
		redactedData[index] = proof
	}
	for index, input := range controlProofs {
		proof, err := encodeV2GranularSlotProof(input, "POST", origin, "/v2/inbox", make([]byte, 32), uint64(len(dataProofs)+index), true)
		if err != nil {
			return nil, err
		}
		redactedControl[index] = proof
	}
	redacted := map[int]any{1: redactedData}
	if len(redactedControl) != 0 {
		redacted[2] = redactedControl
	}
	if len(processedControlIDs) != 0 {
		redacted[3] = processedControlIDs
	}
	redactedBody, err := v2EncMode.Marshal(redacted)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(redactedBody)
	data := make([]any, len(dataProofs))
	control := make([]any, len(controlProofs))
	for index, input := range dataProofs {
		proof, err := encodeV2GranularSlotProof(input, "POST", origin, "/v2/inbox", digest[:], uint64(index), false)
		if err != nil {
			return nil, err
		}
		data[index] = proof
	}
	for index, input := range controlProofs {
		proof, err := encodeV2GranularSlotProof(input, "POST", origin, "/v2/inbox", digest[:], uint64(len(dataProofs)+index), false)
		if err != nil {
			return nil, err
		}
		control[index] = proof
	}
	result := map[int]any{1: data}
	if len(control) != 0 {
		result[2] = control
	}
	if len(processedControlIDs) != 0 {
		result[3] = processedControlIDs
	}
	return v2EncMode.Marshal(result)
}

func queryV2GranularInbox(ctx context.Context, transport v2Transport, origin string, dataProofs, controlProofs []v2GranularSlotProofInput, processedControlIDs [][]byte) (*v2GranularInboxResponse, error) {
	body, err := encodeV2GranularInboxRequest(origin, dataProofs, controlProofs, processedControlIDs)
	if err != nil {
		return nil, err
	}
	response, err := transport.Do(ctx, v2Request{
		Method: "POST",
		Origin: origin,
		Path:   "/v2/inbox",
		Headers: http.Header{
			"Accept":         {v2CBORContentType},
			"Content-Type":   {v2CBORContentType},
			"Content-Length": {fmt.Sprintf("%d", len(body))},
		},
		Body:             body,
		MaxResponseBytes: v2GranularFramePrefixBytes + v2GranularMaxHeaderBytes + v2GranularMaxPayloadBytes,
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, decodeV2HTTPError(response)
	}
	if response.StatusCode != 200 || response.ContentType != v2CBORContentType {
		return nil, fmt.Errorf("granular inbox returned HTTP %d and Content-Type %q", response.StatusCode, response.ContentType)
	}
	header, payload, err := decodeV2GranularFrame(response.Body, 7, 8)
	if err != nil {
		return nil, err
	}
	return &v2GranularInboxResponse{Header: header, Payload: payload}, nil
}

func decodeV2GranularInboxDelivery(response *v2GranularInboxResponse) (*v2GranularInboxDelivery, error) {
	if response == nil {
		return nil, errors.New("granular inbox response is missing")
	}
	for key := range response.Header {
		if key < 1 || key > 9 {
			return nil, fmt.Errorf("granular inbox response contains unknown key %d", key)
		}
	}
	if _, err := decodeV2GranularControlEvents(response.Header); err != nil {
		return nil, err
	}
	if raw, ok := response.Header[1].([]any); !ok || len(raw) > v2GranularMaxSlotProofs {
		return nil, errors.New("granular inbox slot results are invalid")
	}
	for _, key := range []int{7, 8} {
		if _, exists := response.Header[key]; !exists {
			return nil, errors.New("granular inbox payload declaration is missing")
		}
	}
	deliveryID, exists := response.Header[3].([]byte)
	if !exists {
		if response.Header[3] != nil || len(response.Payload) != 0 || response.Header[4] != nil || response.Header[5] != nil || response.Header[6] != nil {
			return nil, errors.New("granular inbox has delivery fields without a delivery ID")
		}
		return nil, nil
	}
	slot, slotOK := response.Header[4].([]byte)
	descriptor, descriptorOK := response.Header[5].([]byte)
	policy, policyErr := normalizeV2Map(response.Header[6])
	if len(deliveryID) != 16 || !slotOK || len(slot) != 16 || !descriptorOK || len(descriptor) == 0 || len(descriptor) > v2MaxDescriptorBytes || policyErr != nil {
		return nil, errors.New("granular inbox delivery is invalid")
	}
	return &v2GranularInboxDelivery{
		ID:                  append([]byte(nil), deliveryID...),
		Slot:                append([]byte(nil), slot...),
		EncryptedDescriptor: append([]byte(nil), descriptor...),
		EffectivePolicy:     policy,
		Payload:             append([]byte(nil), response.Payload...),
	}, nil
}

func encodeV2GranularControlEventRequest(origin string, operationID, envelope []byte, proofInput v2GranularSlotProofInput) ([]byte, error) {
	if origin == "" || len(operationID) != 16 || len(envelope) == 0 || len(envelope) > v2MaxDescriptorBytes {
		return nil, errors.New("granular control event is invalid")
	}
	redactedProof, err := encodeV2GranularSlotProof(proofInput, "POST", origin, "/v2/control-events", make([]byte, 32), 0, true)
	if err != nil {
		return nil, err
	}
	redactedBody, err := v2EncMode.Marshal(map[int]any{1: operationID, 2: redactedProof, 3: envelope})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(redactedBody)
	proof, err := encodeV2GranularSlotProof(proofInput, "POST", origin, "/v2/control-events", digest[:], 0, false)
	if err != nil {
		return nil, err
	}
	return v2EncMode.Marshal(map[int]any{1: operationID, 2: proof, 3: envelope})
}

func publishV2GranularControlEvent(ctx context.Context, transport v2Transport, origin string, operationID, envelope []byte, proofInput v2GranularSlotProofInput) (*v2GranularControlEventResponse, error) {
	body, err := encodeV2GranularControlEventRequest(origin, operationID, envelope, proofInput)
	if err != nil {
		return nil, err
	}
	response, err := transport.Do(ctx, v2Request{
		Method: "POST",
		Origin: origin,
		Path:   "/v2/control-events",
		Headers: http.Header{
			"Accept":         {v2CBORContentType},
			"Content-Type":   {v2CBORContentType},
			"Content-Length": {fmt.Sprintf("%d", len(body))},
		},
		Body:             body,
		MaxResponseBytes: v2MaxDescriptorBytes,
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, decodeV2HTTPError(response)
	}
	if response.StatusCode != 200 || response.ContentType != v2CBORContentType {
		return nil, fmt.Errorf("granular control event returned HTTP %d and Content-Type %q", response.StatusCode, response.ContentType)
	}
	var result map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &result); err != nil {
		return nil, err
	}
	canonical, err := v2EncMode.Marshal(result)
	if err != nil || !bytes.Equal(canonical, response.Body) || len(result) != 2 {
		return nil, errors.New("granular control event response is invalid")
	}
	eventID, idOK := result[1].([]byte)
	idempotent, idempotentOK := result[2].(bool)
	if !idOK || len(eventID) != 16 || !idempotentOK {
		return nil, errors.New("granular control event response is invalid")
	}
	return &v2GranularControlEventResponse{EventID: eventID, Idempotent: idempotent}, nil
}

func encodeV2GranularDeliveryRequest(origin string, operationID, descriptor []byte, policy map[int]any, payload []byte, dataProof v2GranularSlotProofInput, controlProofs []v2GranularSlotProofInput, processedControlIDs [][]byte) ([]byte, error) {
	if origin == "" || len(operationID) != 16 || len(descriptor) == 0 || len(descriptor) > v2MaxDescriptorBytes || policy == nil || len(payload) > v2GranularMaxPayloadBytes || len(controlProofs) > v2GranularMaxSlotProofs || len(processedControlIDs) > v2GranularMaxSlotProofs {
		return nil, errors.New("granular delivery request is invalid")
	}
	for _, id := range processedControlIDs {
		if len(id) != 16 {
			return nil, errors.New("processed control event ID is invalid")
		}
	}
	payloadDigest := sha256.Sum256(payload)
	redactedData, err := encodeV2GranularSlotProof(dataProof, "POST", origin, "/v2/deliveries", make([]byte, 32), 0, true)
	if err != nil {
		return nil, err
	}
	redactedControl := make([]any, len(controlProofs))
	for index, proofInput := range controlProofs {
		proof, proofErr := encodeV2GranularSlotProof(proofInput, "POST", origin, "/v2/deliveries", make([]byte, 32), uint64(index+1), true)
		if proofErr != nil {
			return nil, proofErr
		}
		redactedControl[index] = proof
	}
	redactedHeader := map[int]any{
		1: operationID,
		2: descriptor,
		3: policy,
		4: uint64(len(payload)),
		5: payloadDigest[:],
		6: redactedData,
	}
	if len(redactedControl) != 0 {
		redactedHeader[7] = redactedControl
	}
	if len(processedControlIDs) != 0 {
		redactedHeader[8] = processedControlIDs
	}
	redactedFrame, err := encodeV2GranularFrame(redactedHeader, payload, 4, 5)
	if err != nil {
		return nil, err
	}
	requestDigest := sha256.Sum256(redactedFrame)
	actualData, err := encodeV2GranularSlotProof(dataProof, "POST", origin, "/v2/deliveries", requestDigest[:], 0, false)
	if err != nil {
		return nil, err
	}
	actualControl := make([]any, len(controlProofs))
	for index, proofInput := range controlProofs {
		proof, proofErr := encodeV2GranularSlotProof(proofInput, "POST", origin, "/v2/deliveries", requestDigest[:], uint64(index+1), false)
		if proofErr != nil {
			return nil, proofErr
		}
		actualControl[index] = proof
	}
	header := map[int]any{
		1: operationID,
		2: descriptor,
		3: policy,
		4: uint64(len(payload)),
		5: payloadDigest[:],
		6: actualData,
	}
	if len(actualControl) != 0 {
		header[7] = actualControl
	}
	if len(processedControlIDs) != 0 {
		header[8] = processedControlIDs
	}
	return encodeV2GranularFrame(header, payload, 4, 5)
}

func publishV2GranularDelivery(ctx context.Context, transport v2Transport, origin string, operationID, descriptor []byte, policy map[int]any, payload []byte, dataProof v2GranularSlotProofInput, controlProofs []v2GranularSlotProofInput, processedControlIDs [][]byte) (*v2GranularDeliveryResponse, error) {
	frame, err := encodeV2GranularDeliveryRequest(origin, operationID, descriptor, policy, payload, dataProof, controlProofs, processedControlIDs)
	if err != nil {
		return nil, err
	}
	frameDigest := sha256.Sum256(frame)
	headers := http.Header{
		"Accept":         {v2CBORContentType},
		"Content-Type":   {v2CBORContentType},
		"Content-Length": {fmt.Sprintf("%d", len(frame))},
	}
	headers.Set("DUD-Content-SHA256", hex.EncodeToString(frameDigest[:]))
	response, err := transport.Do(ctx, v2Request{
		Method:           "POST",
		Origin:           origin,
		Path:             "/v2/deliveries",
		Headers:          headers,
		Body:             frame,
		MaxResponseBytes: v2MaxDescriptorBytes,
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, decodeV2HTTPError(response)
	}
	if response.StatusCode != 200 || response.ContentType != v2CBORContentType {
		return nil, fmt.Errorf("granular delivery returned HTTP %d and Content-Type %q", response.StatusCode, response.ContentType)
	}
	var result map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &result); err != nil {
		return nil, err
	}
	canonical, err := v2EncMode.Marshal(result)
	if err != nil || !bytes.Equal(canonical, response.Body) || len(result) != 5 {
		return nil, errors.New("granular delivery response is invalid")
	}
	deliveryID, idOK := result[1].([]byte)
	effectivePolicy, policyErr := normalizeV2Map(result[2])
	idempotent, idempotentOK := result[3].(bool)
	controlResults, resultsOK := result[4].([]any)
	controlEvents, eventsOK := result[5].([]any)
	if !idOK || len(deliveryID) != 16 || policyErr != nil || !idempotentOK || !resultsOK || len(controlResults) > v2GranularMaxSlotProofs || !eventsOK || len(controlEvents) > v2GranularMaxSlotProofs {
		return nil, errors.New("granular delivery response is invalid")
	}
	return &v2GranularDeliveryResponse{
		DeliveryID:      deliveryID,
		EffectivePolicy: effectivePolicy,
		Idempotent:      idempotent,
		ControlResults:  controlResults,
		ControlEvents:   controlEvents,
	}, nil
}

func encodeV2GranularCompletionRequest(origin string, deliveryID, sourceSlot, targetSlot, policyDigest, descriptorDigest []byte, result uint64, operationID, acknowledgement []byte, ackProof, controlProof v2GranularSlotProofInput) ([]byte, error) {
	if origin == "" || len(deliveryID) != 16 || len(sourceSlot) != 16 || len(targetSlot) != 16 || len(policyDigest) != 32 || len(descriptorDigest) != 32 || result > 1 || len(operationID) != 16 || len(acknowledgement) == 0 || len(acknowledgement) > v2MaxDescriptorBytes {
		return nil, errors.New("granular completion request is invalid")
	}
	path := "/v2/deliveries/" + hex.EncodeToString(deliveryID) + "/complete"
	redactedAck, err := encodeV2GranularSlotProof(ackProof, "POST", origin, path, make([]byte, 32), 0, true)
	if err != nil {
		return nil, err
	}
	redactedControl, err := encodeV2GranularSlotProof(controlProof, "POST", origin, path, make([]byte, 32), 1, true)
	if err != nil {
		return nil, err
	}
	redactedBody, err := v2EncMode.Marshal(map[int]any{
		1: deliveryID, 2: redactedAck, 3: redactedControl, 4: sourceSlot, 5: targetSlot,
		6: policyDigest, 7: descriptorDigest, 8: result, 9: operationID, 10: acknowledgement,
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(redactedBody)
	actualAck, err := encodeV2GranularSlotProof(ackProof, "POST", origin, path, digest[:], 0, false)
	if err != nil {
		return nil, err
	}
	actualControl, err := encodeV2GranularSlotProof(controlProof, "POST", origin, path, digest[:], 1, false)
	if err != nil {
		return nil, err
	}
	return v2EncMode.Marshal(map[int]any{
		1: deliveryID, 2: actualAck, 3: actualControl, 4: sourceSlot, 5: targetSlot,
		6: policyDigest, 7: descriptorDigest, 8: result, 9: operationID, 10: acknowledgement,
	})
}

func completeV2GranularDelivery(ctx context.Context, transport v2Transport, origin string, deliveryID, sourceSlot, targetSlot, policyDigest, descriptorDigest []byte, result uint64, operationID, acknowledgement []byte, ackProof, controlProof v2GranularSlotProofInput) (*v2GranularCompletionResponse, error) {
	body, err := encodeV2GranularCompletionRequest(origin, deliveryID, sourceSlot, targetSlot, policyDigest, descriptorDigest, result, operationID, acknowledgement, ackProof, controlProof)
	if err != nil {
		return nil, err
	}
	path := "/v2/deliveries/" + hex.EncodeToString(deliveryID) + "/complete"
	response, err := transport.Do(ctx, v2Request{
		Method: "POST",
		Origin: origin,
		Path:   path,
		Headers: http.Header{
			"Accept":         {v2CBORContentType},
			"Content-Type":   {v2CBORContentType},
			"Content-Length": {fmt.Sprintf("%d", len(body))},
		},
		Body:             body,
		MaxResponseBytes: v2MaxDescriptorBytes,
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, decodeV2HTTPError(response)
	}
	if response.StatusCode != 200 || response.ContentType != v2CBORContentType {
		return nil, fmt.Errorf("granular completion returned HTTP %d and Content-Type %q", response.StatusCode, response.ContentType)
	}
	var value map[int]any
	if err := v2DecMode.Unmarshal(response.Body, &value); err != nil {
		return nil, err
	}
	canonical, err := v2EncMode.Marshal(value)
	if err != nil || !bytes.Equal(canonical, response.Body) || len(value) != 3 {
		return nil, errors.New("granular completion response is invalid")
	}
	returnedDeliveryID, deliveryOK := value[1].([]byte)
	controlEventID, eventOK := value[2].([]byte)
	idempotent, idempotentOK := value[3].(bool)
	if !deliveryOK || len(returnedDeliveryID) != 16 || !bytes.Equal(returnedDeliveryID, deliveryID) || !eventOK || len(controlEventID) != 16 || !idempotentOK {
		return nil, errors.New("granular completion response is invalid")
	}
	return &v2GranularCompletionResponse{DeliveryID: returnedDeliveryID, ControlEventID: controlEventID, Idempotent: idempotent}, nil
}

func encodeV2GranularFrame(header map[int]any, payload []byte, payloadLengthKey, payloadDigestKey int) ([]byte, error) {
	if len(payload) > v2GranularMaxPayloadBytes {
		return nil, errors.New("granular frame payload exceeds the configured limit")
	}
	length, lengthOK := asV2Uint(header[payloadLengthKey])
	digest, digestOK := header[payloadDigestKey].([]byte)
	actualDigest := sha256.Sum256(payload)
	if !lengthOK || length != uint64(len(payload)) || !digestOK || len(digest) != 32 || !bytes.Equal(digest, actualDigest[:]) {
		return nil, errors.New("granular frame payload declaration is invalid")
	}
	encodedHeader, err := v2EncMode.Marshal(header)
	if err != nil {
		return nil, err
	}
	if len(encodedHeader) == 0 || len(encodedHeader) > v2GranularMaxHeaderBytes {
		return nil, errors.New("granular frame header exceeds the configured limit")
	}
	result := make([]byte, v2GranularFramePrefixBytes+len(encodedHeader)+len(payload))
	copy(result, v2GranularFrameMagic)
	binary.BigEndian.PutUint32(result[4:], uint32(len(encodedHeader)))
	copy(result[v2GranularFramePrefixBytes:], encodedHeader)
	copy(result[v2GranularFramePrefixBytes+len(encodedHeader):], payload)
	return result, nil
}

func decodeV2GranularFrame(frame []byte, payloadLengthKey, payloadDigestKey int) (map[int]any, []byte, error) {
	if len(frame) < v2GranularFramePrefixBytes || string(frame[:4]) != v2GranularFrameMagic {
		return nil, nil, errors.New("granular frame magic is invalid")
	}
	headerLength := int(binary.BigEndian.Uint32(frame[4:]))
	if headerLength == 0 || headerLength > v2GranularMaxHeaderBytes || headerLength > len(frame)-v2GranularFramePrefixBytes {
		return nil, nil, errors.New("granular frame header length is invalid")
	}
	headerBytes := frame[v2GranularFramePrefixBytes : v2GranularFramePrefixBytes+headerLength]
	var header map[int]any
	if err := v2DecMode.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("decode granular frame header: %w", err)
	}
	canonical, err := v2EncMode.Marshal(header)
	if err != nil || !bytes.Equal(canonical, headerBytes) {
		return nil, nil, errors.New("granular frame header is not deterministic CBOR")
	}
	payload := append([]byte(nil), frame[v2GranularFramePrefixBytes+headerLength:]...)
	if len(payload) > v2GranularMaxPayloadBytes {
		return nil, nil, errors.New("granular frame payload exceeds the configured limit")
	}
	length, lengthOK := asV2Uint(header[payloadLengthKey])
	digest, digestOK := header[payloadDigestKey].([]byte)
	actualDigest := sha256.Sum256(payload)
	if !lengthOK || length != uint64(len(payload)) || !digestOK || len(digest) != 32 || !bytes.Equal(digest, actualDigest[:]) {
		return nil, nil, errors.New("granular frame payload declaration is invalid")
	}
	return header, payload, nil
}
