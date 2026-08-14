// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  decodeCbor,
  encodeCbor,
  requireCborMap,
  type CborValue,
} from './cbor.js';
import { sha256, StreamingSha256 } from './sha256.js';

/** The wire prefix shared by delivery requests and inbox responses. */
export const V2_DELIVERY_FRAME_MAGIC = Uint8Array.of(0x44, 0x55, 0x44, 0x32);
export const V2_DELIVERY_FRAME_PREFIX_BYTES = 8;
export const V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES = 262_144;
export const V2_MAX_ENCRYPTED_PAYLOAD_BYTES = 104_857_600;
export const V2_MAX_BATCHED_SLOT_PROOFS = 31;
/**
 * Everything a frame header carries besides the encrypted descriptor: two
 * fixed-size identifiers, a slot proof, the small requested-policy map, and the
 * two bounded batched lists. Named so that lowering the configured descriptor
 * limit also lowers how much of a header the server will read, without
 * rejecting a frame whose descriptor sits exactly at that limit.
 */
export const V2_DELIVERY_HEADER_OVERHEAD_BYTES = 8_192;

/** Numeric keys in a POST /v2/deliveries frame header. */
export const V2_DELIVERY_REQUEST_KEYS = {
  operationId: 1,
  encryptedDescriptor: 2,
  requestedPolicy: 3,
  payloadLength: 4,
  payloadDigest: 5,
  dataSlotProof: 6,
  controlQueries: 7,
  processedControlEventIds: 8,
} as const;

/** Numeric keys in a POST /v2/inbox response frame header. */
export const V2_INBOX_RESPONSE_KEYS = {
  slotResults: 1,
  controlEvents: 2,
  deliveryId: 3,
  slot: 4,
  encryptedDescriptor: 5,
  effectivePolicy: 6,
  payloadLength: 7,
  payloadDigest: 8,
  moreDeliveries: 9,
} as const;

/** Numeric keys in a bounded POST /v2/inbox request body. */
export const V2_INBOX_REQUEST_KEYS = {
  dataSlotProofs: 1,
  controlSlotProofs: 2,
  processedControlEventIds: 3,
} as const;

/** Numeric keys in a POST /v2/deliveries/:id/complete request body. */
export const V2_COMPLETION_REQUEST_KEYS = {
  deliveryId: 1,
  dataAckProof: 2,
  controlWriteProof: 3,
  sourceSlot: 4,
  targetSlot: 5,
  policyDigest: 6,
  descriptorDigest: 7,
  result: 8,
  operationId: 9,
  encryptedAcknowledgement: 10,
} as const;

/** Numeric keys in a POST /v2/control-events request body. */
export const V2_CONTROL_EVENT_REQUEST_KEYS = {
  operationId: 1,
  controlSlotProof: 2,
  encryptedEnvelope: 3,
} as const;

/** Numeric keys in the signed transport policy carried by a descriptor. */
export const V2_TRANSPORT_POLICY_KEYS = {
  expiresAt: 1,
  consume: 2,
  claimLeaseSeconds: 3,
  ackMode: 4,
} as const;

/** Numeric keys for each data or control authorization slot proof. */
export const V2_SLOT_PROOF_KEYS = {
  slot: 1,
  epoch: 2,
  chain: 3,
  proof: 4,
} as const;

export interface V2DeliveryFrame {
  header: Map<number, CborValue>;
  payload: Uint8Array;
}

export interface V2InboxRequest {
  header: Map<number, CborValue>;
}

export interface V2SlotProof {
  slot: Uint8Array;
  epoch: number;
  chain: number;
  proof: Uint8Array;
}

const V2_DELIVERY_PROOF_MAC_KEY = 5;

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function requireBytes(
  value: CborValue | undefined,
  length: number | undefined,
  name: string,
): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    (length !== undefined && value.byteLength !== length)
  ) {
    throw new Error(`${name} is invalid.`);
  }
  return value;
}

function requireUnsigned(
  value: CborValue | undefined,
  maximum: number,
  name: string,
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new Error(`${name} is invalid.`);
  }
  return value;
}

/** Decodes the common slot context surrounding an authorization proof. */
export function decodeV2SlotProof(value: CborValue): V2SlotProof {
  const map = requireCborMap(
    value,
    Object.values(V2_SLOT_PROOF_KEYS),
    Object.values(V2_SLOT_PROOF_KEYS),
  );
  return {
    slot: requireBytes(map.get(V2_SLOT_PROOF_KEYS.slot), 16, 'Slot proof slot'),
    epoch: requireUnsigned(
      map.get(V2_SLOT_PROOF_KEYS.epoch),
      Number.MAX_SAFE_INTEGER,
      'Slot proof epoch',
    ),
    chain: requireUnsigned(
      map.get(V2_SLOT_PROOF_KEYS.chain),
      Number.MAX_SAFE_INTEGER,
      'Slot proof chain',
    ),
    proof: requireBytes(
      map.get(V2_SLOT_PROOF_KEYS.proof),
      undefined,
      'Slot authorization proof',
    ),
  };
}

function redactSlotProofMac(value: CborValue): Map<number, CborValue> {
  const slotProof = decodeV2SlotProof(value);
  const proof = requireCborMap(
    decodeCbor(slotProof.proof, {
      maxBytes: 160,
      maxMapPairs: 5,
      maxDepth: 2,
      requireDeterministic: true,
    }),
    [1, 2, 3, 4, V2_DELIVERY_PROOF_MAC_KEY],
    [1, 2, 3, 4, V2_DELIVERY_PROOF_MAC_KEY],
  );
  requireBytes(
    proof.get(V2_DELIVERY_PROOF_MAC_KEY),
    32,
    'Slot authorization proof MAC',
  );
  const redactedProof = new Map(proof);
  redactedProof.set(V2_DELIVERY_PROOF_MAC_KEY, new Uint8Array(32));
  const redactedSlotProof = new Map<number, CborValue>([
    [V2_SLOT_PROOF_KEYS.slot, slotProof.slot],
    [V2_SLOT_PROOF_KEYS.epoch, slotProof.epoch],
    [V2_SLOT_PROOF_KEYS.chain, slotProof.chain],
    [V2_SLOT_PROOF_KEYS.proof, encodeCbor(redactedProof)],
  ]);
  return redactedSlotProof;
}

function redactSlotProofBatch(value: CborValue | undefined): CborValue {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error('Slot proof batch is invalid.');
  }
  return value.map((proof) => redactSlotProofMac(proof));
}

function framePrefix(headerLength: number): Uint8Array {
  const prefix = new Uint8Array(V2_DELIVERY_FRAME_PREFIX_BYTES);
  prefix.set(V2_DELIVERY_FRAME_MAGIC);
  new DataView(prefix.buffer).setUint32(4, headerLength, false);
  return prefix;
}

/**
 * Encodes a complete, bounded V2 delivery frame. The payload length and digest
 * are bound into the deterministic CBOR header before the frame is emitted.
 */
export function encodeV2DeliveryFrame(
  header: Map<number, CborValue>,
  payload: Uint8Array,
  payloadLengthKey: number,
  payloadDigestKey: number,
): Uint8Array {
  if (payload.byteLength > V2_MAX_ENCRYPTED_PAYLOAD_BYTES) {
    throw new Error('Delivery frame payload exceeds the configured limit.');
  }
  const declaredLength = requireUnsigned(
    header.get(payloadLengthKey),
    V2_MAX_ENCRYPTED_PAYLOAD_BYTES,
    'Delivery frame payload length',
  );
  const declaredDigest = requireBytes(
    header.get(payloadDigestKey),
    32,
    'Delivery frame payload digest',
  );
  if (declaredLength !== payload.byteLength) {
    throw new Error('Delivery frame payload length does not match its body.');
  }
  if (!bytesEqual(declaredDigest, sha256(payload))) {
    throw new Error('Delivery frame payload digest does not match its body.');
  }
  const encodedHeader = encodeCbor(header);
  if (
    encodedHeader.byteLength === 0 ||
    encodedHeader.byteLength > V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES
  ) {
    throw new Error('Delivery frame header exceeds the configured limit.');
  }
  const result = new Uint8Array(
    V2_DELIVERY_FRAME_PREFIX_BYTES +
      encodedHeader.byteLength +
      payload.byteLength,
  );
  result.set(framePrefix(encodedHeader.byteLength));
  result.set(encodedHeader, V2_DELIVERY_FRAME_PREFIX_BYTES);
  result.set(
    payload,
    V2_DELIVERY_FRAME_PREFIX_BYTES + encodedHeader.byteLength,
  );
  return result;
}

/** Decodes and verifies the common framing envelope before it is published. */
export function decodeV2DeliveryFrame(
  frame: Uint8Array,
  payloadLengthKey: number,
  payloadDigestKey: number,
): V2DeliveryFrame {
  if (frame.byteLength < V2_DELIVERY_FRAME_PREFIX_BYTES) {
    throw new Error('Delivery frame prefix is truncated.');
  }
  if (!bytesEqual(frame.subarray(0, 4), V2_DELIVERY_FRAME_MAGIC)) {
    throw new Error('Delivery frame magic is invalid.');
  }
  const headerLength = new DataView(
    frame.buffer,
    frame.byteOffset,
    frame.byteLength,
  ).getUint32(4, false);
  if (
    headerLength === 0 ||
    headerLength > V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES ||
    headerLength > frame.byteLength - V2_DELIVERY_FRAME_PREFIX_BYTES
  ) {
    throw new Error('Delivery frame header length is invalid.');
  }
  const headerBytes = frame.subarray(
    V2_DELIVERY_FRAME_PREFIX_BYTES,
    V2_DELIVERY_FRAME_PREFIX_BYTES + headerLength,
  );
  const decoded = decodeCbor(headerBytes, {
    maxBytes: V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES,
    maxMapPairs: 16,
    maxDepth: 4,
    requireDeterministic: true,
  });
  if (!(decoded instanceof Map)) {
    throw new Error('Delivery frame header must be a CBOR map.');
  }
  const payload = frame.subarray(V2_DELIVERY_FRAME_PREFIX_BYTES + headerLength);
  const declaredLength = requireUnsigned(
    decoded.get(payloadLengthKey),
    V2_MAX_ENCRYPTED_PAYLOAD_BYTES,
    'Delivery frame payload length',
  );
  const declaredDigest = requireBytes(
    decoded.get(payloadDigestKey),
    32,
    'Delivery frame payload digest',
  );
  if (declaredLength !== payload.byteLength) {
    throw new Error('Delivery frame payload length does not match its body.');
  }
  if (!bytesEqual(declaredDigest, sha256(payload))) {
    throw new Error('Delivery frame payload digest does not match its body.');
  }
  return { header: decoded, payload: Uint8Array.from(payload) };
}

/** Validates the bounded delivery-request header contract. */
export function validateV2DeliveryRequestHeader(
  header: Map<number, CborValue>,
  maximumDescriptorBytes = V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES,
): Map<number, CborValue> {
  const validated = requireCborMap(
    header,
    Object.values(V2_DELIVERY_REQUEST_KEYS),
    [
      V2_DELIVERY_REQUEST_KEYS.operationId,
      V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor,
      V2_DELIVERY_REQUEST_KEYS.requestedPolicy,
      V2_DELIVERY_REQUEST_KEYS.payloadLength,
      V2_DELIVERY_REQUEST_KEYS.payloadDigest,
      V2_DELIVERY_REQUEST_KEYS.dataSlotProof,
    ],
  );
  requireBytes(
    validated.get(V2_DELIVERY_REQUEST_KEYS.operationId),
    16,
    'Operation ID',
  );
  const descriptor = requireBytes(
    validated.get(V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor),
    undefined,
    'Encrypted descriptor',
  );
  if (
    descriptor.byteLength === 0 ||
    descriptor.byteLength > maximumDescriptorBytes
  ) {
    throw new Error('Encrypted descriptor exceeds the configured limit.');
  }
  const requestedPolicy = validated.get(
    V2_DELIVERY_REQUEST_KEYS.requestedPolicy,
  );
  if (!(requestedPolicy instanceof Map)) {
    throw new Error('Requested transport policy is invalid.');
  }
  // The signed expiry is the only policy field the server acts on, and it can
  // only tighten server-visible expiry, so it has to be present and sane.
  requireUnsigned(
    requestedPolicy.get(V2_TRANSPORT_POLICY_KEYS.expiresAt),
    Number.MAX_SAFE_INTEGER,
    'Requested transport policy expiry',
  );
  decodeV2SlotProof(validated.get(V2_DELIVERY_REQUEST_KEYS.dataSlotProof)!);
  const controlQueries = validated.get(V2_DELIVERY_REQUEST_KEYS.controlQueries);
  if (
    controlQueries !== undefined &&
    (!Array.isArray(controlQueries) ||
      controlQueries.length > V2_MAX_BATCHED_SLOT_PROOFS ||
      controlQueries.some((query) => {
        try {
          decodeV2SlotProof(query);
          return false;
        } catch {
          return true;
        }
      }))
  ) {
    throw new Error('Batched control-slot queries are invalid.');
  }
  const processed = validated.get(
    V2_DELIVERY_REQUEST_KEYS.processedControlEventIds,
  );
  if (
    processed !== undefined &&
    (!Array.isArray(processed) ||
      processed.length > V2_MAX_BATCHED_SLOT_PROOFS ||
      processed.some(
        (id) => !(id instanceof Uint8Array) || id.byteLength !== 16,
      ))
  ) {
    throw new Error('Processed control-event IDs are invalid.');
  }
  return validated;
}

/** Validates the complete bounded delivery-request frame contract. */
export function decodeV2DeliveryRequestFrame(
  frame: Uint8Array,
): V2DeliveryFrame {
  const decoded = decodeV2DeliveryFrame(
    frame,
    V2_DELIVERY_REQUEST_KEYS.payloadLength,
    V2_DELIVERY_REQUEST_KEYS.payloadDigest,
  );
  validateV2DeliveryRequestHeader(decoded.header);
  return decoded;
}

/**
 * Hashes a delivery request after replacing every proof MAC with 32 zero bytes.
 * This breaks the otherwise circular dependency between a proof and the body it
 * authenticates without leaving any request field unsigned.
 */
export function v2DeliveryFrameAuthorizationDigest(
  frame: Uint8Array,
): Uint8Array {
  const decoded = decodeV2DeliveryRequestFrame(frame);
  return new StreamingSha256()
    .update(encodeV2DeliveryFrameAuthorizationPrefix(decoded.header))
    .update(decoded.payload)
    .digest();
}

/**
 * Produces the prefix used to hash a delivery request for authorization. The
 * payload follows this prefix unchanged and may therefore be streamed.
 */
export function encodeV2DeliveryFrameAuthorizationPrefix(
  requestHeader: Map<number, CborValue>,
): Uint8Array {
  const header = new Map(validateV2DeliveryRequestHeader(requestHeader));
  header.set(
    V2_DELIVERY_REQUEST_KEYS.dataSlotProof,
    redactSlotProofMac(header.get(V2_DELIVERY_REQUEST_KEYS.dataSlotProof)!),
  );
  if (header.has(V2_DELIVERY_REQUEST_KEYS.controlQueries)) {
    header.set(
      V2_DELIVERY_REQUEST_KEYS.controlQueries,
      redactSlotProofBatch(header.get(V2_DELIVERY_REQUEST_KEYS.controlQueries)),
    );
  }
  const encodedHeader = encodeCbor(header);
  const result = new Uint8Array(
    V2_DELIVERY_FRAME_PREFIX_BYTES + encodedHeader.byteLength,
  );
  result.set(framePrefix(encodedHeader.byteLength));
  result.set(encodedHeader, V2_DELIVERY_FRAME_PREFIX_BYTES);
  return result;
}

/** Validates the bounded POST /v2/inbox response frame contract. */
export function decodeV2InboxResponseFrame(frame: Uint8Array): V2DeliveryFrame {
  const decoded = decodeV2DeliveryFrame(
    frame,
    V2_INBOX_RESPONSE_KEYS.payloadLength,
    V2_INBOX_RESPONSE_KEYS.payloadDigest,
  );
  const header = requireCborMap(
    decoded.header,
    Object.values(V2_INBOX_RESPONSE_KEYS),
    [
      V2_INBOX_RESPONSE_KEYS.slotResults,
      V2_INBOX_RESPONSE_KEYS.controlEvents,
      V2_INBOX_RESPONSE_KEYS.payloadLength,
      V2_INBOX_RESPONSE_KEYS.payloadDigest,
    ],
  );
  const slotResults = header.get(V2_INBOX_RESPONSE_KEYS.slotResults);
  if (
    !Array.isArray(slotResults) ||
    slotResults.length > V2_MAX_BATCHED_SLOT_PROOFS ||
    slotResults.some((entry) => !(entry instanceof Map))
  ) {
    throw new Error('Inbox slot results are invalid.');
  }
  const controlEvents = header.get(V2_INBOX_RESPONSE_KEYS.controlEvents);
  if (
    !Array.isArray(controlEvents) ||
    controlEvents.length > V2_MAX_BATCHED_SLOT_PROOFS ||
    controlEvents.some((entry) => !(entry instanceof Map))
  ) {
    throw new Error('Inbox control events are invalid.');
  }
  const deliveryId = header.get(V2_INBOX_RESPONSE_KEYS.deliveryId);
  const deliveryFields = [
    V2_INBOX_RESPONSE_KEYS.slot,
    V2_INBOX_RESPONSE_KEYS.encryptedDescriptor,
    V2_INBOX_RESPONSE_KEYS.effectivePolicy,
  ];
  if (deliveryId === undefined) {
    if (
      decoded.payload.byteLength !== 0 ||
      deliveryFields.some((key) => header.has(key))
    ) {
      throw new Error(
        'Inbox response has delivery fields without a delivery ID.',
      );
    }
    return decoded;
  }
  requireBytes(deliveryId, 16, 'Inbox delivery ID');
  requireBytes(header.get(V2_INBOX_RESPONSE_KEYS.slot), 16, 'Inbox slot');
  const descriptor = requireBytes(
    header.get(V2_INBOX_RESPONSE_KEYS.encryptedDescriptor),
    undefined,
    'Inbox encrypted descriptor',
  );
  if (
    descriptor.byteLength === 0 ||
    descriptor.byteLength > V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES
  ) {
    throw new Error('Inbox encrypted descriptor exceeds the configured limit.');
  }
  if (!(header.get(V2_INBOX_RESPONSE_KEYS.effectivePolicy) instanceof Map)) {
    throw new Error('Inbox effective policy is invalid.');
  }
  return decoded;
}

/** Decodes the bounded deterministic-CBOR query body for POST /v2/inbox. */
export function decodeV2InboxRequest(body: Uint8Array): V2InboxRequest {
  const decoded = decodeCbor(body, {
    maxBytes: V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES,
    maxArrayElements: V2_MAX_BATCHED_SLOT_PROOFS,
    maxMapPairs: 8,
    maxDepth: 4,
    requireDeterministic: true,
  });
  const header = requireCborMap(decoded, Object.values(V2_INBOX_REQUEST_KEYS), [
    V2_INBOX_REQUEST_KEYS.dataSlotProofs,
  ]);
  for (const key of [
    V2_INBOX_REQUEST_KEYS.dataSlotProofs,
    V2_INBOX_REQUEST_KEYS.controlSlotProofs,
  ]) {
    const proofs = header.get(key);
    if (
      proofs !== undefined &&
      (!Array.isArray(proofs) ||
        proofs.length > V2_MAX_BATCHED_SLOT_PROOFS ||
        proofs.some((proof) => {
          try {
            decodeV2SlotProof(proof);
            return false;
          } catch {
            return true;
          }
        }))
    ) {
      throw new Error('Inbox slot proofs are invalid.');
    }
  }
  const processed = header.get(V2_INBOX_REQUEST_KEYS.processedControlEventIds);
  if (
    processed !== undefined &&
    (!Array.isArray(processed) ||
      processed.length > V2_MAX_BATCHED_SLOT_PROOFS ||
      processed.some(
        (id) => !(id instanceof Uint8Array) || id.byteLength !== 16,
      ))
  ) {
    throw new Error('Processed control-event IDs are invalid.');
  }
  return { header };
}

/** Hashes an inbox request after canonical proof-MAC redaction. */
export function v2InboxRequestAuthorizationDigest(
  body: Uint8Array,
): Uint8Array {
  const request = decodeV2InboxRequest(body);
  const header = new Map(request.header);
  header.set(
    V2_INBOX_REQUEST_KEYS.dataSlotProofs,
    redactSlotProofBatch(header.get(V2_INBOX_REQUEST_KEYS.dataSlotProofs)),
  );
  if (header.has(V2_INBOX_REQUEST_KEYS.controlSlotProofs)) {
    header.set(
      V2_INBOX_REQUEST_KEYS.controlSlotProofs,
      redactSlotProofBatch(header.get(V2_INBOX_REQUEST_KEYS.controlSlotProofs)),
    );
  }
  return sha256(encodeCbor(header));
}

/** Decodes the bounded deterministic-CBOR body for delivery completion. */
export function decodeV2CompletionRequest(body: Uint8Array): {
  header: Map<number, CborValue>;
} {
  const decoded = decodeCbor(body, {
    maxBytes: V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES,
    maxMapPairs: 12,
    maxDepth: 4,
    requireDeterministic: true,
  });
  const header = requireCborMap(
    decoded,
    Object.values(V2_COMPLETION_REQUEST_KEYS),
    Object.values(V2_COMPLETION_REQUEST_KEYS),
  );
  requireBytes(
    header.get(V2_COMPLETION_REQUEST_KEYS.deliveryId),
    16,
    'Completion delivery ID',
  );
  decodeV2SlotProof(header.get(V2_COMPLETION_REQUEST_KEYS.dataAckProof)!);
  decodeV2SlotProof(header.get(V2_COMPLETION_REQUEST_KEYS.controlWriteProof)!);
  for (const [key, length, name] of [
    [V2_COMPLETION_REQUEST_KEYS.sourceSlot, 16, 'Completion source slot'],
    [V2_COMPLETION_REQUEST_KEYS.targetSlot, 16, 'Completion target slot'],
    [V2_COMPLETION_REQUEST_KEYS.policyDigest, 32, 'Completion policy digest'],
    [
      V2_COMPLETION_REQUEST_KEYS.descriptorDigest,
      32,
      'Completion descriptor digest',
    ],
    [V2_COMPLETION_REQUEST_KEYS.operationId, 16, 'Completion operation ID'],
  ] as const) {
    requireBytes(header.get(key), length, name);
  }
  const result = header.get(V2_COMPLETION_REQUEST_KEYS.result);
  if (result !== 0 && result !== 1) {
    throw new Error('Completion result is invalid.');
  }
  const acknowledgement = requireBytes(
    header.get(V2_COMPLETION_REQUEST_KEYS.encryptedAcknowledgement),
    undefined,
    'Encrypted acknowledgement',
  );
  if (
    acknowledgement.byteLength === 0 ||
    acknowledgement.byteLength > V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES
  ) {
    throw new Error('Encrypted acknowledgement exceeds the configured limit.');
  }
  return { header };
}

/** Hashes completion input after redacting the two self-referential proof MACs. */
export function v2CompletionRequestAuthorizationDigest(
  body: Uint8Array,
): Uint8Array {
  const request = decodeV2CompletionRequest(body);
  const header = new Map(request.header);
  header.set(
    V2_COMPLETION_REQUEST_KEYS.dataAckProof,
    redactSlotProofMac(header.get(V2_COMPLETION_REQUEST_KEYS.dataAckProof)!),
  );
  header.set(
    V2_COMPLETION_REQUEST_KEYS.controlWriteProof,
    redactSlotProofMac(
      header.get(V2_COMPLETION_REQUEST_KEYS.controlWriteProof)!,
    ),
  );
  return sha256(encodeCbor(header));
}

export function decodeV2ControlEventRequest(body: Uint8Array): {
  header: Map<number, CborValue>;
} {
  const decoded = decodeCbor(body, {
    maxBytes: V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES,
    maxMapPairs: 4,
    maxDepth: 3,
    requireDeterministic: true,
  });
  const header = requireCborMap(
    decoded,
    Object.values(V2_CONTROL_EVENT_REQUEST_KEYS),
    Object.values(V2_CONTROL_EVENT_REQUEST_KEYS),
  );
  requireBytes(
    header.get(V2_CONTROL_EVENT_REQUEST_KEYS.operationId),
    16,
    'Control operation ID',
  );
  decodeV2SlotProof(
    header.get(V2_CONTROL_EVENT_REQUEST_KEYS.controlSlotProof)!,
  );
  const envelope = requireBytes(
    header.get(V2_CONTROL_EVENT_REQUEST_KEYS.encryptedEnvelope),
    undefined,
    'Control envelope',
  );
  if (
    envelope.byteLength === 0 ||
    envelope.byteLength > V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES
  ) {
    throw new Error('Control envelope exceeds the configured limit.');
  }
  return { header };
}

export function v2ControlEventRequestAuthorizationDigest(
  body: Uint8Array,
): Uint8Array {
  const request = decodeV2ControlEventRequest(body);
  const header = new Map(request.header);
  header.set(
    V2_CONTROL_EVENT_REQUEST_KEYS.controlSlotProof,
    redactSlotProofMac(
      header.get(V2_CONTROL_EVENT_REQUEST_KEYS.controlSlotProof)!,
    ),
  );
  return sha256(encodeCbor(header));
}
