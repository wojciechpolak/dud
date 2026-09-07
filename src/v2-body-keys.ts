// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { V2_CHUNK_LIMITS } from './v2-contract.js';

const ID = '[a-f0-9]{32}';
const BASELINE_DELIVERY = new RegExp(`^deliveries/(${ID})\\.bin$`);
const BASELINE_STAGING = new RegExp(`^staging/(${ID})\\.bin$`);
const DELIVERY_CHUNK = new RegExp(`^deliveries/(${ID})/chunks/(${ID})\\.age$`);
const STAGED_CHUNK = new RegExp(`^staging/uploads/(${ID})/(${ID})\\.age$`);

function requireId(id: string, name: string): void {
  if (!new RegExp(`^${ID}$`).test(id)) {
    throw new Error(`${name} is invalid.`);
  }
}

export function v2StagedChunkKey(uploadId: string, chunkId: string): string {
  requireId(uploadId, 'Chunk upload ID');
  requireId(chunkId, 'Chunk ID');
  return `staging/uploads/${uploadId}/${chunkId}.age`;
}

export function v2DeliveryChunkKey(
  deliveryId: string,
  chunkId: string,
): string {
  requireId(deliveryId, 'Delivery ID');
  requireId(chunkId, 'Chunk ID');
  return `deliveries/${deliveryId}/chunks/${chunkId}.age`;
}

export type V2BodyKeyKind =
  | 'delivery'
  | 'staging'
  | 'delivery-chunk'
  | 'staged-chunk';

export function v2BodyKeyKind(key: string): V2BodyKeyKind {
  if (BASELINE_DELIVERY.test(key)) {
    return 'delivery';
  }
  if (BASELINE_STAGING.test(key)) {
    return 'staging';
  }
  if (DELIVERY_CHUNK.test(key)) {
    return 'delivery-chunk';
  }
  if (STAGED_CHUNK.test(key)) {
    return 'staged-chunk';
  }
  throw new Error('Delivery body key is invalid.');
}

export function isV2BodyKey(key: string): boolean {
  try {
    v2BodyKeyKind(key);
    return true;
  } catch {
    return false;
  }
}

export function validateV2BodyPartDeclarations(
  parts: readonly { id: string; length: number; digest: Uint8Array }[],
  expectedTotalLength: number,
): void {
  if (
    parts.length < 2 ||
    parts.length > V2_CHUNK_LIMITS.maxChunksPerDelivery ||
    !Number.isSafeInteger(expectedTotalLength) ||
    expectedTotalLength < 1
  ) {
    throw new Error('Delivery chunk manifest is invalid.');
  }
  const seen = new Set<string>();
  let total = 0;
  for (const part of parts) {
    requireId(part.id, 'Chunk ID');
    if (
      seen.has(part.id) ||
      !Number.isSafeInteger(part.length) ||
      part.length < 1 ||
      part.length > V2_CHUNK_LIMITS.maxChunkCiphertextBytes ||
      !(part.digest instanceof Uint8Array) ||
      part.digest.byteLength !== 32
    ) {
      throw new Error('Delivery chunk manifest is invalid.');
    }
    seen.add(part.id);
    total += part.length;
    if (!Number.isSafeInteger(total)) {
      throw new Error('Delivery chunk manifest is invalid.');
    }
  }
  if (
    total !== expectedTotalLength ||
    total > V2_CHUNK_LIMITS.maxChunkedCiphertextBytes
  ) {
    throw new Error('Delivery chunk manifest total is invalid.');
  }
}
