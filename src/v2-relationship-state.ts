// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { openV2AesGcm, sealV2AesGcm } from './v2-aes-gcm.js';
import {
  decodeCbor,
  encodeCbor,
  requireCborMap,
  type CborValue,
} from './cbor.js';
import type { V2RelationshipRecord } from './v2-types.js';

const encoder = new TextEncoder();

function additionalData(relationshipId: string): Uint8Array {
  return encoder.encode(`dud/v2/relationship-state|${relationshipId}`);
}

function value(record: V2RelationshipRecord): Uint8Array {
  return encodeCbor(
    new Map<number, CborValue>([
      [1, 2],
      [2, record.canonicalOrigin],
      [3, record.inviterSigningPublicKey],
      [4, record.inviterAgeRecipient],
      [5, record.inviteeSigningPublicKey],
      [6, record.inviteeAgeRecipient],
      [7, record.createdAt],
      [8, record.generation ?? 0],
    ]),
  );
}

function text(map: Map<number, CborValue>, key: number): string {
  const item = map.get(key);
  if (typeof item !== 'string' || item.length === 0) {
    throw new Error('Encrypted relationship state is invalid.');
  }
  return item;
}

export async function encryptV2RelationshipState(
  deploymentKey: Uint8Array,
  record: V2RelationshipRecord,
  randomBytes: (length: number) => Uint8Array,
): Promise<Uint8Array> {
  if (deploymentKey.byteLength !== 32) {
    throw new Error('V2 deployment key is invalid.');
  }
  const nonce = randomBytes(12);
  if (nonce.byteLength !== 12) {
    throw new Error('V2 random source returned an invalid nonce.');
  }
  return sealV2AesGcm(
    deploymentKey,
    nonce,
    additionalData(record.relationshipId),
    value(record),
  );
}

export async function decryptV2RelationshipState(
  deploymentKey: Uint8Array,
  relationshipId: string,
  encryptedState: Uint8Array,
): Promise<V2RelationshipRecord> {
  if (deploymentKey.byteLength !== 32 || encryptedState.byteLength < 29) {
    throw new Error('Encrypted relationship state is invalid.');
  }
  let decoded: Map<number, CborValue>;
  try {
    const plaintext = await openV2AesGcm(
      deploymentKey,
      encryptedState,
      additionalData(relationshipId),
    );
    const raw = decodeCbor(plaintext);
    if (!(raw instanceof Map)) {
      throw new Error('invalid');
    }
    const version = raw.get(1);
    decoded = requireCborMap(
      raw,
      version === 1 ? [1, 2, 3, 4, 5, 6, 7] : [1, 2, 3, 4, 5, 6, 7, 8],
      version === 1 ? [1, 2, 3, 4, 5, 6, 7] : [1, 2, 3, 4, 5, 6, 7, 8],
    );
  } catch {
    throw new Error('Encrypted relationship state failed authentication.');
  }
  if (
    (decoded.get(1) !== 1 && decoded.get(1) !== 2) ||
    typeof decoded.get(7) !== 'number' ||
    (decoded.get(1) === 2 && typeof decoded.get(8) !== 'number')
  ) {
    throw new Error('Encrypted relationship state is invalid.');
  }
  return {
    relationshipId,
    canonicalOrigin: text(decoded, 2),
    inviterSigningPublicKey: text(decoded, 3),
    inviterAgeRecipient: text(decoded, 4),
    inviteeSigningPublicKey: text(decoded, 5),
    inviteeAgeRecipient: text(decoded, 6),
    createdAt: decoded.get(7) as number,
    generation: decoded.get(1) === 2 ? (decoded.get(8) as number) : 0,
  };
}
