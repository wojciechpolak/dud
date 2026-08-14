// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  decodeCbor,
  encodeCbor,
  requireCborMap,
  type CborValue,
} from './cbor.js';
import type { V2RelationshipRecord } from './v2-types.js';

const encoder = new TextEncoder();

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    parts.reduce((length, part) => length + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

function additionalData(relationshipId: string): Uint8Array {
  return encoder.encode(`dud/v2/relationship-state|${relationshipId}`);
}

function value(record: V2RelationshipRecord): Uint8Array {
  return encodeCbor(
    new Map<number, CborValue>([
      [1, 1],
      [2, record.canonicalOrigin],
      [3, record.inviterSigningPublicKey],
      [4, record.inviterAgeRecipient],
      [5, record.inviteeSigningPublicKey],
      [6, record.inviteeAgeRecipient],
      [7, record.createdAt],
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
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(deploymentKey),
    'AES-GCM',
    false,
    ['encrypt'],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: arrayBuffer(nonce),
        additionalData: arrayBuffer(additionalData(record.relationshipId)),
      },
      key,
      arrayBuffer(value(record)),
    ),
  );
  return concat(nonce, ciphertext);
}

export async function decryptV2RelationshipState(
  deploymentKey: Uint8Array,
  relationshipId: string,
  encryptedState: Uint8Array,
): Promise<V2RelationshipRecord> {
  if (deploymentKey.byteLength !== 32 || encryptedState.byteLength < 29) {
    throw new Error('Encrypted relationship state is invalid.');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(deploymentKey),
    'AES-GCM',
    false,
    ['decrypt'],
  );
  let decoded: Map<number, CborValue>;
  try {
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: arrayBuffer(encryptedState.subarray(0, 12)),
          additionalData: arrayBuffer(additionalData(relationshipId)),
        },
        key,
        arrayBuffer(encryptedState.subarray(12)),
      ),
    );
    decoded = requireCborMap(
      decodeCbor(plaintext),
      [1, 2, 3, 4, 5, 6, 7],
      [1, 2, 3, 4, 5, 6, 7],
    );
  } catch {
    throw new Error('Encrypted relationship state failed authentication.');
  }
  if (decoded.get(1) !== 1 || typeof decoded.get(7) !== 'number') {
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
  };
}
