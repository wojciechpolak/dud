// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { encodeCbor, requireCborMap, type CborValue } from './cbor.js';
import { bytesToHex } from './v2-auth.js';
import { encryptV2AgeGrant } from './v2-age.js';
import { readV2CborRequest } from './v2-http.js';
import { sha256 } from './sha256.js';
import type { V2Direction, V2Scope } from './v2-types.js';

const textEncoder = new TextEncoder();
const ASSIGNED_SCOPES = ['ack', 'read', 'write'] as const;

export const REISSUE_CLOCK_SKEW_SECONDS = 300;

export class ReissueError extends Error {
  constructor(
    readonly code: 1 | 3 | 4 | 5 | 7 | 10 | 13 | 14,
    message: string,
  ) {
    super(message);
  }
}

export interface ParsedV2ReissueRequest {
  relationship: Uint8Array;
  relationshipId: string;
  role: 0 | 1;
  nonce: Uint8Array;
  expiresAt: number;
  scopes: V2Scope[];
  signature: Uint8Array;
  signedMap: Map<number, CborValue>;
}

interface V2ReissueGrantCapability {
  direction: V2Direction;
  scope: V2Scope;
  tokenSecret: Uint8Array;
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

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function requiredBytes(
  map: Map<number, CborValue>,
  key: number,
  length: number,
  name: string,
): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new ReissueError(1, `${name} is invalid.`);
  }
  return value;
}

function parseScopes(value: CborValue | undefined): V2Scope[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > ASSIGNED_SCOPES.length
  ) {
    throw new ReissueError(1, 'Reissue scopes are invalid.');
  }
  const scopes = value.map((scope) => {
    if (
      typeof scope !== 'string' ||
      !ASSIGNED_SCOPES.includes(scope as (typeof ASSIGNED_SCOPES)[number])
    ) {
      throw new ReissueError(1, 'Reissue scope is invalid.');
    }
    return scope as V2Scope;
  });
  const sorted = [...scopes].sort();
  if (
    scopes.some((scope, index) => scope !== sorted[index]) ||
    new Set(scopes).size !== scopes.length
  ) {
    throw new ReissueError(1, 'Reissue scopes must be unique and sorted.');
  }
  return scopes;
}

export function directionForReissue(role: 0 | 1, scope: V2Scope): V2Direction {
  const outbound: V2Direction =
    role === 0 ? 'inviter->invitee' : 'invitee->inviter';
  const inbound: V2Direction =
    role === 0 ? 'invitee->inviter' : 'inviter->invitee';
  return scope === 'write' ? outbound : inbound;
}

export async function parseV2ReissueRequest(
  request: Request,
  maximumDescriptorBytes: number,
  now: number,
  origin: string,
): Promise<ParsedV2ReissueRequest> {
  const wrapper = requireCborMap(
    await readV2CborRequest(request, maximumDescriptorBytes),
    [1, 2],
    [1, 2],
  );
  const signedMap = requireCborMap(
    wrapper.get(1)!,
    [1, 2, 3, 4, 5, 6, 7],
    [1, 2, 3, 4, 5, 6, 7],
  );
  if (signedMap.get(1) !== 2) {
    throw new ReissueError(1, 'Reissue version is unsupported.');
  }

  const relationship = requiredBytes(signedMap, 2, 16, 'Relationship ID');
  const role = signedMap.get(3);
  if (role !== 0 && role !== 1) {
    throw new ReissueError(1, 'Reissue role is invalid.');
  }
  const expiresAt = signedMap.get(5);
  if (
    typeof expiresAt !== 'number' ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt < now - REISSUE_CLOCK_SKEW_SECONDS ||
    expiresAt > now + REISSUE_CLOCK_SKEW_SECONDS ||
    signedMap.get(7) !== origin
  ) {
    throw new ReissueError(1, 'Reissue expiry or origin is invalid.');
  }

  return {
    relationship,
    relationshipId: bytesToHex(relationship),
    role,
    nonce: requiredBytes(signedMap, 4, 32, 'Reissue nonce'),
    expiresAt,
    scopes: parseScopes(signedMap.get(6)),
    signature: requiredBytes(wrapper, 2, 64, 'Reissue signature'),
    signedMap,
  };
}

export async function verifyV2ReissueSignature(
  publicKey: Uint8Array,
  signedMap: Map<number, CborValue>,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      arrayBuffer(publicKey),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const input = concat(
      textEncoder.encode('dud/v2/capability-reissue\0'),
      sha256(encodeCbor(signedMap)),
    );
    return crypto.subtle.verify(
      'Ed25519',
      key,
      arrayBuffer(signature),
      arrayBuffer(input),
    );
  } catch {
    return false;
  }
}

function encodeGrant(
  relationshipId: Uint8Array,
  role: 0 | 1,
  origin: string,
  capabilities: readonly V2ReissueGrantCapability[],
): Uint8Array {
  return encodeCbor(
    new Map<number, CborValue>([
      [1, 2],
      [2, relationshipId],
      [3, role],
      [4, 0],
      [5, origin],
      [
        6,
        capabilities.map(
          (capability) =>
            new Map<number, CborValue>([
              [1, capability.direction === 'inviter->invitee' ? 0 : 1],
              [2, capability.scope],
              [3, capability.tokenSecret],
            ]),
        ),
      ],
    ]),
  );
}

export async function encryptV2ReissueGrant(
  relationshipId: Uint8Array,
  role: 0 | 1,
  origin: string,
  capabilities: readonly V2ReissueGrantCapability[],
  recipient: Uint8Array,
  randomBytes: (length: number) => Uint8Array,
): Promise<Uint8Array> {
  return encryptV2AgeGrant(
    encodeGrant(relationshipId, role, origin, capabilities),
    recipient,
    randomBytes,
  );
}
