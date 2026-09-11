// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  bytesEqual,
  decodeCbor,
  encodeCbor,
  requireCborMap,
  type CborValue,
} from './cbor.js';
import { bytesToHex, decodeBase64Url, encodeBase64Url } from './v2-auth.js';
import {
  readV2CborRequest,
  v2CborResponse,
  v2ErrorResponse,
} from './v2-http.js';
import {
  decryptV2RelationshipState,
  encryptV2RelationshipState,
} from './v2-relationship-state.js';
import { sha256 } from './sha256.js';
import type {
  V2RelationshipRepository,
  V2RelationshipResetRepository,
  V2Repository,
} from './v2-repository.js';
import type {
  V2Limits,
  V2RelationshipRecord,
  V2RelationshipResetRecord,
  V2Store,
} from './v2-types.js';

const encoder = new TextEncoder();
const RESET_CLOCK_SKEW_SECONDS = 300;
const RESET_MAX_LIFETIME_SECONDS = 86_400;

class ResetError extends Error {
  constructor(
    readonly code: 1 | 3 | 4 | 5 | 7 | 8 | 13,
    message: string,
  ) {
    super(message);
  }
}

interface StoredResetData {
  proposal: Map<number, CborValue>;
  proposalSignature: Uint8Array;
  acceptance?: Map<number, CborValue>;
  acceptanceSignature?: Uint8Array;
  receipt?: Uint8Array;
  cancellation?: Map<number, CborValue>;
  cancellationSignature?: Uint8Array;
  relationship: V2RelationshipRecord;
}

interface ResetDependencies {
  store: V2Store;
  repository?: V2Repository;
  deploymentKey: Uint8Array;
  limits: V2Limits;
  now: () => number;
  randomBytes: (length: number) => Uint8Array;
}

function seconds(milliseconds: number): number {
  return Math.floor(milliseconds / 1000);
}

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

function requiredBytes(
  map: Map<number, CborValue>,
  key: number,
  length: number,
  label: string,
): Uint8Array {
  const value = map.get(key);
  if (
    !(value instanceof Uint8Array) ||
    (length >= 0 && value.byteLength !== length)
  ) {
    throw new ResetError(1, `${label} is invalid.`);
  }
  return value;
}

function requiredInteger(
  map: Map<number, CborValue>,
  key: number,
  label: string,
): number {
  const value = map.get(key);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new ResetError(1, `${label} is invalid.`);
  }
  return value;
}

function validateSnapshot(value: CborValue | undefined): void {
  const names = ['out:data', 'out:control', 'in:data', 'in:control'];
  if (!Array.isArray(value) || value.length !== names.length) {
    throw new ResetError(1, 'Reset chain snapshot is invalid.');
  }
  value.forEach((raw, index) => {
    const entry = requireCborMap(raw, [1, 2, 3], [1, 2, 3]);
    if (
      entry.get(1) !== names[index] ||
      requiredInteger(entry, 2, 'Reset chain sequence') < 0
    ) {
      throw new ResetError(1, 'Reset chain snapshot is invalid.');
    }
    requiredBytes(entry, 3, 32, 'Reset chain digest');
  });
}

function validateDisposition(value: CborValue | undefined): void {
  if (value === undefined) {
    throw new ResetError(1, 'Reset disposition is missing.');
  }
  const map = requireCborMap(
    value,
    [1, 2, 3, 4, 5, 6, 7, 8],
    [1, 2, 3, 4, 5, 6, 7, 8],
  );
  for (let key = 1; key <= 8; key++) {
    requiredInteger(map, key, 'Reset disposition count');
  }
}

async function verifyResetSignature(
  label: string,
  value: Map<number, CborValue>,
  signature: Uint8Array,
  encodedPublicKey: string,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      arrayBuffer(decodeBase64Url(encodedPublicKey, 32)),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    return crypto.subtle.verify(
      'Ed25519',
      key,
      arrayBuffer(signature),
      arrayBuffer(
        concat(
          encoder.encode(`dud/v2/relationship-reset/${label}\0`),
          sha256(encodeCbor(value)),
        ),
      ),
    );
  } catch {
    return false;
  }
}

function relationshipMap(record: V2RelationshipRecord): Map<number, CborValue> {
  return new Map<number, CborValue>([
    [1, record.relationshipId],
    [2, record.canonicalOrigin],
    [3, record.inviterSigningPublicKey],
    [4, record.inviterAgeRecipient],
    [5, record.inviteeSigningPublicKey],
    [6, record.inviteeAgeRecipient],
    [7, record.createdAt],
    [8, record.generation ?? 0],
  ]);
}

function decodeRelationship(
  value: CborValue | undefined,
): V2RelationshipRecord {
  if (value === undefined) {
    throw new ResetError(13, 'Stored reset relationship is missing.');
  }
  const map = requireCborMap(
    value,
    [1, 2, 3, 4, 5, 6, 7, 8],
    [1, 2, 3, 4, 5, 6, 7, 8],
  );
  const texts = [1, 2, 3, 4, 5, 6].map((key) => map.get(key));
  if (texts.some((value) => typeof value !== 'string')) {
    throw new ResetError(13, 'Stored reset relationship is invalid.');
  }
  return {
    relationshipId: texts[0] as string,
    canonicalOrigin: texts[1] as string,
    inviterSigningPublicKey: texts[2] as string,
    inviterAgeRecipient: texts[3] as string,
    inviteeSigningPublicKey: texts[4] as string,
    inviteeAgeRecipient: texts[5] as string,
    createdAt: requiredInteger(map, 7, 'Relationship creation time'),
    generation: requiredInteger(map, 8, 'Relationship generation'),
  };
}

function encodeStoredReset(data: StoredResetData): Uint8Array {
  const map = new Map<number, CborValue>([
    [1, data.proposal],
    [2, data.proposalSignature],
    [6, relationshipMap(data.relationship)],
  ]);
  if (data.acceptance) {
    map.set(3, data.acceptance);
  }
  if (data.acceptanceSignature) {
    map.set(4, data.acceptanceSignature);
  }
  if (data.receipt) {
    map.set(5, data.receipt);
  }
  if (data.cancellation) {
    map.set(7, data.cancellation);
  }
  if (data.cancellationSignature) {
    map.set(8, data.cancellationSignature);
  }
  return encodeCbor(map);
}

function decodeStoredReset(value: Uint8Array): StoredResetData {
  const map = requireCborMap(
    decodeCbor(value),
    [1, 2, 3, 4, 5, 6, 7, 8],
    [1, 2, 6],
  );
  const proposal = requireCborMap(
    map.get(1)!,
    Array.from({ length: 16 }, (_, index) => index + 1),
    Array.from({ length: 16 }, (_, index) => index + 1),
  );
  const proposalSignature = requiredBytes(
    map,
    2,
    64,
    'Stored reset proposal signature',
  );
  const acceptance = map.has(3)
    ? requireCborMap(
        map.get(3)!,
        [1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 5, 6, 7, 8, 9],
      )
    : undefined;
  const acceptanceSignature = map.has(4)
    ? requiredBytes(map, 4, 64, 'Stored reset acceptance signature')
    : undefined;
  const receipt = map.has(5)
    ? requiredBytes(map, 5, -1, 'Stored reset receipt')
    : undefined;
  const cancellation = map.has(7)
    ? requireCborMap(map.get(7)!, [1, 2, 3, 4, 5, 6, 7], [1, 2, 3, 4, 5, 6, 7])
    : undefined;
  const cancellationSignature = map.has(8)
    ? requiredBytes(map, 8, 64, 'Stored reset cancellation signature')
    : undefined;
  return {
    proposal,
    proposalSignature,
    ...(acceptance ? { acceptance } : {}),
    ...(acceptanceSignature ? { acceptanceSignature } : {}),
    ...(receipt ? { receipt } : {}),
    ...(cancellation ? { cancellation } : {}),
    ...(cancellationSignature ? { cancellationSignature } : {}),
    relationship: decodeRelationship(map.get(6)),
  };
}

function resetAad(oldRelationshipId: string): Uint8Array {
  return encoder.encode(`dud/v2/relationship-reset-state|${oldRelationshipId}`);
}

async function encryptStoredReset(
  keyBytes: Uint8Array,
  oldRelationshipId: string,
  data: StoredResetData,
  randomBytes: (length: number) => Uint8Array,
): Promise<Uint8Array> {
  const nonce = randomBytes(12);
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(keyBytes),
    'AES-GCM',
    false,
    ['encrypt'],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: arrayBuffer(nonce),
        additionalData: arrayBuffer(resetAad(oldRelationshipId)),
      },
      key,
      arrayBuffer(encodeStoredReset(data)),
    ),
  );
  return concat(nonce, ciphertext);
}

async function decryptStoredReset(
  keyBytes: Uint8Array,
  oldRelationshipId: string,
  encrypted: Uint8Array,
): Promise<StoredResetData> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      arrayBuffer(keyBytes),
      'AES-GCM',
      false,
      ['decrypt'],
    );
    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: arrayBuffer(encrypted.subarray(0, 12)),
          additionalData: arrayBuffer(resetAad(oldRelationshipId)),
        },
        key,
        arrayBuffer(encrypted.subarray(12)),
      ),
    );
    return decodeStoredReset(plaintext);
  } catch {
    throw new ResetError(
      13,
      'Stored relationship reset failed authentication.',
    );
  }
}

function resetRepository(
  repository: ResetDependencies['repository'],
): V2RelationshipResetRepository | undefined {
  const candidate = repository as
    | Partial<V2RelationshipResetRepository>
    | undefined;
  return candidate &&
    typeof candidate.findRelationshipReset === 'function' &&
    typeof candidate.proposeRelationshipReset === 'function' &&
    typeof candidate.activateRelationshipReset === 'function' &&
    typeof candidate.cancelRelationshipReset === 'function'
    ? (candidate as V2RelationshipResetRepository)
    : undefined;
}

function relationshipRepository(
  repository: ResetDependencies['repository'],
): V2RelationshipRepository | undefined {
  const candidate = repository as Partial<V2RelationshipRepository> | undefined;
  return candidate &&
    typeof candidate.findRelationship === 'function' &&
    typeof candidate.createRelationship === 'function'
    ? (candidate as V2RelationshipRepository)
    : undefined;
}

async function loadRelationship(
  dependencies: ResetDependencies,
  relationshipId: string,
): Promise<V2RelationshipRecord | null> {
  const repository = relationshipRepository(dependencies.repository);
  if (repository) {
    const stored = await repository.findRelationship(relationshipId);
    return stored
      ? decryptV2RelationshipState(
          dependencies.deploymentKey,
          relationshipId,
          stored.encryptedState,
        )
      : null;
  }
  const state = await dependencies.store.readState();
  if (state.revocations[`${relationshipId}|*|*`]?.revoked) {
    return null;
  }
  return state.relationships[relationshipId] ?? null;
}

async function loadReset(
  dependencies: ResetDependencies,
  oldRelationshipId: string,
): Promise<{
  data: StoredResetData;
  state: 'proposed' | 'active' | 'cancelled';
  resetId: string;
  newRelationshipId: string;
} | null> {
  const repository = resetRepository(dependencies.repository);
  if (repository) {
    const stored = await repository.findRelationshipReset(oldRelationshipId);
    return stored
      ? {
          data: await decryptStoredReset(
            dependencies.deploymentKey,
            oldRelationshipId,
            stored.encryptedState,
          ),
          state: stored.state,
          resetId: stored.resetId,
          newRelationshipId: stored.newRelationshipId,
        }
      : null;
  }
  const stored = (await dependencies.store.readState()).relationshipResets[
    oldRelationshipId
  ];
  if (!stored) {
    return null;
  }
  return {
    data: {
      proposal: requireCborMap(
        decodeCbor(decodeBase64Url(stored.proposal)),
        Array.from({ length: 16 }, (_, index) => index + 1),
        Array.from({ length: 16 }, (_, index) => index + 1),
      ),
      proposalSignature: decodeBase64Url(stored.proposalSignature, 64),
      ...(stored.acceptance
        ? {
            acceptance: requireCborMap(
              decodeCbor(decodeBase64Url(stored.acceptance)),
              [1, 2, 3, 4, 5, 6, 7, 8, 9],
              [1, 2, 3, 4, 5, 6, 7, 8, 9],
            ),
          }
        : {}),
      ...(stored.acceptanceSignature
        ? {
            acceptanceSignature: decodeBase64Url(
              stored.acceptanceSignature,
              64,
            ),
          }
        : {}),
      ...(stored.receipt ? { receipt: decodeBase64Url(stored.receipt) } : {}),
      ...(stored.cancellation
        ? {
            cancellation: requireCborMap(
              decodeCbor(decodeBase64Url(stored.cancellation)),
              [1, 2, 3, 4, 5, 6, 7],
              [1, 2, 3, 4, 5, 6, 7],
            ),
          }
        : {}),
      ...(stored.cancellationSignature
        ? {
            cancellationSignature: decodeBase64Url(
              stored.cancellationSignature,
              64,
            ),
          }
        : {}),
      relationship: stored.relationship,
    },
    state: stored.state,
    resetId: stored.resetId,
    newRelationshipId: stored.newRelationshipId,
  };
}

function responseForReset(
  data: StoredResetData,
  state: 'proposed' | 'active' | 'cancelled',
): Response {
  const result = new Map<number, CborValue>([
    [1, state === 'active' ? 2 : state === 'cancelled' ? 3 : 1],
    [2, data.proposal],
    [3, data.proposalSignature],
  ]);
  if (
    state === 'active' &&
    data.acceptance &&
    data.acceptanceSignature &&
    data.receipt
  ) {
    result.set(4, data.acceptance);
    result.set(5, data.acceptanceSignature);
    result.set(6, data.receipt);
  }
  if (
    state === 'cancelled' &&
    data.cancellation &&
    data.cancellationSignature
  ) {
    result.set(7, data.cancellation);
    result.set(8, data.cancellationSignature);
  }
  return v2CborResponse(result);
}

async function validateProposal(
  proposal: Map<number, CborValue>,
  signature: Uint8Array,
  relationship: V2RelationshipRecord,
  origin: string,
  now: number,
): Promise<void> {
  if (requiredInteger(proposal, 1, 'Reset version') !== 1) {
    throw new ResetError(1, 'Reset version is unsupported.');
  }
  if (requiredInteger(proposal, 16, 'Old key epoch') !== 0) {
    throw new ResetError(1, 'Reset old key epoch is unsupported.');
  }
  const oldId = requiredBytes(proposal, 2, 16, 'Old relationship ID');
  requiredBytes(proposal, 3, 16, 'Reset ID');
  requiredBytes(proposal, 4, 16, 'New relationship ID');
  const role = requiredInteger(proposal, 5, 'Reset initiator role');
  const generation = requiredInteger(proposal, 6, 'Reset generation');
  const expiresAt = requiredInteger(proposal, 15, 'Reset expiry');
  if (
    bytesToHex(oldId) !== relationship.relationshipId ||
    (role !== 0 && role !== 1) ||
    generation !== (relationship.generation ?? 0) + 1 ||
    proposal.get(7) !== origin ||
    expiresAt < now - RESET_CLOCK_SKEW_SECONDS ||
    expiresAt > now + RESET_MAX_LIFETIME_SECONDS + RESET_CLOCK_SKEW_SECONDS
  ) {
    throw new ResetError(1, 'Reset proposal binding is invalid.');
  }
  validateSnapshot(proposal.get(8));
  requiredBytes(proposal, 9, 16, 'Old initiator device ID');
  requiredBytes(proposal, 10, 16, 'Old peer device ID');
  requiredBytes(proposal, 11, 16, 'New initiator device ID');
  requiredBytes(proposal, 12, 32, 'New initiator signing key');
  requiredBytes(proposal, 13, 1216, 'New initiator recipient');
  validateDisposition(proposal.get(14));
  const publicKey =
    role === 0
      ? relationship.inviterSigningPublicKey
      : relationship.inviteeSigningPublicKey;
  if (
    !(await verifyResetSignature('proposal', proposal, signature, publicKey))
  ) {
    throw new ResetError(3, 'Reset proposal signature is invalid.');
  }
}

async function validateStatus(
  request: Map<number, CborValue>,
  signature: Uint8Array,
  relationship: V2RelationshipRecord,
  origin: string,
  now: number,
): Promise<void> {
  const role = requiredInteger(request, 3, 'Reset status role');
  const expiresAt = requiredInteger(request, 5, 'Reset status expiry');
  if (
    requiredInteger(request, 1, 'Reset status version') !== 1 ||
    bytesToHex(requiredBytes(request, 2, 16, 'Reset status relationship')) !==
      relationship.relationshipId ||
    (role !== 0 && role !== 1) ||
    request.get(6) !== origin ||
    expiresAt < now - RESET_CLOCK_SKEW_SECONDS ||
    expiresAt > now + RESET_CLOCK_SKEW_SECONDS
  ) {
    throw new ResetError(1, 'Reset status request is invalid.');
  }
  requiredBytes(request, 4, 16, 'Reset status nonce');
  const publicKey =
    role === 0
      ? relationship.inviterSigningPublicKey
      : relationship.inviteeSigningPublicKey;
  if (!(await verifyResetSignature('status', request, signature, publicKey))) {
    throw new ResetError(3, 'Reset status signature is invalid.');
  }
}

async function validateAcceptance(
  proposal: Map<number, CborValue>,
  acceptance: Map<number, CborValue>,
  signature: Uint8Array,
  relationship: V2RelationshipRecord,
  now: number,
): Promise<void> {
  const proposalRole = requiredInteger(proposal, 5, 'Reset initiator role');
  const role = requiredInteger(acceptance, 3, 'Reset acceptance role');
  const expiresAt = requiredInteger(acceptance, 9, 'Reset acceptance expiry');
  if (
    requiredInteger(acceptance, 1, 'Reset acceptance version') !== 1 ||
    !bytesEqual(
      requiredBytes(acceptance, 2, 32, 'Reset proposal digest'),
      sha256(encodeCbor(proposal)),
    ) ||
    role !== 1 - proposalRole ||
    expiresAt < now - RESET_CLOCK_SKEW_SECONDS ||
    expiresAt > now + RESET_MAX_LIFETIME_SECONDS + RESET_CLOCK_SKEW_SECONDS
  ) {
    throw new ResetError(1, 'Reset acceptance binding is invalid.');
  }
  requiredBytes(acceptance, 4, 16, 'New accepting device ID');
  requiredBytes(acceptance, 5, 32, 'New accepting signing key');
  requiredBytes(acceptance, 6, 1216, 'New accepting recipient');
  validateSnapshot(acceptance.get(7));
  validateDisposition(acceptance.get(8));
  const publicKey =
    role === 0
      ? relationship.inviterSigningPublicKey
      : relationship.inviteeSigningPublicKey;
  if (
    !(await verifyResetSignature(
      'acceptance',
      acceptance,
      signature,
      publicKey,
    ))
  ) {
    throw new ResetError(3, 'Reset acceptance signature is invalid.');
  }
}

async function validateCancellation(
  request: Map<number, CborValue>,
  signature: Uint8Array,
  relationship: V2RelationshipRecord,
  resetId: string,
  origin: string,
  now: number,
): Promise<void> {
  const role = requiredInteger(request, 4, 'Reset cancellation role');
  const expiresAt = requiredInteger(request, 6, 'Reset cancellation expiry');
  if (
    requiredInteger(request, 1, 'Reset cancellation version') !== 1 ||
    bytesToHex(
      requiredBytes(request, 2, 16, 'Reset cancellation relationship'),
    ) !== relationship.relationshipId ||
    bytesToHex(requiredBytes(request, 3, 16, 'Reset cancellation ID')) !==
      resetId ||
    (role !== 0 && role !== 1) ||
    request.get(7) !== origin ||
    expiresAt < now - RESET_CLOCK_SKEW_SECONDS ||
    expiresAt > now + RESET_CLOCK_SKEW_SECONDS
  ) {
    throw new ResetError(1, 'Reset cancellation request is invalid.');
  }
  requiredBytes(request, 5, 16, 'Reset cancellation nonce');
  const publicKey =
    role === 0
      ? relationship.inviterSigningPublicKey
      : relationship.inviteeSigningPublicKey;
  if (
    !(await verifyResetSignature('cancellation', request, signature, publicKey))
  ) {
    throw new ResetError(3, 'Reset cancellation signature is invalid.');
  }
}

function newRelationship(
  proposal: Map<number, CborValue>,
  acceptance: Map<number, CborValue>,
  origin: string,
  now: number,
): V2RelationshipRecord {
  const proposerRole = requiredInteger(proposal, 5, 'Reset initiator role');
  const proposerSigning = encodeBase64Url(
    requiredBytes(proposal, 12, 32, 'New initiator signing key'),
  );
  const proposerAge = encodeBase64Url(
    requiredBytes(proposal, 13, 1216, 'New initiator recipient'),
  );
  const accepterSigning = encodeBase64Url(
    requiredBytes(acceptance, 5, 32, 'New accepting signing key'),
  );
  const accepterAge = encodeBase64Url(
    requiredBytes(acceptance, 6, 1216, 'New accepting recipient'),
  );
  return {
    relationshipId: bytesToHex(
      requiredBytes(proposal, 4, 16, 'New relationship ID'),
    ),
    canonicalOrigin: origin,
    inviterSigningPublicKey:
      proposerRole === 0 ? proposerSigning : accepterSigning,
    inviterAgeRecipient: proposerRole === 0 ? proposerAge : accepterAge,
    inviteeSigningPublicKey:
      proposerRole === 1 ? proposerSigning : accepterSigning,
    inviteeAgeRecipient: proposerRole === 1 ? proposerAge : accepterAge,
    createdAt: now,
    generation: requiredInteger(proposal, 6, 'Reset generation'),
  };
}

export function createV2ResetHandler(dependencies: ResetDependencies) {
  async function propose(
    wrapper: Map<number, CborValue>,
    origin: string,
    now: number,
  ): Promise<Response> {
    const proposal = requireCborMap(
      wrapper.get(2)!,
      Array.from({ length: 16 }, (_, index) => index + 1),
      Array.from({ length: 16 }, (_, index) => index + 1),
    );
    const signature = requiredBytes(wrapper, 3, 64, 'Reset proposal signature');
    const oldId = bytesToHex(
      requiredBytes(proposal, 2, 16, 'Old relationship ID'),
    );
    const relationship = await loadRelationship(dependencies, oldId);
    if (!relationship) {
      throw new ResetError(4, 'Relationship is not available.');
    }
    await validateProposal(proposal, signature, relationship, origin, now);
    const resetId = bytesToHex(requiredBytes(proposal, 3, 16, 'Reset ID'));
    const newRelationshipId = bytesToHex(
      requiredBytes(proposal, 4, 16, 'New relationship ID'),
    );
    const data: StoredResetData = {
      proposal,
      proposalSignature: signature,
      relationship,
    };
    const repository = resetRepository(dependencies.repository);
    if (repository) {
      const stored = await repository.proposeRelationshipReset({
        oldRelationshipId: oldId,
        resetId,
        newRelationshipId,
        encryptedState: await encryptStoredReset(
          dependencies.deploymentKey,
          oldId,
          data,
          dependencies.randomBytes,
        ),
        now,
      });
      const selected = await decryptStoredReset(
        dependencies.deploymentKey,
        oldId,
        stored.encryptedState,
      );
      return responseForReset(selected, stored.state);
    }
    await dependencies.store.transaction((state) => {
      const existing = state.relationshipResets[oldId];
      if (
        existing &&
        (existing.state === 'active' ||
          (existing.state === 'proposed' && existing.resetId <= resetId))
      ) {
        return;
      }
      state.relationshipResets[oldId] = {
        oldRelationshipId: oldId,
        resetId,
        newRelationshipId,
        state: 'proposed',
        proposal: encodeBase64Url(encodeCbor(proposal)),
        proposalSignature: encodeBase64Url(signature),
        createdAt: now,
        updatedAt: now,
        relationship,
      };
    });
    const selected = await loadReset(dependencies, oldId);
    if (!selected) {
      throw new ResetError(4, 'Relationship is not active.');
    }
    return responseForReset(selected.data, selected.state);
  }

  async function status(
    wrapper: Map<number, CborValue>,
    origin: string,
    now: number,
  ): Promise<Response> {
    const request = requireCborMap(
      wrapper.get(2)!,
      [1, 2, 3, 4, 5, 6],
      [1, 2, 3, 4, 5, 6],
    );
    const signature = requiredBytes(wrapper, 3, 64, 'Reset status signature');
    const oldId = bytesToHex(
      requiredBytes(request, 2, 16, 'Reset status relationship'),
    );
    const stored = await loadReset(dependencies, oldId);
    if (!stored) {
      throw new ResetError(4, 'Relationship reset is not available.');
    }
    await validateStatus(
      request,
      signature,
      stored.data.relationship,
      origin,
      now,
    );
    return responseForReset(stored.data, stored.state);
  }

  async function accept(
    wrapper: Map<number, CborValue>,
    origin: string,
    now: number,
  ): Promise<Response> {
    const proposal = requireCborMap(
      wrapper.get(2)!,
      Array.from({ length: 16 }, (_, index) => index + 1),
      Array.from({ length: 16 }, (_, index) => index + 1),
    );
    const proposalSignature = requiredBytes(
      wrapper,
      3,
      64,
      'Reset proposal signature',
    );
    const acceptance = requireCborMap(
      wrapper.get(4)!,
      [1, 2, 3, 4, 5, 6, 7, 8, 9],
      [1, 2, 3, 4, 5, 6, 7, 8, 9],
    );
    const acceptanceSignature = requiredBytes(
      wrapper,
      5,
      64,
      'Reset acceptance signature',
    );
    const oldId = bytesToHex(
      requiredBytes(proposal, 2, 16, 'Old relationship ID'),
    );
    const stored = await loadReset(dependencies, oldId);
    if (!stored) {
      throw new ResetError(4, 'Relationship reset is not available.');
    }
    if (
      !bytesEqual(encodeCbor(proposal), encodeCbor(stored.data.proposal)) ||
      !bytesEqual(proposalSignature, stored.data.proposalSignature)
    ) {
      throw new ResetError(5, 'A different reset proposal won.');
    }
    if (stored.state === 'active') {
      if (
        !stored.data.acceptance ||
        !stored.data.acceptanceSignature ||
        !bytesEqual(
          encodeCbor(acceptance),
          encodeCbor(stored.data.acceptance),
        ) ||
        !bytesEqual(acceptanceSignature, stored.data.acceptanceSignature)
      ) {
        throw new ResetError(5, 'A different reset acceptance was activated.');
      }
      return responseForReset(stored.data, stored.state);
    }
    if (stored.state === 'cancelled') {
      throw new ResetError(
        5,
        'A cancelled relationship reset cannot activate.',
      );
    }
    await validateProposal(
      proposal,
      proposalSignature,
      stored.data.relationship,
      origin,
      now,
    );
    await validateAcceptance(
      proposal,
      acceptance,
      acceptanceSignature,
      stored.data.relationship,
      now,
    );
    const relationship = newRelationship(proposal, acceptance, origin, now);
    const transcriptDigest = sha256(
      encodeCbor(
        new Map<number, CborValue>([
          [1, proposal],
          [2, proposalSignature],
          [3, acceptance],
          [4, acceptanceSignature],
        ]),
      ),
    );
    const receipt = encodeCbor(
      new Map<number, CborValue>([
        [1, 1],
        [2, requiredBytes(proposal, 3, 16, 'Reset ID')],
        [3, requiredBytes(proposal, 2, 16, 'Old relationship ID')],
        [4, requiredBytes(proposal, 4, 16, 'New relationship ID')],
        [5, requiredInteger(proposal, 6, 'Reset generation')],
        [6, transcriptDigest],
        [7, now],
      ]),
    );
    const activeData: StoredResetData = {
      ...stored.data,
      acceptance,
      acceptanceSignature,
      receipt,
    };
    const repository = resetRepository(dependencies.repository);
    if (repository) {
      const outcome = await repository.activateRelationshipReset({
        oldRelationshipId: oldId,
        resetId: stored.resetId,
        newRelationship: {
          id: relationship.relationshipId,
          canonicalOrigin: relationship.canonicalOrigin,
          encryptedState: await encryptV2RelationshipState(
            dependencies.deploymentKey,
            relationship,
            dependencies.randomBytes,
          ),
          createdAt: now,
        },
        encryptedResetState: await encryptStoredReset(
          dependencies.deploymentKey,
          oldId,
          activeData,
          dependencies.randomBytes,
        ),
        now,
      });
      if (outcome === 'conflict') {
        throw new ResetError(5, 'Relationship reset activation conflicted.');
      }
      if (outcome === 'revoked') {
        throw new ResetError(
          8,
          'Old relationship was revoked before reset activation.',
        );
      }
    } else {
      await dependencies.store.transaction((state) => {
        const current = state.relationshipResets[oldId];
        if (!current || current.resetId !== stored.resetId) {
          throw new ResetError(5, 'Relationship reset activation conflicted.');
        }
        if (current.state === 'active') {
          return;
        }
        if (
          !state.relationships[oldId] ||
          state.revocations[`${oldId}|*|*`]?.revoked
        ) {
          throw new ResetError(
            8,
            'Old relationship was revoked before reset activation.',
          );
        }
        if (state.relationships[relationship.relationshipId]) {
          throw new ResetError(5, 'New relationship ID already exists.');
        }
        state.relationships[relationship.relationshipId] = relationship;
        state.revocations[`${oldId}|*|*`] = {
          relationshipId: oldId,
          revoked: true,
          rotatedAt: now,
        };
        for (const capability of Object.values(state.capabilities)) {
          if (capability.relationshipId === oldId) {
            capability.revoked = true;
            capability.rotatedAt = now;
          }
        }
        Object.assign(current, {
          state: 'active',
          acceptance: encodeBase64Url(encodeCbor(acceptance)),
          acceptanceSignature: encodeBase64Url(acceptanceSignature),
          receipt: encodeBase64Url(receipt),
          updatedAt: now,
          activatedAt: now,
        } satisfies Partial<V2RelationshipResetRecord>);
      });
    }
    const active = await loadReset(dependencies, oldId);
    if (!active) {
      throw new ResetError(13, 'Activated relationship reset is unavailable.');
    }
    return responseForReset(active.data, active.state);
  }

  async function cancel(
    wrapper: Map<number, CborValue>,
    origin: string,
    now: number,
  ): Promise<Response> {
    const cancellation = requireCborMap(
      wrapper.get(2)!,
      [1, 2, 3, 4, 5, 6, 7],
      [1, 2, 3, 4, 5, 6, 7],
    );
    const signature = requiredBytes(
      wrapper,
      3,
      64,
      'Reset cancellation signature',
    );
    const oldId = bytesToHex(
      requiredBytes(cancellation, 2, 16, 'Reset cancellation relationship'),
    );
    const stored = await loadReset(dependencies, oldId);
    if (!stored) {
      throw new ResetError(4, 'Relationship reset is not available.');
    }
    if (stored.state === 'active') {
      throw new ResetError(
        8,
        'An active relationship reset cannot be cancelled.',
      );
    }
    if (stored.state === 'cancelled') {
      if (
        !stored.data.cancellation ||
        !stored.data.cancellationSignature ||
        !bytesEqual(
          encodeCbor(cancellation),
          encodeCbor(stored.data.cancellation),
        ) ||
        !bytesEqual(signature, stored.data.cancellationSignature)
      ) {
        throw new ResetError(5, 'A different reset cancellation was recorded.');
      }
      return responseForReset(stored.data, stored.state);
    }
    await validateCancellation(
      cancellation,
      signature,
      stored.data.relationship,
      stored.resetId,
      origin,
      now,
    );
    const cancelledData: StoredResetData = {
      ...stored.data,
      cancellation,
      cancellationSignature: signature,
    };
    const repository = resetRepository(dependencies.repository);
    if (repository) {
      const outcome = await repository.cancelRelationshipReset({
        oldRelationshipId: oldId,
        resetId: stored.resetId,
        encryptedResetState: await encryptStoredReset(
          dependencies.deploymentKey,
          oldId,
          cancelledData,
          dependencies.randomBytes,
        ),
        now,
      });
      if (outcome === 'active') {
        throw new ResetError(
          8,
          'An active relationship reset cannot be cancelled.',
        );
      }
      if (outcome === 'conflict') {
        throw new ResetError(5, 'Relationship reset cancellation conflicted.');
      }
    } else {
      await dependencies.store.transaction((state) => {
        const current = state.relationshipResets[oldId];
        if (!current || current.resetId !== stored.resetId) {
          throw new ResetError(
            5,
            'Relationship reset cancellation conflicted.',
          );
        }
        if (current.state === 'active') {
          throw new ResetError(
            8,
            'An active relationship reset cannot be cancelled.',
          );
        }
        Object.assign(current, {
          state: 'cancelled',
          cancellation: encodeBase64Url(encodeCbor(cancellation)),
          cancellationSignature: encodeBase64Url(signature),
          updatedAt: now,
        } satisfies Partial<V2RelationshipResetRecord>);
      });
    }
    const cancelled = await loadReset(dependencies, oldId);
    if (!cancelled) {
      throw new ResetError(13, 'Cancelled relationship reset is unavailable.');
    }
    return responseForReset(cancelled.data, cancelled.state);
  }

  return {
    async route(
      request: Request,
      origin: string,
      path: string,
    ): Promise<Response | null> {
      if (request.method !== 'POST' || path !== '/v2/relationships/reset') {
        return null;
      }
      try {
        const wrapper = requireCborMap(
          await readV2CborRequest(
            request,
            dependencies.limits.maxDescriptorBytes,
          ),
          [1, 2, 3, 4, 5],
          [1, 2, 3],
        );
        const action = requiredInteger(wrapper, 1, 'Reset action');
        const now = seconds(dependencies.now());
        if (action === 1) {
          return await propose(wrapper, origin, now);
        }
        if (action === 2) {
          return await status(wrapper, origin, now);
        }
        if (action === 3) {
          return await accept(wrapper, origin, now);
        }
        if (action === 4) {
          return await cancel(wrapper, origin, now);
        }
        throw new ResetError(1, 'Reset action is unsupported.');
      } catch (error) {
        return v2ErrorResponse(
          error instanceof ResetError ? error.code : 1,
          error instanceof Error ? error.message : 'Relationship reset failed.',
        );
      }
    },
  };
}
