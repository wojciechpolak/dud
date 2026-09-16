// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { bytesEqual } from './cbor.js';
import { runMemoryV2Maintenance } from './v2-memory-maintenance.js';
import {
  v2DeliveryChunkKey,
  v2StagedChunkKey,
  validateV2BodyPartDeclarations,
} from './v2-body-keys.js';
import {
  isV2ChunkUploadLeaseWellFormed,
  V2OperationConflictError,
} from './v2-repository.js';
import type {
  V2CapabilityRegistration,
  V2ChunkUpload,
  V2DeliveryReservation,
  V2Repository,
  V2RepositoryAuthorization,
  V2RepositoryCapability,
  V2RepositoryControlEvent,
  V2RepositoryDelivery,
  V2ReconciliationRepository,
} from './v2-repository.js';

export { MemoryV2BodyStore } from './v2-memory-body-store.js';

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function operationKey(operationId: Uint8Array): string {
  if (operationId.byteLength !== 16) {
    throw new Error('Operation ID is invalid.');
  }
  return hex(operationId);
}

type ReserveDeliveryInput = Parameters<V2Repository['reserveDelivery']>[0];

/**
 * Whether an unexpired record belongs to the inbox's relationship and direction
 * and sits in one of the slots it queried, keyed `epoch|slot`.
 */
function isInInbox(
  record: {
    expiresAt: number;
    relationshipId: string;
    direction: V2RepositoryDelivery['direction'];
    epoch: number;
    slot: Uint8Array;
  },
  query: Pick<
    Parameters<V2Repository['queryInbox']>[0],
    'now' | 'relationshipId' | 'direction'
  >,
  slots: ReadonlySet<string>,
): boolean {
  return (
    record.expiresAt > query.now &&
    record.relationshipId === query.relationshipId &&
    record.direction === query.direction &&
    slots.has(`${record.epoch}|${hex(record.slot)}`)
  );
}

/**
 * Body keys an upload still holds: each received part's body and, while the
 * upload is uncommitted, the staged key of a part being written or, when
 * `protectUnwritten` is set, of any unwritten part.
 */
function chunkUploadBodyKeys(
  upload: V2ChunkUpload,
  protectUnwritten: boolean,
): string[] {
  const uncommitted = upload.committedAt === undefined;
  return upload.parts.flatMap((part) =>
    partBodyKeys(
      upload.id,
      part,
      uncommitted && (protectUnwritten || part.writeToken !== undefined),
    ),
  );
}

function partBodyKeys(
  uploadId: string,
  part: V2ChunkUpload['parts'][number],
  protectStaged: boolean,
): string[] {
  if (part.bodyKey !== undefined) {
    return [part.bodyKey];
  }
  return protectStaged ? [v2StagedChunkKey(uploadId, part.id)] : [];
}

/**
 * A chunked publication must name its upload's parts in order, each with the
 * declared length and digest and stored under this delivery's chunk key.
 */
function chunkPublicationMatches(
  deliveryId: string,
  parts: Parameters<V2Repository['publishDelivery']>[0]['parts'],
  upload: V2ChunkUpload | undefined,
): boolean {
  return (
    upload !== undefined &&
    upload.deliveryId === deliveryId &&
    parts !== undefined &&
    parts.length === upload.parts.length &&
    parts.every((committed, index) => {
      const part = upload.parts[index]!;
      return (
        committed.id === part.id &&
        committed.length === part.length &&
        bytesEqual(committed.digest, part.digest) &&
        committed.key === v2DeliveryChunkKey(deliveryId, part.id)
      );
    })
  );
}
type ReserveDeliveryResult =
  | V2DeliveryReservation
  | { existing: V2RepositoryDelivery };

interface DeliveryAuthorizationClaims {
  nonceKeys: string[];
  rateCounts: Map<string, number>;
}

/** Reference repository used by conformance tests and local handler tests. */
export class MemoryV2Repository
  implements V2Repository, V2ReconciliationRepository
{
  private readonly capabilities = new Map<string, V2RepositoryCapability>();
  private readonly lookups = new Map<string, string>();
  private readonly nonces = new Map<string, number>();
  private readonly rateWindows = new Map<
    string,
    { minute: number; count: number }
  >();
  private readonly deliveries = new Map<string, V2RepositoryDelivery>();
  private readonly reservations = new Map<string, V2DeliveryReservation>();
  private readonly stagedBodies = new Map<
    string,
    { capabilityId: string; expiresAt: number; reservedBytes: number }
  >();
  private readonly chunkUploads = new Map<string, V2ChunkUpload>();
  private readonly chunkUploadOperations = new Map<
    string,
    { digest: Uint8Array; uploadId: string }
  >();
  private readonly chunkRenewals = new Map<
    string,
    { operationId: Uint8Array; operationDigest: Uint8Array }
  >();
  private readonly reservationBytes = new Map<string, number>();
  private readonly reservationObjects = new Set<string>();
  private readonly deliveryObjects = new Set<string>();
  private readonly reservationRelationships = new Map<string, string>();
  private readonly reservationDirections = new Map<
    string,
    V2RepositoryCapability['direction']
  >();
  private readonly quotaAccounts = new Map<
    string,
    { committedBytes: number; reservedBytes: number; objectCount: number }
  >();
  private readonly controlEvents = new Map<string, V2RepositoryControlEvent>();
  private readonly operations = new Map<
    string,
    { digest: Uint8Array; deliveryId: string }
  >();
  private readonly controlOperations = new Map<string, string>();
  private readonly controlSequences = new Map<string, number>();
  private readonly deliverySequences = new Map<string, number>();

  async initialize(): Promise<void> {}

  addCapability(
    capability: V2RepositoryCapability,
    lookupId: Uint8Array,
    epoch: number,
  ): void {
    if (lookupId.byteLength !== 16) {
      throw new Error('Capability lookup ID is invalid.');
    }
    this.capabilities.set(capability.id, clone(capability));
    this.lookups.set(`${epoch}|${hex(lookupId)}`, capability.id);
  }

  async registerCapability(
    capability: V2RepositoryCapability,
    lookupId: Uint8Array,
    epoch: number,
  ): Promise<void> {
    this.addCapability(capability, lookupId, epoch);
  }

  async replaceCapabilities(input: {
    revocations: readonly Pick<
      V2RepositoryCapability,
      'relationshipId' | 'direction' | 'scope'
    >[];
    registrations: readonly V2CapabilityRegistration[];
    now: number;
  }): Promise<void> {
    for (const registration of input.registrations) {
      if (registration.lookupId.byteLength !== 16) {
        throw new Error('Capability lookup ID is invalid.');
      }
    }
    for (const revoked of input.revocations) {
      for (const capability of this.capabilities.values()) {
        if (
          capability.relationshipId === revoked.relationshipId &&
          capability.direction === revoked.direction &&
          capability.scope === revoked.scope
        ) {
          capability.revokedAt = input.now;
        }
      }
    }
    for (const registration of input.registrations) {
      this.addCapability(
        registration.capability,
        registration.lookupId,
        registration.epoch,
      );
    }
  }

  async findCapabilityLookup(
    lookupId: Uint8Array,
    epoch: number,
  ): Promise<V2RepositoryCapability | null> {
    const id = this.lookups.get(`${epoch}|${hex(lookupId)}`);
    const capability = id ? this.capabilities.get(id) : undefined;
    return capability ? clone(capability) : null;
  }

  async findDelivery(id: string): Promise<V2RepositoryDelivery | null> {
    const delivery = this.deliveries.get(id);
    return delivery ? clone(delivery) : null;
  }

  async claimNonce(
    capabilityId: string,
    nonce: Uint8Array,
    expiresAt: number,
    now: number,
  ): Promise<boolean> {
    const key = `${capabilityId}|${hex(nonce)}`;
    const previous = this.nonces.get(key);
    if (previous !== undefined && previous >= now) {
      return false;
    }
    this.nonces.set(key, expiresAt);
    return true;
  }

  async claimNonces(
    claims: readonly {
      capabilityId: string;
      nonce: Uint8Array;
      expiresAt: number;
    }[],
    now: number,
  ): Promise<boolean> {
    const keys = claims.map(
      ({ capabilityId, nonce }) => `${capabilityId}|${hex(nonce)}`,
    );
    if (new Set(keys).size !== keys.length) {
      return false;
    }
    if (
      keys.some((key) => {
        const expiresAt = this.nonces.get(key);
        return expiresAt !== undefined && expiresAt >= now;
      })
    ) {
      return false;
    }
    for (const [index, key] of keys.entries()) {
      this.nonces.set(key, claims[index]!.expiresAt);
    }
    return true;
  }

  async reserveStagedBody(input: {
    id: string;
    capabilityId: string;
    expiresAt: number;
    now: number;
    reservedBytes: number;
    maximumConcurrentUploads: number;
    maximumStagedBytes: number;
  }): Promise<string> {
    if (
      !/^[a-f0-9]{32}$/.test(input.id) ||
      input.capabilityId.length === 0 ||
      input.expiresAt < input.now ||
      !Number.isSafeInteger(input.reservedBytes) ||
      input.reservedBytes < 0
    ) {
      throw new Error('Staged body is invalid.');
    }
    for (const [id, staged] of this.stagedBodies) {
      if (staged.expiresAt <= input.now) {
        this.stagedBodies.delete(id);
      }
    }
    const active = Array.from(this.stagedBodies.values()).filter(
      (staged) => staged.capabilityId === input.capabilityId,
    );
    const activeBytes =
      active.reduce((total, staged) => total + staged.reservedBytes, 0) +
      Array.from(this.chunkUploads.values())
        .filter(
          (upload) =>
            upload.capabilityId === input.capabilityId &&
            upload.committedAt === undefined &&
            upload.expiresAt > input.now,
        )
        .reduce((total, upload) => total + upload.totalLength, 0);
    if (
      active.length >= input.maximumConcurrentUploads ||
      activeBytes + input.reservedBytes > input.maximumStagedBytes
    ) {
      throw new Error('Staging quota is exhausted.');
    }
    this.stagedBodies.set(input.id, {
      capabilityId: input.capabilityId,
      expiresAt: input.expiresAt,
      reservedBytes: input.reservedBytes,
    });
    return `staging/${input.id}.bin`;
  }

  async releaseStagedBody(id: string): Promise<void> {
    this.stagedBodies.delete(id);
  }

  async createChunkUpload(
    input: Parameters<V2Repository['createChunkUpload']>[0],
  ): Promise<{ upload: V2ChunkUpload; idempotent: boolean }> {
    validateV2BodyPartDeclarations(input.parts, input.totalLength);
    if (input.operationDigest.byteLength !== 32) {
      throw new Error('Chunk upload operation is invalid.');
    }
    const capability = this.activeDeliveryCapability(
      input.capabilityId,
      input.now,
    );
    if (capability.scope !== 'write') {
      throw new Error('Chunk upload capability is invalid.');
    }
    if (
      input.expiresAt > capability.expiresAt ||
      !isV2ChunkUploadLeaseWellFormed(input)
    ) {
      throw new Error('Chunk upload lease is invalid.');
    }
    const claims = this.validateDeliveryAuthorization(
      input.authorization,
      input.now,
    );
    const operation = operationKey(input.operationId);
    const prior = this.chunkUploadOperations.get(operation);
    if (prior) {
      if (!bytesEqual(prior.digest, input.operationDigest)) {
        throw new V2OperationConflictError(
          'Operation ID conflicts with a chunk upload.',
        );
      }
      const upload = this.chunkUploads.get(prior.uploadId);
      if (!upload) {
        throw new Error('Chunk upload operation is incomplete.');
      }
      this.commitDeliveryAuthorization(
        input.authorization,
        claims.nonceKeys,
        claims.rateCounts,
        input.now,
      );
      return { upload: clone(upload), idempotent: true };
    }
    const active = Array.from(this.chunkUploads.values()).filter(
      (upload) =>
        upload.committedAt === undefined && upload.expiresAt > input.now,
    );
    const activeForCapability = active.filter(
      (upload) => upload.capabilityId === input.capabilityId,
    );
    const activeBytes =
      activeForCapability.reduce(
        (total, upload) => total + upload.totalLength,
        0,
      ) +
      Array.from(this.stagedBodies.values())
        .filter(
          (staged) =>
            staged.capabilityId === input.capabilityId &&
            staged.expiresAt > input.now,
        )
        .reduce((total, staged) => total + staged.reservedBytes, 0);
    if (
      activeForCapability.length >= input.maximumConcurrentUploads ||
      activeBytes + input.totalLength > input.maximumStagedBytes
    ) {
      throw new Error('Chunk upload staging quota is exhausted.');
    }
    const id = crypto.randomUUID().replaceAll('-', '');
    const upload: V2ChunkUpload = {
      id,
      deliveryId: crypto.randomUUID().replaceAll('-', ''),
      capabilityId: input.capabilityId,
      chain: input.chain,
      slot: Uint8Array.from(input.slot),
      epoch: input.epoch,
      totalLength: input.totalLength,
      createdAt: input.now,
      expiresAt: input.expiresAt,
      operationId: Uint8Array.from(input.operationId),
      operationDigest: Uint8Array.from(input.operationDigest),
      parts: input.parts.map((part, ordinal) => ({
        ...clone(part),
        ordinal,
      })),
    };
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
    this.chunkUploads.set(id, upload);
    this.chunkUploadOperations.set(operation, {
      digest: Uint8Array.from(input.operationDigest),
      uploadId: id,
    });
    return { upload: clone(upload), idempotent: false };
  }

  async findChunkUpload(
    input: Parameters<V2Repository['findChunkUpload']>[0],
  ): Promise<V2ChunkUpload | null> {
    const upload = this.chunkUploads.get(input.id);
    if (
      !upload ||
      upload.committedAt !== undefined ||
      upload.capabilityId !== input.capabilityId ||
      upload.expiresAt <= input.now
    ) {
      return null;
    }
    const capability = this.capabilities.get(input.capabilityId);
    return !capability ||
      capability.scope !== 'write' ||
      capability.expiresAt <= input.now ||
      capability.revokedAt !== undefined
      ? null
      : clone(upload);
  }

  async findChunkUploadForCommit(
    input: Parameters<V2Repository['findChunkUploadForCommit']>[0],
  ): Promise<V2ChunkUpload | null> {
    const upload = this.chunkUploads.get(input.id);
    const capability = this.capabilities.get(input.capabilityId);
    return !upload ||
      upload.capabilityId !== input.capabilityId ||
      upload.expiresAt <= input.now ||
      !capability ||
      capability.scope !== 'write' ||
      capability.expiresAt <= input.now ||
      capability.revokedAt !== undefined
      ? null
      : clone(upload);
  }

  async authorizeChunkUpload(
    input: Parameters<V2Repository['authorizeChunkUpload']>[0],
  ): Promise<V2ChunkUpload> {
    const { upload } = this.openChunkUpload(input);
    if (!upload) {
      throw new Error('Chunk upload is unavailable.');
    }
    const claims = this.validateDeliveryAuthorization(
      input.authorization,
      input.now,
    );
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
    return clone(upload);
  }

  async prepareChunkUploadPart(
    input: Parameters<V2Repository['prepareChunkUploadPart']>[0],
  ): Promise<{ upload: V2ChunkUpload; idempotent: boolean }> {
    operationKey(input.operationId);
    if (
      input.operationDigest.byteLength !== 32 ||
      !/^[a-f0-9]{32}$/.test(input.writeToken) ||
      !Number.isSafeInteger(input.writeExpiresAt) ||
      input.writeExpiresAt <= input.now
    ) {
      throw new Error('Chunk upload part write lease is invalid.');
    }
    const { upload } = this.openChunkUpload(input);
    const part = upload?.parts.find(
      (candidate) => candidate.id === input.partId,
    );
    if (!upload || !part) {
      throw new Error('Chunk upload part is unavailable.');
    }
    const claims = this.validateDeliveryAuthorization(
      input.authorization,
      input.now,
    );
    if (part.bodyKey !== undefined) {
      if (
        !part.operationId ||
        !bytesEqual(part.operationId, input.operationId) ||
        !bytesEqual(part.operationDigest!, input.operationDigest)
      ) {
        throw new V2OperationConflictError(
          'Chunk upload part conflicts with existing bytes.',
        );
      }
      this.commitDeliveryAuthorization(
        input.authorization,
        claims.nonceKeys,
        claims.rateCounts,
        input.now,
      );
      return { upload: clone(upload), idempotent: true };
    }
    if (
      part.operationId &&
      (!bytesEqual(part.operationId, input.operationId) ||
        !bytesEqual(part.operationDigest!, input.operationDigest))
    ) {
      throw new V2OperationConflictError(
        'Chunk upload part conflicts with an in-flight write.',
      );
    }
    if (
      part.writeToken !== undefined &&
      part.writeExpiresAt !== undefined &&
      part.writeExpiresAt > input.now
    ) {
      throw new Error('Chunk upload part write is unavailable.');
    }
    part.operationId = Uint8Array.from(input.operationId);
    part.operationDigest = Uint8Array.from(input.operationDigest);
    part.writeToken = input.writeToken;
    part.writeExpiresAt = input.writeExpiresAt;
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
    return { upload: clone(upload), idempotent: false };
  }

  async completeChunkUploadPart(
    input: Parameters<V2Repository['completeChunkUploadPart']>[0],
  ): Promise<V2ChunkUpload> {
    if (
      !/^[a-f0-9]{32}$/.test(input.writeToken) ||
      input.bodyKey !== v2StagedChunkKey(input.id, input.partId)
    ) {
      throw new Error('Chunk upload part completion is invalid.');
    }
    const capability = this.activeDeliveryCapability(
      input.capabilityId,
      input.now,
    );
    const upload = this.chunkUploads.get(input.id);
    const part = upload?.parts.find(
      (candidate) => candidate.id === input.partId,
    );
    if (
      capability.scope !== 'write' ||
      !upload ||
      upload.committedAt !== undefined ||
      upload.capabilityId !== input.capabilityId ||
      upload.expiresAt <= input.now ||
      !part ||
      part.bodyKey !== undefined ||
      part.writeToken !== input.writeToken
    ) {
      throw new Error('Chunk upload part write is unavailable.');
    }
    part.bodyKey = input.bodyKey;
    part.receivedAt = input.now;
    delete part.writeToken;
    delete part.writeExpiresAt;
    return clone(upload);
  }

  async abortChunkUploadPart(
    input: Parameters<V2Repository['abortChunkUploadPart']>[0],
  ): Promise<boolean> {
    if (!/^[a-f0-9]{32}$/.test(input.writeToken)) {
      throw new Error('Chunk upload part write token is invalid.');
    }
    const part = this.chunkUploads
      .get(input.id)
      ?.parts.find((candidate) => candidate.id === input.partId);
    if (!part) {
      return true;
    }
    if (part.bodyKey !== undefined || part.writeToken !== input.writeToken) {
      return false;
    }
    delete part.writeToken;
    delete part.writeExpiresAt;
    delete part.operationId;
    delete part.operationDigest;
    return true;
  }

  async renewChunkUpload(
    input: Parameters<V2Repository['renewChunkUpload']>[0],
  ): Promise<{ upload: V2ChunkUpload; idempotent: boolean }> {
    operationKey(input.operationId);
    if (input.operationDigest.byteLength !== 32) {
      throw new Error('Chunk upload operation is invalid.');
    }
    const { capability, upload } = this.openChunkUpload(input);
    if (!upload || input.expiresAt > capability.expiresAt) {
      throw new Error('Chunk upload lease cannot be renewed.');
    }
    const claims = this.validateDeliveryAuthorization(
      input.authorization,
      input.now,
    );
    const prior = this.chunkRenewals.get(input.id);
    if (prior && bytesEqual(prior.operationId, input.operationId)) {
      if (!bytesEqual(prior.operationDigest, input.operationDigest)) {
        throw new V2OperationConflictError(
          'Chunk upload renewal operation conflicts.',
        );
      }
      this.commitDeliveryAuthorization(
        input.authorization,
        claims.nonceKeys,
        claims.rateCounts,
        input.now,
      );
      return { upload: clone(upload), idempotent: true };
    }
    if (input.expiresAt <= upload.expiresAt) {
      throw new Error('Chunk upload lease cannot be renewed.');
    }
    upload.expiresAt = input.expiresAt;
    this.chunkRenewals.set(input.id, {
      operationId: Uint8Array.from(input.operationId),
      operationDigest: Uint8Array.from(input.operationDigest),
    });
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
    return { upload: clone(upload), idempotent: false };
  }

  async abandonChunkUpload(
    input: Parameters<V2Repository['abandonChunkUpload']>[0],
  ): Promise<void> {
    const { upload } = this.openChunkUpload(input);
    if (!upload) {
      throw new Error('Chunk upload is unavailable.');
    }
    const claims = this.validateDeliveryAuthorization(
      input.authorization,
      input.now,
    );
    upload.expiresAt = input.now;
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
  }

  private activeDeliveryCapability(
    capabilityId: string,
    now: number,
  ): V2RepositoryCapability {
    const capability = this.capabilities.get(capabilityId);
    if (
      !capability ||
      capability.revokedAt !== undefined ||
      capability.expiresAt <= now
    ) {
      throw new Error('Delivery capability is not active.');
    }
    return capability;
  }

  /**
   * Resolves an upload that is still open to its capability: uncommitted,
   * unexpired, and owned by the active write capability named in the request.
   * `upload` is undefined for any other upload, while a missing or inactive
   * capability raises.
   */
  private openChunkUpload(input: {
    id: string;
    capabilityId: string;
    now: number;
  }): { capability: V2RepositoryCapability; upload?: V2ChunkUpload } {
    const capability = this.activeDeliveryCapability(
      input.capabilityId,
      input.now,
    );
    const upload = this.chunkUploads.get(input.id);
    if (
      capability.scope !== 'write' ||
      !upload ||
      upload.committedAt !== undefined ||
      upload.capabilityId !== input.capabilityId ||
      upload.expiresAt <= input.now
    ) {
      return { capability };
    }
    return { capability, upload };
  }

  private validateDeliveryAuthorization(
    authorization: ReserveDeliveryInput['authorization'],
    now: number,
  ): DeliveryAuthorizationClaims {
    const claims = this.inspectClaims(authorization, now);
    if (claims === 'inactive') {
      throw new Error('Request capability is not active.');
    }
    if (claims === 'unavailable') {
      throw new Error('Request authorization is unavailable.');
    }
    return claims;
  }

  /**
   * Checks a request's proofs without recording them. A claim naming a
   * missing, revoked, or expired capability makes the request `inactive`; a
   * repeated or already-spent nonce, or a rate window the claims would
   * overflow, makes it `unavailable`. Otherwise the result is what
   * {@link commitDeliveryAuthorization} records once the request is admitted.
   */
  private inspectClaims(
    authorization: V2RepositoryAuthorization | undefined,
    now: number,
  ): DeliveryAuthorizationClaims | 'inactive' | 'unavailable' {
    const nonceKeys =
      authorization?.claims.map(
        (claim) => `${claim.capabilityId}|${hex(claim.nonce)}`,
      ) ?? [];
    const rateCounts = new Map<string, number>();
    if (!authorization) {
      return { nonceKeys, rateCounts };
    }
    for (const claim of authorization.claims) {
      const authorized = this.capabilities.get(claim.capabilityId);
      if (
        !authorized ||
        authorized.revokedAt !== undefined ||
        authorized.expiresAt <= now
      ) {
        return 'inactive';
      }
      rateCounts.set(
        claim.capabilityId,
        (rateCounts.get(claim.capabilityId) ?? 0) + 1,
      );
    }
    const minute = Math.floor(now / 60);
    const unavailable =
      new Set(nonceKeys).size !== nonceKeys.length ||
      nonceKeys.some((key) => (this.nonces.get(key) ?? -1) >= now) ||
      Array.from(rateCounts).some(([capabilityId, count]) => {
        const window = this.rateWindows.get(capabilityId);
        return (
          (window?.minute === minute ? window.count : 0) + count >
          authorization.maximumRequestsPerMinute
        );
      });
    return unavailable ? 'unavailable' : { nonceKeys, rateCounts };
  }

  private resolveExistingReservation(
    input: ReserveDeliveryInput,
    operation: string,
    claims: DeliveryAuthorizationClaims,
  ): ReserveDeliveryResult | null {
    const existing = this.operations.get(operation);
    if (!existing) {
      return null;
    }
    if (!bytesEqual(existing.digest, input.operationDigest)) {
      throw new V2OperationConflictError(
        'Operation ID conflicts with different bytes.',
      );
    }
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
    this.markControlEventsConsumed(input.consumeControlEvents);
    const delivery = this.deliveries.get(existing.deliveryId);
    if (delivery) {
      return { existing: clone(delivery) };
    }
    const reservation = this.reservations.get(existing.deliveryId);
    if (!reservation) {
      throw new Error('Operation reservation is incomplete.');
    }
    return clone(reservation);
  }

  private assertPendingDeliveryLimit(
    input: ReserveDeliveryInput,
    capability: V2RepositoryCapability,
  ): void {
    if (input.maximumPendingDeliveries === undefined) {
      return;
    }
    const pendingDeliveries = Array.from(this.deliveries.values()).filter(
      (delivery) =>
        delivery.state === 'published' &&
        delivery.expiresAt > input.now &&
        delivery.relationshipId === capability.relationshipId &&
        delivery.direction === capability.direction,
    ).length;
    const pendingReservations = Array.from(this.reservations).filter(
      ([id, reservation]) =>
        reservation.expiresAt > input.now &&
        this.reservationRelationships.get(id) === capability.relationshipId &&
        this.reservationDirections.get(id) === capability.direction,
    ).length;
    if (
      pendingDeliveries + pendingReservations >=
      input.maximumPendingDeliveries
    ) {
      throw new Error('Relationship pending delivery limit is reached.');
    }
  }

  private assertDeliveryQuota(
    input: ReserveDeliveryInput,
    relationshipId: string,
  ): void {
    const account = this.quotaAccounts.get(relationshipId) ?? {
      committedBytes: 0,
      reservedBytes: 0,
      objectCount: 0,
    };
    if (
      input.maximumTotalBytes !== undefined &&
      account.committedBytes + account.reservedBytes + input.payloadLength >
        input.maximumTotalBytes
    ) {
      throw new Error('Relationship delivery quota is exhausted.');
    }
    if (
      input.maximumObjectsPerCapability !== undefined &&
      account.objectCount >= input.maximumObjectsPerCapability
    ) {
      throw new Error('Relationship delivery object quota is exhausted.');
    }
  }

  private createDeliveryReservation(
    input: ReserveDeliveryInput,
    capability: V2RepositoryCapability,
    operation: string,
    claims: DeliveryAuthorizationClaims,
  ): V2DeliveryReservation {
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
    const upload = input.chunkUploadId
      ? this.chunkUploads.get(input.chunkUploadId)
      : undefined;
    if (
      input.chunkUploadId &&
      (!upload ||
        upload.committedAt !== undefined ||
        upload.capabilityId !== input.capabilityId ||
        upload.expiresAt <= input.now ||
        upload.totalLength !== input.payloadLength ||
        upload.parts.some((part) => part.bodyKey === undefined))
    ) {
      throw new Error('Chunk upload cannot be committed.');
    }
    const deliveryId =
      upload?.deliveryId ?? crypto.randomUUID().replaceAll('-', '');
    const reservation = {
      deliveryId,
      payloadKey: upload
        ? v2DeliveryChunkKey(deliveryId, upload.parts[0]!.id)
        : `deliveries/${deliveryId}.bin`,
      expiresAt: input.expiresAt,
    };
    this.reservations.set(deliveryId, reservation);
    this.reservationRelationships.set(deliveryId, capability.relationshipId);
    this.reservationDirections.set(deliveryId, capability.direction);
    this.reserveDeliveryQuota(input, capability.relationshipId, deliveryId);
    this.operations.set(operation, {
      digest: Uint8Array.from(input.operationDigest),
      deliveryId,
    });
    this.markControlEventsConsumed(input.consumeControlEvents);
    return clone(reservation);
  }

  private reserveDeliveryQuota(
    input: ReserveDeliveryInput,
    relationshipId: string,
    deliveryId: string,
  ): void {
    if (
      input.maximumTotalBytes === undefined &&
      input.maximumObjectsPerCapability === undefined
    ) {
      return;
    }
    const account = this.quotaAccounts.get(relationshipId) ?? {
      committedBytes: 0,
      reservedBytes: 0,
      objectCount: 0,
    };
    if (input.maximumTotalBytes !== undefined) {
      account.reservedBytes += input.payloadLength;
      this.reservationBytes.set(deliveryId, input.payloadLength);
    }
    if (input.maximumObjectsPerCapability !== undefined) {
      account.objectCount++;
      this.reservationObjects.add(deliveryId);
    }
    this.quotaAccounts.set(relationshipId, account);
  }

  async reserveDelivery(
    input: ReserveDeliveryInput,
  ): Promise<ReserveDeliveryResult> {
    const capability = this.activeDeliveryCapability(
      input.capabilityId,
      input.now,
    );
    const claims = this.validateDeliveryAuthorization(
      input.authorization,
      input.now,
    );
    const operation = operationKey(input.operationId);
    const existing = this.resolveExistingReservation(input, operation, claims);
    if (existing) {
      return existing;
    }
    this.assertPendingDeliveryLimit(input, capability);
    this.assertDeliveryQuota(input, capability.relationshipId);
    return this.createDeliveryReservation(input, capability, operation, claims);
  }

  async publishDelivery(
    input: Parameters<V2Repository['publishDelivery']>[0],
  ): Promise<{ delivery: V2RepositoryDelivery; idempotent: boolean }> {
    const key = operationKey(input.operationId);
    const operation = this.operations.get(key);
    if (!operation || operation.deliveryId !== input.id) {
      throw new Error('Delivery was not reserved.');
    }
    if (!bytesEqual(operation.digest, input.operationDigest)) {
      throw new V2OperationConflictError(
        'Operation ID conflicts with different bytes.',
      );
    }
    const existing = this.deliveries.get(input.id);
    if (existing) {
      return { delivery: clone(existing), idempotent: true };
    }
    const chunkUpload = input.chunkUploadId
      ? this.chunkUploads.get(input.chunkUploadId)
      : undefined;
    if (
      input.chunkUploadId &&
      !chunkPublicationMatches(input.id, input.parts, chunkUpload)
    ) {
      throw new Error('Chunk delivery publication is invalid.');
    }
    const sequenceKey = `${input.relationshipId}|${input.direction}`;
    const sequence = (this.deliverySequences.get(sequenceKey) ?? 0) + 1;
    this.deliverySequences.set(sequenceKey, sequence);
    const delivery = { ...clone(input), state: 'published' as const, sequence };
    delete (delivery as Partial<typeof delivery>).chunkUploadId;
    this.deliveries.set(delivery.id, delivery);
    this.settleReservation(delivery.id, delivery.relationshipId);
    if (chunkUpload) {
      chunkUpload.committedAt = input.createdAt;
      chunkUpload.expiresAt = input.expiresAt;
      for (const part of chunkUpload.parts) {
        part.bodyKey = undefined;
      }
    }
    return { delivery: clone(delivery), idempotent: false };
  }

  /**
   * Converts a published delivery's reservation into committed accounting: the
   * reserved bytes become committed bytes, and its reserved object becomes a
   * retained delivery object.
   */
  private settleReservation(deliveryId: string, relationshipId: string): void {
    this.reservations.delete(deliveryId);
    this.reservationRelationships.delete(deliveryId);
    this.reservationDirections.delete(deliveryId);
    if (this.reservationObjects.delete(deliveryId)) {
      this.deliveryObjects.add(deliveryId);
    }
    const reservedBytes = this.reservationBytes.get(deliveryId);
    if (reservedBytes === undefined) {
      return;
    }
    const account = this.quotaAccounts.get(relationshipId);
    if (account) {
      account.reservedBytes -= reservedBytes;
      account.committedBytes += reservedBytes;
    }
    this.reservationBytes.delete(deliveryId);
  }

  async queryInbox(input: Parameters<V2Repository['queryInbox']>[0]) {
    const authorization = input.authorization;
    if (authorization) {
      const claims = this.inspectClaims(authorization, input.now);
      if (typeof claims === 'string') {
        return this.rejectedInbox();
      }
      this.commitDeliveryAuthorization(
        authorization,
        claims.nonceKeys,
        claims.rateCounts,
        input.now,
      );
      this.markControlEventsConsumed({
        ids: authorization.consumeControlEventIds ?? [],
        relationshipId: input.relationshipId,
        direction: input.direction,
        now: input.now,
      });
    }
    const dataSlots = new Set(
      input.dataSlots.map(({ slot, epoch }) => `${epoch}|${hex(slot)}`),
    );
    const controlSlots = new Set(
      input.controlSlots.map(({ slot, epoch }) => `${epoch}|${hex(slot)}`),
    );
    const pending = Array.from(this.deliveries.values())
      .filter(
        (delivery) =>
          delivery.state === 'published' &&
          isInInbox(delivery, input, dataSlots),
      )
      .sort(
        (a, b) =>
          a.sequence - b.sequence ||
          a.createdAt - b.createdAt ||
          a.id.localeCompare(b.id),
      );
    const events = Array.from(this.controlEvents.values())
      .filter(
        (event) => !event.consumedAt && isInInbox(event, input, controlSlots),
      )
      .sort((a, b) => a.sequence - b.sequence);
    const boundedEvents: V2RepositoryControlEvent[] = [];
    let controlBytes = 0;
    for (const event of events) {
      if (
        boundedEvents.length >=
          (input.maximumControlEvents ?? Number.MAX_SAFE_INTEGER) ||
        controlBytes + event.encryptedEnvelope.byteLength >
          (input.maximumControlBytes ?? Number.MAX_SAFE_INTEGER)
      ) {
        break;
      }
      boundedEvents.push(event);
      controlBytes += event.encryptedEnvelope.byteLength;
    }
    return {
      delivery: pending[0] ? clone(pending[0]) : null,
      controlEvents: clone(boundedEvents),
      pendingEpochs: new Set(pending.map((delivery) => delivery.epoch)),
      authorizationAccepted: true,
    };
  }

  async completeDelivery(
    input: Parameters<V2Repository['completeDelivery']>[0],
  ) {
    const delivery = this.deliveries.get(input.id);
    if (!delivery) {
      throw new Error('Delivery is unavailable.');
    }
    if (delivery.state === 'completed') {
      if (
        !delivery.completionDigest ||
        !delivery.completionOperationId ||
        !delivery.completionOperationDigest ||
        delivery.completionResult !== input.result ||
        !bytesEqual(delivery.completionDigest, input.completionDigest) ||
        !bytesEqual(delivery.completionOperationId, input.operationId) ||
        !bytesEqual(delivery.completionOperationDigest, input.operationDigest)
      ) {
        throw new V2OperationConflictError(
          'Delivery completion conflicts with prior result.',
        );
      }
      return { delivery: clone(delivery), idempotent: true };
    }
    delivery.state = 'completed';
    delivery.completedAt = input.now;
    delivery.completionOperationId = Uint8Array.from(input.operationId);
    delivery.completionOperationDigest = Uint8Array.from(input.operationDigest);
    delivery.completionDigest = Uint8Array.from(input.completionDigest);
    delivery.completionResult = input.result;
    return { delivery: clone(delivery), idempotent: false };
  }

  async publishControlEvent(
    event: V2RepositoryControlEvent,
    authorization?: Parameters<V2Repository['publishControlEvent']>[1],
  ) {
    const claims = this.inspectClaims(authorization, event.createdAt);
    if (typeof claims === 'string') {
      return { authorizationAccepted: false as const };
    }
    this.assertControlEventCompatible(event);
    const operation = operationKey(event.operationId);
    const existingId = this.controlOperations.get(operation);
    if (existingId) {
      const existing = this.controlEvents.get(existingId);
      if (
        !existing ||
        !bytesEqual(existing.operationDigest, event.operationDigest)
      ) {
        throw new V2OperationConflictError(
          'Control operation conflicts with different bytes.',
        );
      }
      return {
        event: clone(existing),
        idempotent: true,
        authorizationAccepted: true as const,
      };
    }
    if (this.controlEvents.has(event.id)) {
      throw new V2OperationConflictError(
        'Control event ID conflicts with a prior operation.',
      );
    }
    const quota = authorization?.controlQuota;
    if (quota) {
      const active = Array.from(this.controlEvents.values()).filter(
        (existing) =>
          existing.relationshipId === event.relationshipId &&
          existing.direction === event.direction &&
          existing.expiresAt > event.createdAt,
      );
      if (
        active.length >= quota.maximumEvents ||
        active.reduce(
          (total, existing) => total + existing.encryptedEnvelope.byteLength,
          0,
        ) +
          event.encryptedEnvelope.byteLength >
          quota.maximumBytes
      ) {
        throw new Error('Control event quota is exhausted.');
      }
    }
    this.commitDeliveryAuthorization(
      authorization,
      claims.nonceKeys,
      claims.rateCounts,
      event.createdAt,
    );
    const sequenceKey = `${event.relationshipId}|${event.direction}`;
    const sequence = (this.controlSequences.get(sequenceKey) ?? 0) + 1;
    this.controlSequences.set(sequenceKey, sequence);
    const stored = { ...clone(event), sequence };
    this.controlEvents.set(stored.id, stored);
    this.controlOperations.set(operation, stored.id);
    return {
      event: clone(stored),
      idempotent: false,
      authorizationAccepted: true as const,
    };
  }

  async completeDeliveryWithControl(input: {
    completion: Parameters<V2Repository['completeDelivery']>[0];
    event: V2RepositoryControlEvent;
    authorization?: Parameters<
      V2Repository['completeDeliveryWithControl']
    >[0]['authorization'];
  }) {
    const authorization = input.authorization;
    const claims = this.inspectClaims(authorization, input.completion.now);
    if (typeof claims === 'string') {
      return { authorizationAccepted: false as const };
    }
    this.assertCompletionCompatible(input.completion);
    this.assertControlEventCompatible(input.event);
    this.commitDeliveryAuthorization(
      authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.completion.now,
    );
    const completion = await this.completeDelivery(input.completion);
    const control = await this.publishControlEvent(
      input.event,
      authorization
        ? {
            claims: [],
            maximumRequestsPerMinute: authorization.maximumRequestsPerMinute,
            controlQuota: authorization.controlQuota,
          }
        : undefined,
    );
    if (!control.authorizationAccepted) {
      throw new Error('Control event authorization is unavailable.');
    }
    return {
      delivery: completion.delivery,
      event: control.event,
      idempotent: completion.idempotent && control.idempotent,
      authorizationAccepted: true as const,
    };
  }

  async consumeControlEvents(input: {
    ids: readonly string[];
    relationshipId: string;
    direction: V2RepositoryControlEvent['direction'];
    now: number;
  }): Promise<void> {
    this.markControlEventsConsumed(input);
  }

  private markControlEventsConsumed(
    input:
      | {
          ids: readonly string[];
          relationshipId: string;
          direction: V2RepositoryControlEvent['direction'];
          now: number;
        }
      | undefined,
  ): void {
    if (!input) {
      return;
    }
    for (const id of input.ids) {
      const event = this.controlEvents.get(id);
      if (
        event &&
        event.relationshipId === input.relationshipId &&
        event.direction === input.direction
      ) {
        event.consumedAt = input.now;
      }
    }
  }

  private assertCompletionCompatible(
    input: Parameters<V2Repository['completeDelivery']>[0],
  ): void {
    const delivery = this.deliveries.get(input.id);
    if (!delivery) {
      throw new Error('Delivery is unavailable.');
    }
    if (delivery.state !== 'completed') {
      return;
    }
    if (
      !delivery.completionDigest ||
      !delivery.completionOperationId ||
      !delivery.completionOperationDigest ||
      delivery.completionResult !== input.result ||
      !bytesEqual(delivery.completionDigest, input.completionDigest) ||
      !bytesEqual(delivery.completionOperationId, input.operationId) ||
      !bytesEqual(delivery.completionOperationDigest, input.operationDigest)
    ) {
      throw new V2OperationConflictError(
        'Delivery completion conflicts with prior result.',
      );
    }
  }

  private rejectedInbox() {
    return {
      delivery: null,
      controlEvents: [],
      pendingEpochs: new Set<number>(),
      authorizationAccepted: false,
    };
  }

  private assertControlEventCompatible(event: V2RepositoryControlEvent): void {
    const existingId = this.controlOperations.get(
      operationKey(event.operationId),
    );
    if (existingId) {
      const existing = this.controlEvents.get(existingId);
      if (
        !existing ||
        !bytesEqual(existing.operationDigest, event.operationDigest)
      ) {
        throw new V2OperationConflictError(
          'Control operation conflicts with different bytes.',
        );
      }
      return;
    }
    if (this.controlEvents.has(event.id)) {
      throw new V2OperationConflictError(
        'Control event ID conflicts with a prior operation.',
      );
    }
  }
  async runMaintenance(now: number, limit: number) {
    return runMemoryV2Maintenance(
      {
        deliveries: this.deliveries,
        reservations: this.reservations,
        stagedBodies: this.stagedBodies,
        chunkUploads: this.chunkUploads,
        chunkUploadOperations: this.chunkUploadOperations,
        chunkRenewals: this.chunkRenewals,
        reservationBytes: this.reservationBytes,
        reservationObjects: this.reservationObjects,
        deliveryObjects: this.deliveryObjects,
        reservationRelationships: this.reservationRelationships,
        reservationDirections: this.reservationDirections,
        quotaAccounts: this.quotaAccounts,
        operations: this.operations,
        nonces: this.nonces,
        controlEvents: this.controlEvents,
        controlOperations: this.controlOperations,
        rateWindows: this.rateWindows,
      },
      now,
      limit,
    );
  }

  /** Reconciliation-only bounded lookups; no request path calls these. */
  async filterKnownBodyKeys(keys: readonly string[]): Promise<string[]> {
    const known = new Set(this.metadataBodyKeys(true));
    return keys.filter((key) => known.has(key));
  }

  async listBodyKeys(input: {
    cursor?: string;
    limit: number;
  }): Promise<{ keys: string[]; cursor?: string }> {
    if (!Number.isSafeInteger(input.limit) || input.limit < 1) {
      throw new Error('Body key page limit is invalid.');
    }
    const keys = this.metadataBodyKeys(false)
      .filter((key) => input.cursor === undefined || key > input.cursor)
      .sort()
      .slice(0, input.limit);
    return {
      keys,
      ...(keys.length === input.limit ? { cursor: keys[keys.length - 1] } : {}),
    };
  }

  private metadataBodyKeys(protectUnwrittenChunkParts: boolean): string[] {
    return [
      ...Array.from(this.deliveries.values(), (value) => value.payloadKey),
      ...Array.from(this.deliveries.values()).flatMap(
        (delivery) => delivery.parts?.map((part) => part.key) ?? [],
      ),
      ...Array.from(this.reservations.values(), (value) => value.payloadKey),
      ...Array.from(this.chunkUploads.values()).flatMap((upload) =>
        chunkUploadBodyKeys(upload, protectUnwrittenChunkParts),
      ),
    ];
  }

  private commitDeliveryAuthorization(
    authorization: Parameters<
      V2Repository['reserveDelivery']
    >[0]['authorization'],
    nonceKeys: readonly string[],
    rateCounts: ReadonlyMap<string, number>,
    now: number,
  ): void {
    if (!authorization) {
      return;
    }
    for (const [index, key] of nonceKeys.entries()) {
      this.nonces.set(key, authorization.claims[index]!.expiresAt);
    }
    const minute = Math.floor(now / 60);
    for (const [capabilityId, count] of rateCounts) {
      const window = this.rateWindows.get(capabilityId);
      this.rateWindows.set(capabilityId, {
        minute,
        count: (window?.minute === minute ? window.count : 0) + count,
      });
    }
  }
}
