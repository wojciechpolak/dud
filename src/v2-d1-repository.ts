// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { bytesEqual } from './cbor.js';
import { d1Bytes } from './v2-d1-values.js';
import {
  v2DeliveryChunkKey,
  v2StagedChunkKey,
  validateV2BodyPartDeclarations,
} from './v2-body-keys.js';
import type { D1DatabaseLike, D1RunResultLike } from './types.js';
import { V2OperationConflictError } from './v2-repository.js';
import type {
  V2CapabilityRegistration,
  V2CapabilityReissueInput,
  V2CapabilityReissueOutcome,
  V2ChunkUpload,
  V2AdministrativeRepository,
  V2DeliveryReservation,
  V2MaintenanceResult,
  V2Repository,
  V2RepositoryCapability,
  V2RepositoryControlEvent,
  V2RepositoryDelivery,
  V2RepositoryAuthorization,
  V2RelationshipRepository,
  V2RelationshipResetRepository,
  V2StoredRelationshipReset,
  V2ReconciliationRepository,
} from './v2-repository.js';

type Row = Record<string, unknown>;

function directionNumber(
  direction: V2RepositoryCapability['direction'],
): 0 | 1 {
  return direction === 'inviter->invitee' ? 0 : 1;
}

function directionFromRow(value: unknown): V2RepositoryCapability['direction'] {
  return Number(value) === 0 ? 'inviter->invitee' : 'invitee->inviter';
}

function optionalNumber(value: unknown): number | undefined {
  return value === null || value === undefined ? undefined : Number(value);
}

function rows(result: unknown): Row[] {
  if (Array.isArray(result)) {
    return result as Row[];
  }
  const value = result as { results?: unknown };
  return Array.isArray(value.results) ? (value.results as Row[]) : [];
}

function operationId(value: Uint8Array): void {
  if (value.byteLength !== 16) {
    throw new Error('Operation ID is invalid.');
  }
}

/**
 * Granular D1 implementation.  Each mutation is expressed as a bounded D1
 * batch; payload bytes remain in the separately bound R2 body store.
 *
 * D1 migrations are intentionally deployed by Wrangler, so initialize is a
 * no-op rather than attempting to run unbounded schema work from a request.
 */
export class D1V2Repository
  implements
    V2Repository,
    V2AdministrativeRepository,
    V2RelationshipRepository,
    V2RelationshipResetRepository,
    V2ReconciliationRepository
{
  constructor(private readonly database: D1DatabaseLike) {}

  async initialize(): Promise<void> {}

  async registerCapability(
    capability: V2RepositoryCapability,
    lookupId: Uint8Array,
    epoch: number,
  ): Promise<void> {
    await this.database.batch([
      this.insertCapability(capability, true),
      this.database
        .prepare(
          'INSERT INTO capability_lookups(lookup_id, epoch, capability_id) VALUES (?, ?, ?)',
        )
        .bind(lookupId, epoch, capability.id),
    ]);
  }

  async replaceCapabilities(input: {
    revocations: readonly Pick<
      V2RepositoryCapability,
      'relationshipId' | 'direction' | 'scope'
    >[];
    registrations: readonly V2CapabilityRegistration[];
    now: number;
  }): Promise<void> {
    const statements = input.revocations.map((revocation) =>
      this.database
        .prepare(
          'UPDATE capabilities SET revoked_at = ? WHERE relationship_id = ? AND direction = ? AND scope = ? AND revoked_at IS NULL',
        )
        .bind(
          input.now,
          revocation.relationshipId,
          directionNumber(revocation.direction),
          revocation.scope,
        ),
    );
    const registrationIndexes: number[] = [];
    // One capability row backs every daily lookup it publishes.
    const published = new Set<string>();
    for (const registration of input.registrations) {
      const capability = registration.capability;
      if (!published.has(capability.id)) {
        published.add(capability.id);
        registrationIndexes.push(statements.length);
        statements.push(
          this.database
            .prepare(
              'INSERT INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at, revoked_at) SELECT ?, ?, ?, ?, ?, ?, ?, NULL WHERE NOT EXISTS (SELECT 1 FROM revocations WHERE relationship_id = ? AND (direction IS NULL OR direction = ?) AND (scope IS NULL OR scope = ?))',
            )
            .bind(
              capability.id,
              capability.relationshipId,
              directionNumber(capability.direction),
              capability.scope,
              capability.encryptedTokenSecret,
              capability.createdAt,
              capability.expiresAt,
              capability.relationshipId,
              directionNumber(capability.direction),
              capability.scope,
            ),
        );
      }
      statements.push(
        this.database
          .prepare(
            'INSERT INTO capability_lookups(lookup_id, epoch, capability_id) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM capabilities WHERE id = ?)',
          )
          .bind(
            registration.lookupId,
            registration.epoch,
            capability.id,
            capability.id,
          ),
      );
    }
    if (statements.length !== 0) {
      const results = await this.database.batch<D1RunResultLike>(statements);
      if (
        registrationIndexes.some((index) => results[index]?.meta?.changes !== 1)
      ) {
        throw new Error('Capability tuple was revoked during replacement.');
      }
    }
  }

  async findCapabilityLookup(
    lookupId: Uint8Array,
    epoch: number,
  ): Promise<V2RepositoryCapability | null> {
    const row = await this.database
      .prepare(
        'SELECT c.id, c.relationship_id, c.direction, c.scope, c.encrypted_token_secret, c.created_at, c.expires_at, c.revoked_at FROM capability_lookups l JOIN capabilities c ON c.id = l.capability_id WHERE l.lookup_id = ? AND l.epoch = ?',
      )
      .bind(lookupId, epoch)
      .first<Row>();
    return row ? capabilityFromRow(row) : null;
  }

  async findDelivery(id: string): Promise<V2RepositoryDelivery | null> {
    const row = await this.database
      .prepare('SELECT * FROM deliveries WHERE id = ?')
      .bind(id)
      .first<Row>();
    if (!row) {
      return null;
    }
    return this.deliveryWithParts(row);
  }

  private async deliveryWithParts(row: Row): Promise<V2RepositoryDelivery> {
    const delivery = deliveryFromRow(row);
    const parts = await this.selectRows(
      'SELECT part_id, length, digest, body_key FROM delivery_chunks WHERE delivery_id = ? ORDER BY ordinal',
      delivery.id,
    );
    return parts.length === 0
      ? delivery
      : {
          ...delivery,
          parts: parts.map((part) => ({
            id: String(part.part_id),
            length: Number(part.length),
            digest: d1Bytes(part.digest),
            key: String(part.body_key),
          })),
        };
  }

  async createRelationship(input: {
    id: string;
    canonicalOrigin: string;
    encryptedState: Uint8Array;
    createdAt: number;
  }): Promise<void> {
    await this.database
      .prepare(
        "INSERT OR IGNORE INTO relationships(id, canonical_origin, state, encrypted_state, created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?)",
      )
      .bind(
        input.id,
        input.canonicalOrigin,
        input.encryptedState,
        input.createdAt,
        input.createdAt,
      )
      .run();
  }

  async findRelationship(id: string): Promise<{
    id: string;
    canonicalOrigin: string;
    encryptedState: Uint8Array;
    createdAt: number;
    revokedAt?: number;
  } | null> {
    const row = await this.database
      .prepare(
        "SELECT id, canonical_origin, encrypted_state, created_at, revoked_at FROM relationships WHERE id = ? AND state = 'active'",
      )
      .bind(id)
      .first<Row>();
    if (!row) {
      return null;
    }
    return {
      id: String(row.id),
      canonicalOrigin: String(row.canonical_origin),
      encryptedState: d1Bytes(row.encrypted_state),
      createdAt: Number(row.created_at),
      revokedAt: optionalNumber(row.revoked_at),
    };
  }

  async findRelationshipReset(
    oldRelationshipId: string,
  ): Promise<V2StoredRelationshipReset | null> {
    const row = await this.database
      .prepare(
        'SELECT old_relationship_id, reset_id, new_relationship_id, state, encrypted_state, created_at, updated_at, activated_at FROM relationship_resets WHERE old_relationship_id = ?',
      )
      .bind(oldRelationshipId)
      .first<Row>();
    if (!row) {
      return null;
    }
    return {
      oldRelationshipId: String(row.old_relationship_id),
      resetId: String(row.reset_id),
      newRelationshipId: String(row.new_relationship_id),
      state: String(row.state) as V2StoredRelationshipReset['state'],
      encryptedState: d1Bytes(row.encrypted_state),
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
      ...(row.activated_at == null
        ? {}
        : { activatedAt: Number(row.activated_at) }),
    };
  }

  async proposeRelationshipReset(input: {
    oldRelationshipId: string;
    resetId: string;
    newRelationshipId: string;
    encryptedState: Uint8Array;
    now: number;
  }): Promise<V2StoredRelationshipReset> {
    await this.database
      .prepare(
        `INSERT INTO relationship_resets(old_relationship_id, reset_id, new_relationship_id, state, encrypted_state, created_at, updated_at)
				 SELECT ?, ?, ?, 'proposed', ?, ?, ? WHERE EXISTS (SELECT 1 FROM relationships WHERE id = ? AND state = 'active')
				 ON CONFLICT(old_relationship_id) DO UPDATE SET reset_id = excluded.reset_id, new_relationship_id = excluded.new_relationship_id, encrypted_state = excluded.encrypted_state, created_at = excluded.created_at, updated_at = excluded.updated_at
				 WHERE relationship_resets.state = 'cancelled' OR (relationship_resets.state = 'proposed' AND excluded.reset_id < relationship_resets.reset_id)`,
      )
      .bind(
        input.oldRelationshipId,
        input.resetId,
        input.newRelationshipId,
        input.encryptedState,
        input.now,
        input.now,
        input.oldRelationshipId,
      )
      .run();
    const stored = await this.findRelationshipReset(input.oldRelationshipId);
    if (!stored) {
      throw new Error('Relationship is not active.');
    }
    return stored;
  }

  async activateRelationshipReset(input: {
    oldRelationshipId: string;
    resetId: string;
    newRelationship: {
      id: string;
      canonicalOrigin: string;
      encryptedState: Uint8Array;
      createdAt: number;
    };
    encryptedResetState: Uint8Array;
    now: number;
  }): Promise<'accepted' | 'already_active' | 'revoked' | 'conflict'> {
    const stored = await this.findRelationshipReset(input.oldRelationshipId);
    if (
      !stored ||
      stored.resetId !== input.resetId ||
      stored.newRelationshipId !== input.newRelationship.id
    ) {
      return 'conflict';
    }
    if (stored.state === 'active') {
      return 'already_active';
    }
    if (stored.state !== 'proposed') {
      return 'conflict';
    }
    const existingNew = await this.findRelationship(input.newRelationship.id);
    if (existingNew) {
      return 'conflict';
    }
    await this.database.batch([
      this.database
        .prepare(
          "INSERT INTO relationships(id, canonical_origin, state, encrypted_state, created_at, updated_at) SELECT ?, ?, 'active', ?, ?, ? WHERE EXISTS (SELECT 1 FROM relationships WHERE id = ? AND state = 'active') AND EXISTS (SELECT 1 FROM relationship_resets WHERE old_relationship_id = ? AND reset_id = ? AND state = 'proposed')",
        )
        .bind(
          input.newRelationship.id,
          input.newRelationship.canonicalOrigin,
          input.newRelationship.encryptedState,
          input.newRelationship.createdAt,
          input.now,
          input.oldRelationshipId,
          input.oldRelationshipId,
          input.resetId,
        ),
      this.database
        .prepare(
          "UPDATE relationship_resets SET state = 'active', encrypted_state = ?, updated_at = ?, activated_at = ? WHERE old_relationship_id = ? AND reset_id = ? AND state = 'proposed' AND EXISTS (SELECT 1 FROM relationships WHERE id = ? AND state = 'active')",
        )
        .bind(
          input.encryptedResetState,
          input.now,
          input.now,
          input.oldRelationshipId,
          input.resetId,
          input.newRelationship.id,
        ),
      this.database
        .prepare(
          "UPDATE capabilities SET revoked_at = ? WHERE relationship_id = ? AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM relationships WHERE id = ? AND state = 'active')",
        )
        .bind(input.now, input.oldRelationshipId, input.newRelationship.id),
      this.database
        .prepare(
          "INSERT OR IGNORE INTO revocations(id, relationship_id, direction, scope, created_at, expires_at, encrypted_envelope) SELECT ?, ?, NULL, NULL, ?, 2147483647, ? WHERE EXISTS (SELECT 1 FROM relationships WHERE id = ? AND state = 'active')",
        )
        .bind(
          input.resetId,
          input.oldRelationshipId,
          input.now,
          new Uint8Array(),
          input.newRelationship.id,
        ),
      this.database
        .prepare(
          "UPDATE relationships SET state = 'revoked', revoked_at = ?, updated_at = ? WHERE id = ? AND EXISTS (SELECT 1 FROM relationships WHERE id = ? AND state = 'active')",
        )
        .bind(
          input.now,
          input.now,
          input.oldRelationshipId,
          input.newRelationship.id,
        ),
    ]);
    const activated = await this.findRelationshipReset(input.oldRelationshipId);
    if (activated?.state === 'active') {
      return 'accepted';
    }
    return (await this.findRelationship(input.oldRelationshipId))
      ? 'conflict'
      : 'revoked';
  }

  async cancelRelationshipReset(input: {
    oldRelationshipId: string;
    resetId: string;
    encryptedResetState: Uint8Array;
    now: number;
  }): Promise<'accepted' | 'already_cancelled' | 'active' | 'conflict'> {
    const stored = await this.findRelationshipReset(input.oldRelationshipId);
    if (!stored || stored.resetId !== input.resetId) {
      return 'conflict';
    }
    if (stored.state === 'active') {
      return 'active';
    }
    if (stored.state === 'cancelled') {
      return 'already_cancelled';
    }
    await this.database
      .prepare(
        "UPDATE relationship_resets SET state = 'cancelled', encrypted_state = ?, updated_at = ? WHERE old_relationship_id = ? AND reset_id = ? AND state = 'proposed'",
      )
      .bind(
        input.encryptedResetState,
        input.now,
        input.oldRelationshipId,
        input.resetId,
      )
      .run();
    const result = await this.findRelationshipReset(input.oldRelationshipId);
    if (result?.state === 'cancelled' && result.resetId === input.resetId) {
      return 'accepted';
    }
    return result?.state === 'active' ? 'active' : 'conflict';
  }

  async commitCapabilityReissue(
    input: V2CapabilityReissueInput,
  ): Promise<V2CapabilityReissueOutcome> {
    const tuples = input.revocations;
    const revocationGuard = tuples
      .map(
        () =>
          ' AND NOT EXISTS (SELECT 1 FROM revocations WHERE relationship_id = ? AND (direction IS NULL OR direction = ?) AND (scope IS NULL OR scope = ?))',
      )
      .join('');
    const revocationValues = tuples.flatMap((tuple) => [
      tuple.relationshipId,
      directionNumber(tuple.direction),
      tuple.scope,
    ]);
    // The window is charged first and is itself conditional on an unclaimed
    // nonce, a live relationship, and every requested tuple still being
    // unrevoked; every later statement is conditional on the claimed nonce.
    const statements = [
      this.database
        .prepare('DELETE FROM relationship_nonces WHERE expires_at < ?')
        .bind(input.now),
      this.database
        .prepare(
          `INSERT INTO relationship_rate_windows(relationship_id, minute, count) SELECT ?, ?, 1 WHERE NOT EXISTS (SELECT 1 FROM relationship_nonces WHERE relationship_id = ? AND nonce = ?) AND EXISTS (SELECT 1 FROM relationships WHERE id = ? AND state = 'active')${revocationGuard} ON CONFLICT(relationship_id, minute) DO UPDATE SET count = count + 1 WHERE count < ?`,
        )
        .bind(
          input.relationshipId,
          input.minute,
          input.relationshipId,
          input.nonce,
          input.relationshipId,
          ...revocationValues,
          input.maximumRequestsPerMinute,
        ),
      this.database
        .prepare(
          'INSERT INTO relationship_nonces(relationship_id, nonce, expires_at) SELECT ?, ?, ? WHERE changes() = 1',
        )
        .bind(input.relationshipId, input.nonce, input.nonceExpiresAt),
    ];
    // Every publication statement changes exactly one row when it runs, so a
    // rejected request breaks the `changes()` chain at the nonce claim and
    // publishes nothing.
    const published = new Set<string>();
    for (const registration of input.registrations) {
      const capability = registration.capability;
      if (!published.has(capability.id)) {
        published.add(capability.id);
        statements.push(
          this.database
            .prepare(
              'INSERT INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at, revoked_at) SELECT ?, ?, ?, ?, ?, ?, ?, NULL WHERE changes() = 1',
            )
            .bind(
              capability.id,
              capability.relationshipId,
              directionNumber(capability.direction),
              capability.scope,
              capability.encryptedTokenSecret,
              capability.createdAt,
              capability.expiresAt,
            ),
        );
      }
      statements.push(
        this.database
          .prepare(
            'INSERT INTO capability_lookups(lookup_id, epoch, capability_id) SELECT ?, ?, ? WHERE changes() = 1',
          )
          .bind(registration.lookupId, registration.epoch, capability.id),
      );
    }
    // Retirement runs last against a marker only this request could publish:
    // its own freshly derived lookup ID.  Retiring zero rows is legal, so the
    // `changes()` chain cannot carry the condition.
    const marker = input.registrations[0];
    if (marker) {
      const replaced = Array.from(published);
      const excluded = replaced.map(() => '?').join(', ');
      for (const tuple of tuples) {
        statements.push(
          this.database
            .prepare(
              `UPDATE capabilities SET revoked_at = ? WHERE relationship_id = ? AND direction = ? AND scope = ? AND revoked_at IS NULL AND id NOT IN (${excluded}) AND EXISTS (SELECT 1 FROM capability_lookups WHERE lookup_id = ? AND epoch = ?)`,
            )
            .bind(
              input.now,
              tuple.relationshipId,
              directionNumber(tuple.direction),
              tuple.scope,
              ...replaced,
              marker.lookupId,
              marker.epoch,
            ),
        );
      }
    }
    const results = await this.database.batch<D1RunResultLike>(statements);
    if (results[2]?.meta?.changes === 1) {
      return 'accepted';
    }
    return this.classifyReissueRejection(input);
  }

  /** Rejections mutate nothing, so the reason is read back for the caller. */
  private async classifyReissueRejection(
    input: V2CapabilityReissueInput,
  ): Promise<Exclude<V2CapabilityReissueOutcome, 'accepted'>> {
    const replayed = await this.database
      .prepare(
        'SELECT 1 AS present FROM relationship_nonces WHERE relationship_id = ? AND nonce = ?',
      )
      .bind(input.relationshipId, input.nonce)
      .first<Row>();
    if (replayed) {
      return 'replayed';
    }
    const relationship = await this.database
      .prepare(
        "SELECT 1 AS present FROM relationships WHERE id = ? AND state = 'active'",
      )
      .bind(input.relationshipId)
      .first<Row>();
    if (!relationship) {
      return 'revoked';
    }
    for (const tuple of input.revocations) {
      const revoked = await this.database
        .prepare(
          'SELECT 1 AS present FROM revocations WHERE relationship_id = ? AND (direction IS NULL OR direction = ?) AND (scope IS NULL OR scope = ?)',
        )
        .bind(
          tuple.relationshipId,
          directionNumber(tuple.direction),
          tuple.scope,
        )
        .first<Row>();
      if (revoked) {
        return 'revoked';
      }
    }
    return 'rate_limited';
  }

  async claimRequestWindow(input: {
    key: string;
    minute: number;
    maximum: number;
  }): Promise<boolean> {
    const result = await this.database
      .prepare(
        'INSERT INTO pairing_rate_windows(key, minute, count) VALUES (?, ?, 1) ON CONFLICT(key, minute) DO UPDATE SET count = count + 1 WHERE count < ?',
      )
      .bind(input.key, input.minute, input.maximum)
      .run<D1RunResultLike>();
    return result.meta?.changes === 1;
  }

  async claimNonce(
    capabilityId: string,
    nonce: Uint8Array,
    expiresAt: number,
    now: number,
  ): Promise<boolean> {
    const results = await this.database.batch<D1RunResultLike>([
      this.database
        .prepare('DELETE FROM nonces WHERE expires_at < ?')
        .bind(now),
      this.database
        .prepare(
          'INSERT OR IGNORE INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?)',
        )
        .bind(capabilityId, nonce, expiresAt),
    ]);
    return results[1]?.meta?.changes === 1;
  }

  async claimNonces(
    claims: readonly {
      capabilityId: string;
      nonce: Uint8Array;
      expiresAt: number;
    }[],
    now: number,
  ): Promise<boolean> {
    if (claims.length === 0) {
      return true;
    }
    const unique = new Set(
      claims.map(
        ({ capabilityId, nonce }) =>
          `${capabilityId}:${Array.from(nonce).join(',')}`,
      ),
    );
    if (unique.size !== claims.length) {
      return false;
    }
    const values = claims.flatMap(({ capabilityId, nonce, expiresAt }) => [
      capabilityId,
      nonce,
      expiresAt,
    ]);
    const placeholders = claims.map(() => '(?, ?, ?)').join(', ');
    const results = await this.database.batch<D1RunResultLike>([
      this.database
        .prepare('DELETE FROM nonces WHERE expires_at < ?')
        .bind(now),
      this.database
        .prepare(
          `WITH claims(capability_id, nonce, expires_at) AS (VALUES ${placeholders}), conflict AS (SELECT 1 FROM nonces n JOIN claims c ON c.capability_id = n.capability_id AND c.nonce = n.nonce WHERE n.expires_at >= ? LIMIT 1) INSERT INTO nonces(capability_id, nonce, expires_at) SELECT capability_id, nonce, expires_at FROM claims WHERE NOT EXISTS (SELECT 1 FROM conflict)`,
        )
        .bind(...values, now),
    ]);
    return results[1]?.meta?.changes === claims.length;
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
      !Number.isSafeInteger(input.reservedBytes) ||
      input.reservedBytes < 0
    ) {
      throw new Error('Staged body ID is invalid.');
    }
    const key = `staging/${input.id}.bin`;
    const result = await this.database
      .prepare(
        'INSERT INTO staged_bodies(id, capability_id, body_key, expires_at, reserved_bytes) SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM staged_bodies WHERE (capability_id = ? OR capability_id IS NULL) AND expires_at > ?) < ? AND (SELECT COALESCE(SUM(reserved_bytes), 0) FROM staged_bodies WHERE (capability_id = ? OR capability_id IS NULL) AND expires_at > ?) + (SELECT COALESCE(SUM(total_length), 0) FROM chunk_uploads WHERE capability_id = ? AND committed_at IS NULL AND expires_at > ?) + ? <= ?',
      )
      .bind(
        input.id,
        input.capabilityId,
        key,
        input.expiresAt,
        input.reservedBytes,
        input.capabilityId,
        input.now,
        input.maximumConcurrentUploads,
        input.capabilityId,
        input.now,
        input.capabilityId,
        input.now,
        input.reservedBytes,
        input.maximumStagedBytes,
      )
      .run<D1RunResultLike>();
    if (result.meta?.changes !== 1) {
      throw new Error('Staging quota is exhausted.');
    }
    return key;
  }

  async releaseStagedBody(id: string): Promise<void> {
    await this.database
      .prepare('DELETE FROM staged_bodies WHERE id = ?')
      .bind(id)
      .run();
  }

  async createChunkUpload(
    input: Parameters<V2Repository['createChunkUpload']>[0],
  ): Promise<{ upload: V2ChunkUpload; idempotent: boolean }> {
    validateV2BodyPartDeclarations(input.parts, input.totalLength);
    this.validateChunkOperation(input.operationId, input.operationDigest);
    if (
      input.expiresAt <= input.now ||
      !Number.isSafeInteger(input.chain) ||
      input.chain < 0 ||
      input.slot.byteLength !== 16 ||
      !Number.isSafeInteger(input.epoch) ||
      input.epoch < 0 ||
      !Number.isSafeInteger(input.maximumConcurrentUploads) ||
      input.maximumConcurrentUploads < 1 ||
      !Number.isSafeInteger(input.maximumStagedBytes) ||
      input.maximumStagedBytes < input.totalLength
    ) {
      throw new Error('Chunk upload lease is invalid.');
    }
    const id = crypto.randomUUID().replaceAll('-', '');
    const deliveryId = crypto.randomUUID().replaceAll('-', '');
    const authorization = this.chunkAuthorizationStatements(
      input.capabilityId,
      input.authorization,
      input.now,
    );
    const statements = [
      ...authorization.statements,
      this.database
        .prepare(
          `INSERT OR IGNORE INTO chunk_uploads(id, delivery_id, capability_id, chain, slot, epoch, total_length, created_at, expires_at, operation_id, operation_digest)
           SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
           WHERE EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?)
             AND ? <= (SELECT expires_at FROM capabilities WHERE id = ?)
             AND (SELECT COUNT(*) FROM chunk_uploads WHERE capability_id = ? AND committed_at IS NULL AND expires_at > ?) < ?
             AND (SELECT COALESCE(SUM(total_length), 0) FROM chunk_uploads WHERE capability_id = ? AND committed_at IS NULL AND expires_at > ?)
               + (SELECT COALESCE(SUM(reserved_bytes), 0) FROM staged_bodies WHERE (capability_id = ? OR capability_id IS NULL) AND expires_at > ?)
               + ? <= ?`,
        )
        .bind(
          id,
          deliveryId,
          input.capabilityId,
          input.chain,
          input.slot,
          input.epoch,
          input.totalLength,
          input.now,
          input.expiresAt,
          input.operationId,
          input.operationDigest,
          authorization.gate,
          input.expiresAt,
          input.capabilityId,
          input.capabilityId,
          input.now,
          input.maximumConcurrentUploads,
          input.capabilityId,
          input.now,
          input.capabilityId,
          input.now,
          input.totalLength,
          input.maximumStagedBytes,
        ),
      ...input.parts.map((part, ordinal) =>
        this.database
          .prepare(
            'INSERT OR IGNORE INTO chunk_upload_parts(upload_id, part_id, ordinal, length, digest) SELECT id, ?, ?, ?, ? FROM chunk_uploads WHERE operation_id = ? AND operation_digest = ?',
          )
          .bind(
            part.id,
            ordinal,
            part.length,
            part.digest,
            input.operationId,
            input.operationDigest,
          ),
      ),
      this.database
        .prepare(
          "INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-chunk-create-assertion', NULL WHERE NOT EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?) OR NOT EXISTS (SELECT 1 FROM chunk_uploads WHERE operation_id = ? AND operation_digest = ?)",
        )
        .bind(authorization.gate, input.operationId, input.operationDigest),
      this.database
        .prepare('DELETE FROM maintenance_leases WHERE name = ?')
        .bind(authorization.gate),
    ];
    let mutationChanges = 0;
    try {
      const results = await this.database.batch<D1RunResultLike>(statements);
      mutationChanges =
        results[authorization.statements.length]?.meta?.changes ?? 0;
    } catch (error) {
      if (
        error instanceof Error &&
        /maintenance_leases\.expires_at/i.test(error.message)
      ) {
        if (await this.hasLiveNonce(input.authorization.claims, input.now)) {
          throw new Error('Chunk upload authorization is unavailable.');
        }
        const conflict = await this.findChunkUploadByOperation(
          input.operationId,
        );
        if (conflict) {
          this.requireMatchingOperation(
            conflict.operationDigest,
            input.operationDigest,
          );
        }
        throw new Error('Chunk upload staging quota is exhausted.');
      }
      throw error;
    }
    const upload = await this.findChunkUploadByOperation(input.operationId);
    if (!upload) {
      throw new Error('Chunk upload reservation is unavailable.');
    }
    this.requireMatchingOperation(
      upload.operationDigest,
      input.operationDigest,
    );
    return { upload, idempotent: mutationChanges !== 1 };
  }

  async findChunkUpload(
    input: Parameters<V2Repository['findChunkUpload']>[0],
  ): Promise<V2ChunkUpload | null> {
    const row = await this.database
      .prepare(
        "SELECT u.id FROM chunk_uploads u JOIN capabilities c ON c.id = u.capability_id WHERE u.id = ? AND u.capability_id = ? AND u.committed_at IS NULL AND u.expires_at > ? AND c.scope = 'write' AND c.expires_at > ? AND c.revoked_at IS NULL",
      )
      .bind(input.id, input.capabilityId, input.now, input.now)
      .first<Row>();
    return row ? this.requireChunkUpload(String(row.id)) : null;
  }

  async findChunkUploadForCommit(
    input: Parameters<V2Repository['findChunkUploadForCommit']>[0],
  ): Promise<V2ChunkUpload | null> {
    const row = await this.database
      .prepare(
        "SELECT u.id FROM chunk_uploads u JOIN capabilities c ON c.id = u.capability_id WHERE u.id = ? AND u.capability_id = ? AND u.expires_at > ? AND c.scope = 'write' AND c.expires_at > ? AND c.revoked_at IS NULL",
      )
      .bind(input.id, input.capabilityId, input.now, input.now)
      .first<Row>();
    return row ? this.requireChunkUpload(String(row.id)) : null;
  }

  async authorizeChunkUpload(
    input: Parameters<V2Repository['authorizeChunkUpload']>[0],
  ): Promise<V2ChunkUpload> {
    const authorization = this.chunkAuthorizationStatements(
      input.capabilityId,
      input.authorization,
      input.now,
    );
    try {
      await this.database.batch([
        ...authorization.statements,
        this.database
          .prepare(
            `INSERT INTO maintenance_leases(name, expires_at)
             SELECT 'v2-chunk-authorize-assertion', NULL
             WHERE NOT EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?)
                OR NOT EXISTS (
                  SELECT 1 FROM chunk_uploads u
                  JOIN capabilities c ON c.id = u.capability_id
                  WHERE u.id = ? AND u.capability_id = ? AND u.committed_at IS NULL AND u.expires_at > ?
                    AND c.scope = 'write' AND c.expires_at > ? AND c.revoked_at IS NULL
                )`,
          )
          .bind(
            authorization.gate,
            input.id,
            input.capabilityId,
            input.now,
            input.now,
          ),
        this.database
          .prepare('DELETE FROM maintenance_leases WHERE name = ?')
          .bind(authorization.gate),
      ]);
    } catch (error) {
      if (
        error instanceof Error &&
        /maintenance_leases\.expires_at/i.test(error.message)
      ) {
        throw new Error('Chunk upload is unavailable.');
      }
      throw error;
    }
    return this.requireChunkUpload(input.id);
  }

  async prepareChunkUploadPart(
    input: Parameters<V2Repository['prepareChunkUploadPart']>[0],
  ): Promise<{ upload: V2ChunkUpload; idempotent: boolean }> {
    this.validateChunkOperation(input.operationId, input.operationDigest);
    if (
      !/^[a-f0-9]{32}$/.test(input.writeToken) ||
      !Number.isSafeInteger(input.writeExpiresAt) ||
      input.writeExpiresAt <= input.now
    ) {
      throw new Error('Chunk upload part write lease is invalid.');
    }
    const bodyKey = v2StagedChunkKey(input.id, input.partId);
    const authorization = this.chunkAuthorizationStatements(
      input.capabilityId,
      input.authorization,
      input.now,
    );
    const statements = [
      ...authorization.statements,
      this.database
        .prepare(
          `UPDATE chunk_upload_parts SET write_token = ?, write_expires_at = ?, operation_id = ?, operation_digest = ?
           WHERE upload_id = ? AND part_id = ? AND body_key IS NULL
             AND (write_token IS NULL OR write_expires_at <= ?)
             AND (operation_id IS NULL OR (operation_id = ? AND operation_digest = ?))
             AND EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?)
             AND EXISTS (SELECT 1 FROM chunk_uploads u JOIN capabilities c ON c.id = u.capability_id WHERE u.id = ? AND u.capability_id = ? AND u.committed_at IS NULL AND u.expires_at > ? AND c.scope = 'write' AND c.expires_at > ? AND c.revoked_at IS NULL)`,
        )
        .bind(
          input.writeToken,
          input.writeExpiresAt,
          input.operationId,
          input.operationDigest,
          input.id,
          input.partId,
          input.now,
          input.operationId,
          input.operationDigest,
          authorization.gate,
          input.id,
          input.capabilityId,
          input.now,
          input.now,
        ),
      this.database
        .prepare(
          "INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-chunk-part-assertion', NULL WHERE NOT EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?) OR NOT EXISTS (SELECT 1 FROM chunk_upload_parts WHERE upload_id = ? AND part_id = ? AND operation_id = ? AND operation_digest = ? AND ((body_key = ?) OR (body_key IS NULL AND write_token = ?)))",
        )
        .bind(
          authorization.gate,
          input.id,
          input.partId,
          input.operationId,
          input.operationDigest,
          bodyKey,
          input.writeToken,
        ),
      this.database
        .prepare('DELETE FROM maintenance_leases WHERE name = ?')
        .bind(authorization.gate),
    ];
    try {
      await this.database.batch<D1RunResultLike>(statements);
    } catch (error) {
      if (
        error instanceof Error &&
        /maintenance_leases\.expires_at/i.test(error.message)
      ) {
        if (await this.hasLiveNonce(input.authorization.claims, input.now)) {
          throw new Error('Chunk upload authorization is unavailable.');
        }
        const conflict = await this.database
          .prepare(
            'SELECT operation_id, operation_digest FROM chunk_upload_parts WHERE upload_id = ? AND part_id = ?',
          )
          .bind(input.id, input.partId)
          .first<Row>();
        if (conflict?.operation_id) {
          this.requireMatchingOperation(
            d1Bytes(conflict.operation_digest),
            input.operationDigest,
          );
        }
        throw new Error('Chunk upload part is unavailable.');
      }
      throw error;
    }
    const upload = await this.requireChunkUpload(input.id);
    const part = upload.parts.find(
      (candidate) => candidate.id === input.partId,
    );
    if (!part) {
      throw new Error('Chunk upload part is unavailable.');
    }
    return {
      upload,
      idempotent: part.bodyKey !== undefined,
    };
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
    const result = await this.database
      .prepare(
        `UPDATE chunk_upload_parts SET body_key = ?, received_at = ?, write_token = NULL, write_expires_at = NULL
         WHERE upload_id = ? AND part_id = ? AND body_key IS NULL AND write_token = ?
           AND EXISTS (SELECT 1 FROM chunk_uploads u JOIN capabilities c ON c.id = u.capability_id WHERE u.id = ? AND u.capability_id = ? AND u.committed_at IS NULL AND u.expires_at > ? AND c.scope = 'write' AND c.expires_at > ? AND c.revoked_at IS NULL)`,
      )
      .bind(
        input.bodyKey,
        input.now,
        input.id,
        input.partId,
        input.writeToken,
        input.id,
        input.capabilityId,
        input.now,
        input.now,
      )
      .run<D1RunResultLike>();
    if ((result.meta?.changes ?? 0) !== 1) {
      throw new Error('Chunk upload part write is unavailable.');
    }
    return this.requireChunkUpload(input.id);
  }

  async abortChunkUploadPart(
    input: Parameters<V2Repository['abortChunkUploadPart']>[0],
  ): Promise<boolean> {
    if (!/^[a-f0-9]{32}$/.test(input.writeToken)) {
      throw new Error('Chunk upload part write token is invalid.');
    }
    const result = await this.database
      .prepare(
        'UPDATE chunk_upload_parts SET write_token = NULL, write_expires_at = NULL, operation_id = NULL, operation_digest = NULL WHERE upload_id = ? AND part_id = ? AND body_key IS NULL AND write_token = ?',
      )
      .bind(input.id, input.partId, input.writeToken)
      .run<D1RunResultLike>();
    if ((result.meta?.changes ?? 0) === 1) {
      return true;
    }
    const part = await this.database
      .prepare(
        'SELECT 1 FROM chunk_upload_parts WHERE upload_id = ? AND part_id = ?',
      )
      .bind(input.id, input.partId)
      .first<Row>();
    return part === null;
  }

  async renewChunkUpload(
    input: Parameters<V2Repository['renewChunkUpload']>[0],
  ): Promise<{ upload: V2ChunkUpload; idempotent: boolean }> {
    this.validateChunkOperation(input.operationId, input.operationDigest);
    const authorization = this.chunkAuthorizationStatements(
      input.capabilityId,
      input.authorization,
      input.now,
    );
    const statements = [
      ...authorization.statements,
      this.database
        .prepare(
          `UPDATE chunk_uploads SET expires_at = ?, renewal_operation_id = ?, renewal_operation_digest = ?
           WHERE id = ? AND capability_id = ? AND committed_at IS NULL AND expires_at > ?
             AND EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?)
             AND EXISTS (SELECT 1 FROM capabilities WHERE id = ? AND scope = 'write' AND expires_at >= ? AND revoked_at IS NULL)
             AND expires_at < ?`,
        )
        .bind(
          input.expiresAt,
          input.operationId,
          input.operationDigest,
          input.id,
          input.capabilityId,
          input.now,
          authorization.gate,
          input.capabilityId,
          input.expiresAt,
          input.expiresAt,
        ),
      this.database
        .prepare(
          "INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-chunk-renew-assertion', NULL WHERE NOT EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?) OR NOT EXISTS (SELECT 1 FROM chunk_uploads WHERE id = ? AND renewal_operation_id = ? AND renewal_operation_digest = ?)",
        )
        .bind(
          authorization.gate,
          input.id,
          input.operationId,
          input.operationDigest,
        ),
      this.database
        .prepare('DELETE FROM maintenance_leases WHERE name = ?')
        .bind(authorization.gate),
    ];
    let mutationChanges = 0;
    try {
      const results = await this.database.batch<D1RunResultLike>(statements);
      mutationChanges =
        results[authorization.statements.length]?.meta?.changes ?? 0;
    } catch (error) {
      if (
        error instanceof Error &&
        /maintenance_leases\.expires_at/i.test(error.message)
      ) {
        if (await this.hasLiveNonce(input.authorization.claims, input.now)) {
          throw new Error('Chunk upload authorization is unavailable.');
        }
        throw new Error('Chunk upload lease cannot be renewed.');
      }
      throw error;
    }
    return {
      upload: await this.requireChunkUpload(input.id),
      idempotent: mutationChanges !== 1,
    };
  }

  async abandonChunkUpload(
    input: Parameters<V2Repository['abandonChunkUpload']>[0],
  ): Promise<void> {
    const authorization = this.chunkAuthorizationStatements(
      input.capabilityId,
      input.authorization,
      input.now,
    );
    try {
      await this.database.batch([
        ...authorization.statements,
        this.database
          .prepare(
            `UPDATE chunk_uploads SET expires_at = ? WHERE id = ? AND capability_id = ? AND committed_at IS NULL AND expires_at > ?
             AND EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?)
             AND EXISTS (SELECT 1 FROM capabilities WHERE id = ? AND scope = 'write' AND expires_at > ? AND revoked_at IS NULL)`,
          )
          .bind(
            input.now,
            input.id,
            input.capabilityId,
            input.now,
            authorization.gate,
            input.capabilityId,
            input.now,
          ),
        this.database
          .prepare(
            "INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-chunk-abandon-assertion', NULL WHERE NOT EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?) OR NOT EXISTS (SELECT 1 FROM chunk_uploads WHERE id = ? AND capability_id = ? AND expires_at = ?)",
          )
          .bind(authorization.gate, input.id, input.capabilityId, input.now),
        this.database
          .prepare('DELETE FROM maintenance_leases WHERE name = ?')
          .bind(authorization.gate),
      ]);
    } catch (error) {
      if (
        error instanceof Error &&
        /maintenance_leases\.expires_at/i.test(error.message)
      ) {
        throw new Error('Chunk upload is unavailable.');
      }
      throw error;
    }
  }

  async reserveDelivery(input: {
    capabilityId: string;
    operationId: Uint8Array;
    operationDigest: Uint8Array;
    payloadLength: number;
    chunkUploadId?: string;
    maximumTotalBytes?: number;
    maximumPendingDeliveries?: number;
    maximumObjectsPerCapability?: number;
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
    };
    consumeControlEvents?: {
      ids: readonly string[];
      relationshipId: string;
      direction: V2RepositoryCapability['direction'];
      now: number;
    };
    now: number;
    expiresAt: number;
  }): Promise<V2DeliveryReservation | { existing: V2RepositoryDelivery }> {
    operationId(input.operationId);
    const upload = input.chunkUploadId
      ? await this.requireChunkUpload(input.chunkUploadId)
      : undefined;
    const deliveryId =
      upload?.deliveryId ?? crypto.randomUUID().replaceAll('-', '');
    const payloadKey = upload
      ? v2DeliveryChunkKey(deliveryId, upload.parts[0]!.id)
      : `deliveries/${deliveryId}.bin`;
    const chunkGuard = input.chunkUploadId
      ? ' AND EXISTS (SELECT 1 FROM chunk_uploads u WHERE u.id = ? AND u.delivery_id = ? AND u.capability_id = ? AND u.committed_at IS NULL AND u.expires_at > ? AND u.total_length = ? AND NOT EXISTS (SELECT 1 FROM chunk_upload_parts p WHERE p.upload_id = u.id AND p.body_key IS NULL))'
      : '';
    const chunkValues = input.chunkUploadId
      ? [
          input.chunkUploadId,
          deliveryId,
          input.capabilityId,
          input.now,
          input.payloadLength,
        ]
      : [];
    // Published-but-uncollected deliveries plus in-flight reservations for the
    // capability's own relationship and direction.
    const pendingGuard =
      input.maximumPendingDeliveries === undefined
        ? ''
        : ` AND (SELECT COUNT(*) FROM deliveries d WHERE d.relationship_id = (SELECT relationship_id FROM capabilities WHERE id = ?) AND d.direction = (SELECT direction FROM capabilities WHERE id = ?) AND d.state = 'published' AND d.expires_at > ?) + (SELECT COUNT(*) FROM reservations r WHERE r.expires_at > ? AND r.capability_id IN (SELECT id FROM capabilities WHERE relationship_id = (SELECT relationship_id FROM capabilities WHERE id = ?) AND direction = (SELECT direction FROM capabilities WHERE id = ?))) < ?`;
    const pendingValues =
      input.maximumPendingDeliveries === undefined
        ? []
        : [
            input.capabilityId,
            input.capabilityId,
            input.now,
            input.now,
            input.capabilityId,
            input.capabilityId,
            input.maximumPendingDeliveries,
          ];
    const statements: ReturnType<D1DatabaseLike['prepare']>[] = [];
    let gateChanges = 1;
    let authorizationIndex: number | undefined;
    const authorization = input.authorization;

    if (authorization?.claims.length) {
      const claims = authorization.claims;
      const keys = new Set(
        claims.map(
          ({ capabilityId, nonce }) =>
            `${capabilityId}:${Array.from(nonce).join(',')}`,
        ),
      );
      if (keys.size !== claims.length) {
        throw new Error('Request authorization nonce is duplicated.');
      }
      const counts = new Map<string, number>();
      for (const claim of claims) {
        counts.set(
          claim.capabilityId,
          (counts.get(claim.capabilityId) ?? 0) + 1,
        );
      }
      const claimValues = claims.flatMap(
        ({ capabilityId, nonce, expiresAt }) => [
          capabilityId,
          nonce,
          expiresAt,
        ],
      );
      const countValues = Array.from(counts, ([capabilityId, count]) => [
        capabilityId,
        count,
      ]).flat();
      const claimPlaceholders = claims.map(() => '(?, ?, ?)').join(', ');
      const countPlaceholders = Array.from(counts)
        .map(() => '(?, ?)')
        .join(', ');
      // A replayed proof nonce must fail the whole request even when the
      // operation it names was already published, so this runs before the
      // claim insert makes every claimed nonce present. `changes()` is not
      // read by the claim insert, so an extra statement here is safe.
      statements.push(
        this.database
          .prepare(
            `WITH claims(capability_id, nonce) AS (VALUES ${claims
              .map(() => '(?, ?)')
              .join(
                ', ',
              )}) INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-request-nonce-assertion', NULL WHERE EXISTS (SELECT 1 FROM nonces n JOIN claims c ON c.capability_id = n.capability_id AND c.nonce = n.nonce WHERE n.expires_at >= ?)`,
          )
          .bind(
            ...claims.flatMap(({ capabilityId, nonce }) => [
              capabilityId,
              nonce,
            ]),
            input.now,
          ),
      );
      authorizationIndex = statements.length;
      statements.push(
        this.database
          .prepare(
            `WITH claims(capability_id, nonce, expires_at) AS (VALUES ${claimPlaceholders}), counts(capability_id, claim_count) AS (VALUES ${countPlaceholders}), conflict AS (SELECT 1 FROM nonces n JOIN claims c ON c.capability_id = n.capability_id AND c.nonce = n.nonce WHERE n.expires_at >= ? LIMIT 1), inactive AS (SELECT 1 FROM claims cl LEFT JOIN capabilities c ON c.id = cl.capability_id AND c.expires_at > ? AND c.revoked_at IS NULL WHERE c.id IS NULL LIMIT 1), rate_exceeded AS (SELECT 1 FROM counts cl LEFT JOIN rate_windows r ON r.capability_id = cl.capability_id AND r.minute = ? WHERE COALESCE(r.count, 0) + cl.claim_count > ? LIMIT 1) INSERT INTO nonces(capability_id, nonce, expires_at) SELECT capability_id, nonce, expires_at FROM claims WHERE NOT EXISTS (SELECT 1 FROM conflict) AND NOT EXISTS (SELECT 1 FROM inactive) AND NOT EXISTS (SELECT 1 FROM rate_exceeded) AND EXISTS (SELECT 1 FROM capabilities WHERE id = ? AND expires_at > ? AND revoked_at IS NULL) ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?`,
          )
          .bind(
            ...claimValues,
            ...countValues,
            input.now,
            input.now,
            Math.floor(input.now / 60),
            authorization.maximumRequestsPerMinute,
            input.capabilityId,
            input.now,
            input.now,
          ),
      );
      gateChanges = claims.length;
      for (const [capabilityId, count] of counts) {
        statements.push(
          this.database
            .prepare(
              'INSERT INTO rate_windows(capability_id, minute, count) SELECT ?, ?, ? WHERE changes() = ? ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + excluded.count WHERE count + excluded.count <= ?',
            )
            .bind(
              capabilityId,
              Math.floor(input.now / 60),
              count,
              gateChanges,
              authorization.maximumRequestsPerMinute,
            ),
        );
        gateChanges = 1;
      }
    } else {
      // `changes()` carries the active-capability decision into the following
      // reservation mutation without a preceding read or state rewrite.
      statements.push(
        this.database
          .prepare(
            'UPDATE capabilities SET created_at = created_at WHERE id = ? AND expires_at > ? AND revoked_at IS NULL',
          )
          .bind(input.capabilityId, input.now),
      );
    }

    if (
      input.maximumTotalBytes === undefined &&
      input.maximumObjectsPerCapability === undefined
    ) {
      statements.push(
        this.database
          .prepare(
            `INSERT OR IGNORE INTO reservations(delivery_id, capability_id, payload_key, reserved_bytes, expires_at, operation_id, operation_digest) SELECT ?, ?, ?, ?, ?, ?, ? WHERE changes() = ? AND EXISTS (SELECT 1 FROM capabilities WHERE id = ? AND expires_at > ? AND revoked_at IS NULL) AND NOT EXISTS (SELECT 1 FROM deliveries WHERE operation_id = ?)${pendingGuard}${chunkGuard}`,
          )
          .bind(
            deliveryId,
            input.capabilityId,
            payloadKey,
            input.payloadLength,
            input.expiresAt,
            input.operationId,
            input.operationDigest,
            gateChanges,
            input.capabilityId,
            input.now,
            input.operationId,
            ...pendingValues,
            ...chunkValues,
          ),
      );
    } else {
      statements.push(
        this.database
          .prepare(
            `INSERT INTO quota_accounts(relationship_id, committed_bytes, reserved_bytes, object_count, updated_at) SELECT relationship_id, 0, ?, 1, ? FROM capabilities WHERE changes() = ? AND id = ? AND expires_at > ? AND revoked_at IS NULL AND ? <= ? AND NOT EXISTS (SELECT 1 FROM reservations WHERE operation_id = ?) AND NOT EXISTS (SELECT 1 FROM deliveries WHERE operation_id = ?)${pendingGuard} ON CONFLICT(relationship_id) DO UPDATE SET reserved_bytes = reserved_bytes + excluded.reserved_bytes, object_count = object_count + 1, updated_at = excluded.updated_at WHERE committed_bytes + reserved_bytes + excluded.reserved_bytes <= ? AND object_count < ?`,
          )
          .bind(
            input.payloadLength,
            input.now,
            gateChanges,
            input.capabilityId,
            input.now,
            input.payloadLength,
            input.maximumTotalBytes ?? Number.MAX_SAFE_INTEGER,
            input.operationId,
            input.operationId,
            ...pendingValues,
            input.maximumTotalBytes ?? Number.MAX_SAFE_INTEGER,
            input.maximumObjectsPerCapability ?? Number.MAX_SAFE_INTEGER,
          ),
      );
      statements.push(
        this.database
          .prepare(
            `INSERT INTO reservations(delivery_id, capability_id, payload_key, reserved_bytes, expires_at, operation_id, operation_digest) SELECT ?, ?, ?, ?, ?, ?, ? WHERE changes() = 1${chunkGuard}`,
          )
          .bind(
            deliveryId,
            input.capabilityId,
            payloadKey,
            input.payloadLength,
            input.expiresAt,
            input.operationId,
            input.operationDigest,
            ...chunkValues,
          ),
      );
    }

    // A D1 batch commits only if every statement succeeds. This raises a
    // bounded NOT NULL violation when the preceding conditional
    // mutation did not admit either a new reservation or an exact retry, so
    // failed authorization/rate/quota checks cannot leave nonce or rate rows.
    statements.push(
      this.database
        .prepare(
          "INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-request-admission-assertion', NULL WHERE changes() != 1 AND NOT EXISTS (SELECT 1 FROM reservations WHERE operation_id = ? AND operation_digest = ?) AND NOT EXISTS (SELECT 1 FROM deliveries WHERE operation_id = ? AND operation_digest = ?)",
        )
        .bind(
          input.operationId,
          input.operationDigest,
          input.operationId,
          input.operationDigest,
        ),
    );
    if (input.consumeControlEvents?.ids.length) {
      const placeholders = input.consumeControlEvents.ids
        .map(() => '?')
        .join(', ');
      statements.push(
        this.database
          .prepare(
            `UPDATE control_events SET consumed_at = ? WHERE consumed_at IS NULL AND relationship_id = ? AND direction = ? AND id IN (${placeholders})`,
          )
          .bind(
            input.consumeControlEvents.now,
            input.consumeControlEvents.relationshipId,
            directionNumber(input.consumeControlEvents.direction),
            ...input.consumeControlEvents.ids,
          ),
      );
    }
    try {
      await this.database.batch<D1RunResultLike>(statements);
    } catch (error) {
      if (
        error instanceof Error &&
        /maintenance_leases\.expires_at/i.test(error.message)
      ) {
        // A spent proof nonce is a replay whatever else the request asks for,
        // so it outranks the idempotency and conflict answers below. Without
        // this an exact replay of a published operation would be admitted here
        // and refused by the Memory and SQLite repositories.
        if (
          authorization?.claims.length &&
          (await this.hasLiveNonce(authorization.claims, input.now))
        ) {
          throw new Error('Request authorization is unavailable.');
        }
        const prior = await this.database
          .prepare(
            'SELECT operation_digest FROM reservations WHERE operation_id = ? UNION ALL SELECT operation_digest FROM deliveries WHERE operation_id = ? LIMIT 1',
          )
          .bind(input.operationId, input.operationId)
          .first<Row>();
        if (prior) {
          this.requireMatchingOperation(
            d1Bytes(prior.operation_digest),
            input.operationDigest,
          );
        }
        if (authorizationIndex !== undefined) {
          throw new Error('Request authorization is unavailable.');
        }
        if (input.maximumTotalBytes !== undefined) {
          throw new Error('Relationship delivery quota is exhausted.');
        }
        throw new Error('Delivery capability is not active.');
      }
      throw error;
    }

    const reservation = await this.database
      .prepare(
        'SELECT delivery_id, payload_key, expires_at, operation_digest FROM reservations WHERE operation_id = ?',
      )
      .bind(input.operationId)
      .first<Row>();
    if (reservation) {
      this.requireMatchingOperation(
        d1Bytes(reservation.operation_digest),
        input.operationDigest,
      );
      return {
        deliveryId: String(reservation.delivery_id),
        payloadKey: String(reservation.payload_key),
        expiresAt: Number(reservation.expires_at),
      };
    }

    // A concurrent publisher may have finalized the reservation between the
    // insert and read. The delivery row remains the durable idempotency record.
    const raced = await this.findDeliveryByOperation(input.operationId);
    if (!raced) {
      if (input.maximumTotalBytes !== undefined) {
        throw new Error('Relationship delivery quota is exhausted.');
      }
      throw new Error('Delivery capability is not active.');
    }
    this.requireMatchingOperation(raced.operationDigest, input.operationDigest);
    return { existing: raced };
  }

  async publishDelivery(
    input: Parameters<V2Repository['publishDelivery']>[0],
  ): Promise<{
    delivery: V2RepositoryDelivery;
    idempotent: boolean;
  }> {
    operationId(input.operationId);
    const upload = input.chunkUploadId
      ? await this.requireChunkUpload(input.chunkUploadId)
      : undefined;
    if (
      input.chunkUploadId &&
      (!upload ||
        upload.deliveryId !== input.id ||
        !input.parts ||
        input.parts.length !== upload.parts.length ||
        input.parts.some((part, index) => {
          const declared = upload.parts[index]!;
          return (
            part.id !== declared.id ||
            part.length !== declared.length ||
            !bytesEqual(part.digest, declared.digest) ||
            part.key !== v2DeliveryChunkKey(input.id, part.id)
          );
        }))
    ) {
      throw new Error('Chunk delivery publication is invalid.');
    }
    const statements = [
      this.database
        .prepare(
          // `sequence` is assigned by the same statement that commits the row,
          // so the inbox can return deliveries in publication order instead of
          // whole-second creation order.
          "INSERT INTO deliveries(id, relationship_id, direction, slot, epoch, authorization_chain, encrypted_descriptor, requested_policy, effective_policy, policy_digest, payload_key, payload_length, payload_digest, operation_id, operation_digest, state, sequence, created_at, expires_at) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, payload_key, ?, ?, operation_id, operation_digest, 'published', COALESCE((SELECT MAX(sequence) + 1 FROM deliveries WHERE relationship_id = ? AND direction = ?), 1), ?, ? FROM reservations WHERE delivery_id = ? AND payload_key = ? AND operation_id = ? AND operation_digest = ?",
        )
        .bind(
          input.id,
          input.relationshipId,
          directionNumber(input.direction),
          input.slot,
          input.epoch,
          input.chain ?? null,
          input.encryptedDescriptor,
          input.requestedPolicy,
          input.effectivePolicy,
          input.policyDigest,
          input.payloadLength,
          input.payloadDigest,
          input.relationshipId,
          directionNumber(input.direction),
          input.createdAt,
          input.expiresAt,
          input.id,
          input.payloadKey,
          input.operationId,
          input.operationDigest,
        ),
      this.database
        .prepare(
          'UPDATE quota_accounts SET reserved_bytes = MAX(0, reserved_bytes - ?), committed_bytes = committed_bytes + ? WHERE changes() = 1 AND relationship_id = ? AND EXISTS (SELECT 1 FROM deliveries WHERE id = ? AND operation_id = ? AND operation_digest = ?)',
        )
        .bind(
          input.payloadLength,
          input.payloadLength,
          input.relationshipId,
          input.id,
          input.operationId,
          input.operationDigest,
        ),
      ...(input.parts ?? []).map((part, ordinal) =>
        this.database
          .prepare(
            'INSERT OR IGNORE INTO delivery_chunks(delivery_id, part_id, ordinal, length, digest, body_key) SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM deliveries WHERE id = ? AND operation_id = ? AND operation_digest = ?)',
          )
          .bind(
            input.id,
            part.id,
            ordinal,
            part.length,
            part.digest,
            part.key,
            input.id,
            input.operationId,
            input.operationDigest,
          ),
      ),
      ...(input.chunkUploadId
        ? [
            this.database
              .prepare(
                'UPDATE chunk_uploads SET committed_at = ?, expires_at = ? WHERE id = ? AND delivery_id = ? AND committed_at IS NULL AND EXISTS (SELECT 1 FROM deliveries WHERE id = ?)',
              )
              .bind(
                input.createdAt,
                input.expiresAt,
                input.chunkUploadId,
                input.id,
                input.id,
              ),
            this.database
              .prepare(
                'UPDATE chunk_upload_parts SET body_key = NULL WHERE upload_id = ? AND EXISTS (SELECT 1 FROM deliveries WHERE id = ?)',
              )
              .bind(input.chunkUploadId, input.id),
          ]
        : []),
      this.database
        .prepare(
          'DELETE FROM reservations WHERE delivery_id = ? AND payload_key = ? AND EXISTS (SELECT 1 FROM deliveries WHERE id = ? AND operation_id = ? AND operation_digest = ?)',
        )
        .bind(
          input.id,
          input.payloadKey,
          input.id,
          input.operationId,
          input.operationDigest,
        ),
    ];
    const results = await this.database.batch<D1RunResultLike>(statements);
    const delivery = await this.findDelivery(input.id);
    if (!delivery) {
      throw new Error('Delivery reservation is unavailable.');
    }
    this.requireMatchingOperation(
      delivery.operationDigest,
      input.operationDigest,
    );
    return { delivery, idempotent: results[0]?.meta?.changes !== 1 };
  }

  async queryInbox(input: {
    relationshipId: string;
    direction: V2RepositoryCapability['direction'];
    dataSlots: readonly { slot: Uint8Array; epoch: number }[];
    controlSlots: readonly { slot: Uint8Array; epoch: number }[];
    maximumControlEvents?: number;
    maximumControlBytes?: number;
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
      consumeControlEventIds?: readonly string[];
    };
    now: number;
  }): Promise<{
    delivery: V2RepositoryDelivery | null;
    controlEvents: V2RepositoryControlEvent[];
    pendingEpochs: Set<number>;
    authorizationAccepted: boolean;
  }> {
    if (input.authorization?.claims.length) {
      const claims = input.authorization.claims;
      const keys = new Set(
        claims.map(
          ({ capabilityId, nonce }) =>
            `${capabilityId}:${Array.from(nonce).join(',')}`,
        ),
      );
      if (keys.size !== claims.length) {
        return this.rejectedInbox();
      }
      const counts = new Map<string, number>();
      for (const claim of claims) {
        counts.set(
          claim.capabilityId,
          (counts.get(claim.capabilityId) ?? 0) + 1,
        );
      }
      const claimPlaceholders = claims.map(() => '(?, ?, ?)').join(', ');
      const countPlaceholders = Array.from(counts)
        .map(() => '(?, ?)')
        .join(', ');
      const statements: ReturnType<D1DatabaseLike['prepare']>[] = [
        this.database
          .prepare(
            `WITH claims(capability_id, nonce, expires_at) AS (VALUES ${claimPlaceholders}), counts(capability_id, claim_count) AS (VALUES ${countPlaceholders}), conflict AS (SELECT 1 FROM nonces n JOIN claims c ON c.capability_id = n.capability_id AND c.nonce = n.nonce WHERE n.expires_at >= ? LIMIT 1), inactive AS (SELECT 1 FROM claims cl LEFT JOIN capabilities c ON c.id = cl.capability_id AND c.expires_at > ? AND c.revoked_at IS NULL WHERE c.id IS NULL LIMIT 1), rate_exceeded AS (SELECT 1 FROM counts cl LEFT JOIN rate_windows r ON r.capability_id = cl.capability_id AND r.minute = ? WHERE COALESCE(r.count, 0) + cl.claim_count > ? LIMIT 1) INSERT INTO nonces(capability_id, nonce, expires_at) SELECT capability_id, nonce, expires_at FROM claims WHERE NOT EXISTS (SELECT 1 FROM conflict) AND NOT EXISTS (SELECT 1 FROM inactive) AND NOT EXISTS (SELECT 1 FROM rate_exceeded) ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?`,
          )
          .bind(
            ...claims.flatMap(({ capabilityId, nonce, expiresAt }) => [
              capabilityId,
              nonce,
              expiresAt,
            ]),
            ...Array.from(counts)
              .map(([capabilityId, count]) => [capabilityId, count])
              .flat(),
            input.now,
            input.now,
            Math.floor(input.now / 60),
            input.authorization.maximumRequestsPerMinute,
            input.now,
          ),
      ];
      let expectedChanges = claims.length;
      for (const [capabilityId, count] of counts) {
        statements.push(
          this.database
            .prepare(
              'INSERT INTO rate_windows(capability_id, minute, count) SELECT ?, ?, ? WHERE changes() = ? ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + excluded.count WHERE count + excluded.count <= ?',
            )
            .bind(
              capabilityId,
              Math.floor(input.now / 60),
              count,
              expectedChanges,
              input.authorization.maximumRequestsPerMinute,
            ),
        );
        expectedChanges = 1;
      }
      const ids = input.authorization.consumeControlEventIds ?? [];
      if (ids.length) {
        statements.push(
          this.database
            .prepare(
              `UPDATE control_events SET consumed_at = ? WHERE changes() = 1 AND consumed_at IS NULL AND relationship_id = ? AND direction = ? AND id IN (${ids.map(() => '?').join(', ')})`,
            )
            .bind(
              input.now,
              input.relationshipId,
              directionNumber(input.direction),
              ...ids,
            ),
        );
      }
      const results = await this.database.batch<D1RunResultLike>(statements);
      if (results[0]?.meta?.changes !== claims.length) {
        return this.rejectedInbox();
      }
    }
    const [delivery, controlEvents, pendingEpochs] = await Promise.all([
      this.queryDelivery(
        input.relationshipId,
        input.direction,
        input.dataSlots,
        input.now,
      ),
      this.queryControlEvents(
        input.relationshipId,
        input.direction,
        input.controlSlots,
        input.now,
        input.maximumControlEvents,
        input.maximumControlBytes,
      ),
      this.queryPendingEpochs(
        input.relationshipId,
        input.direction,
        input.dataSlots,
        input.now,
      ),
    ]);
    return {
      delivery,
      controlEvents,
      pendingEpochs,
      authorizationAccepted: true,
    };
  }

  private rejectedInbox() {
    return {
      delivery: null,
      controlEvents: [],
      pendingEpochs: new Set<number>(),
      authorizationAccepted: false,
    };
  }

  async completeDelivery(input: {
    id: string;
    operationId: Uint8Array;
    operationDigest: Uint8Array;
    completionDigest: Uint8Array;
    result: 0 | 1;
    now: number;
  }): Promise<{ delivery: V2RepositoryDelivery; idempotent: boolean }> {
    operationId(input.operationId);
    const result = await this.database
      .prepare(
        "UPDATE deliveries SET state = 'completed', completed_at = ?, completion_operation_id = ?, completion_operation_digest = ?, completion_digest = ?, completion_result = ? WHERE id = ? AND state = 'published'",
      )
      .bind(
        input.now,
        input.operationId,
        input.operationDigest,
        input.completionDigest,
        input.result,
        input.id,
      )
      .run<D1RunResultLike>();
    const delivery = await this.findDelivery(input.id);
    if (!delivery) {
      throw new Error('Delivery is unavailable.');
    }
    this.requireMatchingCompletion(delivery, input);
    return { delivery, idempotent: result.meta?.changes !== 1 };
  }

  async completeDeliveryWithControl(input: {
    completion: {
      id: string;
      operationId: Uint8Array;
      operationDigest: Uint8Array;
      completionDigest: Uint8Array;
      result: 0 | 1;
      now: number;
    };
    event: V2RepositoryControlEvent;
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
      controlQuota?: {
        maximumEvents: number;
        maximumBytes: number;
      };
    };
  }): Promise<
    | {
        delivery: V2RepositoryDelivery;
        event: V2RepositoryControlEvent;
        idempotent: boolean;
        authorizationAccepted: true;
      }
    | { authorizationAccepted: false }
  > {
    operationId(input.completion.operationId);
    operationId(input.event.operationId);
    const event = input.event;
    const completion = input.completion;
    const statements: ReturnType<D1DatabaseLike['prepare']>[] = [];
    const authorization = input.authorization;
    let authorizationIndex: number | undefined;
    let eventIndex: number;
    let marker: string | undefined;
    if (authorization?.claims.length) {
      const claims = authorization.claims;
      const keys = new Set(
        claims.map(
          ({ capabilityId, nonce }) =>
            `${capabilityId}:${Array.from(nonce).join(',')}`,
        ),
      );
      if (keys.size !== claims.length) {
        return { authorizationAccepted: false };
      }
      const counts = new Map<string, number>();
      for (const claim of claims) {
        counts.set(
          claim.capabilityId,
          (counts.get(claim.capabilityId) ?? 0) + 1,
        );
      }
      authorizationIndex = statements.length;
      statements.push(
        this.database
          .prepare(
            `WITH claims(capability_id, nonce, expires_at) AS (VALUES ${claims.map(() => '(?, ?, ?)').join(', ')}), counts(capability_id, claim_count) AS (VALUES ${Array.from(
              counts,
            )
              .map(() => '(?, ?)')
              .join(
                ', ',
              )}), conflict AS (SELECT 1 FROM nonces n JOIN claims c ON c.capability_id = n.capability_id AND c.nonce = n.nonce WHERE n.expires_at >= ? LIMIT 1), inactive AS (SELECT 1 FROM claims cl LEFT JOIN capabilities c ON c.id = cl.capability_id AND c.expires_at > ? AND c.revoked_at IS NULL WHERE c.id IS NULL LIMIT 1), rate_exceeded AS (SELECT 1 FROM counts cl LEFT JOIN rate_windows r ON r.capability_id = cl.capability_id AND r.minute = ? WHERE COALESCE(r.count, 0) + cl.claim_count > ? LIMIT 1) INSERT INTO nonces(capability_id, nonce, expires_at) SELECT capability_id, nonce, expires_at FROM claims WHERE NOT EXISTS (SELECT 1 FROM conflict) AND NOT EXISTS (SELECT 1 FROM inactive) AND NOT EXISTS (SELECT 1 FROM rate_exceeded) ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?`,
          )
          .bind(
            ...claims.flatMap(({ capabilityId, nonce, expiresAt }) => [
              capabilityId,
              nonce,
              expiresAt,
            ]),
            ...Array.from(counts)
              .map(([capabilityId, count]) => [capabilityId, count])
              .flat(),
            completion.now,
            completion.now,
            Math.floor(completion.now / 60),
            authorization.maximumRequestsPerMinute,
            completion.now,
          ),
      );
      let expectedChanges = claims.length;
      for (const [capabilityId, count] of counts) {
        statements.push(
          this.database
            .prepare(
              'INSERT INTO rate_windows(capability_id, minute, count) SELECT ?, ?, ? WHERE changes() = ? ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + excluded.count WHERE count + excluded.count <= ?',
            )
            .bind(
              capabilityId,
              Math.floor(completion.now / 60),
              count,
              expectedChanges,
              authorization.maximumRequestsPerMinute,
            ),
        );
        expectedChanges = 1;
      }
      marker = `v2-completion-admission:${Array.from(
        completion.operationId,
        (byte) => byte.toString(16).padStart(2, '0'),
      ).join('')}`;
      statements.push(
        this.database
          .prepare(
            'INSERT OR IGNORE INTO maintenance_leases(name, expires_at) SELECT ?, ? WHERE changes() = 1',
          )
          .bind(marker, completion.now),
      );
    }
    eventIndex = statements.length;
    statements.push(
      this.database
        .prepare(
          `INSERT INTO control_events(id, relationship_id, direction, slot, epoch, encrypted_envelope, operation_id, operation_digest, sequence, created_at, expires_at) SELECT ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT MAX(sequence) + 1 FROM control_events WHERE relationship_id = ? AND direction = ?), 1), ?, ? WHERE ${marker ? 'changes() = 1 AND ' : ''}NOT EXISTS (SELECT 1 FROM control_events WHERE operation_id = ?)${authorization?.controlQuota ? ' AND (SELECT COUNT(*) FROM control_events WHERE relationship_id = ? AND direction = ? AND expires_at > ?) < ? AND (SELECT COALESCE(SUM(length(encrypted_envelope)), 0) FROM control_events WHERE relationship_id = ? AND direction = ? AND expires_at > ?) + ? <= ?' : ''} AND (EXISTS (SELECT 1 FROM deliveries WHERE id = ? AND state = 'published') OR EXISTS (SELECT 1 FROM deliveries WHERE id = ? AND state = 'completed' AND completion_operation_id = ? AND completion_operation_digest = ? AND completion_digest = ? AND completion_result = ?))`,
        )
        .bind(
          event.id,
          event.relationshipId,
          directionNumber(event.direction),
          event.slot,
          event.epoch,
          event.encryptedEnvelope,
          event.operationId,
          event.operationDigest,
          event.relationshipId,
          directionNumber(event.direction),
          event.createdAt,
          event.expiresAt,
          event.operationId,
          ...(authorization?.controlQuota
            ? [
                event.relationshipId,
                directionNumber(event.direction),
                event.createdAt,
                authorization.controlQuota.maximumEvents,
                event.relationshipId,
                directionNumber(event.direction),
                event.createdAt,
                event.encryptedEnvelope.byteLength,
                authorization.controlQuota.maximumBytes,
              ]
            : []),
          completion.id,
          completion.id,
          completion.operationId,
          completion.operationDigest,
          completion.completionDigest,
          completion.result,
        ),
    );
    statements.push(
      this.database
        .prepare(
          `UPDATE deliveries SET state = 'completed', completed_at = ?, completion_operation_id = ?, completion_operation_digest = ?, completion_digest = ?, completion_result = ? WHERE id = ? AND state = 'published' AND ${marker ? 'changes() = 1 AND ' : ''}NOT EXISTS (SELECT 1 FROM control_events WHERE operation_id = ? AND operation_digest <> ?)`,
        )
        .bind(
          completion.now,
          completion.operationId,
          completion.operationDigest,
          completion.completionDigest,
          completion.result,
          completion.id,
          event.operationId,
          event.operationDigest,
        ),
    );
    if (marker) {
      statements.push(
        this.database
          .prepare(
            "INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-completion-admission-assertion', NULL WHERE EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?) AND changes() != 1 AND NOT (EXISTS (SELECT 1 FROM deliveries WHERE id = ? AND state = 'completed' AND completion_operation_id = ? AND completion_operation_digest = ? AND completion_digest = ? AND completion_result = ?) AND EXISTS (SELECT 1 FROM control_events WHERE operation_id = ? AND operation_digest = ?))",
          )
          .bind(
            marker,
            completion.id,
            completion.operationId,
            completion.operationDigest,
            completion.completionDigest,
            completion.result,
            event.operationId,
            event.operationDigest,
          ),
        this.database
          .prepare('DELETE FROM maintenance_leases WHERE name = ?')
          .bind(marker),
      );
    }
    const results = await this.database.batch<D1RunResultLike>(statements);
    if (
      authorizationIndex !== undefined &&
      results[authorizationIndex]?.meta?.changes !==
        authorization?.claims.length
    ) {
      return { authorizationAccepted: false };
    }
    const [delivery, storedEvent] = await Promise.all([
      this.findDelivery(completion.id),
      this.findControlEventByOperation(event.operationId),
    ]);
    if (!delivery || !storedEvent) {
      throw new Error('Completion transaction is unavailable.');
    }
    this.requireMatchingCompletion(delivery, completion);
    this.requireMatchingOperation(
      storedEvent.operationDigest,
      event.operationDigest,
    );
    return {
      delivery,
      event: storedEvent,
      idempotent:
        results[eventIndex]?.meta?.changes !== 1 &&
        results[eventIndex + 1]?.meta?.changes !== 1,
      authorizationAccepted: true,
    };
  }

  async publishControlEvent(
    event: V2RepositoryControlEvent,
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
      controlQuota?: {
        maximumEvents: number;
        maximumBytes: number;
      };
    },
  ): Promise<
    | {
        event: V2RepositoryControlEvent;
        idempotent: boolean;
        authorizationAccepted: true;
      }
    | { authorizationAccepted: false }
  > {
    operationId(event.operationId);
    const statements: ReturnType<D1DatabaseLike['prepare']>[] = [];
    let authorizationIndex: number | undefined;
    let marker: string | undefined;
    if (authorization?.claims.length) {
      const claims = authorization.claims;
      const keys = new Set(
        claims.map(
          ({ capabilityId, nonce }) =>
            `${capabilityId}:${Array.from(nonce).join(',')}`,
        ),
      );
      if (keys.size !== claims.length) {
        return { authorizationAccepted: false };
      }
      const counts = new Map<string, number>();
      for (const claim of claims) {
        counts.set(
          claim.capabilityId,
          (counts.get(claim.capabilityId) ?? 0) + 1,
        );
      }
      authorizationIndex = 0;
      statements.push(
        this.database
          .prepare(
            `WITH claims(capability_id, nonce, expires_at) AS (VALUES ${claims.map(() => '(?, ?, ?)').join(', ')}), counts(capability_id, claim_count) AS (VALUES ${Array.from(
              counts,
            )
              .map(() => '(?, ?)')
              .join(
                ', ',
              )}), conflict AS (SELECT 1 FROM nonces n JOIN claims c ON c.capability_id = n.capability_id AND c.nonce = n.nonce WHERE n.expires_at >= ? LIMIT 1), inactive AS (SELECT 1 FROM claims cl LEFT JOIN capabilities c ON c.id = cl.capability_id AND c.expires_at > ? AND c.revoked_at IS NULL WHERE c.id IS NULL LIMIT 1), rate_exceeded AS (SELECT 1 FROM counts cl LEFT JOIN rate_windows r ON r.capability_id = cl.capability_id AND r.minute = ? WHERE COALESCE(r.count, 0) + cl.claim_count > ? LIMIT 1) INSERT INTO nonces(capability_id, nonce, expires_at) SELECT capability_id, nonce, expires_at FROM claims WHERE NOT EXISTS (SELECT 1 FROM conflict) AND NOT EXISTS (SELECT 1 FROM inactive) AND NOT EXISTS (SELECT 1 FROM rate_exceeded) ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?`,
          )
          .bind(
            ...claims.flatMap(({ capabilityId, nonce, expiresAt }) => [
              capabilityId,
              nonce,
              expiresAt,
            ]),
            ...Array.from(counts)
              .map(([capabilityId, count]) => [capabilityId, count])
              .flat(),
            event.createdAt,
            event.createdAt,
            Math.floor(event.createdAt / 60),
            authorization.maximumRequestsPerMinute,
            event.createdAt,
          ),
      );
      let expectedChanges = claims.length;
      for (const [capabilityId, count] of counts) {
        statements.push(
          this.database
            .prepare(
              'INSERT INTO rate_windows(capability_id, minute, count) SELECT ?, ?, ? WHERE changes() = ? ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + excluded.count WHERE count + excluded.count <= ?',
            )
            .bind(
              capabilityId,
              Math.floor(event.createdAt / 60),
              count,
              expectedChanges,
              authorization.maximumRequestsPerMinute,
            ),
        );
        expectedChanges = 1;
      }
      marker = `v2-control-admission:${Array.from(event.operationId, (byte) =>
        byte.toString(16).padStart(2, '0'),
      ).join('')}`;
      statements.push(
        this.database
          .prepare(
            'INSERT OR IGNORE INTO maintenance_leases(name, expires_at) SELECT ?, ? WHERE changes() = 1',
          )
          .bind(marker, event.createdAt),
      );
    }
    const eventIndex = statements.length;
    statements.push(
      this.database
        .prepare(
          `INSERT INTO control_events(id, relationship_id, direction, slot, epoch, encrypted_envelope, operation_id, operation_digest, sequence, created_at, expires_at) SELECT ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT MAX(sequence) + 1 FROM control_events WHERE relationship_id = ? AND direction = ?), 1), ?, ? WHERE ${marker ? 'changes() = 1 AND ' : ''}NOT EXISTS (SELECT 1 FROM control_events WHERE operation_id = ?)${authorization?.controlQuota ? ' AND (SELECT COUNT(*) FROM control_events WHERE relationship_id = ? AND direction = ? AND expires_at > ?) < ? AND (SELECT COALESCE(SUM(length(encrypted_envelope)), 0) FROM control_events WHERE relationship_id = ? AND direction = ? AND expires_at > ?) + ? <= ?' : ''}`,
        )
        .bind(
          event.id,
          event.relationshipId,
          directionNumber(event.direction),
          event.slot,
          event.epoch,
          event.encryptedEnvelope,
          event.operationId,
          event.operationDigest,
          event.relationshipId,
          directionNumber(event.direction),
          event.createdAt,
          event.expiresAt,
          event.operationId,
          ...(authorization?.controlQuota
            ? [
                event.relationshipId,
                directionNumber(event.direction),
                event.createdAt,
                authorization.controlQuota.maximumEvents,
                event.relationshipId,
                directionNumber(event.direction),
                event.createdAt,
                event.encryptedEnvelope.byteLength,
                authorization.controlQuota.maximumBytes,
              ]
            : []),
        ),
    );
    if (marker) {
      statements.push(
        this.database
          .prepare(
            "INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-control-admission-assertion', NULL WHERE EXISTS (SELECT 1 FROM maintenance_leases WHERE name = ?) AND changes() != 1 AND NOT EXISTS (SELECT 1 FROM control_events WHERE operation_id = ? AND operation_digest = ?)",
          )
          .bind(marker, event.operationId, event.operationDigest),
        this.database
          .prepare('DELETE FROM maintenance_leases WHERE name = ?')
          .bind(marker),
      );
    }
    const results = await this.database.batch<D1RunResultLike>(statements);
    if (
      authorizationIndex !== undefined &&
      results[authorizationIndex]?.meta?.changes !==
        authorization?.claims.length
    ) {
      return { authorizationAccepted: false };
    }
    const stored = await this.findControlEventByOperation(event.operationId);
    if (!stored) {
      throw new Error('Control event is unavailable.');
    }
    this.requireMatchingOperation(
      stored.operationDigest,
      event.operationDigest,
    );
    return {
      event: stored,
      idempotent: results[eventIndex]?.meta?.changes !== 1,
      authorizationAccepted: true,
    };
  }

  async consumeControlEvents(input: {
    ids: readonly string[];
    relationshipId: string;
    direction: V2RepositoryCapability['direction'];
    now: number;
  }): Promise<void> {
    if (input.ids.length === 0) {
      return;
    }
    const placeholders = input.ids.map(() => '?').join(', ');
    await this.database
      .prepare(
        `UPDATE control_events SET consumed_at = ? WHERE consumed_at IS NULL AND relationship_id = ? AND direction = ? AND id IN (${placeholders})`,
      )
      .bind(
        input.now,
        input.relationshipId,
        directionNumber(input.direction),
        ...input.ids,
      )
      .run();
  }

  async runMaintenance(
    now: number,
    limit: number,
  ): Promise<V2MaintenanceResult> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new Error('D1 maintenance limit is invalid.');
    }
    const [
      expiredDeliveries,
      expiredReservations,
      expiredControls,
      expiredStaging,
      expiredDeliveryParts,
      expiredChunkParts,
      expiredChunkUploads,
      expiredInvitations,
    ] = await Promise.all([
      this.selectRows(
        'SELECT id, payload_key, EXISTS (SELECT 1 FROM chunk_uploads u WHERE u.delivery_id = deliveries.id) AS chunked FROM deliveries WHERE expires_at <= ? AND NOT EXISTS (SELECT 1 FROM delivery_chunks p WHERE p.delivery_id = deliveries.id) ORDER BY expires_at, id LIMIT ?',
        now,
        limit,
      ),
      this.selectRows(
        'SELECT delivery_id, payload_key FROM reservations WHERE expires_at <= ? ORDER BY expires_at, delivery_id LIMIT ?',
        now,
        limit,
      ),
      this.selectRows(
        'SELECT id FROM control_events WHERE expires_at <= ? ORDER BY expires_at, id LIMIT ?',
        now,
        limit,
      ),
      this.selectRows(
        'SELECT id, body_key FROM staged_bodies WHERE expires_at <= ? ORDER BY expires_at, id LIMIT ?',
        now,
        limit,
      ),
      this.selectRows(
        'SELECT p.delivery_id, p.part_id, p.body_key FROM delivery_chunks p JOIN deliveries d ON d.id = p.delivery_id WHERE d.expires_at <= ? ORDER BY d.expires_at, p.delivery_id, p.ordinal LIMIT ?',
        now,
        limit,
      ),
      this.selectRows(
        'SELECT p.upload_id, p.part_id, p.body_key, u.committed_at FROM chunk_upload_parts p JOIN chunk_uploads u ON u.id = p.upload_id WHERE u.expires_at <= ? ORDER BY u.expires_at, p.upload_id, p.ordinal LIMIT ?',
        now,
        limit,
      ),
      this.selectRows(
        'SELECT id FROM chunk_uploads WHERE expires_at <= ? AND NOT EXISTS (SELECT 1 FROM chunk_upload_parts p WHERE p.upload_id = chunk_uploads.id) ORDER BY expires_at, id LIMIT ?',
        now,
        limit,
      ),
      this.selectRows(
        'SELECT id FROM invitations WHERE expires_at <= ? ORDER BY expires_at, id LIMIT ?',
        now,
        limit,
      ),
    ]);
    const statements = [
      ...expiredDeliveries.map((row) =>
        this.database
          .prepare(
            'UPDATE quota_accounts SET committed_bytes = MAX(0, committed_bytes - (SELECT payload_length FROM deliveries WHERE id = ?)), object_count = MAX(0, object_count - 1) WHERE relationship_id = (SELECT relationship_id FROM deliveries WHERE id = ?)',
          )
          .bind(row.id, row.id),
      ),
      ...expiredDeliveries.map((row) =>
        this.database
          .prepare('DELETE FROM deliveries WHERE id = ?')
          .bind(row.id),
      ),
      ...expiredReservations.map((row) =>
        this.database
          .prepare(
            'UPDATE quota_accounts SET reserved_bytes = MAX(0, reserved_bytes - (SELECT reserved_bytes FROM reservations WHERE delivery_id = ?)), object_count = MAX(0, object_count - 1) WHERE relationship_id = (SELECT c.relationship_id FROM reservations r JOIN capabilities c ON c.id = r.capability_id WHERE r.delivery_id = ?)',
          )
          .bind(row.delivery_id, row.delivery_id),
      ),
      ...expiredReservations.map((row) =>
        this.database
          .prepare('DELETE FROM reservations WHERE delivery_id = ?')
          .bind(row.delivery_id),
      ),
      ...expiredControls.map((row) =>
        this.database
          .prepare('DELETE FROM control_events WHERE id = ?')
          .bind(row.id),
      ),
      ...expiredStaging.map((row) =>
        this.database
          .prepare('DELETE FROM staged_bodies WHERE id = ?')
          .bind(row.id),
      ),
      ...expiredDeliveryParts.map((row) =>
        this.database
          .prepare(
            'DELETE FROM delivery_chunks WHERE delivery_id = ? AND part_id = ?',
          )
          .bind(row.delivery_id, row.part_id),
      ),
      ...expiredChunkParts.map((row) =>
        this.database
          .prepare(
            'DELETE FROM chunk_upload_parts WHERE upload_id = ? AND part_id = ?',
          )
          .bind(row.upload_id, row.part_id),
      ),
      ...expiredChunkUploads.map((row) =>
        this.database
          .prepare('DELETE FROM chunk_uploads WHERE id = ?')
          .bind(row.id),
      ),
      ...expiredInvitations.map((row) =>
        this.database
          .prepare('DELETE FROM invitations WHERE id = ?')
          .bind(row.id),
      ),
      this.database
        .prepare(
          'DELETE FROM nonces WHERE rowid IN (SELECT rowid FROM nonces WHERE expires_at < ? ORDER BY expires_at LIMIT ?)',
        )
        .bind(now, limit),
      this.database
        .prepare(
          'DELETE FROM rate_windows WHERE rowid IN (SELECT rowid FROM rate_windows WHERE minute < ? ORDER BY minute LIMIT ?)',
        )
        .bind(Math.floor(now / 60), limit),
      this.database
        .prepare(
          'DELETE FROM relationship_nonces WHERE rowid IN (SELECT rowid FROM relationship_nonces WHERE expires_at < ? ORDER BY expires_at LIMIT ?)',
        )
        .bind(now, limit),
      this.database
        .prepare(
          'DELETE FROM relationship_rate_windows WHERE rowid IN (SELECT rowid FROM relationship_rate_windows WHERE minute < ? ORDER BY minute LIMIT ?)',
        )
        .bind(Math.floor(now / 60), limit),
      this.database
        .prepare(
          'DELETE FROM pairing_rate_windows WHERE rowid IN (SELECT rowid FROM pairing_rate_windows WHERE minute < ? ORDER BY minute LIMIT ?)',
        )
        .bind(Math.floor(now / 60), limit),
    ];
    const results = await this.database.batch<D1RunResultLike>(statements);
    const nonceIndex = statements.length - 5;
    const changes = (offset: number): number =>
      results[nonceIndex + offset]?.meta?.changes ?? 0;
    const deletedNonces = changes(0) + changes(2);
    const deletedRateWindows = changes(1) + changes(3) + changes(4);
    return {
      expiredDeliveryIds: expiredDeliveries.map((row) => String(row.id)),
      expiredBodyKeys: Array.from(
        new Set([
          ...expiredDeliveries.flatMap((row) =>
            Number(row.chunked) === 1 ? [] : [String(row.payload_key)],
          ),
          ...expiredReservations.map((row) => String(row.payload_key)),
          ...expiredStaging.map((row) => String(row.body_key)),
          ...expiredDeliveryParts.map((row) => String(row.body_key)),
          ...expiredChunkParts.flatMap((row) =>
            row.body_key === null || row.body_key === undefined
              ? row.committed_at === null || row.committed_at === undefined
                ? [v2StagedChunkKey(String(row.upload_id), String(row.part_id))]
                : []
              : [String(row.body_key)],
          ),
        ]),
      ),
      deletedNonces,
      deletedControlEvents: expiredControls.length,
      deletedRateWindows,
      deletedInvitations: expiredInvitations.length,
      complete:
        expiredDeliveries.length < limit &&
        expiredReservations.length < limit &&
        expiredControls.length < limit &&
        expiredStaging.length < limit &&
        expiredDeliveryParts.length < limit &&
        expiredChunkParts.length < limit &&
        expiredChunkUploads.length < limit &&
        expiredInvitations.length < limit &&
        changes(0) < limit &&
        changes(1) < limit &&
        changes(2) < limit &&
        changes(3) < limit &&
        changes(4) < limit,
    };
  }

  /**
   * Reconciliation-only bounded lookups for the administrator command. No
   * delivery, inbox, control, or pairing request path calls these, and neither
   * ever lists the R2 bucket.
   */
  async filterKnownBodyKeys(keys: readonly string[]): Promise<string[]> {
    if (keys.length === 0) {
      return [];
    }
    if (keys.length > 1_000) {
      throw new Error('D1 body key lookup batch is too large.');
    }
    const placeholders = keys.map(() => '?').join(', ');
    const rows = await this.selectRows(
      `SELECT payload_key AS key FROM deliveries WHERE payload_key IN (${placeholders})
       UNION SELECT payload_key AS key FROM reservations WHERE payload_key IN (${placeholders})
       UNION SELECT body_key AS key FROM staged_bodies WHERE body_key IN (${placeholders})
       UNION SELECT body_key AS key FROM chunk_upload_parts WHERE body_key IN (${placeholders})
       UNION SELECT 'staging/uploads/' || part.upload_id || '/' || part.part_id || '.age' AS key
         FROM chunk_upload_parts AS part
         JOIN chunk_uploads AS upload ON upload.id = part.upload_id
         WHERE part.body_key IS NULL AND upload.committed_at IS NULL
           AND 'staging/uploads/' || part.upload_id || '/' || part.part_id || '.age' IN (${placeholders})
       UNION SELECT body_key AS key FROM delivery_chunks WHERE body_key IN (${placeholders})`,
      ...keys,
      ...keys,
      ...keys,
      ...keys,
      ...keys,
      ...keys,
    );
    const known = new Set(rows.map((row) => String(row.key)));
    return keys.filter((key) => known.has(key));
  }

  async listBodyKeys(input: {
    cursor?: string;
    limit: number;
  }): Promise<{ keys: string[]; cursor?: string }> {
    if (
      !Number.isSafeInteger(input.limit) ||
      input.limit < 1 ||
      input.limit > 1_000
    ) {
      throw new Error('D1 body key page limit is invalid.');
    }
    const cursor = input.cursor ?? '';
    const rows = await this.selectRows(
      `SELECT key FROM (
         SELECT payload_key AS key FROM deliveries WHERE payload_key > ?
         UNION SELECT payload_key AS key FROM reservations WHERE payload_key > ?
         UNION SELECT body_key AS key FROM staged_bodies WHERE body_key > ?
         UNION SELECT body_key AS key FROM chunk_upload_parts WHERE body_key > ?
         UNION SELECT 'staging/uploads/' || part.upload_id || '/' || part.part_id || '.age' AS key
           FROM chunk_upload_parts AS part
           JOIN chunk_uploads AS upload ON upload.id = part.upload_id
           WHERE part.body_key IS NULL AND part.write_token IS NOT NULL AND upload.committed_at IS NULL
             AND 'staging/uploads/' || part.upload_id || '/' || part.part_id || '.age' > ?
         UNION SELECT body_key AS key FROM delivery_chunks WHERE body_key > ?
       ) ORDER BY key LIMIT ?`,
      cursor,
      cursor,
      cursor,
      cursor,
      cursor,
      cursor,
      input.limit,
    );
    const keys = rows.map((row) => String(row.key));
    return {
      keys,
      ...(keys.length === input.limit ? { cursor: keys[keys.length - 1] } : {}),
    };
  }

  async revokeRelationship(input: {
    relationshipId: string;
    direction?: V2RepositoryCapability['direction'];
    scope?: V2RepositoryCapability['scope'];
    now: number;
  }): Promise<void> {
    const conditions = ['relationship_id = ?'];
    const values: unknown[] = [input.relationshipId];
    if (input.direction) {
      conditions.push('direction = ?');
      values.push(directionNumber(input.direction));
    }
    if (input.scope) {
      conditions.push('scope = ?');
      values.push(input.scope);
    }
    const statements = [
      this.database
        .prepare(
          `UPDATE capabilities SET revoked_at = ? WHERE ${conditions.join(' AND ')} AND revoked_at IS NULL`,
        )
        .bind(input.now, ...values),
      this.database
        .prepare(
          'INSERT INTO revocations(id, relationship_id, direction, scope, created_at, expires_at, encrypted_envelope) VALUES (?, ?, ?, ?, ?, ?, ?)',
        )
        .bind(
          crypto.randomUUID().replaceAll('-', ''),
          input.relationshipId,
          input.direction ? directionNumber(input.direction) : null,
          input.scope ?? null,
          input.now,
          2_147_483_647,
          new Uint8Array(),
        ),
    ];
    if (!input.direction && !input.scope) {
      statements.push(
        this.database
          .prepare(
            "UPDATE relationships SET state = 'revoked', revoked_at = ?, updated_at = ? WHERE id = ?",
          )
          .bind(input.now, input.now, input.relationshipId),
      );
    }
    await this.database.batch(statements);
  }

  async rotateCapability(input: {
    relationshipId: string;
    direction: V2RepositoryCapability['direction'];
    scope: V2RepositoryCapability['scope'];
    now: number;
  }): Promise<boolean> {
    const result = await this.database
      .prepare(
        'UPDATE capabilities SET revoked_at = ? WHERE relationship_id = ? AND direction = ? AND scope = ? AND revoked_at IS NULL',
      )
      .bind(
        input.now,
        input.relationshipId,
        directionNumber(input.direction),
        input.scope,
      )
      .run<D1RunResultLike>();
    return (result.meta?.changes ?? 0) > 0;
  }

  async relationshipStatus(relationshipId: string): Promise<{
    fullyRevoked: boolean;
    tuples: Array<{
      direction: V2RepositoryCapability['direction'];
      scope: V2RepositoryCapability['scope'];
      revoked: boolean;
      rotatedAt: number;
    }>;
  }> {
    const [capabilities, revocations] = await Promise.all([
      this.database
        .prepare(
          'SELECT direction, scope, revoked_at, created_at FROM capabilities WHERE relationship_id = ? ORDER BY direction, scope, created_at DESC',
        )
        .bind(relationshipId)
        .all(),
      this.database
        .prepare(
          'SELECT direction, scope, created_at FROM revocations WHERE relationship_id = ? ORDER BY created_at DESC',
        )
        .bind(relationshipId)
        .all(),
    ]);
    const revocationRows = rows(revocations);
    const fullyRevoked = revocationRows.some(
      (row) => row.direction === null && row.scope === null,
    );
    const tuples = new Map<
      string,
      {
        direction: V2RepositoryCapability['direction'];
        scope: V2RepositoryCapability['scope'];
        revoked: boolean;
        rotatedAt: number;
      }
    >();
    const revokedByRecord = (
      direction: V2RepositoryCapability['direction'],
      scope: V2RepositoryCapability['scope'],
    ): number | undefined => {
      const records = revocationRows.filter(
        (row) =>
          (row.direction === null ||
            directionFromRow(row.direction) === direction) &&
          (row.scope === null || row.scope === scope),
      );
      return records.length === 0
        ? undefined
        : Math.max(...records.map((row) => Number(row.created_at)));
    };
    for (const row of rows(capabilities)) {
      const direction = directionFromRow(row.direction);
      const scope = row.scope as V2RepositoryCapability['scope'];
      const key = `${direction}|${scope}`;
      const revokedAt = optionalNumber(row.revoked_at);
      const recordedRevocation = revokedByRecord(direction, scope);
      const existing = tuples.get(key);
      const rotatedAt = Math.max(
        Number(row.created_at),
        revokedAt ?? 0,
        recordedRevocation ?? 0,
        existing?.rotatedAt ?? 0,
      );
      tuples.set(key, {
        direction,
        scope,
        revoked:
          fullyRevoked ||
          revokedAt !== undefined ||
          recordedRevocation !== undefined ||
          existing?.revoked === true,
        rotatedAt,
      });
    }
    for (const row of revocationRows) {
      if (row.direction === null || row.scope === null) {
        continue;
      }
      const direction = directionFromRow(row.direction);
      const scope = row.scope as V2RepositoryCapability['scope'];
      const key = `${direction}|${scope}`;
      const existing = tuples.get(key);
      tuples.set(key, {
        direction,
        scope,
        revoked: true,
        rotatedAt: Math.max(existing?.rotatedAt ?? 0, Number(row.created_at)),
      });
    }
    return {
      fullyRevoked,
      tuples: Array.from(tuples.values()).sort((a, b) =>
        `${a.direction}|${a.scope}`.localeCompare(`${b.direction}|${b.scope}`),
      ),
    };
  }

  private insertCapability(
    capability: V2RepositoryCapability,
    ignore: boolean,
  ) {
    return this.database
      .prepare(
        `${ignore ? 'INSERT OR IGNORE' : 'INSERT'} INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        capability.id,
        capability.relationshipId,
        directionNumber(capability.direction),
        capability.scope,
        capability.encryptedTokenSecret,
        capability.createdAt,
        capability.expiresAt,
        capability.revokedAt ?? null,
      );
  }

  private async findDeliveryByOperation(
    id: Uint8Array,
  ): Promise<V2RepositoryDelivery | null> {
    const row = await this.database
      .prepare('SELECT * FROM deliveries WHERE operation_id = ?')
      .bind(id)
      .first<Row>();
    return row ? this.deliveryWithParts(row) : null;
  }

  private async findControlEventByOperation(
    id: Uint8Array,
  ): Promise<V2RepositoryControlEvent | null> {
    const row = await this.database
      .prepare('SELECT * FROM control_events WHERE operation_id = ?')
      .bind(id)
      .first<Row>();
    return row ? controlEventFromRow(row) : null;
  }

  private async queryDelivery(
    relationshipId: string,
    direction: V2RepositoryCapability['direction'],
    slots: readonly { slot: Uint8Array; epoch: number }[],
    now: number,
  ): Promise<V2RepositoryDelivery | null> {
    if (slots.length === 0) {
      return null;
    }
    const { clause, values } = slotClause(slots);
    const row = await this.database
      .prepare(
        `SELECT * FROM deliveries WHERE relationship_id = ? AND direction = ? AND state = 'published' AND expires_at > ? AND (${clause}) ORDER BY sequence, created_at, id LIMIT 1`,
      )
      .bind(relationshipId, directionNumber(direction), now, ...values)
      .first<Row>();
    return row ? this.deliveryWithParts(row) : null;
  }

  private async queryControlEvents(
    relationshipId: string,
    direction: V2RepositoryCapability['direction'],
    slots: readonly { slot: Uint8Array; epoch: number }[],
    now: number,
    maximumEvents = Number.MAX_SAFE_INTEGER,
    maximumBytes = Number.MAX_SAFE_INTEGER,
  ): Promise<V2RepositoryControlEvent[]> {
    if (slots.length === 0) {
      return [];
    }
    const { clause, values } = slotClause(slots);
    const result = await this.database
      .prepare(
        `SELECT * FROM control_events WHERE relationship_id = ? AND direction = ? AND consumed_at IS NULL AND expires_at > ? AND (${clause}) ORDER BY sequence, id LIMIT ?`,
      )
      .bind(
        relationshipId,
        directionNumber(direction),
        now,
        ...values,
        maximumEvents,
      )
      .all();
    const events: V2RepositoryControlEvent[] = [];
    let bytes = 0;
    for (const row of rows(result)) {
      const event = controlEventFromRow(row);
      if (bytes + event.encryptedEnvelope.byteLength > maximumBytes) {
        break;
      }
      events.push(event);
      bytes += event.encryptedEnvelope.byteLength;
    }
    return events;
  }

  private async queryPendingEpochs(
    relationshipId: string,
    direction: V2RepositoryCapability['direction'],
    slots: readonly { slot: Uint8Array; epoch: number }[],
    now: number,
  ): Promise<Set<number>> {
    if (slots.length === 0) {
      return new Set();
    }
    const { clause, values } = slotClause(slots);
    const result = await this.database
      .prepare(
        `SELECT DISTINCT epoch FROM deliveries WHERE relationship_id = ? AND direction = ? AND state = 'published' AND expires_at > ? AND (${clause})`,
      )
      .bind(relationshipId, directionNumber(direction), now, ...values)
      .all();
    return new Set(rows(result).map((row) => Number(row.epoch)));
  }

  private async selectRows(
    query: string,
    ...values: unknown[]
  ): Promise<Row[]> {
    return rows(
      await this.database
        .prepare(query)
        .bind(...values)
        .all(),
    );
  }

  /**
   * True when any of these proof nonces is already claimed and unexpired.
   * Only the rolled-back failure path reads this, to tell a replay apart from
   * a quota or rate rejection.
   */
  private async hasLiveNonce(
    claims: readonly { capabilityId: string; nonce: Uint8Array }[],
    now: number,
  ): Promise<boolean> {
    const placeholders = claims
      .map(() => '(capability_id = ? AND nonce = ?)')
      .join(' OR ');
    const row = await this.database
      .prepare(
        `SELECT 1 AS found FROM nonces WHERE expires_at >= ? AND (${placeholders}) LIMIT 1`,
      )
      .bind(
        now,
        ...claims.flatMap(({ capabilityId, nonce }) => [capabilityId, nonce]),
      )
      .first<Row>();
    return row !== null && row !== undefined;
  }

  private validateChunkOperation(
    operationIdValue: Uint8Array,
    operationDigest: Uint8Array,
  ): void {
    if (
      operationIdValue.byteLength !== 16 ||
      operationDigest.byteLength !== 32
    ) {
      throw new Error('Chunk upload operation is invalid.');
    }
  }

  private chunkAuthorizationStatements(
    capabilityId: string,
    authorization: V2RepositoryAuthorization,
    now: number,
  ): {
    gate: string;
    statements: ReturnType<D1DatabaseLike['prepare']>[];
  } {
    if (
      authorization.claims.length !== 1 ||
      authorization.claims[0]!.capabilityId !== capabilityId ||
      !Number.isSafeInteger(authorization.maximumRequestsPerMinute) ||
      authorization.maximumRequestsPerMinute < 1
    ) {
      throw new Error('Chunk upload authorization is invalid.');
    }
    const claim = authorization.claims[0]!;
    const minute = Math.floor(now / 60);
    const gate = `v2-chunk-gate-${crypto.randomUUID()}`;
    return {
      gate,
      statements: [
        this.database
          .prepare(
            "INSERT INTO maintenance_leases(name, expires_at) SELECT 'v2-chunk-nonce-assertion', NULL WHERE EXISTS (SELECT 1 FROM nonces WHERE capability_id = ? AND nonce = ? AND expires_at >= ?)",
          )
          .bind(claim.capabilityId, claim.nonce, now),
        this.database
          .prepare(
            `INSERT INTO nonces(capability_id, nonce, expires_at)
             SELECT ?, ?, ?
             WHERE EXISTS (SELECT 1 FROM capabilities WHERE id = ? AND scope = 'write' AND expires_at > ? AND revoked_at IS NULL)
               AND NOT EXISTS (SELECT 1 FROM nonces WHERE capability_id = ? AND nonce = ? AND expires_at >= ?)
               AND COALESCE((SELECT count FROM rate_windows WHERE capability_id = ? AND minute = ?), 0) < ?
             ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?`,
          )
          .bind(
            claim.capabilityId,
            claim.nonce,
            claim.expiresAt,
            claim.capabilityId,
            now,
            claim.capabilityId,
            claim.nonce,
            now,
            claim.capabilityId,
            minute,
            authorization.maximumRequestsPerMinute,
            now,
          ),
        this.database
          .prepare(
            'INSERT INTO rate_windows(capability_id, minute, count) SELECT ?, ?, 1 WHERE changes() = 1 ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + 1 WHERE count < ?',
          )
          .bind(
            claim.capabilityId,
            minute,
            authorization.maximumRequestsPerMinute,
          ),
        this.database
          .prepare(
            'INSERT INTO maintenance_leases(name, expires_at) SELECT ?, ? WHERE changes() = 1',
          )
          .bind(gate, now),
      ],
    };
  }

  private async findChunkUploadByOperation(
    operationIdValue: Uint8Array,
  ): Promise<V2ChunkUpload | null> {
    const row = await this.database
      .prepare('SELECT id FROM chunk_uploads WHERE operation_id = ?')
      .bind(operationIdValue)
      .first<Row>();
    return row ? this.requireChunkUpload(String(row.id)) : null;
  }

  private async requireChunkUpload(id: string): Promise<V2ChunkUpload> {
    const row = await this.database
      .prepare(
        'SELECT id, delivery_id, capability_id, chain, slot, epoch, total_length, created_at, expires_at, operation_id, operation_digest, committed_at FROM chunk_uploads WHERE id = ?',
      )
      .bind(id)
      .first<Row>();
    if (!row) {
      throw new Error('Chunk upload is unavailable.');
    }
    const parts = await this.selectRows(
      'SELECT part_id, ordinal, length, digest, body_key, received_at, operation_id, operation_digest FROM chunk_upload_parts WHERE upload_id = ? ORDER BY ordinal',
      id,
    );
    return {
      id: String(row.id),
      deliveryId: String(row.delivery_id),
      capabilityId: String(row.capability_id),
      chain: Number(row.chain),
      slot: d1Bytes(row.slot),
      epoch: Number(row.epoch),
      totalLength: Number(row.total_length),
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
      operationId: d1Bytes(row.operation_id),
      operationDigest: d1Bytes(row.operation_digest),
      ...(optionalNumber(row.committed_at) === undefined
        ? {}
        : { committedAt: optionalNumber(row.committed_at) }),
      parts: parts.map((part) => ({
        id: String(part.part_id),
        ordinal: Number(part.ordinal),
        length: Number(part.length),
        digest: d1Bytes(part.digest),
        ...(part.body_key === null || part.body_key === undefined
          ? {}
          : { bodyKey: String(part.body_key) }),
        ...(optionalNumber(part.received_at) === undefined
          ? {}
          : { receivedAt: optionalNumber(part.received_at) }),
        ...(part.operation_id === null || part.operation_id === undefined
          ? {}
          : {
              operationId: d1Bytes(part.operation_id),
              operationDigest: d1Bytes(part.operation_digest),
            }),
      })),
    };
  }

  private requireMatchingOperation(
    actual: Uint8Array,
    expected: Uint8Array,
  ): void {
    if (!bytesEqual(actual, expected)) {
      throw new V2OperationConflictError(
        'Operation ID conflicts with different bytes.',
      );
    }
  }

  private requireMatchingCompletion(
    delivery: V2RepositoryDelivery,
    input: {
      operationId: Uint8Array;
      operationDigest: Uint8Array;
      completionDigest: Uint8Array;
      result: 0 | 1;
    },
  ): void {
    if (
      delivery.state !== 'completed' ||
      delivery.completionResult !== input.result ||
      !delivery.completionOperationId ||
      !delivery.completionOperationDigest ||
      !delivery.completionDigest
    ) {
      throw new V2OperationConflictError(
        'Delivery completion conflicts with prior result.',
      );
    }
    this.requireMatchingOperation(
      delivery.completionOperationId,
      input.operationId,
    );
    this.requireMatchingOperation(
      delivery.completionOperationDigest,
      input.operationDigest,
    );
    this.requireMatchingOperation(
      delivery.completionDigest,
      input.completionDigest,
    );
  }
}

function slotClause(slots: readonly { slot: Uint8Array; epoch: number }[]): {
  clause: string;
  values: unknown[];
} {
  return {
    clause: slots.map(() => '(slot = ? AND epoch = ?)').join(' OR '),
    values: slots.flatMap(({ slot, epoch }) => [slot, epoch]),
  };
}

function capabilityFromRow(row: Row): V2RepositoryCapability {
  return {
    id: String(row.id),
    relationshipId: String(row.relationship_id),
    direction: directionFromRow(row.direction),
    scope: row.scope as V2RepositoryCapability['scope'],
    encryptedTokenSecret: String(row.encrypted_token_secret),
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    ...(optionalNumber(row.revoked_at) === undefined
      ? {}
      : { revokedAt: optionalNumber(row.revoked_at) }),
  };
}

function deliveryFromRow(row: Row): V2RepositoryDelivery {
  return {
    id: String(row.id),
    relationshipId: String(row.relationship_id),
    direction: directionFromRow(row.direction),
    slot: d1Bytes(row.slot),
    epoch: Number(row.epoch),
    ...(row.authorization_chain === null ||
    row.authorization_chain === undefined
      ? {}
      : { chain: Number(row.authorization_chain) }),
    encryptedDescriptor: d1Bytes(row.encrypted_descriptor),
    requestedPolicy: d1Bytes(row.requested_policy),
    effectivePolicy: d1Bytes(row.effective_policy),
    policyDigest: d1Bytes(row.policy_digest),
    payloadKey: String(row.payload_key),
    payloadLength: Number(row.payload_length),
    payloadDigest: d1Bytes(row.payload_digest),
    operationId: d1Bytes(row.operation_id),
    operationDigest: d1Bytes(row.operation_digest),
    state: row.state as V2RepositoryDelivery['state'],
    sequence: Number(row.sequence),
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    ...(optionalNumber(row.completed_at) === undefined
      ? {}
      : { completedAt: optionalNumber(row.completed_at) }),
    ...(row.completion_operation_id === null ||
    row.completion_operation_id === undefined
      ? {}
      : { completionOperationId: d1Bytes(row.completion_operation_id) }),
    ...(row.completion_operation_digest === null ||
    row.completion_operation_digest === undefined
      ? {}
      : {
          completionOperationDigest: d1Bytes(row.completion_operation_digest),
        }),
    ...(row.completion_digest === null || row.completion_digest === undefined
      ? {}
      : { completionDigest: d1Bytes(row.completion_digest) }),
    ...(optionalNumber(row.completion_result) === undefined
      ? {}
      : { completionResult: Number(row.completion_result) as 0 | 1 }),
  };
}

function controlEventFromRow(row: Row): V2RepositoryControlEvent {
  return {
    id: String(row.id),
    relationshipId: String(row.relationship_id),
    direction: directionFromRow(row.direction),
    slot: d1Bytes(row.slot),
    epoch: Number(row.epoch),
    encryptedEnvelope: d1Bytes(row.encrypted_envelope),
    operationId: d1Bytes(row.operation_id),
    operationDigest: d1Bytes(row.operation_digest),
    sequence: Number(row.sequence),
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    ...(optionalNumber(row.consumed_at) === undefined
      ? {}
      : { consumedAt: optionalNumber(row.consumed_at) }),
  };
}
