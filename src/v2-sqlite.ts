// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { mkdir, open } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';

import { bytesEqual } from './cbor.js';
import {
  applyV2SQLiteMigrations,
  type V2SQLiteDatabase,
} from './v2-sqlite-schema.js';
import { V2OperationConflictError } from './v2-repository.js';
import type {
  V2CapabilityRegistration,
  V2CapabilityReissueInput,
  V2CapabilityReissueOutcome,
  V2DeliveryReservation,
  V2MaintenanceResult,
  V2RepositoryCapability,
  V2RepositoryControlEvent,
  V2RepositoryDelivery,
} from './v2-repository.js';
import type {
  D1PairingRecord,
  V2PairingCommit,
} from './v2-d1-pairing-repository.js';

function randomRecordId(): string {
  return crypto.randomUUID().replaceAll('-', '');
}

/** Isolated Node metadata database; it never opens `v2/state.json`. */
export class SQLiteV2Database {
  private database: DatabaseSync | undefined;
  private readonly path: string;

  constructor(rootDir: string) {
    this.path = join(rootDir, 'v2', 'v2.sqlite');
  }

  async initialize(now = Math.floor(Date.now() / 1000)): Promise<void> {
    if (this.database) {
      return;
    }
    await mkdir(join(this.path, '..'), { recursive: true, mode: 0o700 });
    const database = new DatabaseSync(this.path);
    const databaseFile = await open(this.path, 'r');
    try {
      await databaseFile.chmod(0o600);
    } finally {
      await databaseFile.close();
    }
    database.exec(
      'PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;',
    );
    applyV2SQLiteMigrations(database as V2SQLiteDatabase, now);
    this.database = database;
  }

  close(): void {
    this.database?.close();
    this.database = undefined;
  }

  /**
   * Reports the durability settings this connection actually runs with, so
   * deployments and tests can verify them instead of trusting initialization.
   */
  describeDurability(): {
    journalMode: string;
    synchronous: number;
    foreignKeys: number;
    busyTimeout: number;
    appliedMigrations: number[];
  } {
    const database = this.requireDatabase();
    const value = (pragma: string): unknown =>
      Object.values(
        (database.prepare(`PRAGMA ${pragma}`).get() ?? {}) as Record<
          string,
          unknown
        >,
      )[0];
    return {
      journalMode: String(value('journal_mode')),
      synchronous: Number(value('synchronous')),
      foreignKeys: Number(value('foreign_keys')),
      busyTimeout: Number(value('busy_timeout')),
      appliedMigrations: (
        database
          .prepare('SELECT version FROM schema_migrations ORDER BY version')
          .all() as Record<string, unknown>[]
      ).map((row) => Number(row.version)),
    };
  }

  putCapabilityLookup(
    capability: V2RepositoryCapability,
    lookupId: Uint8Array,
    epoch: number,
  ): void {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      database
        .prepare(
          'INSERT OR IGNORE INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        )
        .run(
          capability.id,
          capability.relationshipId,
          capability.direction === 'inviter->invitee' ? 0 : 1,
          capability.scope,
          capability.encryptedTokenSecret,
          capability.createdAt,
          capability.expiresAt,
          capability.revokedAt ?? null,
        );
      database
        .prepare(
          'INSERT INTO capability_lookups(lookup_id, epoch, capability_id) VALUES (?, ?, ?)',
        )
        .run(lookupId, epoch, capability.id);
      database.exec('COMMIT');
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  replaceCapabilities(input: {
    revocations: readonly Pick<
      V2RepositoryCapability,
      'relationshipId' | 'direction' | 'scope'
    >[];
    registrations: readonly V2CapabilityRegistration[];
    now: number;
  }): void {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      this.applyCapabilityReplacement(input);
      database.exec('COMMIT');
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  /** Revokes and republishes tuples inside the caller's open transaction. */
  private applyCapabilityReplacement(input: {
    revocations: readonly Pick<
      V2RepositoryCapability,
      'relationshipId' | 'direction' | 'scope'
    >[];
    registrations: readonly V2CapabilityRegistration[];
    now: number;
  }): void {
    const database = this.requireDatabase();
    for (const revoked of input.revocations) {
      database
        .prepare(
          'UPDATE capabilities SET revoked_at = ? WHERE relationship_id = ? AND direction = ? AND scope = ? AND revoked_at IS NULL',
        )
        .run(
          input.now,
          revoked.relationshipId,
          revoked.direction === 'inviter->invitee' ? 0 : 1,
          revoked.scope,
        );
    }
    // One capability spans every daily lookup it publishes, so its row is
    // inserted once while each epoch gets its own lookup.
    const published = new Set<string>();
    for (const registration of input.registrations) {
      const { capability, lookupId, epoch } = registration;
      // A durable revocation always wins, so an administrative revoke cannot
      // be raced by a reissue that resurrects the revoked tuple.
      if (
        this.isTupleRevoked(
          capability.relationshipId,
          capability.direction,
          capability.scope,
        )
      ) {
        throw new Error('Capability tuple was revoked during replacement.');
      }
      if (!published.has(capability.id)) {
        published.add(capability.id);
        database
          .prepare(
            'INSERT INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          )
          .run(
            capability.id,
            capability.relationshipId,
            capability.direction === 'inviter->invitee' ? 0 : 1,
            capability.scope,
            capability.encryptedTokenSecret,
            capability.createdAt,
            capability.expiresAt,
            capability.revokedAt ?? null,
          );
      }
      database
        .prepare(
          'INSERT INTO capability_lookups(lookup_id, epoch, capability_id) VALUES (?, ?, ?)',
        )
        .run(lookupId, epoch, capability.id);
    }
  }

  private isTupleRevoked(
    relationshipId: string,
    direction: V2RepositoryCapability['direction'],
    scope: V2RepositoryCapability['scope'],
  ): boolean {
    return Boolean(
      this.requireDatabase()
        .prepare(
          'SELECT 1 AS present FROM revocations WHERE relationship_id = ? AND (direction IS NULL OR direction = ?) AND (scope IS NULL OR scope = ?)',
        )
        .get(relationshipId, direction === 'inviter->invitee' ? 0 : 1, scope),
    );
  }

  findCapabilityLookup(
    lookupId: Uint8Array,
    epoch: number,
  ): V2RepositoryCapability | null {
    const row = this.requireDatabase()
      .prepare(
        'SELECT c.id, c.relationship_id, c.direction, c.scope, c.encrypted_token_secret, c.created_at, c.expires_at, c.revoked_at FROM capability_lookups l JOIN capabilities c ON c.id = l.capability_id WHERE l.lookup_id = ? AND l.epoch = ?',
      )
      .get(lookupId, epoch) as Record<string, unknown> | undefined;
    if (!row) {
      return null;
    }
    return {
      id: String(row.id),
      relationshipId: String(row.relationship_id),
      direction:
        Number(row.direction) === 0 ? 'inviter->invitee' : 'invitee->inviter',
      scope: row.scope as V2RepositoryCapability['scope'],
      encryptedTokenSecret: String(row.encrypted_token_secret),
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
      ...(row.revoked_at === null ? {} : { revokedAt: Number(row.revoked_at) }),
    };
  }

  reserveStagedBody(
    id: string,
    expiresAt: number,
    now: number,
    reservedBytes: number,
    maximumConcurrentUploads: number,
    maximumStagedBytes: number,
  ): string {
    if (
      !/^[a-f0-9]{32}$/.test(id) ||
      !Number.isSafeInteger(expiresAt) ||
      !Number.isSafeInteger(now) ||
      !Number.isSafeInteger(reservedBytes) ||
      reservedBytes < 0
    ) {
      throw new Error('Staged body is invalid.');
    }
    const database = this.requireDatabase();
    const active = database
      .prepare(
        'SELECT COUNT(*) AS count, COALESCE(SUM(reserved_bytes), 0) AS bytes FROM staged_bodies WHERE expires_at > ?',
      )
      .get(now) as { count: number; bytes: number };
    if (
      Number(active.count) >= maximumConcurrentUploads ||
      Number(active.bytes) + reservedBytes > maximumStagedBytes
    ) {
      throw new Error('Staging quota is exhausted.');
    }
    const key = `staging/${id}.bin`;
    database
      .prepare(
        'INSERT INTO staged_bodies(id, body_key, expires_at, reserved_bytes) VALUES (?, ?, ?, ?)',
      )
      .run(id, key, expiresAt, reservedBytes);
    return key;
  }

  releaseStagedBody(id: string): void {
    this.requireDatabase()
      .prepare('DELETE FROM staged_bodies WHERE id = ?')
      .run(id);
  }

  createRelationship(input: {
    id: string;
    canonicalOrigin: string;
    encryptedState: Uint8Array;
    createdAt: number;
  }): void {
    this.requireDatabase()
      .prepare(
        "INSERT OR IGNORE INTO relationships(id, canonical_origin, state, encrypted_state, created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?)",
      )
      .run(
        input.id,
        input.canonicalOrigin,
        input.encryptedState,
        input.createdAt,
        input.createdAt,
      );
  }

  findRelationship(id: string): {
    id: string;
    canonicalOrigin: string;
    encryptedState: Uint8Array;
    createdAt: number;
    revokedAt?: number;
  } | null {
    const row = this.requireDatabase()
      .prepare(
        "SELECT id, canonical_origin, encrypted_state, created_at, revoked_at FROM relationships WHERE id = ? AND state = 'active'",
      )
      .get(id) as Record<string, unknown> | undefined;
    return row
      ? {
          id: String(row.id),
          canonicalOrigin: String(row.canonical_origin),
          encryptedState: Uint8Array.from(row.encrypted_state as Uint8Array),
          createdAt: Number(row.created_at),
          ...(row.revoked_at === null
            ? {}
            : { revokedAt: Number(row.revoked_at) }),
        }
      : null;
  }

  /**
   * Commits a whole reissue request: the relationship nonce claim, the rate
   * window, the live revocation check and the capability replacement share one
   * immediate transaction, so a rejection leaves the database untouched.
   */
  commitCapabilityReissue(
    input: V2CapabilityReissueInput,
  ): V2CapabilityReissueOutcome {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      database
        .prepare('DELETE FROM relationship_nonces WHERE expires_at < ?')
        .run(input.now);
      const claimed = database
        .prepare(
          'INSERT OR IGNORE INTO relationship_nonces(relationship_id, nonce, expires_at) VALUES (?, ?, ?)',
        )
        .run(input.relationshipId, input.nonce, input.nonceExpiresAt) as {
        changes: number;
      };
      if (claimed.changes !== 1) {
        database.exec('ROLLBACK');
        return 'replayed';
      }
      const relationship = database
        .prepare(
          "SELECT 1 AS present FROM relationships WHERE id = ? AND state = 'active'",
        )
        .get(input.relationshipId);
      if (
        !relationship ||
        input.revocations.some((tuple) =>
          this.isTupleRevoked(
            tuple.relationshipId,
            tuple.direction,
            tuple.scope,
          ),
        )
      ) {
        database.exec('ROLLBACK');
        return 'revoked';
      }
      const charged = database
        .prepare(
          'INSERT INTO relationship_rate_windows(relationship_id, minute, count) VALUES (?, ?, 1) ON CONFLICT(relationship_id, minute) DO UPDATE SET count = count + 1 WHERE count < ?',
        )
        .run(
          input.relationshipId,
          input.minute,
          input.maximumRequestsPerMinute,
        ) as { changes: number };
      if (charged.changes !== 1) {
        database.exec('ROLLBACK');
        return 'rate_limited';
      }
      this.applyCapabilityReplacement(input);
      database.exec('COMMIT');
      return 'accepted';
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  claimRequestWindow(input: {
    key: string;
    minute: number;
    maximum: number;
  }): boolean {
    const result = this.requireDatabase()
      .prepare(
        'INSERT INTO pairing_rate_windows(key, minute, count) VALUES (?, ?, 1) ON CONFLICT(key, minute) DO UPDATE SET count = count + 1 WHERE count < ?',
      )
      .run(input.key, input.minute, input.maximum) as { changes: number };
    return result.changes === 1;
  }

  revokeRelationship(input: {
    relationshipId: string;
    direction?: V2RepositoryCapability['direction'];
    scope?: V2RepositoryCapability['scope'];
    now: number;
  }): void {
    const database = this.requireDatabase();
    const clauses = ['relationship_id = ?'];
    const values: unknown[] = [input.relationshipId];
    if (input.direction) {
      clauses.push('direction = ?');
      values.push(input.direction === 'inviter->invitee' ? 0 : 1);
    }
    if (input.scope) {
      clauses.push('scope = ?');
      values.push(input.scope);
    }
    database.exec('BEGIN IMMEDIATE');
    try {
      database
        .prepare(
          `UPDATE capabilities SET revoked_at = ? WHERE ${clauses.join(' AND ')}`,
        )
        .run(input.now, ...values);
      database
        .prepare(
          'INSERT INTO revocations(id, relationship_id, direction, scope, created_at, expires_at, encrypted_envelope) VALUES (?, ?, ?, ?, ?, ?, ?)',
        )
        .run(
          randomRecordId(),
          input.relationshipId,
          input.direction
            ? input.direction === 'inviter->invitee'
              ? 0
              : 1
            : null,
          input.scope ?? null,
          input.now,
          2_147_483_647,
          new Uint8Array(),
        );
      if (!input.direction && !input.scope) {
        database
          .prepare(
            "UPDATE relationships SET state = 'revoked', revoked_at = ?, updated_at = ? WHERE id = ?",
          )
          .run(input.now, input.now, input.relationshipId);
      }
      database.exec('COMMIT');
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  rotateCapability(input: {
    relationshipId: string;
    direction: V2RepositoryCapability['direction'];
    scope: V2RepositoryCapability['scope'];
    now: number;
  }): boolean {
    const result = this.requireDatabase()
      .prepare(
        'UPDATE capabilities SET revoked_at = ? WHERE relationship_id = ? AND direction = ? AND scope = ? AND revoked_at IS NULL',
      )
      .run(
        input.now,
        input.relationshipId,
        input.direction === 'inviter->invitee' ? 0 : 1,
        input.scope,
      ) as { changes: number };
    return result.changes > 0;
  }

  relationshipStatus(relationshipId: string): {
    fullyRevoked: boolean;
    tuples: Array<{
      direction: V2RepositoryCapability['direction'];
      scope: V2RepositoryCapability['scope'];
      revoked: boolean;
      rotatedAt: number;
    }>;
  } {
    const database = this.requireDatabase();
    const relationship = database
      .prepare('SELECT state, revoked_at FROM relationships WHERE id = ?')
      .get(relationshipId) as Record<string, unknown> | undefined;
    const revocations = database
      .prepare(
        'SELECT direction, scope, created_at FROM revocations WHERE relationship_id = ?',
      )
      .all(relationshipId) as Record<string, unknown>[];
    const fullyRevoked =
      relationship?.state === 'revoked' ||
      revocations.some((row) => row.direction === null && row.scope === null);
    const covering = (
      direction: V2RepositoryCapability['direction'],
      scope: V2RepositoryCapability['scope'],
    ): number | undefined => {
      const matches = revocations.filter(
        (row) =>
          (row.direction === null ||
            Number(row.direction) ===
              (direction === 'inviter->invitee' ? 0 : 1)) &&
          (row.scope === null || row.scope === scope),
      );
      return matches.length === 0
        ? undefined
        : Math.max(...matches.map((row) => Number(row.created_at)));
    };
    const tuples = new Map<
      string,
      {
        direction: V2RepositoryCapability['direction'];
        scope: V2RepositoryCapability['scope'];
        revoked: boolean;
        rotatedAt: number;
      }
    >();
    const rows = database
      .prepare(
        'SELECT direction, scope, revoked_at, created_at FROM capabilities WHERE relationship_id = ?',
      )
      .all(relationshipId) as Record<string, unknown>[];
    for (const row of rows) {
      const direction: V2RepositoryCapability['direction'] =
        Number(row.direction) === 0 ? 'inviter->invitee' : 'invitee->inviter';
      const scope = row.scope as V2RepositoryCapability['scope'];
      const key = `${direction}|${scope}`;
      const revokedAt =
        row.revoked_at === null ? undefined : Number(row.revoked_at);
      const recorded = covering(direction, scope);
      const existing = tuples.get(key);
      tuples.set(key, {
        direction,
        scope,
        revoked:
          fullyRevoked ||
          revokedAt !== undefined ||
          recorded !== undefined ||
          existing?.revoked === true,
        rotatedAt: Math.max(
          Number(row.created_at),
          revokedAt ?? 0,
          recorded ?? 0,
          existing?.rotatedAt ?? 0,
        ),
      });
    }
    for (const row of revocations) {
      if (row.direction === null || row.scope === null) {
        continue;
      }
      const direction: V2RepositoryCapability['direction'] =
        Number(row.direction) === 0 ? 'inviter->invitee' : 'invitee->inviter';
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

  findPairing(locator: string): D1PairingRecord | null {
    const row = this.requireDatabase()
      .prepare(
        'SELECT id, phase, encrypted_grant, created_at, expires_at, revision FROM invitations WHERE id = ?',
      )
      .get(locator) as Record<string, unknown> | undefined;
    return row
      ? {
          locator: String(row.id),
          phase: Number(row.phase),
          createdAt: Number(row.created_at),
          expiresAt: Number(row.expires_at),
          value: Uint8Array.from(row.encrypted_grant as Uint8Array),
          revision: Number(row.revision),
        }
      : null;
  }

  /** Charges the pairing window and swaps the record in one transaction. */
  commitPairing(input: {
    record: D1PairingRecord;
    next: Pick<D1PairingRecord, 'phase' | 'value'>;
    rate?: { key: string; minute: number; maximum: number };
  }): V2PairingCommit {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      const current = database
        .prepare('SELECT revision FROM invitations WHERE id = ?')
        .get(input.record.locator) as { revision: number } | undefined;
      if (!current || Number(current.revision) !== input.record.revision) {
        database.exec('ROLLBACK');
        return { status: 'conflict' };
      }
      if (input.rate && !this.claimRequestWindow(input.rate)) {
        database.exec('ROLLBACK');
        return { status: 'rate_limited' };
      }
      database
        .prepare(
          'UPDATE invitations SET phase = ?, encrypted_grant = ?, revision = revision + 1 WHERE id = ? AND revision = ?',
        )
        .run(
          String(input.next.phase),
          input.next.value,
          input.record.locator,
          input.record.revision,
        );
      database.exec('COMMIT');
      return {
        status: 'committed',
        record: {
          ...input.record,
          phase: input.next.phase,
          value: input.next.value,
          revision: input.record.revision + 1,
        },
      };
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  compareAndSwapPairing(
    record: D1PairingRecord,
    next: Pick<D1PairingRecord, 'phase' | 'value'>,
  ): boolean {
    return this.commitPairing({ record, next }).status === 'committed';
  }

  admitPairing(input: {
    record: Omit<D1PairingRecord, 'revision'>;
    sourceKey: string;
    minute: number;
    globalMaximum: number;
    sourceMaximum: number;
    pendingMaximum: number;
    now: number;
  }): boolean {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      const existing = database
        .prepare('SELECT 1 FROM invitations WHERE id = ?')
        .get(input.record.locator);
      const pending = database
        .prepare(
          'SELECT COUNT(*) AS count FROM invitations WHERE expires_at > ?',
        )
        .get(input.now) as { count: number };
      if (existing || Number(pending.count) >= input.pendingMaximum) {
        database.exec('ROLLBACK');
        return false;
      }
      const increment = (key: string, maximum: number) => {
        const result = database
          .prepare(
            'INSERT INTO pairing_rate_windows(key, minute, count) VALUES (?, ?, 1) ON CONFLICT(key, minute) DO UPDATE SET count = count + 1 WHERE count < ?',
          )
          .run(key, input.minute, maximum) as { changes: number };
        return result.changes === 1;
      };
      if (
        !increment('pairing-create:global', input.globalMaximum) ||
        !increment(input.sourceKey, input.sourceMaximum)
      ) {
        database.exec('ROLLBACK');
        return false;
      }
      database
        .prepare(
          'INSERT INTO invitations(id, relationship_id, phase, encrypted_grant, created_at, expires_at) VALUES (?, NULL, ?, ?, ?, ?)',
        )
        .run(
          input.record.locator,
          String(input.record.phase),
          input.record.value,
          input.record.createdAt,
          input.record.expiresAt,
        );
      database.exec('COMMIT');
      return true;
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  activatePairing(input: {
    record: D1PairingRecord;
    invitationValue: Uint8Array;
    relationship: {
      id: string;
      canonicalOrigin: string;
      encryptedState: Uint8Array;
      createdAt: number;
    };
    registrations: readonly V2CapabilityRegistration[];
  }): boolean {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      const current = database
        .prepare('SELECT revision FROM invitations WHERE id = ?')
        .get(input.record.locator) as { revision: number } | undefined;
      if (!current || Number(current.revision) !== input.record.revision) {
        database.exec('ROLLBACK');
        return false;
      }
      database
        .prepare(
          "INSERT OR IGNORE INTO relationships(id, canonical_origin, state, encrypted_state, created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?)",
        )
        .run(
          input.relationship.id,
          input.relationship.canonicalOrigin,
          input.relationship.encryptedState,
          input.relationship.createdAt,
          input.relationship.createdAt,
        );
      for (const registration of input.registrations) {
        const capability = registration.capability;
        database
          .prepare(
            'INSERT OR IGNORE INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)',
          )
          .run(
            capability.id,
            capability.relationshipId,
            capability.direction === 'inviter->invitee' ? 0 : 1,
            capability.scope,
            capability.encryptedTokenSecret,
            capability.createdAt,
            capability.expiresAt,
          );
        database
          .prepare(
            'INSERT OR IGNORE INTO capability_lookups(lookup_id, epoch, capability_id) VALUES (?, ?, ?)',
          )
          .run(registration.lookupId, registration.epoch, capability.id);
      }
      const result = database
        .prepare(
          'UPDATE invitations SET phase = ?, encrypted_grant = ?, revision = revision + 1 WHERE id = ? AND revision = ?',
        )
        .run(
          3,
          input.invitationValue,
          input.record.locator,
          input.record.revision,
        ) as {
        changes: number;
      };
      if (result.changes !== 1) {
        database.exec('ROLLBACK');
        return false;
      }
      database.exec('COMMIT');
      return true;
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  claimNonce(
    capabilityId: string,
    nonce: Uint8Array,
    expiresAt: number,
    now: number,
  ): boolean {
    const database = this.requireDatabase();
    database.prepare('DELETE FROM nonces WHERE expires_at < ?').run(now);
    const result = database
      .prepare(
        'INSERT OR IGNORE INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?)',
      )
      .run(capabilityId, nonce, expiresAt) as { changes: number };
    return result.changes === 1;
  }

  claimNonces(
    claims: readonly {
      capabilityId: string;
      nonce: Uint8Array;
      expiresAt: number;
    }[],
    now: number,
  ): boolean {
    const database = this.requireDatabase();
    const unique = new Set(
      claims.map(
        ({ capabilityId, nonce }) =>
          `${capabilityId}:${Array.from(nonce).join(',')}`,
      ),
    );
    if (unique.size !== claims.length) {
      return false;
    }
    database.exec('BEGIN IMMEDIATE');
    try {
      database.prepare('DELETE FROM nonces WHERE expires_at < ?').run(now);
      for (const claim of claims) {
        const existing = database
          .prepare(
            'SELECT 1 FROM nonces WHERE capability_id = ? AND nonce = ? AND expires_at >= ?',
          )
          .get(claim.capabilityId, claim.nonce, now);
        if (existing) {
          database.exec('ROLLBACK');
          return false;
        }
      }
      for (const claim of claims) {
        database
          .prepare(
            'INSERT INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?)',
          )
          .run(claim.capabilityId, claim.nonce, claim.expiresAt);
      }
      database.exec('COMMIT');
      return true;
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  claimInboxAuthorization(input: {
    claims: readonly {
      capabilityId: string;
      nonce: Uint8Array;
      expiresAt: number;
    }[];
    maximumRequestsPerMinute: number;
    consumeControlEventIds: readonly string[];
    relationshipId: string;
    direction: 0 | 1;
    now: number;
  }): boolean {
    const database = this.requireDatabase();
    const keys = input.claims.map(
      ({ capabilityId, nonce }) =>
        `${capabilityId}:${Array.from(nonce).join(',')}`,
    );
    if (new Set(keys).size !== keys.length) {
      return false;
    }
    database.exec('BEGIN IMMEDIATE');
    try {
      const minute = Math.floor(input.now / 60);
      const counts = new Map<string, number>();
      for (const claim of input.claims) {
        const active = database
          .prepare(
            'SELECT 1 FROM capabilities WHERE id = ? AND expires_at > ? AND revoked_at IS NULL',
          )
          .get(claim.capabilityId, input.now);
        const replay = database
          .prepare(
            'SELECT 1 FROM nonces WHERE capability_id = ? AND nonce = ? AND expires_at >= ?',
          )
          .get(claim.capabilityId, claim.nonce, input.now);
        if (!active || replay) {
          database.exec('ROLLBACK');
          return false;
        }
        counts.set(
          claim.capabilityId,
          (counts.get(claim.capabilityId) ?? 0) + 1,
        );
      }
      for (const [capabilityId, count] of counts) {
        const window = database
          .prepare(
            'SELECT count FROM rate_windows WHERE capability_id = ? AND minute = ?',
          )
          .get(capabilityId, minute) as { count: number } | undefined;
        if ((window?.count ?? 0) + count > input.maximumRequestsPerMinute) {
          database.exec('ROLLBACK');
          return false;
        }
      }
      for (const claim of input.claims) {
        database
          .prepare(
            'INSERT INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?) ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?',
          )
          .run(claim.capabilityId, claim.nonce, claim.expiresAt, input.now);
      }
      for (const [capabilityId, count] of counts) {
        database
          .prepare(
            'INSERT INTO rate_windows(capability_id, minute, count) VALUES (?, ?, ?) ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + excluded.count',
          )
          .run(capabilityId, minute, count);
      }
      if (input.consumeControlEventIds.length) {
        const placeholders = input.consumeControlEventIds
          .map(() => '?')
          .join(', ');
        database
          .prepare(
            `UPDATE control_events SET consumed_at = ? WHERE consumed_at IS NULL AND relationship_id = ? AND direction = ? AND id IN (${placeholders})`,
          )
          .run(
            input.now,
            input.relationshipId,
            input.direction,
            ...input.consumeControlEventIds,
          );
      }
      database.exec('COMMIT');
      return true;
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  reserveDelivery(
    capabilityId: string,
    operationId: Uint8Array,
    operationDigest: Uint8Array,
    reservedBytes: number,
    expiresAt: number,
    maximumTotalBytes?: number,
    now = 0,
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
    },
    consumeControlEvents?: {
      ids: readonly string[];
      relationshipId: string;
      direction: 0 | 1 | 'inviter->invitee' | 'invitee->inviter';
      now: number;
    },
    maximumPendingDeliveries?: number,
    maximumObjectsPerCapability?: number,
  ): V2DeliveryReservation | { existing: V2RepositoryDelivery } {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      const consumeControls = () => {
        if (!consumeControlEvents || consumeControlEvents.ids.length === 0) {
          return;
        }
        const placeholders = consumeControlEvents.ids.map(() => '?').join(', ');
        database
          .prepare(
            `UPDATE control_events SET consumed_at = ? WHERE consumed_at IS NULL AND relationship_id = ? AND direction = ? AND id IN (${placeholders})`,
          )
          .run(
            consumeControlEvents.now,
            consumeControlEvents.relationshipId,
            consumeControlEvents.direction === 'inviter->invitee' ||
              consumeControlEvents.direction === 0
              ? 0
              : 1,
            ...consumeControlEvents.ids,
          );
      };
      const activeCapability = database
        .prepare(
          'SELECT relationship_id FROM capabilities WHERE id = ? AND expires_at > ? AND revoked_at IS NULL',
        )
        .get(capabilityId, now) as { relationship_id: string } | undefined;
      if (!activeCapability) {
        throw new Error('Delivery capability is not active.');
      }
      if (authorization) {
        const claims = authorization.claims;
        const keys = claims.map(
          (claim) =>
            `${claim.capabilityId}:${Array.from(claim.nonce).join(',')}`,
        );
        if (new Set(keys).size !== keys.length) {
          throw new Error('Request authorization nonce is duplicated.');
        }
        const minute = Math.floor(now / 60);
        const counts = new Map<string, number>();
        for (const claim of claims) {
          const active = database
            .prepare(
              'SELECT 1 FROM capabilities WHERE id = ? AND expires_at > ? AND revoked_at IS NULL',
            )
            .get(claim.capabilityId, now);
          const replay = database
            .prepare(
              'SELECT 1 FROM nonces WHERE capability_id = ? AND nonce = ? AND expires_at >= ?',
            )
            .get(claim.capabilityId, claim.nonce, now);
          if (!active || replay) {
            throw new Error('Request authorization is unavailable.');
          }
          counts.set(
            claim.capabilityId,
            (counts.get(claim.capabilityId) ?? 0) + 1,
          );
        }
        for (const [capabilityId, count] of counts) {
          const row = database
            .prepare(
              'SELECT count FROM rate_windows WHERE capability_id = ? AND minute = ?',
            )
            .get(capabilityId, minute) as { count: number } | undefined;
          if (
            (row?.count ?? 0) + count >
            authorization.maximumRequestsPerMinute
          ) {
            throw new Error('Request rate limit is exceeded.');
          }
        }
        for (const claim of claims) {
          database
            .prepare(
              'INSERT INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?) ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?',
            )
            .run(claim.capabilityId, claim.nonce, claim.expiresAt, now);
        }
        for (const [capabilityId, count] of counts) {
          database
            .prepare(
              'INSERT INTO rate_windows(capability_id, minute, count) VALUES (?, ?, ?) ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + excluded.count',
            )
            .run(capabilityId, minute, count);
        }
      }
      const published = database
        .prepare('SELECT * FROM deliveries WHERE operation_id = ?')
        .get(operationId) as Record<string, unknown> | undefined;
      if (published) {
        if (
          !bytesEqual(published.operation_digest as Uint8Array, operationDigest)
        ) {
          throw new V2OperationConflictError(
            'Operation ID conflicts with existing delivery.',
          );
        }
        consumeControls();
        database.exec('COMMIT');
        return { existing: this.deliveryFromRow(published) };
      }
      const prior = database
        .prepare(
          'SELECT delivery_id, payload_key, operation_digest FROM reservations WHERE operation_id = ?',
        )
        .get(operationId) as Record<string, unknown> | undefined;
      if (prior) {
        if (
          !bytesEqual(prior.operation_digest as Uint8Array, operationDigest)
        ) {
          throw new V2OperationConflictError(
            'Operation ID conflicts with existing reservation.',
          );
        }
        consumeControls();
        database.exec('COMMIT');
        return {
          deliveryId: String(prior.delivery_id),
          payloadKey: String(prior.payload_key),
          expiresAt,
        };
      }
      const deliveryId = crypto.randomUUID().replaceAll('-', '');
      const payloadKey = `deliveries/${deliveryId}.bin`;
      if (maximumPendingDeliveries !== undefined) {
        const pending = database
          .prepare(
            "SELECT (SELECT COUNT(*) FROM deliveries d WHERE d.relationship_id = c.relationship_id AND d.direction = c.direction AND d.state = 'published' AND d.expires_at > ?) + (SELECT COUNT(*) FROM reservations r JOIN capabilities rc ON rc.id = r.capability_id WHERE rc.relationship_id = c.relationship_id AND rc.direction = c.direction AND r.expires_at > ?) AS pending FROM capabilities c WHERE c.id = ?",
          )
          .get(now, now, capabilityId) as { pending: number } | undefined;
        if (Number(pending?.pending ?? 0) >= maximumPendingDeliveries) {
          throw new Error('Relationship pending delivery limit is reached.');
        }
      }
      if (maximumTotalBytes !== undefined) {
        const capability = database
          .prepare('SELECT relationship_id FROM capabilities WHERE id = ?')
          .get(capabilityId) as { relationship_id: string } | undefined;
        if (!capability) {
          throw new Error('Delivery capability is unavailable.');
        }
        const committed = database
          .prepare(
            'SELECT COALESCE(SUM(payload_length), 0) AS bytes FROM deliveries WHERE relationship_id = ?',
          )
          .get(capability.relationship_id) as { bytes: number };
        const inFlight = database
          .prepare(
            'SELECT COALESCE(SUM(reserved_bytes), 0) AS bytes FROM reservations r JOIN capabilities c ON c.id = r.capability_id WHERE c.relationship_id = ?',
          )
          .get(capability.relationship_id) as { bytes: number };
        if (
          Number(committed.bytes) + Number(inFlight.bytes) + reservedBytes >
          maximumTotalBytes
        ) {
          throw new Error('Relationship delivery quota is exhausted.');
        }
      }
      if (maximumObjectsPerCapability !== undefined) {
        const retained = database
          .prepare(
            'SELECT (SELECT COUNT(*) FROM deliveries WHERE relationship_id = ?) + (SELECT COUNT(*) FROM reservations r JOIN capabilities c ON c.id = r.capability_id WHERE c.relationship_id = ?) AS objects',
          )
          .get(
            activeCapability.relationship_id,
            activeCapability.relationship_id,
          ) as {
          objects: number;
        };
        if (Number(retained.objects) >= maximumObjectsPerCapability) {
          throw new Error('Relationship delivery object quota is exhausted.');
        }
      }
      database
        .prepare(
          'INSERT INTO reservations(delivery_id, capability_id, payload_key, reserved_bytes, expires_at, operation_id, operation_digest) VALUES (?, ?, ?, ?, ?, ?, ?)',
        )
        .run(
          deliveryId,
          capabilityId,
          payloadKey,
          reservedBytes,
          expiresAt,
          operationId,
          operationDigest,
        );
      consumeControls();
      database.exec('COMMIT');
      return { deliveryId, payloadKey, expiresAt };
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  finalizeReservation(
    deliveryId: string,
    values: {
      relationshipId: string;
      direction: 0 | 1;
      slot: Uint8Array;
      epoch: number;
      descriptor: Uint8Array;
      requestedPolicy: Uint8Array;
      effectivePolicy: Uint8Array;
      policyDigest: Uint8Array;
      payloadLength: number;
      payloadDigest: Uint8Array;
      payloadKey: string;
      operationId: Uint8Array;
      operationDigest: Uint8Array;
      createdAt: number;
      expiresAt: number;
    },
  ): void {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      const reservation = database
        .prepare(
          'SELECT payload_key, operation_id, operation_digest FROM reservations WHERE delivery_id = ?',
        )
        .get(deliveryId) as Record<string, unknown> | undefined;
      if (!reservation) {
        throw new Error('Delivery reservation is unavailable.');
      }
      if (
        reservation.payload_key !== values.payloadKey ||
        !bytesEqual(
          reservation.operation_id as Uint8Array,
          values.operationId,
        ) ||
        !bytesEqual(
          reservation.operation_digest as Uint8Array,
          values.operationDigest,
        )
      ) {
        throw new Error('Delivery publication conflicts with its reservation.');
      }
      // Publication order, assigned here under the same transaction that
      // commits the row, so the inbox can hand deliveries back in the order the
      // sender published them rather than in whole-second creation order.
      const sequence = Number(
        (
          database
            .prepare(
              'SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM deliveries WHERE relationship_id = ? AND direction = ?',
            )
            .get(values.relationshipId, values.direction) as {
            next_sequence: number;
          }
        ).next_sequence,
      );
      database
        .prepare(
          'INSERT INTO deliveries(id, relationship_id, direction, slot, epoch, encrypted_descriptor, requested_policy, effective_policy, policy_digest, payload_key, payload_length, payload_digest, operation_id, operation_digest, state, sequence, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        )
        .run(
          deliveryId,
          values.relationshipId,
          values.direction,
          values.slot,
          values.epoch,
          values.descriptor,
          values.requestedPolicy,
          values.effectivePolicy,
          values.policyDigest,
          reservation.payload_key,
          values.payloadLength,
          values.payloadDigest,
          reservation.operation_id,
          reservation.operation_digest,
          'published',
          sequence,
          values.createdAt,
          values.expiresAt,
        );
      database
        .prepare('DELETE FROM reservations WHERE delivery_id = ?')
        .run(deliveryId);
      database.exec('COMMIT');
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  selectOldestDelivery(
    relationshipId: string,
    direction: 0 | 1,
    slots: readonly { slot: Uint8Array; epoch: number }[],
    now: number,
  ): Record<string, unknown> | null {
    if (slots.length === 0) {
      return null;
    }
    const clauses = slots.map(() => '(slot = ? AND epoch = ?)').join(' OR ');
    const parameters: unknown[] = [relationshipId, direction, now];
    for (const entry of slots) {
      parameters.push(entry.slot, entry.epoch);
    }
    return (
      (this.requireDatabase()
        .prepare(
          `SELECT * FROM deliveries WHERE relationship_id = ? AND direction = ? AND state = 'published' AND expires_at > ? AND (${clauses}) ORDER BY sequence, created_at, id LIMIT 1`,
        )
        .get(...parameters) as Record<string, unknown> | undefined) ?? null
    );
  }

  findDeliveryById(deliveryId: string): V2RepositoryDelivery | null {
    const row = this.requireDatabase()
      .prepare('SELECT * FROM deliveries WHERE id = ?')
      .get(deliveryId) as Record<string, unknown> | undefined;
    return row ? this.deliveryFromRow(row) : null;
  }

  pendingDeliveryEpochs(
    relationshipId: string,
    direction: 0 | 1,
    slots: readonly { slot: Uint8Array; epoch: number }[],
    now: number,
  ): Set<number> {
    if (slots.length === 0) {
      return new Set();
    }
    const clauses = slots.map(() => '(slot = ? AND epoch = ?)').join(' OR ');
    const parameters: unknown[] = [relationshipId, direction, now];
    for (const entry of slots) {
      parameters.push(entry.slot, entry.epoch);
    }
    const rows = this.requireDatabase()
      .prepare(
        `SELECT DISTINCT epoch FROM deliveries WHERE relationship_id = ? AND direction = ? AND state = 'published' AND expires_at > ? AND (${clauses})`,
      )
      .all(...parameters) as Record<string, unknown>[];
    return new Set(rows.map((row) => Number(row.epoch)));
  }

  completeDelivery(
    deliveryId: string,
    completionOperationId: Uint8Array,
    completionOperationDigest: Uint8Array,
    completionDigest: Uint8Array,
    result: 0 | 1,
    now: number,
  ): boolean {
    const resultInfo = this.requireDatabase()
      .prepare(
        "UPDATE deliveries SET state = 'completed', completed_at = ?, completion_operation_id = ?, completion_operation_digest = ?, completion_digest = ?, completion_result = ? WHERE id = ? AND state = 'published'",
      )
      .run(
        now,
        completionOperationId,
        completionOperationDigest,
        completionDigest,
        result,
        deliveryId,
      ) as { changes: number };
    if (resultInfo.changes === 1) {
      return false;
    }
    const prior = this.requireDatabase()
      .prepare(
        'SELECT completion_operation_id, completion_operation_digest, completion_digest, completion_result FROM deliveries WHERE id = ? AND state = ?',
      )
      .get(deliveryId, 'completed') as Record<string, unknown> | undefined;
    if (!prior) {
      throw new Error('Delivery is unavailable.');
    }
    const operationId = prior.completion_operation_id as Uint8Array;
    const operationDigest = prior.completion_operation_digest as Uint8Array;
    const digest = prior.completion_digest as Uint8Array;
    if (
      prior.completion_result !== result ||
      !bytesEqual(operationId, completionOperationId) ||
      !bytesEqual(operationDigest, completionOperationDigest) ||
      !bytesEqual(digest, completionDigest)
    ) {
      throw new V2OperationConflictError(
        'Delivery completion conflicts with prior result.',
      );
    }
    return true;
  }

  publishControlEvent(
    event: Omit<V2RepositoryControlEvent, 'sequence'>,
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
  ):
    | {
        event: V2RepositoryControlEvent;
        idempotent: boolean;
      }
    | undefined {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      if (authorization) {
        const keys = authorization.claims.map(
          ({ capabilityId, nonce }) =>
            `${capabilityId}:${Array.from(nonce).join(',')}`,
        );
        if (new Set(keys).size !== keys.length) {
          database.exec('ROLLBACK');
          return undefined;
        }
        const minute = Math.floor(event.createdAt / 60);
        const counts = new Map<string, number>();
        for (const claim of authorization.claims) {
          const active = database
            .prepare(
              'SELECT 1 FROM capabilities WHERE id = ? AND expires_at > ? AND revoked_at IS NULL',
            )
            .get(claim.capabilityId, event.createdAt);
          const replay = database
            .prepare(
              'SELECT 1 FROM nonces WHERE capability_id = ? AND nonce = ? AND expires_at >= ?',
            )
            .get(claim.capabilityId, claim.nonce, event.createdAt);
          if (!active || replay) {
            database.exec('ROLLBACK');
            return undefined;
          }
          counts.set(
            claim.capabilityId,
            (counts.get(claim.capabilityId) ?? 0) + 1,
          );
        }
        for (const [capabilityId, count] of counts) {
          const window = database
            .prepare(
              'SELECT count FROM rate_windows WHERE capability_id = ? AND minute = ?',
            )
            .get(capabilityId, minute) as { count: number } | undefined;
          if (
            (window?.count ?? 0) + count >
            authorization.maximumRequestsPerMinute
          ) {
            database.exec('ROLLBACK');
            return undefined;
          }
        }
        for (const claim of authorization.claims) {
          database
            .prepare(
              'INSERT INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?) ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?',
            )
            .run(
              claim.capabilityId,
              claim.nonce,
              claim.expiresAt,
              event.createdAt,
            );
        }
        for (const [capabilityId, count] of counts) {
          database
            .prepare(
              'INSERT INTO rate_windows(capability_id, minute, count) VALUES (?, ?, ?) ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + excluded.count',
            )
            .run(capabilityId, minute, count);
        }
      }
      const result = this.publishControlEventInTransaction(
        event,
        authorization?.controlQuota,
      );
      database.exec('COMMIT');
      return result;
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  completeDeliveryWithControl(input: {
    completion: {
      id: string;
      operationId: Uint8Array;
      operationDigest: Uint8Array;
      completionDigest: Uint8Array;
      result: 0 | 1;
      now: number;
    };
    event: Omit<V2RepositoryControlEvent, 'sequence'>;
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
  }):
    | {
        delivery: V2RepositoryDelivery;
        event: V2RepositoryControlEvent;
        idempotent: boolean;
      }
    | undefined {
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      const authorization = input.authorization;
      if (authorization) {
        const keys = authorization.claims.map(
          ({ capabilityId, nonce }) =>
            `${capabilityId}:${Array.from(nonce).join(',')}`,
        );
        if (new Set(keys).size !== keys.length) {
          database.exec('ROLLBACK');
          return undefined;
        }
        const minute = Math.floor(input.completion.now / 60);
        const counts = new Map<string, number>();
        for (const claim of authorization.claims) {
          const active = database
            .prepare(
              'SELECT 1 FROM capabilities WHERE id = ? AND expires_at > ? AND revoked_at IS NULL',
            )
            .get(claim.capabilityId, input.completion.now);
          const replay = database
            .prepare(
              'SELECT 1 FROM nonces WHERE capability_id = ? AND nonce = ? AND expires_at >= ?',
            )
            .get(claim.capabilityId, claim.nonce, input.completion.now);
          if (!active || replay) {
            database.exec('ROLLBACK');
            return undefined;
          }
          counts.set(
            claim.capabilityId,
            (counts.get(claim.capabilityId) ?? 0) + 1,
          );
        }
        for (const [capabilityId, count] of counts) {
          const window = database
            .prepare(
              'SELECT count FROM rate_windows WHERE capability_id = ? AND minute = ?',
            )
            .get(capabilityId, minute) as { count: number } | undefined;
          if (
            (window?.count ?? 0) + count >
            authorization.maximumRequestsPerMinute
          ) {
            database.exec('ROLLBACK');
            return undefined;
          }
        }
        for (const claim of authorization.claims) {
          database
            .prepare(
              'INSERT INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?) ON CONFLICT(capability_id, nonce) DO UPDATE SET expires_at = excluded.expires_at WHERE nonces.expires_at < ?',
            )
            .run(
              claim.capabilityId,
              claim.nonce,
              claim.expiresAt,
              input.completion.now,
            );
        }
        for (const [capabilityId, count] of counts) {
          database
            .prepare(
              'INSERT INTO rate_windows(capability_id, minute, count) VALUES (?, ?, ?) ON CONFLICT(capability_id, minute) DO UPDATE SET count = count + excluded.count',
            )
            .run(capabilityId, minute, count);
        }
      }
      const completionIdempotent = this.completeDelivery(
        input.completion.id,
        input.completion.operationId,
        input.completion.operationDigest,
        input.completion.completionDigest,
        input.completion.result,
        input.completion.now,
      );
      const control = this.publishControlEventInTransaction(
        input.event,
        authorization?.controlQuota,
      );
      const delivery = this.findDeliveryById(input.completion.id);
      if (!delivery) {
        throw new Error('Completed delivery is unavailable.');
      }
      database.exec('COMMIT');
      return {
        delivery,
        event: control.event,
        idempotent: completionIdempotent && control.idempotent,
      };
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  private publishControlEventInTransaction(
    event: Omit<V2RepositoryControlEvent, 'sequence'>,
    controlQuota?: { maximumEvents: number; maximumBytes: number },
  ): { event: V2RepositoryControlEvent; idempotent: boolean } {
    const database = this.requireDatabase();
    const prior = database
      .prepare('SELECT * FROM control_events WHERE operation_id = ?')
      .get(event.operationId) as Record<string, unknown> | undefined;
    if (prior) {
      if (
        !bytesEqual(prior.operation_digest as Uint8Array, event.operationDigest)
      ) {
        throw new V2OperationConflictError(
          'Control operation conflicts with different bytes.',
        );
      }
      return { event: this.controlEventFromRow(prior), idempotent: true };
    }
    if (controlQuota) {
      const active = database
        .prepare(
          'SELECT COUNT(*) AS count, COALESCE(SUM(length(encrypted_envelope)), 0) AS bytes FROM control_events WHERE relationship_id = ? AND direction = ? AND expires_at > ?',
        )
        .get(
          event.relationshipId,
          event.direction === 'inviter->invitee' ? 0 : 1,
          event.createdAt,
        ) as { count: number; bytes: number };
      if (
        Number(active.count) >= controlQuota.maximumEvents ||
        Number(active.bytes) + event.encryptedEnvelope.byteLength >
          controlQuota.maximumBytes
      ) {
        throw new Error('Control event quota is exhausted.');
      }
    }
    const sequence = Number(
      (
        database
          .prepare(
            'SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM control_events WHERE relationship_id = ? AND direction = ?',
          )
          .get(
            event.relationshipId,
            event.direction === 'inviter->invitee' ? 0 : 1,
          ) as Record<string, unknown>
      ).next_sequence,
    );
    database
      .prepare(
        'INSERT INTO control_events(id, relationship_id, direction, slot, epoch, encrypted_envelope, operation_id, operation_digest, sequence, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      )
      .run(
        event.id,
        event.relationshipId,
        event.direction === 'inviter->invitee' ? 0 : 1,
        event.slot,
        event.epoch,
        event.encryptedEnvelope,
        event.operationId,
        event.operationDigest,
        sequence,
        event.createdAt,
        event.expiresAt,
      );
    return { event: { ...event, sequence }, idempotent: false };
  }

  queryPendingControlEvents(
    relationshipId: string,
    direction: 0 | 1,
    slots: readonly { slot: Uint8Array; epoch: number }[],
    now: number,
    maximumEvents = Number.MAX_SAFE_INTEGER,
    maximumBytes = Number.MAX_SAFE_INTEGER,
  ): V2RepositoryControlEvent[] {
    if (slots.length === 0) {
      return [];
    }
    const clauses = slots.map(() => '(slot = ? AND epoch = ?)').join(' OR ');
    const parameters: unknown[] = [relationshipId, direction, now];
    for (const entry of slots) {
      parameters.push(entry.slot, entry.epoch);
    }
    const rows = this.requireDatabase()
      .prepare(
        `SELECT * FROM control_events WHERE relationship_id = ? AND direction = ? AND consumed_at IS NULL AND expires_at > ? AND (${clauses}) ORDER BY sequence, id LIMIT ?`,
      )
      .all(...parameters, maximumEvents) as Record<string, unknown>[];
    const events: V2RepositoryControlEvent[] = [];
    let bytes = 0;
    for (const row of rows) {
      const event = this.controlEventFromRow(row);
      if (bytes + event.encryptedEnvelope.byteLength > maximumBytes) {
        break;
      }
      events.push(event);
      bytes += event.encryptedEnvelope.byteLength;
    }
    return events;
  }

  consumeControlEvents(input: {
    ids: readonly string[];
    relationshipId: string;
    direction: V2RepositoryControlEvent['direction'];
    now: number;
  }): void {
    if (input.ids.length === 0) {
      return;
    }
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      const placeholders = input.ids.map(() => '?').join(', ');
      database
        .prepare(
          `UPDATE control_events SET consumed_at = ? WHERE consumed_at IS NULL AND relationship_id = ? AND direction = ? AND id IN (${placeholders})`,
        )
        .run(
          input.now,
          input.relationshipId,
          input.direction === 'inviter->invitee' ? 0 : 1,
          ...input.ids,
        );
      database.exec('COMMIT');
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  runMaintenance(now: number, limit: number): V2MaintenanceResult {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new Error('SQLite maintenance limit is invalid.');
    }
    const database = this.requireDatabase();
    database.exec('BEGIN IMMEDIATE');
    try {
      const expired = database
        .prepare(
          'SELECT id, payload_key FROM deliveries WHERE expires_at <= ? ORDER BY expires_at, id LIMIT ?',
        )
        .all(now, limit) as Record<string, unknown>[];
      for (const row of expired) {
        database.prepare('DELETE FROM deliveries WHERE id = ?').run(row.id);
      }
      const abandoned = database
        .prepare(
          'SELECT delivery_id, payload_key FROM reservations WHERE expires_at <= ? ORDER BY expires_at, delivery_id LIMIT ?',
        )
        .all(now, limit) as Record<string, unknown>[];
      for (const row of abandoned) {
        database
          .prepare('DELETE FROM reservations WHERE delivery_id = ?')
          .run(row.delivery_id);
      }
      const controls = database
        .prepare(
          'SELECT id FROM control_events WHERE expires_at <= ? ORDER BY expires_at, id LIMIT ?',
        )
        .all(now, limit) as Record<string, unknown>[];
      for (const row of controls) {
        database.prepare('DELETE FROM control_events WHERE id = ?').run(row.id);
      }
      const nonceResult = database
        .prepare(
          'DELETE FROM nonces WHERE rowid IN (SELECT rowid FROM nonces WHERE expires_at < ? ORDER BY expires_at LIMIT ?)',
        )
        .run(now, limit) as { changes: number };
      const rateResult = database
        .prepare(
          'DELETE FROM rate_windows WHERE rowid IN (SELECT rowid FROM rate_windows WHERE minute < ? ORDER BY minute LIMIT ?)',
        )
        .run(Math.floor(now / 60), limit) as { changes: number };
      const relationshipNonceResult = database
        .prepare(
          'DELETE FROM relationship_nonces WHERE rowid IN (SELECT rowid FROM relationship_nonces WHERE expires_at < ? ORDER BY expires_at LIMIT ?)',
        )
        .run(now, limit) as { changes: number };
      const relationshipRateResult = database
        .prepare(
          'DELETE FROM relationship_rate_windows WHERE rowid IN (SELECT rowid FROM relationship_rate_windows WHERE minute < ? ORDER BY minute LIMIT ?)',
        )
        .run(Math.floor(now / 60), limit) as { changes: number };
      const pairingRateResult = database
        .prepare(
          'DELETE FROM pairing_rate_windows WHERE rowid IN (SELECT rowid FROM pairing_rate_windows WHERE minute < ? ORDER BY minute LIMIT ?)',
        )
        .run(Math.floor(now / 60), limit) as { changes: number };
      const staged = database
        .prepare(
          'SELECT body_key FROM staged_bodies WHERE expires_at <= ? ORDER BY expires_at, id LIMIT ?',
        )
        .all(now, limit) as Record<string, unknown>[];
      for (const row of staged) {
        database
          .prepare('DELETE FROM staged_bodies WHERE body_key = ?')
          .run(row.body_key);
      }
      const invitationResult = database
        .prepare(
          'DELETE FROM invitations WHERE id IN (SELECT id FROM invitations WHERE expires_at <= ? ORDER BY expires_at, id LIMIT ?)',
        )
        .run(now, limit) as { changes: number };
      database.exec('COMMIT');
      const deletedNonces =
        nonceResult.changes + relationshipNonceResult.changes;
      const deletedRateWindows =
        rateResult.changes +
        relationshipRateResult.changes +
        pairingRateResult.changes;
      const deletedInvitations = Number(invitationResult.changes);
      return {
        expiredDeliveryIds: expired.map((row) => String(row.id)),
        expiredBodyKeys: [
          ...[...expired, ...abandoned].map((row) => String(row.payload_key)),
          ...staged.map((row) => String(row.body_key)),
        ],
        deletedNonces,
        deletedControlEvents: controls.length,
        deletedRateWindows,
        deletedInvitations,
        complete:
          expired.length < limit &&
          abandoned.length < limit &&
          controls.length < limit &&
          staged.length < limit &&
          nonceResult.changes < limit &&
          relationshipNonceResult.changes < limit &&
          rateResult.changes < limit &&
          relationshipRateResult.changes < limit &&
          pairingRateResult.changes < limit &&
          deletedInvitations < limit,
      };
    } catch (error) {
      database.exec('ROLLBACK');
      throw error;
    }
  }

  /**
   * Reconciliation-only lookups. Both are bounded and parameterized, and no
   * delivery, inbox, control, or pairing path calls them; only the explicit
   * administrator reconciliation command does.
   */
  filterKnownBodyKeys(keys: readonly string[]): string[] {
    if (keys.length === 0) {
      return [];
    }
    if (keys.length > 1_000) {
      throw new Error('Body key lookup batch is too large.');
    }
    const database = this.requireDatabase();
    const placeholders = keys.map(() => '?').join(', ');
    const rows = database
      .prepare(
        `SELECT payload_key AS key FROM deliveries WHERE payload_key IN (${placeholders})
         UNION SELECT payload_key AS key FROM reservations WHERE payload_key IN (${placeholders})
         UNION SELECT body_key AS key FROM staged_bodies WHERE body_key IN (${placeholders})`,
      )
      .all(...keys, ...keys, ...keys) as Record<string, unknown>[];
    const known = new Set(rows.map((row) => String(row.key)));
    return keys.filter((key) => known.has(key));
  }

  listBodyKeys(input: { cursor?: string; limit: number }): {
    keys: string[];
    cursor?: string;
  } {
    if (
      !Number.isSafeInteger(input.limit) ||
      input.limit < 1 ||
      input.limit > 1_000
    ) {
      throw new Error('Body key page limit is invalid.');
    }
    const database = this.requireDatabase();
    const cursor = input.cursor ?? '';
    const rows = database
      .prepare(
        `SELECT key FROM (
           SELECT payload_key AS key FROM deliveries WHERE payload_key > ?
           UNION SELECT payload_key AS key FROM reservations WHERE payload_key > ?
           UNION SELECT body_key AS key FROM staged_bodies WHERE body_key > ?
         ) ORDER BY key LIMIT ?`,
      )
      .all(cursor, cursor, cursor, input.limit) as Record<string, unknown>[];
    const keys = rows.map((row) => String(row.key));
    return {
      keys,
      ...(keys.length === input.limit ? { cursor: keys[keys.length - 1] } : {}),
    };
  }

  private controlEventFromRow(
    row: Record<string, unknown>,
  ): V2RepositoryControlEvent {
    return {
      id: String(row.id),
      relationshipId: String(row.relationship_id),
      direction:
        Number(row.direction) === 0 ? 'inviter->invitee' : 'invitee->inviter',
      slot: Uint8Array.from(row.slot as Uint8Array),
      epoch: Number(row.epoch),
      encryptedEnvelope: Uint8Array.from(row.encrypted_envelope as Uint8Array),
      operationId: Uint8Array.from(row.operation_id as Uint8Array),
      operationDigest: Uint8Array.from(row.operation_digest as Uint8Array),
      sequence: Number(row.sequence),
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
      ...(row.consumed_at === null
        ? {}
        : { consumedAt: Number(row.consumed_at) }),
    };
  }

  private deliveryFromRow(row: Record<string, unknown>): V2RepositoryDelivery {
    return {
      id: String(row.id),
      relationshipId: String(row.relationship_id),
      direction:
        Number(row.direction) === 0 ? 'inviter->invitee' : 'invitee->inviter',
      slot: Uint8Array.from(row.slot as Uint8Array),
      epoch: Number(row.epoch),
      encryptedDescriptor: Uint8Array.from(
        row.encrypted_descriptor as Uint8Array,
      ),
      requestedPolicy: Uint8Array.from(row.requested_policy as Uint8Array),
      effectivePolicy: Uint8Array.from(row.effective_policy as Uint8Array),
      policyDigest: Uint8Array.from(row.policy_digest as Uint8Array),
      payloadKey: String(row.payload_key),
      payloadLength: Number(row.payload_length),
      payloadDigest: Uint8Array.from(row.payload_digest as Uint8Array),
      operationId: Uint8Array.from(row.operation_id as Uint8Array),
      operationDigest: Uint8Array.from(row.operation_digest as Uint8Array),
      state: row.state as V2RepositoryDelivery['state'],
      sequence: Number(row.sequence),
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
      ...(row.completed_at === null
        ? {}
        : { completedAt: Number(row.completed_at) }),
      ...(row.completion_operation_id === null
        ? {}
        : {
            completionOperationId: Uint8Array.from(
              row.completion_operation_id as Uint8Array,
            ),
          }),
      ...(row.completion_operation_digest === null
        ? {}
        : {
            completionOperationDigest: Uint8Array.from(
              row.completion_operation_digest as Uint8Array,
            ),
          }),
      ...(row.completion_digest === null
        ? {}
        : {
            completionDigest: Uint8Array.from(
              row.completion_digest as Uint8Array,
            ),
          }),
      ...(row.completion_result === null
        ? {}
        : { completionResult: Number(row.completion_result) as 0 | 1 }),
    };
  }

  private requireDatabase(): any {
    if (!this.database) {
      throw new Error('V2 SQLite database is not initialized.');
    }
    return this.database;
  }
}
