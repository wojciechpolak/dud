// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { D1DatabaseLike, D1RunResultLike } from './types.js';
import { d1Bytes } from './v2-d1-values.js';
import type { V2CapabilityRegistration } from './v2-repository.js';

export interface D1PairingRecord {
  locator: string;
  phase: number;
  createdAt: number;
  expiresAt: number;
  value: Uint8Array;
  revision: number;
}

export type V2PairingCommit =
  | { status: 'committed'; record: D1PairingRecord }
  | { status: 'conflict' | 'rate_limited' };

/** Backend-neutral bounded pairing record operations. */
export interface V2PairingRepository {
  find(locator: string): Promise<D1PairingRecord | null>;
  /**
   * Charges the request window and swaps the rendezvous record under its exact
   * revision in one mutation, returning the committed record so a caller never
   * re-reads the rendezvous to learn its new revision.
   */
  commit(input: {
    record: D1PairingRecord;
    next: Pick<D1PairingRecord, 'phase' | 'value'>;
    rate?: { key: string; minute: number; maximum: number };
  }): Promise<V2PairingCommit>;
  compareAndSwap(
    record: D1PairingRecord,
    next: Pick<D1PairingRecord, 'phase' | 'value'>,
  ): Promise<boolean>;
  admit(input: {
    record: Omit<D1PairingRecord, 'revision'>;
    sourceKey: string;
    minute: number;
    globalMaximum: number;
    sourceMaximum: number;
    pendingMaximum: number;
    now: number;
  }): Promise<boolean>;
  activate(input: {
    record: D1PairingRecord;
    invitationValue: Uint8Array;
    relationship: {
      id: string;
      canonicalOrigin: string;
      encryptedState: Uint8Array;
      createdAt: number;
    };
    registrations: readonly V2CapabilityRegistration[];
  }): Promise<boolean>;
}

function recordFromRow(row: Record<string, unknown>): D1PairingRecord {
  return {
    locator: String(row.id),
    phase: Number(row.phase),
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    value: d1Bytes(row.encrypted_grant),
    revision: Number(row.revision),
  };
}

/** Bounded per-rendezvous D1 storage; no whole-state reads or rewrites. */
export class D1V2PairingRepository implements V2PairingRepository {
  constructor(private readonly database: D1DatabaseLike) {}

  async find(locator: string): Promise<D1PairingRecord | null> {
    const row = await this.database
      .prepare(
        'SELECT id, phase, encrypted_grant, created_at, expires_at, revision FROM invitations WHERE id = ?',
      )
      .bind(locator)
      .first<Record<string, unknown>>();
    return row ? recordFromRow(row) : null;
  }

  async create(record: Omit<D1PairingRecord, 'revision'>): Promise<boolean> {
    const result = await this.database
      .prepare(
        'INSERT OR IGNORE INTO invitations(id, relationship_id, phase, encrypted_grant, created_at, expires_at) VALUES (?, NULL, ?, ?, ?, ?)',
      )
      .bind(
        record.locator,
        String(record.phase),
        record.value,
        record.createdAt,
        record.expiresAt,
      )
      .run<D1RunResultLike>();
    return result.meta?.changes === 1;
  }

  async commit(input: {
    record: D1PairingRecord;
    next: Pick<D1PairingRecord, 'phase' | 'value'>;
    rate?: { key: string; minute: number; maximum: number };
  }): Promise<V2PairingCommit> {
    const swap = this.database
      .prepare(
        `UPDATE invitations SET phase = ?, encrypted_grant = ?, revision = revision + 1 WHERE id = ? AND revision = ?${
          input.rate ? ' AND changes() = 1' : ''
        }`,
      )
      .bind(
        String(input.next.phase),
        input.next.value,
        input.record.locator,
        input.record.revision,
      );
    const statements = input.rate
      ? [
          this.database
            .prepare(
              'INSERT INTO pairing_rate_windows(key, minute, count) SELECT ?, ?, 1 WHERE EXISTS (SELECT 1 FROM invitations WHERE id = ? AND revision = ?) ON CONFLICT(key, minute) DO UPDATE SET count = count + 1 WHERE count < ?',
            )
            .bind(
              input.rate.key,
              input.rate.minute,
              input.record.locator,
              input.record.revision,
              input.rate.maximum,
            ),
          swap,
        ]
      : [swap];
    const results = await this.database.batch<D1RunResultLike>(statements);
    if (results.at(-1)?.meta?.changes === 1) {
      return {
        status: 'committed',
        record: {
          ...input.record,
          phase: input.next.phase,
          value: input.next.value,
          revision: input.record.revision + 1,
        },
      };
    }
    // The guarded window and the swap both report zero changes, so the reason
    // is resolved from the record itself rather than from a rejected mutation.
    const current = await this.find(input.record.locator);
    return current && current.revision === input.record.revision
      ? { status: 'rate_limited' }
      : { status: 'conflict' };
  }

  async compareAndSwap(
    record: D1PairingRecord,
    next: Pick<D1PairingRecord, 'phase' | 'value'>,
  ): Promise<boolean> {
    return (await this.commit({ record, next })).status === 'committed';
  }

  async countActive(now: number): Promise<number> {
    const row = await this.database
      .prepare('SELECT COUNT(*) AS count FROM invitations WHERE expires_at > ?')
      .bind(now)
      .first<Record<string, unknown>>();
    return Number(row?.count ?? 0);
  }

  async claimRateWindow(
    key: string,
    minute: number,
    maximum: number,
  ): Promise<boolean> {
    const result = await this.database
      .prepare(
        'INSERT INTO pairing_rate_windows(key, minute, count) VALUES (?, ?, 1) ON CONFLICT(key, minute) DO UPDATE SET count = count + 1 WHERE count < ?',
      )
      .bind(key, minute, maximum)
      .run<D1RunResultLike>();
    return result.meta?.changes === 1;
  }

  /** Atomically admits a new opaque rendezvous or rejects it without charging
   * either rate window. `changes()` links the bounded batch statements. */
  async admit(input: {
    record: Omit<D1PairingRecord, 'revision'>;
    sourceKey: string;
    minute: number;
    globalMaximum: number;
    sourceMaximum: number;
    pendingMaximum: number;
    now: number;
  }): Promise<boolean> {
    const source = this.database
      .prepare(
        'INSERT INTO pairing_rate_windows(key, minute, count) SELECT ?, ?, 1 WHERE NOT EXISTS (SELECT 1 FROM invitations WHERE id = ?) AND (SELECT COUNT(*) FROM invitations WHERE expires_at > ?) < ? ON CONFLICT(key, minute) DO UPDATE SET count = count + 1 WHERE count < ?',
      )
      .bind(
        input.sourceKey,
        input.minute,
        input.record.locator,
        input.now,
        input.pendingMaximum,
        input.sourceMaximum,
      );
    const global = this.database
      .prepare(
        "INSERT INTO pairing_rate_windows(key, minute, count) SELECT 'pairing-create:global', ?, 1 WHERE changes() = 1 ON CONFLICT(key, minute) DO UPDATE SET count = count + 1 WHERE count < ?",
      )
      .bind(input.minute, input.globalMaximum);
    const insert = this.database
      .prepare(
        'INSERT INTO invitations(id, relationship_id, phase, encrypted_grant, created_at, expires_at) SELECT ?, NULL, ?, ?, ?, ? WHERE changes() = 1',
      )
      .bind(
        input.record.locator,
        String(input.record.phase),
        input.record.value,
        input.record.createdAt,
        input.record.expiresAt,
      );
    const results = await this.database.batch<D1RunResultLike>([
      source,
      global,
      insert,
    ]);
    return results[2]?.meta?.changes === 1;
  }

  /** Publishes the relationship, granular capabilities, and phase-3 grant in
   * one D1 batch, conditional on the exact pairing revision. */
  async activate(input: {
    record: D1PairingRecord;
    invitationValue: Uint8Array;
    relationship: {
      id: string;
      canonicalOrigin: string;
      encryptedState: Uint8Array;
      createdAt: number;
    };
    registrations: readonly V2CapabilityRegistration[];
  }): Promise<boolean> {
    const condition =
      'EXISTS (SELECT 1 FROM invitations WHERE id = ? AND revision = ?)';
    const conditionValues = [input.record.locator, input.record.revision];
    const statements = [
      this.database
        .prepare(
          `INSERT OR IGNORE INTO relationships(id, canonical_origin, state, encrypted_state, created_at, updated_at) SELECT ?, ?, 'active', ?, ?, ? WHERE ${condition}`,
        )
        .bind(
          input.relationship.id,
          input.relationship.canonicalOrigin,
          input.relationship.encryptedState,
          input.relationship.createdAt,
          input.relationship.createdAt,
          ...conditionValues,
        ),
    ];
    for (const registration of input.registrations) {
      const capability = registration.capability;
      statements.push(
        this.database
          .prepare(
            `INSERT OR IGNORE INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at, revoked_at) SELECT ?, ?, ?, ?, ?, ?, ?, NULL WHERE ${condition}`,
          )
          .bind(
            capability.id,
            capability.relationshipId,
            capability.direction === 'inviter->invitee' ? 0 : 1,
            capability.scope,
            capability.encryptedTokenSecret,
            capability.createdAt,
            capability.expiresAt,
            ...conditionValues,
          ),
        this.database
          .prepare(
            `INSERT OR IGNORE INTO capability_lookups(lookup_id, epoch, capability_id) SELECT ?, ?, ? WHERE ${condition}`,
          )
          .bind(
            registration.lookupId,
            registration.epoch,
            capability.id,
            ...conditionValues,
          ),
      );
    }
    statements.push(
      this.database
        .prepare(
          'UPDATE invitations SET phase = ?, encrypted_grant = ?, revision = revision + 1 WHERE id = ? AND revision = ?',
        )
        .bind(
          3,
          input.invitationValue,
          input.record.locator,
          input.record.revision,
        ),
    );
    const results = await this.database.batch<D1RunResultLike>(statements);
    return results.at(-1)?.meta?.changes === 1;
  }
}
