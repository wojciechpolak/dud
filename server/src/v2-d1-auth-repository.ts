// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { D1DatabaseLike, D1RunResultLike } from './types.js';
import type {
  V2CapabilityRegistration,
  V2RepositoryCapability,
} from './v2-repository.js';

function directionNumber(
  direction: V2RepositoryCapability['direction'],
): 0 | 1 {
  return direction === 'inviter->invitee' ? 0 : 1;
}

function capabilityFromRow(
  row: Record<string, unknown>,
): V2RepositoryCapability {
  return {
    id: String(row.id),
    relationshipId: String(row.relationship_id),
    direction:
      Number(row.direction) === 0 ? 'inviter->invitee' : 'invitee->inviter',
    scope: row.scope as V2RepositoryCapability['scope'],
    encryptedTokenSecret: String(row.encrypted_token_secret),
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    ...(row.revoked_at === null || row.revoked_at === undefined
      ? {}
      : { revokedAt: Number(row.revoked_at) }),
  };
}

/**
 * Prepared-statement D1 foundation for the granular authorization hot path.
 * Each mutating method uses one D1 batch, so the lookup registry and nonce
 * claim never require an R2 read/modify/write transaction.
 */
export class D1V2AuthorizationRepository {
  constructor(private readonly database: D1DatabaseLike) {}

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
    const statements = input.revocations.map((revoked) =>
      this.database
        .prepare(
          'UPDATE capabilities SET revoked_at = ? WHERE relationship_id = ? AND direction = ? AND scope = ? AND revoked_at IS NULL',
        )
        .bind(
          input.now,
          revoked.relationshipId,
          directionNumber(revoked.direction),
          revoked.scope,
        ),
    );
    for (const registration of input.registrations) {
      statements.push(
        this.insertCapability(registration.capability, false),
        this.database
          .prepare(
            'INSERT INTO capability_lookups(lookup_id, epoch, capability_id) VALUES (?, ?, ?)',
          )
          .bind(
            registration.lookupId,
            registration.epoch,
            registration.capability.id,
          ),
      );
    }
    if (statements.length !== 0) {
      await this.database.batch(statements);
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
      .first<Record<string, unknown>>();
    return row ? capabilityFromRow(row) : null;
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
}
