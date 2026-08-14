// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { D1V2Repository } from '../dist/src/v2-d1-repository.js';
import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import { readD1Migrations } from './d1-local.mjs';

const bytes = (length, seed) =>
  Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);

const RELATIONSHIP = 'aa'.repeat(16);

/** Runs the exact D1 migrations through D1's prepared/batch surface. */
class LocalD1Statement {
  constructor(database, query, values = []) {
    this.database = database;
    this.query = query;
    this.values = values;
  }

  bind(...values) {
    return new LocalD1Statement(this.database, this.query, values);
  }

  async run() {
    const result = this.database.prepare(this.query).run(...this.values);
    return { meta: { changes: Number(result.changes) } };
  }

  async first() {
    return this.database.prepare(this.query).get(...this.values) ?? null;
  }

  async all() {
    return { results: this.database.prepare(this.query).all(...this.values) };
  }
}

class LocalD1Database {
  constructor(path) {
    this.database = new DatabaseSync(path);
    this.database.exec('PRAGMA foreign_keys = ON;');
  }

  prepare(query) {
    return new LocalD1Statement(this.database, query);
  }

  async batch(statements) {
    this.database.exec('BEGIN IMMEDIATE');
    try {
      const results = [];
      for (const statement of statements) {
        results.push(await statement.run());
      }
      this.database.exec('COMMIT');
      return results;
    } catch (error) {
      this.database.exec('ROLLBACK');
      throw error;
    }
  }

  close() {
    this.database.close();
  }
}

async function d1Backend(t) {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-invariants-d1-'));
  const database = new LocalD1Database(join(directory, 'd1.sqlite'));
  for (const migration of await readD1Migrations()) {
    database.database.exec(migration);
  }
  const repository = new D1V2Repository(database);
  t.after(async () => {
    database.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { repository, sql: database.database };
}

async function sqliteBackend(t) {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-invariants-sqlite-'));
  const repository = new SQLiteV2Repository(directory);
  await repository.initialize();
  const sql = new DatabaseSync(join(directory, 'v2', 'v2.sqlite'));
  sql.exec('PRAGMA foreign_keys = ON;');
  t.after(async () => {
    sql.close();
    repository.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { repository, sql };
}

const backends = [
  ['sqlite', sqliteBackend],
  ['d1', d1Backend],
];

function writeCapability(id, createdAt = 1_000) {
  return {
    id,
    relationshipId: RELATIONSHIP,
    direction: 'inviter->invitee',
    scope: 'write',
    encryptedTokenSecret: `opaque-${id}`,
    createdAt,
    expiresAt: 100_000,
  };
}

async function seed(repository, capabilityId = 'capability') {
  await repository.initialize();
  await repository.createRelationship({
    id: RELATIONSHIP,
    canonicalOrigin: 'https://dud.example.com',
    encryptedState: bytes(48, 9),
    createdAt: 1_000,
  });
  await repository.registerCapability(
    writeCapability(capabilityId),
    bytes(16, 1),
    20_000,
  );
}

function deliveryRecord(reservation, overrides = {}) {
  return {
    id: reservation.deliveryId,
    relationshipId: RELATIONSHIP,
    direction: 'inviter->invitee',
    slot: bytes(16, 1),
    epoch: 20_000,
    encryptedDescriptor: bytes(4, 20),
    requestedPolicy: bytes(2, 21),
    effectivePolicy: bytes(2, 21),
    policyDigest: bytes(32, 22),
    payloadKey: reservation.payloadKey,
    payloadLength: 3,
    payloadDigest: bytes(32, 23),
    createdAt: 1_100,
    expiresAt: 100_000,
    ...overrides,
  };
}

for (const [name, backend] of backends) {
  test(`${name} rejects duplicate nonces and conflicting operation IDs`, async (t) => {
    const { repository, sql } = await backend(t);
    await seed(repository);

    const nonce = bytes(16, 30);
    assert.equal(
      await repository.claimNonce('capability', nonce, 5_000, 1_000),
      true,
    );
    assert.equal(
      await repository.claimNonce('capability', nonce, 5_000, 1_000),
      false,
    );
    assert.throws(() =>
      sql
        .prepare(
          'INSERT INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?)',
        )
        .run('capability', nonce, 6_000),
    );

    const operationId = bytes(16, 31);
    const reservation = await repository.reserveDelivery({
      capabilityId: 'capability',
      operationId,
      operationDigest: bytes(32, 32),
      payloadLength: 3,
      now: 1_000,
      expiresAt: 100_000,
    });
    await assert.rejects(
      repository.reserveDelivery({
        capabilityId: 'capability',
        operationId,
        operationDigest: bytes(32, 33),
        payloadLength: 3,
        now: 1_000,
        expiresAt: 100_000,
      }),
      /conflict/i,
    );
    await repository.publishDelivery(
      deliveryRecord(reservation, {
        operationId,
        operationDigest: bytes(32, 32),
      }),
    );
    assert.throws(() =>
      sql
        .prepare(
          "INSERT INTO deliveries(id, relationship_id, direction, slot, epoch, encrypted_descriptor, requested_policy, effective_policy, policy_digest, payload_key, payload_length, payload_digest, operation_id, operation_digest, state, created_at, expires_at) VALUES ('duplicate', ?, 0, ?, 20000, ?, ?, ?, ?, 'deliveries/duplicate.bin', 3, ?, ?, ?, 'published', 1100, 100000)",
        )
        .run(
          RELATIONSHIP,
          bytes(16, 1),
          bytes(4, 20),
          bytes(2, 21),
          bytes(2, 21),
          bytes(32, 22),
          bytes(32, 23),
          operationId,
          bytes(32, 32),
        ),
    );
  });

  test(`${name} enforces foreign keys, legal states and non-negative counters`, async (t) => {
    const { repository, sql } = await backend(t);
    await seed(repository);

    assert.throws(
      () =>
        sql
          .prepare(
            'INSERT INTO capability_lookups(lookup_id, epoch, capability_id) VALUES (?, ?, ?)',
          )
          .run(bytes(16, 40), 20_001, 'absent-capability'),
      /FOREIGN KEY/i,
    );
    assert.throws(
      () =>
        sql
          .prepare(
            'INSERT INTO reservations(delivery_id, capability_id, payload_key, reserved_bytes, expires_at) VALUES (?, ?, ?, ?, ?)',
          )
          .run(
            'orphan',
            'absent-capability',
            'deliveries/orphan.bin',
            1,
            9_000,
          ),
      /FOREIGN KEY/i,
    );
    assert.throws(
      () =>
        sql
          .prepare(
            'INSERT INTO relationship_nonces(relationship_id, nonce, expires_at) VALUES (?, ?, ?)',
          )
          .run('absent-relationship', bytes(32, 41), 9_000),
      /FOREIGN KEY/i,
    );

    assert.throws(
      () =>
        sql
          .prepare("UPDATE relationships SET state = 'archived' WHERE id = ?")
          .run(RELATIONSHIP),
      /CHECK/i,
    );
    assert.throws(
      () =>
        sql
          .prepare('UPDATE capabilities SET scope = ? WHERE id = ?')
          .run('upload', 'capability'),
      /CHECK/i,
    );
    assert.throws(
      () =>
        sql
          .prepare('UPDATE capabilities SET direction = 2 WHERE id = ?')
          .run('capability'),
      /CHECK/i,
    );

    assert.throws(
      () =>
        sql
          .prepare(
            'INSERT INTO rate_windows(capability_id, minute, count) VALUES (?, ?, -1)',
          )
          .run('capability', 5),
      /CHECK/i,
    );
    assert.throws(
      () =>
        sql
          .prepare(
            'INSERT INTO quota_accounts(relationship_id, committed_bytes, reserved_bytes, object_count, updated_at) VALUES (?, -1, 0, 0, 1)',
          )
          .run(RELATIONSHIP),
      /CHECK/i,
    );
    assert.throws(
      () =>
        sql
          .prepare(
            'INSERT INTO quota_accounts(relationship_id, committed_bytes, reserved_bytes, object_count, updated_at) VALUES (?, 0, 0, -1, 1)',
          )
          .run('another-relationship'),
      /CHECK/i,
    );
  });

  test(`${name} accounts aggregate delivery bytes exactly through expiry`, async (t) => {
    const { repository } = await backend(t);
    await seed(repository);
    // The enforced quota is the observable aggregate, so every assertion here
    // probes the limit itself rather than a backend-specific counter column.
    const reserve = (seed, payloadLength, now, expiresAt) =>
      repository.reserveDelivery({
        capabilityId: 'capability',
        operationId: bytes(16, seed),
        operationDigest: bytes(32, seed + 1),
        payloadLength,
        maximumTotalBytes: 10,
        now,
        expiresAt,
      });
    const assertExhausted = async (seed, now) => {
      await assert.rejects(reserve(seed, 1, now, 9_000), /quota/i);
    };

    const first = await reserve(50, 3, 1_000, 2_000);
    await assert.rejects(reserve(52, 8, 1_000, 2_000), /quota/i);
    const abandoned = await reserve(54, 7, 1_000, 2_000);
    await assertExhausted(56, 1_000);

    await repository.publishDelivery(
      deliveryRecord(first, {
        operationId: bytes(16, 50),
        operationDigest: bytes(32, 51),
        expiresAt: 5_000,
      }),
    );
    await assertExhausted(58, 1_000);

    const released = await repository.runMaintenance(3_000, 32);
    assert.ok(released.expiredBodyKeys.includes(abandoned.payloadKey));
    assert.deepEqual(released.expiredDeliveryIds, []);
    // Exactly the abandoned seven bytes came back, and no more.
    assert.ok(await reserve(60, 7, 3_000, 9_000));
    await assertExhausted(62, 3_000);

    const expired = await repository.runMaintenance(6_000, 32);
    assert.deepEqual(expired.expiredDeliveryIds, [first.deliveryId]);
    assert.ok(await reserve(64, 3, 6_000, 9_000));
    await assertExhausted(66, 6_000);
  });

  test(`${name} hides expired deliveries and reclaims expired nonces`, async (t) => {
    const { repository } = await backend(t);
    await seed(repository);
    const reservation = await repository.reserveDelivery({
      capabilityId: 'capability',
      operationId: bytes(16, 60),
      operationDigest: bytes(32, 61),
      payloadLength: 3,
      now: 1_000,
      expiresAt: 2_000,
    });
    await repository.publishDelivery(
      deliveryRecord(reservation, {
        operationId: bytes(16, 60),
        operationDigest: bytes(32, 61),
        expiresAt: 2_000,
      }),
    );
    const query = (now) =>
      repository.queryInbox({
        relationshipId: RELATIONSHIP,
        direction: 'inviter->invitee',
        dataSlots: [{ slot: bytes(16, 1), epoch: 20_000 }],
        controlSlots: [],
        now,
      });
    assert.equal((await query(1_500)).delivery.id, reservation.deliveryId);
    assert.equal((await query(2_000)).delivery, null);

    const nonce = bytes(16, 62);
    assert.equal(
      await repository.claimNonce('capability', nonce, 2_000, 1_000),
      true,
    );
    assert.equal(
      await repository.claimNonce('capability', nonce, 4_000, 2_500),
      true,
    );
  });

  test(`${name} enforces the pending delivery limit without blocking retries`, async (t) => {
    const { repository } = await backend(t);
    await seed(repository);
    const reserve = (seed, maximumPendingDeliveries) =>
      repository.reserveDelivery({
        capabilityId: 'capability',
        operationId: bytes(16, seed),
        operationDigest: bytes(32, seed + 1),
        payloadLength: 3,
        maximumPendingDeliveries,
        now: 1_000,
        expiresAt: 100_000,
      });

    const first = await reserve(70, 2);
    await repository.publishDelivery(
      deliveryRecord(first, {
        operationId: bytes(16, 70),
        operationDigest: bytes(32, 71),
      }),
    );
    const second = await reserve(72, 2);
    await assert.rejects(reserve(74, 2));
    // The in-flight reservation counts, and an exact retry is still admitted.
    assert.deepEqual(await reserve(72, 2), second);
    await repository.publishDelivery(
      deliveryRecord(second, {
        operationId: bytes(16, 72),
        operationDigest: bytes(32, 73),
        payloadKey: second.payloadKey,
      }),
    );
    await assert.rejects(reserve(76, 2));
    assert.ok(await reserve(78, 3));
  });
}
