// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import { applyV2SQLiteMigrations } from '../dist/src/v2-sqlite-schema.js';

const bytes = (length, value) => new Uint8Array(length).fill(value);

test('warm SQLite empty inbox p95 stays below the V2 25ms gate with a full metadata working set', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'dud-v2-sqlite-performance-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'v2', 'v2.sqlite');
  const repository = new SQLiteV2Repository(root);
  await repository.initialize();
  repository.close();

  const database = new DatabaseSync(path);
  applyV2SQLiteMigrations(database, 1_800_000_000);
  const insertDelivery = database.prepare(
    "INSERT INTO deliveries(id, relationship_id, direction, slot, epoch, encrypted_descriptor, requested_policy, effective_policy, policy_digest, payload_key, payload_length, payload_digest, operation_id, operation_digest, state, created_at, expires_at) VALUES (?, ?, 0, ?, 20000, ?, ?, ?, ?, ?, 1, ?, ?, ?, 'published', ?, ?)",
  );
  // A warm database is not only deliveries: an inbox query runs alongside the
  // capability lookups, control events, nonce records and rate windows a live
  // deployment accumulates, plus the expired rows awaiting maintenance.
  // Seeding only deliveries would measure an index that never competes with
  // anything.
  const insertCapability = database.prepare(
    'INSERT INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  );
  const insertLookup = database.prepare(
    'INSERT INTO capability_lookups(lookup_id, epoch, capability_id) VALUES (?, ?, ?)',
  );
  const insertControlEvent = database.prepare(
    'INSERT INTO control_events(id, relationship_id, direction, slot, epoch, encrypted_envelope, operation_id, operation_digest, sequence, created_at, expires_at, consumed_at) VALUES (?, ?, 1, ?, 20000, ?, ?, ?, ?, ?, ?, ?)',
  );
  const insertNonce = database.prepare(
    'INSERT INTO nonces(capability_id, nonce, expires_at) VALUES (?, ?, ?)',
  );
  const insertRateWindow = database.prepare(
    'INSERT INTO rate_windows(capability_id, minute, count) VALUES (?, ?, ?)',
  );

  const counted = (fill, index) => {
    const value = bytes(16, fill);
    new DataView(value.buffer).setUint32(12, index);
    return value;
  };

  database.exec('BEGIN IMMEDIATE');
  try {
    const scopes = ['write', 'read', 'ack'];
    for (let index = 0; index < 300; index++) {
      const capabilityId = `capability-${index}`;
      // A third of the capabilities are already expired, and a third of those
      // are revoked, which is the shape maintenance is always catching up with.
      const expired = index % 3 === 0;
      insertCapability.run(
        capabilityId,
        `relationship-${index % 100}`,
        index % 2,
        scopes[index % scopes.length],
        bytes(64, index & 0xff),
        1_799_000_000,
        expired ? 1_799_900_000 : 1_900_000_000,
      );
      // Each capability is published under a fortnight of daily lookups, which
      // is what a real reissue window leaves behind.
      for (let epoch = 20_000; epoch < 20_014; epoch++) {
        insertLookup.run(
          counted(0x20, index * 100 + (epoch - 20_000)),
          epoch,
          capabilityId,
        );
      }
      for (let nonce = 0; nonce < 10; nonce++) {
        insertNonce.run(
          capabilityId,
          counted(nonce, index),
          nonce % 2 === 0 ? 1_799_900_000 : 1_900_000_000,
        );
      }
      insertRateWindow.run(capabilityId, 29_999_999 + (index % 5), index % 60);
    }
    for (let index = 0; index < 2_000; index++) {
      const id = (index + 0x1000000).toString(16).padStart(32, '0');
      insertControlEvent.run(
        id,
        `relationship-${index % 100}`,
        bytes(16, index & 0xff),
        bytes(8, 9),
        counted(0x0a, index),
        bytes(32, 11),
        index,
        1_800_000_000,
        index % 4 === 0 ? 1_799_900_000 : 1_900_000_000,
        index % 2 === 0 ? 1_800_000_100 : null,
      );
    }
    for (let index = 0; index < 10_000; index++) {
      const id = index.toString(16).padStart(32, '0');
      insertDelivery.run(
        id,
        `relationship-${index % 100}`,
        bytes(16, index & 0xff),
        bytes(2, 1),
        bytes(2, 2),
        bytes(2, 3),
        bytes(32, 4),
        `deliveries/${id}.bin`,
        bytes(32, 5),
        counted(6, index),
        bytes(32, 7),
        index,
        // A tenth of the deliveries are already expired.
        index % 10 === 0 ? 1_799_900_000 : 1_900_000_000,
      );
    }
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  } finally {
    database.close();
  }

  await repository.initialize();
  const emptySlot = bytes(16, 0xff);
  await repository.queryInbox({
    relationshipId: 'missing-relationship',
    direction: 'inviter->invitee',
    dataSlots: [{ slot: emptySlot, epoch: 20_000 }],
    controlSlots: [],
    now: 1_800_000_000,
  });
  const samples = [];
  for (let index = 0; index < 100; index++) {
    const started = performance.now();
    await repository.queryInbox({
      relationshipId: 'missing-relationship',
      direction: 'inviter->invitee',
      dataSlots: [{ slot: emptySlot, epoch: 20_000 }],
      controlSlots: [],
      now: 1_800_000_000,
    });
    samples.push(performance.now() - started);
  }
  samples.sort((left, right) => left - right);
  const p95 = samples[Math.ceil(samples.length * 0.95) - 1];
  assert.ok(p95 < 25, `warm empty inbox p95 = ${p95.toFixed(3)}ms`);
  repository.close();
});
