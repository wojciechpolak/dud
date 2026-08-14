// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import { V2_SQLITE_MIGRATIONS } from '../dist/src/v2-sqlite-schema.js';

const RELATIONSHIP = 'cc'.repeat(16);
const bytes = (length, seed) =>
  Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);

async function createRepository(t) {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-durability-'));
  const repository = new SQLiteV2Repository(directory);
  await repository.initialize();
  t.after(async () => {
    repository.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { repository, directory, path: join(directory, 'v2', 'v2.sqlite') };
}

async function seed(repository, capabilityId = 'capability') {
  await repository.createRelationship({
    id: RELATIONSHIP,
    canonicalOrigin: 'https://dud.example.com',
    encryptedState: bytes(48, 3),
    createdAt: 1_000,
  });
  await repository.registerCapability(
    {
      id: capabilityId,
      relationshipId: RELATIONSHIP,
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1_000,
      expiresAt: 100_000,
    },
    bytes(16, 1),
    20_000,
  );
}

test('the v2 metadata database runs with durable, ordered settings', async (t) => {
  const { repository } = await createRepository(t);
  const durability = repository.describeDurability();
  assert.equal(durability.journalMode, 'wal');
  assert.equal(durability.synchronous, 2);
  assert.equal(durability.foreignKeys, 1);
  assert.equal(durability.busyTimeout, 5_000);
  assert.deepEqual(
    durability.appliedMigrations,
    Array.from({ length: V2_SQLITE_MIGRATIONS.length - 1 }, (_, i) => i + 1),
  );
});

test('reopening the v2 metadata database applies no further migrations', async (t) => {
  const { repository, directory } = await createRepository(t);
  const first = repository.describeDurability();
  const reopened = new SQLiteV2Repository(directory);
  await reopened.initialize();
  t.after(() => reopened.close());
  assert.deepEqual(reopened.describeDurability(), first);
});

test('the v2 metadata database and its directory stay private', async (t) => {
  const { directory, path } = await createRepository(t);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal((await stat(join(directory, 'v2'))).mode & 0o777, 0o700);
});

test('concurrent Node writes serialize into exact quota accounting', async (t) => {
  const { repository } = await createRepository(t);
  await seed(repository);
  const attempts = await Promise.allSettled(
    Array.from({ length: 8 }, (_, index) =>
      repository.reserveDelivery({
        capabilityId: 'capability',
        operationId: bytes(16, 100 + index * 2),
        operationDigest: bytes(32, 101 + index * 2),
        payloadLength: 4,
        maximumTotalBytes: 12,
        now: 1_000,
        expiresAt: 100_000,
      }),
    ),
  );
  const reserved = attempts.filter((entry) => entry.status === 'fulfilled');
  assert.equal(reserved.length, 3);
  assert.equal(new Set(reserved.map((e) => e.value.deliveryId)).size, 3);
  for (const rejected of attempts.filter((e) => e.status === 'rejected')) {
    assert.match(rejected.reason.message, /quota/i);
  }
});

/** Holds a write transaction in a separate process for `holdMs`. */
function holdWriteLock(path, holdMs) {
  const script = `
    const { DatabaseSync } = require('node:sqlite');
    const database = new DatabaseSync(${JSON.stringify(path)});
    database.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    database.exec('BEGIN IMMEDIATE');
    database
      .prepare(
        "INSERT INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at, revoked_at) VALUES ('other-process', ?, 0, 'read', 'opaque', 1000, 100000, NULL)",
      )
      .run(${JSON.stringify(RELATIONSHIP)});
    process.stdout.write('locked\\n');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ${holdMs});
    database.exec('COMMIT');
    database.close();
  `;
  const child = spawn(process.execPath, ['-e', script], {
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const locked = new Promise((resolve, reject) => {
    child.stdout.on('data', (chunk) => {
      if (String(chunk).includes('locked')) {
        resolve();
      }
    });
    child.on('error', reject);
    child.on('exit', (code) =>
      code === 0 ? resolve() : reject(new Error(`child exited ${code}`)),
    );
  });
  const exited = new Promise((resolve) => child.on('exit', resolve));
  return { locked, exited };
}

test('a cross-process write lock is awaited, not rejected', async (t) => {
  const { repository, path } = await createRepository(t);
  await seed(repository);
  const holder = holdWriteLock(path, 400);
  await holder.locked;

  const startedAt = Date.now();
  await repository.registerCapability(
    {
      id: 'this-process',
      relationshipId: RELATIONSHIP,
      direction: 'invitee->inviter',
      scope: 'ack',
      encryptedTokenSecret: 'opaque',
      createdAt: 1_000,
      expiresAt: 100_000,
    },
    bytes(16, 40),
    20_000,
  );
  await holder.exited;
  // The write waited for the other process instead of failing with SQLITE_BUSY.
  assert.ok(Date.now() - startedAt >= 100);
  assert.equal(
    (await repository.findCapabilityLookup(bytes(16, 40), 20_000)).id,
    'this-process',
  );
  // The committed row from the other process is visible without reopening.
  assert.equal(
    (await repository.relationshipStatus(RELATIONSHIP)).tuples.length,
    3,
  );
});
