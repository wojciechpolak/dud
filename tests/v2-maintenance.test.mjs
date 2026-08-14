// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, utimes } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { D1V2Repository } from '../dist/src/v2-d1-repository.js';
import { D1V2PairingRepository } from '../dist/src/v2-d1-pairing-repository.js';
import { FilesystemV2BodyStore } from '../dist/src/v2-filesystem-body-store.js';
import {
  reconcileV2Storage,
  runV2MaintenancePass,
} from '../dist/src/v2-maintenance.js';
import { R2V2BodyStore } from '../dist/src/v2-r2.js';
import { sha256 } from '../dist/src/sha256.js';
import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import { readD1Migrations } from './d1-local.mjs';
import { MockR2Bucket } from './v2-helpers.mjs';

globalThis.FixedLengthStream ??= class FixedLengthStream extends (
  TransformStream
) {
  constructor() {
    super();
  }
};

const bytes = (length, seed) =>
  Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);

const stream = (value) =>
  new ReadableStream({
    start(controller) {
      controller.enqueue(value);
      controller.close();
    },
  });

/** The exact D1 migrations, executed through D1's prepared/batch surface. */
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
  constructor(file) {
    this.database = new DatabaseSync(file);
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

async function createD1(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'dud-v2-maint-d1-'));
  const database = new LocalD1Database(path.join(directory, 'd1.sqlite'));
  for (const migration of await readD1Migrations()) {
    database.database.exec(migration);
  }
  t.after(async () => {
    database.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { repository: new D1V2Repository(database), database };
}

async function createSQLite(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'dud-v2-maint-fs-'));
  const repository = new SQLiteV2Repository(directory);
  await repository.initialize();
  t.after(async () => {
    repository.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { repository, directory };
}

const backends = [
  ['sqlite', createSQLite],
  ['d1', createD1],
];

async function seedCapability(repository, id = 'capability') {
  await repository.registerCapability(
    {
      id,
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 100_000,
    },
    bytes(16, 1),
    20_000,
  );
}

/** Reserves and publishes one delivery whose metadata expires at `expiresAt`. */
async function publishDelivery(
  repository,
  index,
  expiresAt,
  payloadLength,
  maximumTotalBytes,
) {
  const operationId = bytes(16, index);
  const operationDigest = bytes(32, index);
  const reservation = await repository.reserveDelivery({
    capabilityId: 'capability',
    operationId,
    operationDigest,
    payloadLength,
    now: 10,
    expiresAt,
    ...(maximumTotalBytes === undefined ? {} : { maximumTotalBytes }),
  });
  await repository.publishDelivery({
    id: reservation.deliveryId,
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    slot: bytes(16, 1),
    epoch: 20_000,
    encryptedDescriptor: bytes(2, index),
    requestedPolicy: bytes(2, index),
    effectivePolicy: bytes(2, index),
    policyDigest: bytes(32, index),
    payloadKey: reservation.payloadKey,
    payloadLength,
    payloadDigest: bytes(32, index),
    operationId,
    operationDigest,
    createdAt: 10,
    expiresAt,
  });
  return reservation;
}

for (const [name, factory] of backends) {
  test(`${name} maintenance reports an unfinished batch and drains on restart`, async (t) => {
    const { repository } = await factory(t);
    await seedCapability(repository);
    const keys = [];
    for (let index = 0; index < 5; index++) {
      keys.push(
        (await publishDelivery(repository, index + 20, 100, 1)).payloadKey,
      );
    }

    // A bounded batch that fills its limit never claims the backend is drained.
    const first = await repository.runMaintenance(200, 2);
    assert.equal(first.expiredDeliveryIds.length, 2);
    assert.equal(first.complete, false);
    const second = await repository.runMaintenance(200, 2);
    assert.equal(second.complete, false);
    const third = await repository.runMaintenance(200, 2);
    assert.equal(third.expiredDeliveryIds.length, 1);
    assert.equal(third.complete, true);

    const removed = [
      ...first.expiredBodyKeys,
      ...second.expiredBodyKeys,
      ...third.expiredBodyKeys,
    ];
    assert.deepEqual(removed.slice().sort(), keys.slice().sort());
  });

  test(`${name} maintenance releases the exact aggregate byte accounting`, async (t) => {
    const { repository } = await factory(t);
    await seedCapability(repository);
    await publishDelivery(repository, 40, 100, 700, 1_000);
    const kept = await publishDelivery(repository, 41, 100_000, 200, 1_000);
    // A reservation that never published still holds its bytes until expiry.
    await repository.reserveDelivery({
      capabilityId: 'capability',
      operationId: bytes(16, 42),
      operationDigest: bytes(32, 42),
      payloadLength: 90,
      now: 10,
      expiresAt: 100,
      maximumTotalBytes: 1_000,
    });

    // The quota is exhausted while the expired records still hold their bytes.
    await assert.rejects(
      repository.reserveDelivery({
        capabilityId: 'capability',
        operationId: bytes(16, 43),
        operationDigest: bytes(32, 43),
        payloadLength: 100,
        now: 20,
        expiresAt: 100_000,
        maximumTotalBytes: 1_000,
      }),
      /quota/i,
    );

    const maintenance = await repository.runMaintenance(200, 32);
    assert.equal(maintenance.complete, true);
    assert.equal(maintenance.expiredDeliveryIds.length, 1);

    // Exactly the 790 released bytes come back; the live delivery keeps its 200.
    const accepted = await repository.reserveDelivery({
      capabilityId: 'capability',
      operationId: bytes(16, 44),
      operationDigest: bytes(32, 44),
      payloadLength: 800,
      now: 210,
      expiresAt: 100_000,
      maximumTotalBytes: 1_000,
    });
    assert.ok('deliveryId' in accepted);
    assert.ok(kept.deliveryId);
    await assert.rejects(
      repository.reserveDelivery({
        capabilityId: 'capability',
        operationId: bytes(16, 45),
        operationDigest: bytes(32, 45),
        payloadLength: 1,
        now: 210,
        expiresAt: 100_000,
        maximumTotalBytes: 1_000,
      }),
      /quota/i,
    );
  });
}

test('sqlite maintenance prunes expired pairing rendezvous records', async (t) => {
  const { repository } = await createSQLite(t);
  assert.equal(
    await repository.admit({
      record: {
        locator: 'a'.repeat(64),
        phase: 0,
        createdAt: 10,
        expiresAt: 100,
        value: bytes(32, 5),
      },
      sourceKey: 'source',
      minute: 1,
      globalMaximum: 10,
      sourceMaximum: 10,
      pendingMaximum: 10,
      now: 10,
    }),
    true,
  );
  assert.ok(await repository.find('a'.repeat(64)));

  const maintenance = await repository.runMaintenance(200, 32);
  assert.equal(maintenance.deletedInvitations, 1);
  assert.equal(maintenance.complete, true);
  assert.equal(await repository.find('a'.repeat(64)), null);
});

test('d1 maintenance prunes expired pairing rendezvous records', async (t) => {
  const { repository, database } = await createD1(t);
  const pairing = new D1V2PairingRepository(database);
  assert.equal(
    await pairing.admit({
      record: {
        locator: 'b'.repeat(64),
        phase: 0,
        createdAt: 10,
        expiresAt: 100,
        value: bytes(32, 6),
      },
      sourceKey: 'source',
      minute: 1,
      globalMaximum: 10,
      sourceMaximum: 10,
      pendingMaximum: 10,
      now: 10,
    }),
    true,
  );
  assert.ok(await pairing.find('b'.repeat(64)));

  const maintenance = await repository.runMaintenance(200, 32);
  assert.equal(maintenance.deletedInvitations, 1);
  assert.equal(await pairing.find('b'.repeat(64)), null);
});

test('a bounded pass deletes only the bodies its metadata batches named', async (t) => {
  const { repository, directory } = await createSQLite(t);
  const bodyStore = new FilesystemV2BodyStore(directory);
  await seedCapability(repository);
  const expired = [];
  for (let index = 0; index < 3; index++) {
    const reservation = await publishDelivery(repository, index + 60, 100, 3);
    await bodyStore.put(
      reservation.payloadKey,
      stream(bytes(3, 1)),
      3,
      sha256(bytes(3, 1)),
    );
    expired.push(reservation.payloadKey);
  }
  const live = await publishDelivery(repository, 70, 100_000, 3);
  await bodyStore.put(
    live.payloadKey,
    stream(bytes(3, 1)),
    3,
    sha256(bytes(3, 1)),
  );

  const result = await runV2MaintenancePass(repository, bodyStore, 200, 2);
  assert.equal(result.complete, true);
  assert.equal(result.batches, 2);
  assert.equal(result.deletedBodies, 3);
  for (const key of expired) {
    assert.equal(await bodyStore.head(key), false);
  }
  assert.equal(await bodyStore.head(live.payloadKey), true);
});

test('filesystem reconciliation reports orphans and missing bodies without mutating', async (t) => {
  const { repository, directory } = await createSQLite(t);
  const bodyStore = new FilesystemV2BodyStore(directory);
  await seedCapability(repository);
  const live = await publishDelivery(repository, 80, 100_000, 3);
  await bodyStore.put(
    live.payloadKey,
    stream(bytes(3, 1)),
    3,
    sha256(bytes(3, 1)),
  );
  // A body no metadata names: a crash between the body write and its record.
  const orphan = `deliveries/${'c'.repeat(32)}.bin`;
  await bodyStore.put(orphan, stream(bytes(3, 1)), 3, sha256(bytes(3, 1)));
  // A metadata record whose body is gone: the reverse direction.
  const missing = await publishDelivery(repository, 81, 100_000, 3);

  const aged = new Date(1_000_000);
  await utimes(
    path.join(directory, 'v2', 'delivery-bodies', `${'c'.repeat(32)}.bin`),
    aged,
    aged,
  );

  const report = await reconcileV2Storage(repository, bodyStore, {
    now: 2_000_000,
    limit: 100,
    minimumAgeSeconds: 86_400,
    apply: false,
  });
  assert.deepEqual(report.orphanBodies, [orphan]);
  assert.deepEqual(report.missingBodies, [missing.payloadKey]);
  assert.deepEqual(report.deletedBodies, []);
  assert.equal(report.complete, true);
  assert.equal(report.cursor, undefined);
  assert.equal(await bodyStore.head(orphan), true);
});

test('filesystem reconciliation deletes an aged orphan only when applied', async (t) => {
  const { repository, directory } = await createSQLite(t);
  const bodyStore = new FilesystemV2BodyStore(directory);
  const orphan = `staging/${'d'.repeat(32)}.bin`;
  await bodyStore.put(orphan, stream(bytes(3, 1)), 3, sha256(bytes(3, 1)));
  const recent = `deliveries/${'e'.repeat(32)}.bin`;
  await bodyStore.put(recent, stream(bytes(3, 1)), 3, sha256(bytes(3, 1)));
  const aged = new Date(1_000_000);
  await utimes(
    path.join(directory, 'v2', 'delivery-staging', `${'d'.repeat(32)}.bin`),
    aged,
    aged,
  );

  const report = await reconcileV2Storage(repository, bodyStore, {
    now: 2_000_000,
    limit: 100,
    minimumAgeSeconds: 86_400,
    apply: true,
  });
  assert.deepEqual(report.orphanBodies.slice().sort(), [recent, orphan].sort());
  assert.deepEqual(report.deletedBodies, [orphan]);
  assert.equal(report.retainedRecentBodies, 1);
  assert.equal(await bodyStore.head(orphan), false);
  // A body younger than the minimum age is never removed, so a reconciliation
  // racing an in-flight upload cannot delete live bytes.
  assert.equal(await bodyStore.head(recent), true);
});

test('reconciliation paginates both walks through an opaque resume cursor', async (t) => {
  const { repository, directory } = await createSQLite(t);
  const bodyStore = new FilesystemV2BodyStore(directory);
  await seedCapability(repository);
  const keys = [];
  for (let index = 0; index < 5; index++) {
    const reservation = await publishDelivery(
      repository,
      index + 90,
      100_000,
      3,
    );
    await bodyStore.put(
      reservation.payloadKey,
      stream(bytes(3, 1)),
      3,
      sha256(bytes(3, 1)),
    );
    keys.push(reservation.payloadKey);
  }

  let cursor;
  let pages = 0;
  let scannedBodies = 0;
  let scannedMetadata = 0;
  do {
    const report = await reconcileV2Storage(repository, bodyStore, {
      now: 2_000_000,
      limit: 2,
      ...(cursor === undefined ? {} : { cursor }),
      minimumAgeSeconds: 86_400,
      apply: false,
    });
    pages++;
    scannedBodies += report.scannedBodies;
    scannedMetadata += report.scannedMetadataKeys;
    assert.deepEqual(report.orphanBodies, []);
    assert.deepEqual(report.missingBodies, []);
    cursor = report.cursor;
    assert.ok(pages < 10, 'pagination terminates');
  } while (cursor !== undefined);

  assert.equal(scannedBodies, keys.length);
  assert.equal(scannedMetadata, keys.length);
  assert.ok(pages > 1, 'the walk actually paginated');
});

test('reconciliation rejects a malformed resume cursor', async (t) => {
  const { repository, directory } = await createSQLite(t);
  await assert.rejects(
    reconcileV2Storage(repository, new FilesystemV2BodyStore(directory), {
      now: 2_000_000,
      limit: 10,
      cursor: 'not-a-cursor',
      minimumAgeSeconds: 0,
      apply: false,
    }),
    /cursor is invalid/,
  );
});

test('D1/R2 reconciliation walks both body prefixes against D1 metadata', async (t) => {
  const { repository } = await createD1(t);
  const bucket = new MockR2Bucket();
  const bodyStore = new R2V2BodyStore(bucket);
  await seedCapability(repository);
  const live = await publishDelivery(repository, 120, 100_000, 3);
  bucket.uploaded = new Date(1_000_000_000);
  await bodyStore.put(
    live.payloadKey,
    stream(bytes(3, 1)),
    3,
    sha256(bytes(3, 1)),
  );
  const stagedKey = await repository.reserveStagedBody({
    id: 'a'.repeat(32),
    expiresAt: 100_000,
    now: 0,
    reservedBytes: 3,
    maximumConcurrentUploads: 1,
    maximumStagedBytes: 3,
  });
  await bodyStore.put(stagedKey, stream(bytes(3, 1)), 3, sha256(bytes(3, 1)));
  const orphanDelivery = `deliveries/${'b'.repeat(32)}.bin`;
  const orphanStaging = `staging/${'c'.repeat(32)}.bin`;
  await bodyStore.put(
    orphanDelivery,
    stream(bytes(3, 1)),
    3,
    sha256(bytes(3, 1)),
  );
  await bodyStore.put(
    orphanStaging,
    stream(bytes(3, 1)),
    3,
    sha256(bytes(3, 1)),
  );

  let cursor;
  const orphans = [];
  let pages = 0;
  do {
    const report = await reconcileV2Storage(repository, bodyStore, {
      now: 1_000_100_000,
      limit: 1,
      ...(cursor === undefined ? {} : { cursor }),
      minimumAgeSeconds: 86_400,
      apply: true,
    });
    orphans.push(...report.deletedBodies);
    cursor = report.cursor;
    assert.ok(++pages < 20, 'pagination terminates');
  } while (cursor !== undefined);

  assert.deepEqual(orphans.slice().sort(), [orphanDelivery, orphanStaging]);
  assert.equal(await bodyStore.head(live.payloadKey), true);
  assert.equal(await bodyStore.head(stagedKey), true);
});

test('reconciliation lives outside every request path', async () => {
  const requestModules = [
    'service.js',
    'v2-service.js',
    'v2-delivery-service.js',
    'v2-pairing.js',
    'v2-reissue.js',
  ];
  for (const name of requestModules) {
    const source = await readFile(
      new URL(`../dist/src/${name}`, import.meta.url),
      'utf8',
    );
    assert.equal(
      /listBodies|listBodyKeys|filterKnownBodyKeys|v2-maintenance\.js/.test(
        source,
      ),
      false,
      `${name} must not reach the reconciliation surface`,
    );
  }
});

function runAdmin(args) {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      ['dist/src/v2-admin.js', ...args],
      { env: { ...process.env } },
      (error, stdout, stderr) =>
        error
          ? reject(new Error(`${error.message}\n${stderr}`))
          : resolve(stdout),
    );
  });
}

test('the administrator reconcile command reports before it removes anything', async (t) => {
  const { repository, directory } = await createSQLite(t);
  const bodyStore = new FilesystemV2BodyStore(directory);
  const orphan = `deliveries/${'f'.repeat(32)}.bin`;
  await bodyStore.put(orphan, stream(bytes(3, 1)), 3, sha256(bytes(3, 1)));
  const aged = new Date(1_000_000);
  await utimes(
    path.join(directory, 'v2', 'delivery-bodies', `${'f'.repeat(32)}.bin`),
    aged,
    aged,
  );
  repository.close();

  const dryRun = await runAdmin(['reconcile', '--data-dir', directory]);
  assert.match(dryRun, /Orphan bodies \(no live metadata\): 1/);
  assert.match(dryRun, /Dry run: no body was deleted/);
  assert.match(dryRun, new RegExp(`orphan ${orphan}`));
  assert.match(dryRun, /Reconciliation walk is complete\./);
  assert.equal(await bodyStore.head(orphan), true);

  const json = await runAdmin([
    'reconcile',
    '--data-dir',
    directory,
    '--json',
    '--limit',
    '10',
  ]);
  assert.deepEqual(JSON.parse(json).orphanBodies, [orphan]);
  assert.equal(await bodyStore.head(orphan), true);

  const applied = await runAdmin([
    'reconcile',
    '--data-dir',
    directory,
    '--apply',
  ]);
  assert.match(applied, /Deleted orphan bodies: 1/);
  assert.equal(await bodyStore.head(orphan), false);
});

test('the administrator reconcile command validates its bounded options', async (t) => {
  const { repository, directory } = await createSQLite(t);
  repository.close();
  await assert.rejects(
    runAdmin(['reconcile', '--data-dir', directory, '--limit', '5000']),
    /must not exceed 1000/,
  );
  await assert.rejects(
    runAdmin(['reconcile', '--data-dir', directory, '--limit', 'many']),
    /non-negative integer/,
  );
  await assert.rejects(
    runAdmin(['reconcile', '--data-dir', directory, '--unknown', 'x']),
    /Unknown option --unknown/,
  );
  assert.match(await runAdmin(['help']), /reconcile --data-dir DIR/);
});
