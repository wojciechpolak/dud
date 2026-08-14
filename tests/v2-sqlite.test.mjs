// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { SQLiteV2Database } from '../dist/src/v2-sqlite.js';

test('SQLite V2 bootstrap creates an isolated database without reading legacy state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dud-v2-sqlite-'));
  const legacyPath = join(root, 'v2', 'state.json');
  await (
    await import('node:fs/promises')
  ).mkdir(join(root, 'v2'), { recursive: true });
  await writeFile(legacyPath, '{"legacy":true}', 'utf8');
  const database = new SQLiteV2Database(root);
  await database.initialize(1_800_000_000);
  database.close();
  assert.equal(await readFile(legacyPath, 'utf8'), '{"legacy":true}');
  const databaseBytes = await readFile(join(root, 'v2', 'v2.sqlite'));
  assert.ok(databaseBytes.byteLength > 0);
  assert.equal((await stat(join(root, 'v2', 'v2.sqlite'))).mode & 0o777, 0o600);
});

test('SQLite maintenance reclaims only metadata-named staged bodies', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dud-v2-sqlite-'));
  const database = new SQLiteV2Database(root);
  await database.initialize();
  assert.equal(
    database.reserveStagedBody('a'.repeat(32), 10, 0, 0, 1, 1),
    `staging/${'a'.repeat(32)}.bin`,
  );
  assert.deepEqual(database.runMaintenance(11, 8).expiredBodyKeys, [
    `staging/${'a'.repeat(32)}.bin`,
  ]);
});

test('SQLite V2 indexes a capability lookup and atomically claims nonces', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dud-v2-sqlite-'));
  const database = new SQLiteV2Database(root);
  await database.initialize();
  const lookup = Uint8Array.from({ length: 16 }, (_, index) => index);
  database.putCapabilityLookup(
    {
      id: 'cap',
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'secret',
      createdAt: 1,
      expiresAt: 100,
    },
    lookup,
    20_000,
  );
  assert.equal(database.findCapabilityLookup(lookup, 20_000).id, 'cap');
  assert.equal(database.claimNonce('cap', lookup, 100, 10), true);
  assert.equal(database.claimNonce('cap', lookup, 100, 10), false);
  const operation = Uint8Array.from({ length: 16 }, (_, index) => index + 32);
  const digest = Uint8Array.from({ length: 32 }, (_, index) => index + 64);
  const reservation = database.reserveDelivery(
    'cap',
    operation,
    digest,
    12,
    100,
  );
  assert.equal(
    database.reserveDelivery('cap', operation, digest, 12, 100).deliveryId,
    reservation.deliveryId,
  );
  database.finalizeReservation(reservation.deliveryId, {
    relationshipId: 'relationship',
    direction: 0,
    slot: lookup,
    epoch: 20_000,
    descriptor: Uint8Array.of(1),
    requestedPolicy: Uint8Array.of(2),
    effectivePolicy: Uint8Array.of(3),
    policyDigest: digest,
    payloadLength: 12,
    payloadDigest: digest,
    payloadKey: reservation.payloadKey,
    operationId: operation,
    operationDigest: digest,
    createdAt: 20,
    expiresAt: 100,
  });
  const publishedRetry = database.reserveDelivery(
    'cap',
    operation,
    digest,
    12,
    100,
  );
  assert.equal('existing' in publishedRetry, true);
  assert.equal(
    'existing' in publishedRetry && publishedRetry.existing.id,
    reservation.deliveryId,
  );
  assert.equal(
    database.selectOldestDelivery(
      'relationship',
      0,
      [{ slot: lookup, epoch: 20_000 }],
      21,
    )?.id,
    reservation.deliveryId,
  );
  const completionOperation = Uint8Array.from(
    { length: 16 },
    (_, index) => index + 96,
  );
  const completionOperationDigest = Uint8Array.from(
    { length: 32 },
    (_, index) => index + 112,
  );
  assert.equal(
    database.completeDelivery(
      reservation.deliveryId,
      completionOperation,
      completionOperationDigest,
      digest,
      0,
      22,
    ),
    false,
  );
  assert.equal(
    database.completeDelivery(
      reservation.deliveryId,
      completionOperation,
      completionOperationDigest,
      digest,
      0,
      22,
    ),
    true,
  );
  assert.throws(
    () =>
      database.completeDelivery(
        reservation.deliveryId,
        completionOperation,
        Uint8Array.from(completionOperationDigest, (value) => value ^ 1),
        digest,
        0,
        22,
      ),
    /conflicts/,
  );
  const controlSlot = Uint8Array.from(lookup, (value) => value + 1);
  const control = database.publishControlEvent({
    id: 'control-1',
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    slot: controlSlot,
    epoch: 20_000,
    encryptedEnvelope: Uint8Array.of(4),
    operationId: Uint8Array.from({ length: 16 }, (_, index) => index + 144),
    operationDigest: Uint8Array.from({ length: 32 }, (_, index) => index + 160),
    createdAt: 23,
    expiresAt: 100,
  });
  assert.equal(control.idempotent, false);
  assert.equal(
    database.publishControlEvent({ ...control.event, sequence: undefined })
      .idempotent,
    true,
  );
  assert.deepEqual(
    database
      .queryPendingControlEvents(
        'relationship',
        0,
        [{ slot: controlSlot, epoch: 20_000 }],
        24,
      )
      .map((event) => event.id),
    ['control-1'],
  );
  database.consumeControlEvents({
    ids: ['control-1'],
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    now: 25,
  });
  assert.deepEqual(
    database.queryPendingControlEvents(
      'relationship',
      0,
      [{ slot: controlSlot, epoch: 20_000 }],
      26,
    ),
    [],
  );
  database.close();
});
