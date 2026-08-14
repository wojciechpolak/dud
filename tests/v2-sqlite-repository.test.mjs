// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';

const bytes = (length, seed = 0) =>
  Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);

test('SQLite granular repository publishes, queries, completes, and maintains a delivery', async () => {
  const repository = new SQLiteV2Repository(
    await mkdtemp(join(tmpdir(), 'dud-v2-repository-')),
  );
  await repository.initialize();
  const lookup = bytes(16, 1);
  repository.addCapability(
    {
      id: 'capability',
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 100,
    },
    lookup,
    20_000,
  );
  const nextLookup = bytes(16, 101);
  repository.addCapability(
    {
      id: 'capability',
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 100,
    },
    nextLookup,
    20_001,
  );
  assert.equal(
    (await repository.findCapabilityLookup(nextLookup, 20_001)).id,
    'capability',
  );
  const operationId = bytes(16, 2);
  const operationDigest = bytes(32, 3);
  const reserved = await repository.reserveDelivery({
    capabilityId: 'capability',
    operationId,
    operationDigest,
    payloadLength: 3,
    now: 10,
    expiresAt: 100,
  });
  assert.ok('deliveryId' in reserved);
  const published = await repository.publishDelivery({
    id: reserved.deliveryId,
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    slot: lookup,
    epoch: 20_000,
    encryptedDescriptor: bytes(2, 4),
    requestedPolicy: bytes(2, 5),
    effectivePolicy: bytes(2, 6),
    policyDigest: bytes(32, 7),
    payloadKey: reserved.payloadKey,
    payloadLength: 3,
    payloadDigest: bytes(32, 8),
    operationId,
    operationDigest,
    createdAt: 11,
    expiresAt: 100,
  });
  assert.equal(published.idempotent, false);
  assert.equal(
    (
      await repository.reserveDelivery({
        capabilityId: 'capability',
        operationId,
        operationDigest,
        payloadLength: 3,
        now: 12,
        expiresAt: 100,
      })
    ).existing.id,
    reserved.deliveryId,
  );
  assert.equal(
    (
      await repository.queryInbox({
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        dataSlots: [{ slot: lookup, epoch: 20_000 }],
        controlSlots: [],
        now: 12,
      })
    ).delivery.id,
    reserved.deliveryId,
  );
  const completion = {
    id: reserved.deliveryId,
    operationId: bytes(16, 9),
    operationDigest: bytes(32, 10),
    completionDigest: bytes(32, 11),
    result: 0,
    now: 13,
  };
  assert.equal(
    (await repository.completeDelivery(completion)).idempotent,
    false,
  );
  assert.equal(
    (await repository.completeDelivery(completion)).idempotent,
    true,
  );
  const acknowledgement = {
    id: 'completion-control',
    relationshipId: 'relationship',
    direction: 'invitee->inviter',
    slot: bytes(16, 12),
    epoch: 20_000,
    encryptedEnvelope: bytes(2, 13),
    operationId: bytes(16, 14),
    operationDigest: bytes(32, 15),
    sequence: 0,
    createdAt: 14,
    expiresAt: 100,
  };
  assert.equal(
    (
      await repository.completeDeliveryWithControl({
        completion,
        event: acknowledgement,
      })
    ).idempotent,
    false,
  );
  assert.equal(
    (
      await repository.completeDeliveryWithControl({
        completion,
        event: acknowledgement,
      })
    ).idempotent,
    true,
  );
  const maintenance = await repository.runMaintenance(101, 4);
  assert.deepEqual(maintenance.expiredDeliveryIds, [reserved.deliveryId]);
  assert.deepEqual(maintenance.expiredBodyKeys, [reserved.payloadKey]);
  repository.close();
});

test('SQLite granular pairing activation and relationship reissue stay out of legacy state', async (t) => {
  const repository = new SQLiteV2Repository(
    await mkdtemp(join(tmpdir(), 'dud-v2-pairing-sqlite-')),
  );
  t.after(() => repository.close());
  await repository.initialize();
  const locator = 'a'.repeat(64);
  const invitation = {
    locator,
    phase: 0,
    createdAt: 10,
    expiresAt: 100,
    value: bytes(32, 50),
  };
  assert.equal(
    await repository.admit({
      record: invitation,
      sourceKey: 'source',
      minute: 0,
      globalMaximum: 2,
      sourceMaximum: 2,
      pendingMaximum: 2,
      now: 10,
    }),
    true,
  );
  const record = await repository.find(locator);
  assert.equal(record?.revision, 0);
  await repository.createRelationship({
    id: 'relationship',
    canonicalOrigin: 'https://example.test',
    encryptedState: bytes(32, 60),
    createdAt: 11,
  });
  const reissue = (nonce, minute) =>
    repository.commitCapabilityReissue({
      relationshipId: 'relationship',
      nonce,
      nonceExpiresAt: 90,
      now: 11,
      minute,
      maximumRequestsPerMinute: 1,
      revocations: [],
      registrations: [],
    });
  assert.equal(await reissue(bytes(16, 70), 0), 'accepted');
  assert.equal(await reissue(bytes(16, 71), 0), 'rate_limited');
  // The rejected request released its nonce, so the same one still commits in
  // the next window.
  assert.equal(await reissue(bytes(16, 71), 1), 'accepted');
  assert.equal(await reissue(bytes(16, 71), 2), 'replayed');
  await repository.activate({
    record,
    invitationValue: bytes(32, 80),
    relationship: {
      id: 'relationship',
      canonicalOrigin: 'https://example.test',
      encryptedState: bytes(32, 81),
      createdAt: 11,
    },
    registrations: [
      {
        capability: {
          id: 'pairing-capability',
          relationshipId: 'relationship',
          direction: 'inviter->invitee',
          scope: 'write',
          encryptedTokenSecret: 'opaque',
          createdAt: 11,
          expiresAt: 100,
        },
        lookupId: bytes(16, 90),
        epoch: 0,
      },
    ],
  });
  assert.equal(
    (await repository.findCapabilityLookup(bytes(16, 90), 0))?.id,
    'pairing-capability',
  );
});
