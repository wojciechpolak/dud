// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  MemoryV2BodyStore,
  MemoryV2Repository,
} from '../dist/src/v2-memory-repository.js';
import { sha256 } from '../dist/src/sha256.js';

const bytes = (length, seed = 0) =>
  Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);

function delivery(id, operationId, createdAt) {
  return {
    id,
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    slot: bytes(16, 10),
    epoch: 20_000,
    encryptedDescriptor: bytes(3, 20),
    requestedPolicy: bytes(2, 30),
    effectivePolicy: bytes(2, 40),
    policyDigest: bytes(32, 50),
    payloadKey: `deliveries/${id}.bin`,
    payloadLength: 3,
    payloadDigest: bytes(32, 60),
    operationId,
    operationDigest: bytes(32, 70),
    createdAt,
    expiresAt: 2_000,
  };
}

test('memory V2 body store verifies opaque body length and digest', async () => {
  const store = new MemoryV2BodyStore();
  const body = Uint8Array.of(1, 2, 3);
  const stream = () =>
    new ReadableStream({
      start(controller) {
        controller.enqueue(body);
        controller.close();
      },
    });
  await store.put('deliveries/test.bin', stream(), 3, sha256(body));
  const object = await store.get('deliveries/test.bin');
  assert.deepEqual(
    new Uint8Array(await new Response(object.body).arrayBuffer()),
    body,
  );
  await assert.rejects(
    store.put('deliveries/bad.bin', stream(), 2, sha256(body)),
  );
  assert.equal(await store.head('deliveries/bad.bin'), false);
});

test('memory V2 body store stages before promoting a delivery', async () => {
  const store = new MemoryV2BodyStore();
  const body = Uint8Array.of(4, 5, 6);
  const staged = await store.stage(
    new ReadableStream({
      start(controller) {
        controller.enqueue(body);
        controller.close();
      },
    }),
    body.byteLength,
    sha256(body),
  );
  const key = `deliveries/${'c'.repeat(32)}.bin`;
  await store.promote(staged, key);
  assert.equal(await store.head(staged), false);
  const object = await store.get(key);
  assert.ok(object);
  assert.deepEqual(
    new Uint8Array(await new Response(object.body).arrayBuffer()),
    body,
  );
});

test('memory repository enforces lookup, nonce, publication and completion idempotency', async () => {
  const repository = new MemoryV2Repository();
  const lookup = bytes(16, 1);
  repository.addCapability(
    {
      id: 'capability',
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 2_000,
    },
    lookup,
    20_000,
  );
  assert.equal(
    (await repository.findCapabilityLookup(lookup, 20_000)).id,
    'capability',
  );
  assert.equal(
    await repository.claimNonce('capability', bytes(16, 2), 100, 10),
    true,
  );
  assert.equal(
    await repository.claimNonce('capability', bytes(16, 2), 100, 10),
    false,
  );

  const operationId = bytes(16, 3);
  const reserved = await repository.reserveDelivery({
    capabilityId: 'capability',
    operationId,
    operationDigest: bytes(32, 70),
    payloadLength: 3,
    now: 10,
    expiresAt: 2_000,
  });
  assert.ok('deliveryId' in reserved);
  const retriedReservation = await repository.reserveDelivery({
    capabilityId: 'capability',
    operationId,
    operationDigest: bytes(32, 70),
    payloadLength: 3,
    now: 11,
    expiresAt: 2_000,
  });
  assert.deepEqual(retriedReservation, reserved);
  const published = await repository.publishDelivery({
    ...delivery(reserved.deliveryId, operationId, 20),
    payloadKey: reserved.payloadKey,
  });
  assert.equal(published.idempotent, false);
  assert.equal(
    (
      await repository.publishDelivery({
        ...delivery(reserved.deliveryId, operationId, 20),
        payloadKey: reserved.payloadKey,
      })
    ).idempotent,
    true,
  );
  const completion = {
    id: reserved.deliveryId,
    operationId: bytes(16, 4),
    operationDigest: bytes(32, 5),
    completionDigest: bytes(32, 6),
    result: 0,
    now: 30,
  };
  const acknowledgement = {
    id: 'completion-control',
    relationshipId: 'relationship',
    direction: 'invitee->inviter',
    slot: bytes(16, 7),
    epoch: 20_000,
    encryptedEnvelope: bytes(3, 8),
    operationId: bytes(16, 9),
    operationDigest: bytes(32, 10),
    sequence: 0,
    createdAt: 30,
    expiresAt: 2_000,
  };
  const completed = await repository.completeDeliveryWithControl({
    completion,
    event: acknowledgement,
  });
  assert.equal(completed.idempotent, false);
  assert.equal(completed.event.sequence, 1);
  assert.equal(
    (
      await repository.completeDeliveryWithControl({
        completion,
        event: acknowledgement,
      })
    ).idempotent,
    true,
  );
  await assert.rejects(
    repository.completeDelivery({
      ...completion,
      operationId: bytes(16, 99),
    }),
    /conflicts/,
  );
  await assert.rejects(
    repository.publishControlEvent({
      ...acknowledgement,
      id: 'conflicting-control',
      operationDigest: bytes(32, 99),
    }),
    /conflicts/,
  );
  const nextOperation = bytes(16, 100);
  const nextReservation = await repository.reserveDelivery({
    capabilityId: 'capability',
    operationId: nextOperation,
    operationDigest: bytes(32, 101),
    payloadLength: 3,
    now: 31,
    expiresAt: 2_000,
  });
  assert.ok('deliveryId' in nextReservation);
  await repository.publishDelivery({
    ...delivery(nextReservation.deliveryId, nextOperation, 31),
    payloadKey: nextReservation.payloadKey,
    operationDigest: bytes(32, 101),
  });
  await assert.rejects(
    repository.completeDeliveryWithControl({
      completion: {
        ...completion,
        id: nextReservation.deliveryId,
        operationId: bytes(16, 102),
      },
      event: {
        ...acknowledgement,
        operationId: bytes(16, 103),
      },
    }),
    /conflicts/,
  );
  assert.equal(
    (await repository.findDelivery(nextReservation.deliveryId))?.state,
    'published',
  );
});

test('memory repository selects the oldest inbox entry and keeps reads non-consuming', async () => {
  const repository = new MemoryV2Repository();
  repository.addCapability(
    {
      id: 'capability',
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 2_000,
    },
    bytes(16, 1),
    20_000,
  );
  let oldestID = '';
  for (const [operation, createdAt] of [
    [8, 20],
    [9, 30],
  ]) {
    const operationId = bytes(16, operation);
    const reserved = await repository.reserveDelivery({
      capabilityId: 'capability',
      operationId,
      operationDigest: bytes(32, 70),
      payloadLength: 3,
      now: 10,
      expiresAt: 2_000,
    });
    await repository.publishDelivery({
      ...delivery(reserved.deliveryId, operationId, createdAt),
      payloadKey: reserved.payloadKey,
    });
    if (createdAt === 20) {
      oldestID = reserved.deliveryId;
    }
  }
  const inbox = await repository.queryInbox({
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    dataSlots: [{ slot: bytes(16, 10), epoch: 20_000 }],
    controlSlots: [],
    now: 100,
  });
  assert.equal(inbox.delivery.id, oldestID);
  assert.equal(
    (
      await repository.queryInbox({
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        dataSlots: [{ slot: bytes(16, 10), epoch: 20_000 }],
        controlSlots: [],
        now: 100,
      })
    ).delivery.id,
    oldestID,
  );
  const controlSlot = bytes(16, 90);
  await repository.publishControlEvent({
    id: 'control-event',
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    slot: controlSlot,
    epoch: 20_000,
    encryptedEnvelope: bytes(2, 91),
    operationId: bytes(16, 92),
    operationDigest: bytes(32, 93),
    sequence: 0,
    createdAt: 40,
    expiresAt: 2_000,
  });
  assert.deepEqual(
    (
      await repository.queryInbox({
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        dataSlots: [{ slot: bytes(16, 10), epoch: 20_000 }],
        controlSlots: [{ slot: controlSlot, epoch: 20_000 }],
        now: 100,
      })
    ).controlEvents.map((event) => event.id),
    ['control-event'],
  );
  await repository.publishControlEvent({
    id: 'other-control-event',
    relationshipId: 'other-relationship',
    direction: 'inviter->invitee',
    slot: controlSlot,
    epoch: 20_000,
    encryptedEnvelope: bytes(2, 94),
    operationId: bytes(16, 95),
    operationDigest: bytes(32, 96),
    sequence: 0,
    createdAt: 40,
    expiresAt: 2_000,
  });
  await repository.consumeControlEvents({
    ids: ['other-control-event'],
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    now: 101,
  });
  assert.deepEqual(
    (
      await repository.queryInbox({
        relationshipId: 'other-relationship',
        direction: 'inviter->invitee',
        dataSlots: [],
        controlSlots: [{ slot: controlSlot, epoch: 20_000 }],
        now: 102,
      })
    ).controlEvents.map((event) => event.id),
    ['other-control-event'],
  );
});
