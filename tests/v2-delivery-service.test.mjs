// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// End-to-end behavior of the granular delivery handler: staged publication,
// batched control queries, completion, inline control events, and the uniform
// rejections every backend must produce.

import assert from 'node:assert/strict';
import test from 'node:test';

import { deriveV2DailyCapabilityLookupId } from '../dist/src/v2-auth.js';
import { decodeV2InboxResponseFrame } from '../dist/src/v2-delivery-frame.js';
import { D1V2Repository } from '../dist/src/v2-d1-repository.js';
import {
  MemoryV2BodyStore,
  MemoryV2Repository,
} from '../dist/src/v2-memory-repository.js';
import { sha256 } from '../dist/src/sha256.js';
import { R2V2BodyStore } from '../dist/src/v2-r2.js';
import { createMigratedLocalD1, LocalD1Database } from './d1-local.mjs';
import {
  attachHandler,
  buildDeliveryRequest,
  createDeliveryFixture,
  decodeBody,
  fill,
  hex,
  registerCapability,
  V2_CONTROL_SLOT,
  V2_EPOCH,
  V2_NOW,
  V2_REPOSITORY_BACKENDS,
  V2_SIGNED_DESCRIPTOR_DIGEST,
  V2_TOKENS,
  requestedPolicy,
} from './v2-delivery-fixtures.mjs';
import { MockR2Bucket } from './v2-helpers.mjs';

const MEMORY_BACKEND = V2_REPOSITORY_BACKENDS[0][1];

test('delivery admission enforces the configured encrypted descriptor limit', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND, {
    handler: { maximumDescriptorBytes: 3 },
  });
  const oversized = await fixture.route(
    await buildDeliveryRequest({
      encryptedDescriptor: Uint8Array.of(1, 2, 3, 4),
    }),
    '/v2/deliveries',
  );
  assert.equal(oversized.status, 400);

  const accepted = await fixture.deliver({
    encryptedDescriptor: Uint8Array.of(1, 2, 3),
    nonce: fill(201),
  });
  assert.equal(accepted.status, 200);
});

test('delivery admission enforces the configured encrypted payload limit', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND, {
    handler: { maximumObjectBytes: 3 },
  });
  assert.equal(
    (await fixture.deliver({ payload: Uint8Array.of(1, 2, 3, 4) })).status,
    400,
  );
  assert.equal(
    (
      await fixture.deliver({
        payload: Uint8Array.of(1, 2, 3),
        nonce: fill(202),
      })
    ).status,
    200,
  );
});

test('delivery retention enforces the configured maximum TTL', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND, {
    handler: { maximumTtlSeconds: 3 },
  });
  assert.equal(
    (await fixture.deliver({ policy: requestedPolicy(V2_NOW + 60) })).status,
    200,
  );
  fixture.setNow(V2_NOW + 4);
  const inbox = decodeV2InboxResponseFrame(
    new Uint8Array(await (await fixture.inbox()).arrayBuffer()),
  );
  assert.equal(inbox.header.has(3), false);
});

test('atomic delivery stages and publishes only after proof verification', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND);
  const response = await fixture.deliver();
  assert.equal(response.status, 200);
  const result = await decodeBody(response);
  const id = hex(result.get(1));
  assert.equal(result.get(3), false);
  assert.equal(await fixture.bodyStore.head(`deliveries/${id}.bin`), true);
  const retry = await fixture.deliver({ nonce: fill(2) });
  assert.equal(retry.status, 200);
  assert.equal((await decodeBody(retry)).get(3), true);
  await fixture.repository.publishControlEvent({
    id: 'a'.repeat(32),
    relationshipId: fixture.relationshipId,
    direction: 'inviter->invitee',
    slot: V2_CONTROL_SLOT,
    epoch: V2_EPOCH,
    encryptedEnvelope: Uint8Array.of(10, 11),
    operationId: fill(12),
    operationDigest: fill(13, 32),
    sequence: 0,
    createdAt: V2_NOW,
    expiresAt: V2_NOW + 60,
  });
  const deliveryWithControl = await fixture.deliver({
    nonce: fill(4),
    controlQueries: [
      { tokenSecret: V2_TOKENS.read, slot: V2_CONTROL_SLOT, nonce: fill(5) },
    ],
  });
  assert.equal(deliveryWithControl.status, 200);
  assert.equal((await decodeBody(deliveryWithControl)).get(5).length, 1);
  const inbox = await fixture.inbox();
  assert.equal(inbox.status, 200);
  const received = decodeV2InboxResponseFrame(
    new Uint8Array(await inbox.arrayBuffer()),
  );
  assert.deepEqual(received.payload, Uint8Array.of(7, 8, 9));
  assert.equal(received.header.get(3).byteLength, 16);
  const replayedInbox = await fixture.inbox();
  assert.equal(replayedInbox.status, 409);
  const completed = await fixture.complete({
    deliveryId: id,
    ackNonce: fill(7),
    controlNonce: fill(8),
  });
  assert.equal(completed.status, 200);
  assert.equal((await decodeBody(completed)).get(3), false);
  const completionRetry = await fixture.complete({
    deliveryId: id,
    ackNonce: fill(9),
    controlNonce: fill(10),
  });
  assert.equal(completionRetry.status, 200);
  assert.equal((await decodeBody(completionRetry)).get(3), true);
});

test('completion accepts the signed descriptor digest a receiver actually holds', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND);
  const published = await fixture.deliver();
  assert.equal(published.status, 200);
  const id = hex((await decodeBody(published)).get(1));

  // A real receiver decrypts the descriptor and sends SHA-256 of its signed map.
  // The server holds only the ciphertext, so it must not require the two to
  // agree; requiring it rejected every completion with error 3.
  assert.notDeepEqual(
    V2_SIGNED_DESCRIPTOR_DIGEST,
    sha256(Uint8Array.of(1, 2, 3)),
  );
  const completed = await fixture.complete({
    deliveryId: id,
    ackNonce: fill(11),
    controlNonce: fill(12),
  });
  assert.equal(completed.status, 200);
  assert.equal((await decodeBody(completed)).get(3), false);

  // The digest still binds the completion through the operation digest: a
  // replay carrying it is idempotent, while a different descriptor digest under
  // the same operation ID is rejected rather than completing a second time.
  const replay = await fixture.complete({
    deliveryId: id,
    ackNonce: fill(13),
    controlNonce: fill(14),
  });
  assert.equal(replay.status, 200);
  assert.equal((await decodeBody(replay)).get(3), true);
  const forked = await fixture.complete({
    deliveryId: id,
    ackNonce: fill(15),
    controlNonce: fill(16),
    descriptorDigest: sha256(Uint8Array.of(4, 5, 6)),
  });
  assert.equal(forked.status, 409);
  assert.equal((await decodeBody(forked)).get(1), 5);
});

test('D1/R2 delivery handler reserves quota and preserves an idempotent retry', async (t) => {
  const database = await createMigratedLocalD1(t);
  const repository = new D1V2Repository(database);
  const bodies = new R2V2BodyStore(new MockR2Bucket());
  const lookup = await deriveV2DailyCapabilityLookupId(
    V2_TOKENS.write,
    V2_EPOCH,
  );
  const capability = await registerCapability(repository, {
    id: 'd1-write-capability',
    scope: 'write',
    direction: 'inviter->invitee',
    tokenSecret: V2_TOKENS.write,
    relationshipId: 'd1-relationship',
  });
  assert.equal(
    (await repository.findCapabilityLookup(lookup, V2_EPOCH))?.id,
    capability.id,
  );
  const fixture = attachHandler(repository, bodies, {
    handler: { maximumTotalBytes: 6 },
  });
  const first = await fixture.deliver({ nonce: fill(53) });
  assert.equal(first.status, 200);
  const restartedDatabase = new LocalD1Database(database.path);
  t.after(() => restartedDatabase.close());
  const restarted = attachHandler(
    new D1V2Repository(restartedDatabase),
    bodies,
    { handler: { maximumTotalBytes: 6 } },
  );
  const retry = await restarted.deliver({ nonce: fill(54) });
  assert.equal(retry.status, 200);
  assert.equal((await decodeBody(retry)).get(3), true);
  const [concurrentFirst, concurrentSecond] = await Promise.all([
    fixture.deliver({ nonce: fill(55), operationId: fill(10) }),
    restarted.deliver({ nonce: fill(56), operationId: fill(10) }),
  ]);
  assert.equal(concurrentFirst.status, 200);
  assert.equal(concurrentSecond.status, 200);
  const firstId = (await decodeBody(concurrentFirst)).get(1);
  const secondId = (await decodeBody(concurrentSecond)).get(1);
  assert.deepEqual(firstId, secondId);
});

test('inline control event verifies its write proof and is idempotent', async () => {
  const repository = new MemoryV2Repository();
  const controlToken = fill(41, 32);
  const controlSlot = fill(42);
  await registerCapability(repository, {
    id: 'inline-control-write',
    scope: 'write',
    direction: 'invitee->inviter',
    tokenSecret: controlToken,
    relationshipId: 'relationship',
  });
  const fixture = attachHandler(repository, new MemoryV2BodyStore());
  const request = (nonce, envelope) =>
    fixture.control({
      nonce,
      envelope,
      tokenSecret: controlToken,
      slot: controlSlot,
    });
  const first = await request(fill(47));
  assert.equal(first.status, 200);
  assert.equal((await decodeBody(first)).get(2), false);
  const retry = await request(fill(48));
  assert.equal(retry.status, 200);
  assert.equal((await decodeBody(retry)).get(2), true);
  // Reusing the operation ID with a different envelope is the caller's own
  // fork, so it is a conflict rather than a second control event.
  const forked = await request(fill(49), Uint8Array.of(45, 47));
  assert.equal(forked.status, 409);
  assert.equal((await decodeBody(forked)).get(1), 5);
});

for (const [name, createRepository] of V2_REPOSITORY_BACKENDS) {
  test(`${name} reports a reused delivery operation ID as a conflict`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      relationshipId: 'conflict-relationship',
    });
    const operationId = fill(71);
    const publish = (seed, encryptedDescriptor) =>
      fixture.deliver({
        nonce: fill(seed),
        operationId,
        ...(encryptedDescriptor ? { encryptedDescriptor } : {}),
      });

    assert.equal((await publish(72)).status, 200);
    const idempotent = await publish(73);
    assert.equal(idempotent.status, 200);
    assert.equal((await decodeBody(idempotent)).get(3), true);

    // The same operation ID carrying a different descriptor is a fork of the
    // caller's own publication, not a malformed request.
    const forked = await publish(74, Uint8Array.of(1, 2, 4));
    assert.equal(forked.status, 409);
    const body = await decodeBody(forked);
    assert.equal(body.get(1), 5);
    assert.match(body.get(2), /conflicts with a prior request/);
  });
}

for (const [name, createRepository] of V2_REPOSITORY_BACKENDS) {
  test(`${name} delivery rejections are indistinguishable to a caller`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      relationshipId: 'reject-relationship',
      handler: {
        maximumTotalBytes: 3,
        maximumRequestsPerMinute: 2,
        maximumPendingDeliveries: 1,
      },
    });
    const publish = (seed, overrides) =>
      fixture.deliver({
        nonce: fill(seed),
        operationId: fill(seed),
        ...overrides,
      });
    const describe = async (response) => [
      response.status,
      response.headers.get('content-type'),
      hex(new Uint8Array(await response.arrayBuffer())),
    ];

    // An unregistered lookup, a proof signed with the wrong secret and a proof
    // bound to another scope are one response, so no caller can probe which
    // capability lookups a relationship holds.
    const foreign = Uint8Array.from(V2_TOKENS.write, (byte) => byte ^ 0xff);
    const unregistered = await describe(
      await publish(61, { tokenSecret: foreign }),
    );
    const forgedProof = await describe(
      await publish(62, {
        tokenSecret: foreign,
        lookupSecret: V2_TOKENS.write,
      }),
    );
    const wrongScope = await describe(await publish(63, { scope: 'read' }));
    assert.equal(unregistered[0], 401);
    assert.deepEqual(forgedProof, unregistered);
    assert.deepEqual(wrongScope, unregistered);

    // Rejections after a proven proof stay uniform too, so quota, rate and
    // replay state never leaks back to the holder of a valid capability.
    const accepted = await publish(64);
    assert.equal(accepted.status, 200);
    const replayed = await describe(
      await fixture.deliver({ nonce: fill(64), operationId: fill(65) }),
    );
    const quotaExhausted = await describe(await publish(66));
    const rateLimited = await describe(await publish(67));
    assert.equal(replayed[0], 400);
    assert.deepEqual(quotaExhausted, replayed);
    assert.deepEqual(rateLimited, replayed);
    assert.notDeepEqual(replayed, unregistered);
  });
}

// The refusal a caller sees is uniform on purpose, so quota, replay, and
// capability state never leak back to a proven capability holder. That leaves
// an operator with nothing to debug from, which is what this hook fixes: the
// reason reaches the log while the wire response stays exactly as it was.
test('a refused v2 request reports its reason to the operator only', async (t) => {
  const rejections = [];
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND, {
    capabilityExpiresAt: V2_NOW - 1,
    handler: {
      observeRejection: (rejection) => rejections.push(rejection),
    },
  });

  const inbox = await fixture.inbox();
  assert.equal(inbox.status, 400);
  const body = await decodeBody(inbox);
  assert.equal(body.get(1), 1);
  assert.equal(body.get(2), 'Inbox request is invalid.');

  assert.equal(rejections.length, 1);
  assert.equal(rejections[0].route, '/v2/inbox');
  assert.match(rejections[0].reason, /capability is not active/i);
});

test('an operation-ID conflict stays a distinct code and is not logged as a refusal', async (t) => {
  const rejections = [];
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND, {
    handler: {
      observeRejection: (rejection) => rejections.push(rejection),
    },
  });
  assert.equal((await fixture.deliver()).status, 200);
  // Same operation ID, different bytes: the caller must see the fork rather
  // than the uniform refusal.
  const conflict = await fixture.deliver({
    nonce: fill(31),
    payload: Uint8Array.of(1, 2, 3, 4),
  });
  assert.equal((await decodeBody(conflict)).get(1), 5);
  assert.deepEqual(rejections, []);
});
