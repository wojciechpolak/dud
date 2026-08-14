// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// The core V2 invariants, proved against every repository backend. Each test
// states one property the release depends on; a backend that cannot uphold it
// fails here rather than in production.

import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeCbor, encodeCbor } from '../dist/src/cbor.js';
import { decodeV2InboxResponseFrame } from '../dist/src/v2-delivery-frame.js';
import { sha256 } from '../dist/src/sha256.js';
import {
  createDeliveryFixture,
  decodeBody,
  fill,
  hex,
  requestedPolicy,
  V2_DATA_SLOT,
  V2_EPOCH,
  V2_NOW,
  V2_RELATIONSHIP_CAPABILITIES,
  V2_REPOSITORY_BACKENDS,
  V2_TOKENS,
  V2_TARGET_SLOT,
} from './v2-delivery-fixtures.mjs';

const DELIVERY_RESPONSE = { id: 1, policy: 2, idempotent: 3, events: 5 };
const COMPLETION_RESPONSE = { id: 1, controlEventId: 2, idempotent: 3 };

async function publishOne(fixture, options = {}) {
  const response = await fixture.deliver(options);
  assert.equal(response.status, 200, 'delivery was not accepted');
  const body = await decodeBody(response);
  return { id: hex(body.get(DELIVERY_RESPONSE.id)), body };
}

async function readInbox(fixture, options) {
  const response = await fixture.inbox(options);
  assert.equal(response.status, 200, 'inbox was not accepted');
  return decodeV2InboxResponseFrame(
    new Uint8Array(await response.arrayBuffer()),
  );
}

for (const [name, createRepository] of V2_REPOSITORY_BACKENDS) {
  test(`${name} inbox reads never consume a delivery`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const { id } = await publishOne(fixture);

    // Reading the same slot repeatedly must keep returning the delivery: only
    // completion removes it, so a client that crashes mid-receive can retry.
    for (const nonce of [fill(31), fill(32), fill(33)]) {
      const frame = await readInbox(fixture, { nonce });
      assert.equal(hex(frame.header.get(3)), id, 'inbox stopped returning it');
      assert.deepEqual(frame.payload, Uint8Array.of(7, 8, 9));
    }

    await fixture.complete({
      deliveryId: id,
      ackNonce: fill(34),
      controlNonce: fill(35),
    });

    // Only after completion does the slot drain.
    const drained = await readInbox(fixture, { nonce: fill(36) });
    assert.equal(drained.header.has(3), false, 'completion left the delivery');
    assert.equal(drained.payload.byteLength, 0);
  });

  test(`${name} a duplicate completion cannot duplicate its control event`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const { id } = await publishOne(fixture);

    const first = await fixture.complete({
      deliveryId: id,
      ackNonce: fill(41),
      controlNonce: fill(42),
    });
    assert.equal(first.status, 200);
    const firstBody = await decodeBody(first);
    assert.equal(firstBody.get(COMPLETION_RESPONSE.idempotent), false);

    const retry = await fixture.complete({
      deliveryId: id,
      ackNonce: fill(43),
      controlNonce: fill(44),
    });
    assert.equal(retry.status, 200);
    const retryBody = await decodeBody(retry);
    assert.equal(retryBody.get(COMPLETION_RESPONSE.idempotent), true);
    assert.deepEqual(
      retryBody.get(COMPLETION_RESPONSE.controlEventId),
      firstBody.get(COMPLETION_RESPONSE.controlEventId),
      'the retry minted a second control event',
    );

    // The peer's control slot must hold exactly the one acknowledgement.
    const events = await fixture.repository.queryInbox({
      relationshipId: fixture.relationshipId,
      direction: 'invitee->inviter',
      dataSlots: [],
      controlSlots: [{ slot: V2_TARGET_SLOT, epoch: V2_EPOCH }],
      now: V2_NOW,
    });
    assert.equal(
      events.controlEvents.length,
      1,
      'a duplicate completion produced a second control event',
    );
  });

  test(`${name} retains completed deliveries in the object quota until expiry cleanup`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      capabilityExpiresAt: V2_NOW + 600,
      handler: { maximumObjectsPerCapability: 1 },
    });
    const { id } = await publishOne(fixture, {
      nonce: fill(45),
      operationId: fill(46),
    });
    assert.equal(
      (
        await fixture.complete({
          deliveryId: id,
          ackNonce: fill(47),
          controlNonce: fill(48),
        })
      ).status,
      200,
    );
    const exhausted = await fixture.deliver({
      nonce: fill(49),
      operationId: fill(50),
    });
    assert.equal(exhausted.status, 400);

    fixture.setNow(V2_NOW + 61);
    await fixture.repository.runMaintenance(fixture.now(), 10);
    const admitted = await fixture.deliver({
      nonce: fill(51),
      operationId: fill(52),
      policy: requestedPolicy(V2_NOW + 120),
      proofExpiresAt: V2_NOW + 120,
    });
    assert.equal(
      admitted.status,
      200,
      'expiry cleanup did not restore capacity',
    );
  });

  test(`${name} refuses an invalid proof before writing ciphertext when staging is full`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      handler: { maximumConcurrentUploads: 1, maximumStagedBytes: 3 },
    });
    await fixture.repository.reserveStagedBody({
      id: 'a'.repeat(32),
      expiresAt: V2_NOW + 60,
      now: V2_NOW,
      reservedBytes: 3,
      maximumConcurrentUploads: 1,
      maximumStagedBytes: 3,
    });
    let writes = 0;
    const put = fixture.bodyStore.put.bind(fixture.bodyStore);
    fixture.bodyStore.put = async (...args) => {
      writes++;
      return put(...args);
    };
    const refused = await fixture.deliver({
      tokenSecret: fill(0xee, 32),
      lookupSecret: V2_TOKENS.write,
    });
    assert.equal(refused.status, 400);
    assert.equal(writes, 0, 'invalid ciphertext reached persistent staging');

    await fixture.repository.releaseStagedBody('a'.repeat(32));
    const accepted = await fixture.deliver({
      nonce: fill(53),
      operationId: fill(54),
    });
    assert.equal(accepted.status, 200);
    assert.equal(writes, 1, 'a legitimate upload did not reach staging');
  });

  test(`${name} a retry preserves operation bytes while refreshing its nonce`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const operationId = fill(51);
    const first = await publishOne(fixture, { nonce: fill(52), operationId });
    assert.equal(first.body.get(DELIVERY_RESPONSE.idempotent), false);

    // A fresh proof nonce over the identical operation is the retry contract.
    const retry = await publishOne(fixture, { nonce: fill(53), operationId });
    assert.equal(retry.body.get(DELIVERY_RESPONSE.idempotent), true);
    assert.equal(retry.id, first.id, 'the retry minted a second delivery');
    assert.equal(
      await fixture.bodyStore.head(`deliveries/${first.id}.bin`),
      true,
    );

    // Reusing the spent nonce is a replay and never reaches the operation.
    const replayed = await fixture.deliver({ nonce: fill(52), operationId });
    assert.equal(replayed.status, 400);

    // Changing a single operation byte under the same ID is the caller's own
    // fork, reported as a conflict rather than silently accepted.
    const forked = await fixture.deliver({
      nonce: fill(54),
      operationId,
      encryptedDescriptor: Uint8Array.of(1, 2, 4),
    });
    assert.equal(forked.status, 409);
    assert.equal((await decodeBody(forked)).get(1), 5);
  });

  test(`${name} an inline control event replays idempotently`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const operationId = fill(61);
    const first = await fixture.control({ nonce: fill(62), operationId });
    assert.equal(first.status, 200);
    const firstBody = await decodeBody(first);
    assert.equal(firstBody.get(2), false);

    const retry = await fixture.control({ nonce: fill(63), operationId });
    assert.equal(retry.status, 200);
    const retryBody = await decodeBody(retry);
    assert.equal(retryBody.get(2), true);
    assert.deepEqual(retryBody.get(1), firstBody.get(1));

    const events = await fixture.repository.queryInbox({
      relationshipId: fixture.relationshipId,
      direction: 'invitee->inviter',
      dataSlots: [],
      controlSlots: [{ slot: V2_TARGET_SLOT, epoch: V2_EPOCH }],
      now: V2_NOW,
    });
    assert.equal(events.controlEvents.length, 1, 'replay duplicated the event');
  });

  test(`${name} bounds pending control storage and inbox batches`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      handler: {
        maximumPendingControlEvents: 2,
        maximumControlEventBytes: 4,
        maximumInboxControlEvents: 1,
        maximumInboxControlBytes: 2,
      },
    });
    for (const [nonce, operationId, envelope] of [
      [fill(64), fill(65), Uint8Array.of(1, 2)],
      [fill(66), fill(67), Uint8Array.of(3, 4)],
    ]) {
      assert.equal(
        (await fixture.control({ nonce, operationId, envelope })).status,
        200,
      );
    }
    const exhausted = await fixture.control({
      nonce: fill(68),
      operationId: fill(69),
      envelope: Uint8Array.of(5),
    });
    assert.equal(exhausted.status, 400, 'control quota accepted a third event');

    const frame = await readInbox(fixture, {
      nonce: fill(70),
      tokenSecret: V2_TOKENS.peerRead,
      direction: 'invitee->inviter',
      slot: V2_TARGET_SLOT,
      controlSlots: [
        {
          nonce: fill(71),
          tokenSecret: V2_TOKENS.peerRead,
          direction: 'invitee->inviter',
          slot: V2_TARGET_SLOT,
        },
      ],
    });
    assert.equal(
      frame.header.get(2).length,
      1,
      'inbox materialized more than its bounded control batch',
    );
  });

  test(`${name} effective policy can only tighten expiry, never extend it`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      // A capability that outlives the sender's own requested expiry: without
      // dominance the delivery would sit in the slot long after it expired.
      capabilityExpiresAt: V2_NOW + 86_400,
    });
    const signedExpiry = V2_NOW + 30;
    const policy = requestedPolicy(signedExpiry);
    const { id } = await publishOne(fixture, { policy });

    // The stored effective policy is the signed map, unchanged.
    const frame = await readInbox(fixture, { nonce: fill(71) });
    assert.deepEqual(frame.header.get(6), policy);

    // And the server-visible expiry is no later than the signed one.
    const stored = await fixture.repository.findDelivery(id);
    assert.ok(stored, 'delivery was not stored');
    assert.ok(
      stored.expiresAt <= signedExpiry,
      `server expiry ${stored.expiresAt} outlives the signed ${signedExpiry}`,
    );

    // Past the signed expiry the delivery is no longer served, even though the
    // capability and the deployment TTL cap would both still allow it.
    fixture.setNow(signedExpiry + 1);
    const afterExpiry = await readInbox(fixture, { nonce: fill(72) });
    assert.equal(
      afterExpiry.header.has(3),
      false,
      'a delivery outlived the expiry its sender signed',
    );
  });

  test(`${name} revocation blocks every later relationship operation`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const { id } = await publishOne(fixture, { nonce: fill(81) });

    // Revoke every tuple the relationship holds, which is what an
    // administrative revocation does through the shared repository contract.
    await fixture.repository.replaceCapabilities({
      revocations: V2_RELATIONSHIP_CAPABILITIES.map(({ direction, scope }) => ({
        relationshipId: fixture.relationshipId,
        direction,
        scope,
      })),
      registrations: [],
      now: V2_NOW,
    });

    // Every authenticated surface must refuse: delivery, inbox, completion of
    // an already-published delivery, and inline control.
    const rejected = [
      await fixture.deliver({ nonce: fill(82), operationId: fill(83) }),
      await fixture.inbox({ nonce: fill(84) }),
      await fixture.complete({
        deliveryId: id,
        ackNonce: fill(85),
        controlNonce: fill(86),
      }),
      await fixture.control({ nonce: fill(87), operationId: fill(88) }),
    ];
    for (const response of rejected) {
      assert.ok(
        response.status >= 400,
        `a revoked relationship still served ${response.url}`,
      );
    }
  });
}

test('output and chain state are durable before a completion is accepted', async (t) => {
  // Completion is what tells a sender its delivery was committed, so nothing
  // may become completable before the body and its metadata are both durable.
  const fixture = await createDeliveryFixture(t, V2_REPOSITORY_BACKENDS[1][1]);
  const { id } = await publishOne(fixture, { nonce: fill(91) });

  const stored = await fixture.repository.findDelivery(id);
  assert.ok(stored, 'delivery metadata was not durable at publication');
  assert.equal(
    await fixture.bodyStore.head(stored.payloadKey),
    true,
    'delivery body was not durable at publication',
  );
  assert.deepEqual(stored.payloadDigest, sha256(Uint8Array.of(7, 8, 9)));
  assert.equal(stored.payloadLength, 3);

  // A completion naming a delivery that was never published finds nothing to
  // complete, so a sender can never be told about an output that does not exist.
  const missing = await fixture.complete({
    deliveryId: 'f'.repeat(32),
    ackNonce: fill(92),
    controlNonce: fill(93),
  });
  assert.ok(missing.status >= 400);
});

test('a completion bound to another policy digest is refused', async (t) => {
  const fixture = await createDeliveryFixture(t, V2_REPOSITORY_BACKENDS[0][1]);
  const { id } = await publishOne(fixture, { nonce: fill(95) });
  const refused = await fixture.complete({
    deliveryId: id,
    ackNonce: fill(96),
    controlNonce: fill(97),
    // The signed policy the receiver claims to have seen differs from the one
    // the sender published, so the two disagree about the transport contract.
    policy: requestedPolicy(V2_NOW + 61),
  });
  assert.ok(refused.status >= 400);
  assert.notEqual(
    hex(sha256(encodeCbor(requestedPolicy(V2_NOW + 61)))),
    hex(sha256(encodeCbor(requestedPolicy()))),
  );

  // The delivery survives the refusal and is still completable on the real
  // policy digest, so a mismatched retry cannot strand it.
  const accepted = await fixture.complete({
    deliveryId: id,
    ackNonce: fill(98),
    controlNonce: fill(99),
  });
  assert.equal(accepted.status, 200);
});

test('an inbox read reports the delivery slot it was authorized for', async (t) => {
  const fixture = await createDeliveryFixture(t, V2_REPOSITORY_BACKENDS[0][1]);
  await publishOne(fixture, { nonce: fill(101) });
  const frame = await readInbox(fixture, { nonce: fill(102) });
  assert.deepEqual(frame.header.get(4), V2_DATA_SLOT);
  const slotResults = frame.header.get(1);
  assert.equal(slotResults.length, 1);
  assert.deepEqual(slotResults[0].get(1), V2_DATA_SLOT);
  assert.equal(slotResults[0].get(2), V2_EPOCH);
  // A response never carries a decodable descriptor: the server holds only
  // ciphertext, which must stay opaque bytes on the wire.
  assert.ok(frame.header.get(5) instanceof Uint8Array);
  assert.throws(() => decodeCbor(frame.header.get(5)));
});
