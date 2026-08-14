// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Hostile-input coverage for the granular delivery surface: proof splicing and
// reordering, nonce replay on every authenticated endpoint, mixed relationship
// and direction proofs, rate and quota limits, and control consume-after-read
// timing.

import assert from 'node:assert/strict';
import test from 'node:test';

import { encodeCbor } from '../dist/src/cbor.js';
import {
  decodeV2ControlEventRequest,
  decodeV2DeliveryRequestFrame,
  decodeV2InboxRequest,
  decodeV2InboxResponseFrame,
  encodeV2DeliveryFrame,
  V2_CONTROL_EVENT_REQUEST_KEYS,
  V2_DELIVERY_REQUEST_KEYS,
  V2_INBOX_REQUEST_KEYS,
  V2_SLOT_PROOF_KEYS,
} from '../dist/src/v2-delivery-frame.js';
import { sha256 } from '../dist/src/sha256.js';
import {
  buildControlEventRequest,
  buildDeliveryRequest,
  buildInboxRequest,
  createDeliveryFixture,
  decodeBody,
  fill,
  hex,
  registerCapability,
  V2_CONTROL_SLOT,
  V2_DATA_SLOT,
  V2_EPOCH,
  V2_NOW,
  V2_ORIGIN,
  V2_REPOSITORY_BACKENDS,
  V2_TARGET_SLOT,
  V2_TOKENS,
} from './v2-delivery-fixtures.mjs';

const MALFORMED_ERROR = 1;
const AUTHORIZATION_ERROR = 3;
const MEMORY_BACKEND = V2_REPOSITORY_BACKENDS[0][1];

async function errorCode(response) {
  return (await decodeBody(response)).get(1);
}

/** Reads a built request back so a test can tamper with its bytes. */
async function bodyOf(request) {
  return new Uint8Array(await request.arrayBuffer());
}

/** Re-sends tampered bytes with headers the transport layer will accept. */
function resend(path, body) {
  return new Request(`${V2_ORIGIN}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/dud+cbor; version=2',
      'content-length': String(body.byteLength),
      ...(path === '/v2/deliveries'
        ? { 'dud-content-sha256': hex(sha256(body)) }
        : {}),
    },
    body,
  });
}

function reframe(frame, mutate) {
  const decoded = decodeV2DeliveryRequestFrame(frame);
  const header = new Map(decoded.header);
  mutate(header);
  return encodeV2DeliveryFrame(
    header,
    decoded.payload,
    V2_DELIVERY_REQUEST_KEYS.payloadLength,
    V2_DELIVERY_REQUEST_KEYS.payloadDigest,
  );
}

for (const [name, createRepository] of V2_REPOSITORY_BACKENDS) {
  test(`${name} refuses a proof spliced in from another request`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);

    // Two well-formed deliveries differing only in their descriptor. Lifting
    // the donor's proof into the target must fail: each proof commits to the
    // digest of the request that carries it.
    const donorFrame = await bodyOf(
      await buildDeliveryRequest({
        nonce: fill(11),
        operationId: fill(12),
        encryptedDescriptor: Uint8Array.of(9, 9, 9),
      }),
    );
    const donorProof = decodeV2DeliveryRequestFrame(donorFrame).header.get(
      V2_DELIVERY_REQUEST_KEYS.dataSlotProof,
    );
    const targetFrame = await bodyOf(
      await buildDeliveryRequest({ nonce: fill(13), operationId: fill(14) }),
    );
    const spliced = reframe(targetFrame, (header) => {
      header.set(V2_DELIVERY_REQUEST_KEYS.dataSlotProof, donorProof);
    });
    const response = await fixture.route(
      resend('/v2/deliveries', spliced),
      '/v2/deliveries',
    );
    assert.equal(response.status, 401, 'a spliced proof was accepted');
  });

  test(`${name} refuses a slot proof retargeted to another slot`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const frame = await bodyOf(
      await buildDeliveryRequest({ nonce: fill(15), operationId: fill(16) }),
    );
    const retargeted = reframe(frame, (header) => {
      const proof = new Map(header.get(V2_DELIVERY_REQUEST_KEYS.dataSlotProof));
      proof.set(
        V2_SLOT_PROOF_KEYS.slot,
        Uint8Array.from(V2_DATA_SLOT, (byte) => byte ^ 0x01),
      );
      header.set(V2_DELIVERY_REQUEST_KEYS.dataSlotProof, proof);
    });
    const response = await fixture.route(
      resend('/v2/deliveries', retargeted),
      '/v2/deliveries',
    );
    assert.equal(response.status, 401, 'a retargeted slot proof was accepted');
  });

  test(`${name} refuses reordered inbox proofs`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    // One data proof at position 0 and one control proof at position 1, then
    // the two arrays swapped. Each proof names the position it was built for.
    const request = await buildInboxRequest({
      nonce: fill(21),
      controlSlots: [{ slot: V2_CONTROL_SLOT, nonce: fill(22) }],
    });
    const header = new Map(decodeV2InboxRequest(await bodyOf(request)).header);
    const dataProofs = header.get(V2_INBOX_REQUEST_KEYS.dataSlotProofs);
    header.set(
      V2_INBOX_REQUEST_KEYS.dataSlotProofs,
      header.get(V2_INBOX_REQUEST_KEYS.controlSlotProofs),
    );
    header.set(V2_INBOX_REQUEST_KEYS.controlSlotProofs, dataProofs);
    const swapped = await fixture.route(
      resend('/v2/inbox', encodeCbor(header)),
      '/v2/inbox',
    );
    assert.ok(swapped.status >= 400, 'swapped proof positions were accepted');
  });

  test(`${name} refuses a replayed nonce on every authenticated endpoint`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);

    const deliveryNonce = fill(31);
    const published = await fixture.deliver({
      nonce: deliveryNonce,
      operationId: fill(32),
    });
    assert.equal(published.status, 200);
    const id = hex((await decodeBody(published)).get(1));

    // A replayed delivery nonce, even under a brand-new operation ID.
    assert.ok(
      (await fixture.deliver({ nonce: deliveryNonce, operationId: fill(33) }))
        .status >= 400,
      'delivery nonce replay accepted',
    );
    // And a replay of the exact original request, which the backends must
    // refuse identically rather than answering with the published delivery.
    assert.ok(
      (await fixture.deliver({ nonce: deliveryNonce, operationId: fill(32) }))
        .status >= 400,
      'exact delivery replay accepted',
    );

    const inboxNonce = fill(34);
    assert.equal((await fixture.inbox({ nonce: inboxNonce })).status, 200);
    assert.ok(
      (await fixture.inbox({ nonce: inboxNonce })).status >= 400,
      'inbox nonce replay accepted',
    );

    const controlNonce = fill(35);
    assert.equal(
      (await fixture.control({ nonce: controlNonce, operationId: fill(36) }))
        .status,
      200,
    );
    assert.ok(
      (await fixture.control({ nonce: controlNonce, operationId: fill(37) }))
        .status >= 400,
      'control nonce replay accepted',
    );

    const ackNonce = fill(38);
    assert.equal(
      (
        await fixture.complete({
          deliveryId: id,
          ackNonce,
          controlNonce: fill(39),
        })
      ).status,
      200,
    );
    assert.ok(
      (
        await fixture.complete({
          deliveryId: id,
          ackNonce,
          controlNonce: fill(40),
        })
      ).status >= 400,
      'completion nonce replay accepted',
    );
  });

  test(`${name} refuses a request that spends one nonce twice`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    // The same capability and nonce in two positions of one request: accepting
    // it would let a caller spend a single nonce on two operations.
    const shared = fill(41);
    const response = await fixture.inbox({
      nonce: shared,
      controlSlots: [{ slot: V2_CONTROL_SLOT, nonce: shared }],
    });
    assert.ok(response.status >= 400, 'a duplicated nonce was accepted');
  });

  test(`${name} refuses proofs mixing relationships or directions`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const foreignToken = Uint8Array.from(V2_TOKENS.read, (byte) => byte ^ 0x5a);
    await registerCapability(fixture.repository, {
      id: 'foreign-read-capability',
      scope: 'read',
      direction: 'inviter->invitee',
      tokenSecret: foreignToken,
      relationshipId: 'another-relationship',
    });

    // A control proof from a different relationship riding alongside a valid
    // data proof: no capability may speak for two peers.
    const crossRelationship = await fixture.inbox({
      nonce: fill(51),
      controlSlots: [
        {
          slot: V2_CONTROL_SLOT,
          nonce: fill(52),
          tokenSecret: foreignToken,
        },
      ],
    });
    assert.equal(crossRelationship.status, 403);
    assert.equal(await errorCode(crossRelationship), AUTHORIZATION_ERROR);

    // The same relationship in the opposite direction is equally invalid.
    const crossDirection = await fixture.inbox({
      nonce: fill(53),
      controlSlots: [
        {
          slot: V2_TARGET_SLOT,
          nonce: fill(54),
          tokenSecret: V2_TOKENS.peerRead,
          direction: 'invitee->inviter',
        },
      ],
    });
    assert.equal(crossDirection.status, 403);

    // The same guard covers control queries batched onto a delivery.
    const batchedDelivery = await fixture.deliver({
      nonce: fill(55),
      operationId: fill(56),
      controlQueries: [
        {
          slot: V2_CONTROL_SLOT,
          nonce: fill(57),
          tokenSecret: foreignToken,
          direction: 'inviter->invitee',
        },
      ],
    });
    assert.equal(batchedDelivery.status, 403);
  });

  test(`${name} enforces the relationship byte quota exactly`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      handler: { maximumTotalBytes: 6 },
    });
    // Two three-byte payloads fill the quota exactly; the third must not fit.
    assert.equal(
      (await fixture.deliver({ nonce: fill(61), operationId: fill(62) }))
        .status,
      200,
    );
    assert.equal(
      (await fixture.deliver({ nonce: fill(63), operationId: fill(64) }))
        .status,
      200,
    );
    const exceeded = await fixture.deliver({
      nonce: fill(65),
      operationId: fill(66),
    });
    assert.equal(exceeded.status, 400);
    assert.equal(await errorCode(exceeded), MALFORMED_ERROR);
  });

  test(`${name} enforces the per-capability request rate window`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      handler: { maximumRequestsPerMinute: 2 },
      capabilityExpiresAt: V2_NOW + 600,
    });
    assert.equal(
      (await fixture.deliver({ nonce: fill(71), operationId: fill(72) }))
        .status,
      200,
    );
    assert.equal(
      (await fixture.deliver({ nonce: fill(73), operationId: fill(74) }))
        .status,
      200,
    );
    assert.ok(
      (await fixture.deliver({ nonce: fill(75), operationId: fill(76) }))
        .status >= 400,
      'the rate window did not close',
    );

    // The window is per minute, so the next one admits requests again.
    fixture.setNow(V2_NOW + 60);
    assert.equal(
      (
        await fixture.deliver({
          nonce: fill(77),
          operationId: fill(78),
          proofExpiresAt: V2_NOW + 120,
        })
      ).status,
      200,
    );
  });

  test(`${name} authorizes across a slot epoch boundary in order`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository, {
      capabilityExpiresAt: V2_NOW + 172_800,
    });
    // A capability is published under one daily lookup per epoch it spans, so
    // a proof minted after the day rolls over still resolves to it. Without
    // the later epoch registered, the same proof is unauthorized.
    const nextEpoch = await fixture.deliver({
      nonce: fill(121),
      operationId: fill(122),
      epoch: V2_EPOCH + 1,
    });
    assert.equal(nextEpoch.status, 401);

    await registerCapability(
      fixture.repository,
      {
        id: 'write-capability',
        scope: 'write',
        direction: 'inviter->invitee',
        tokenSecret: V2_TOKENS.write,
        relationshipId: fixture.relationshipId,
        expiresAt: V2_NOW + 172_800,
      },
      V2_EPOCH + 1,
    );
    assert.equal(
      (
        await fixture.deliver({
          nonce: fill(123),
          operationId: fill(124),
          epoch: V2_EPOCH + 1,
        })
      ).status,
      200,
    );

    // The earlier epoch keeps working, so a rollover never strands a sender
    // whose proof was minted moments before midnight.
    assert.equal(
      (await fixture.deliver({ nonce: fill(125), operationId: fill(126) }))
        .status,
      200,
    );
  });

  test(`${name} consumes a control event only after the reader confirms it`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const publish = await fixture.control({
      nonce: fill(81),
      operationId: fill(82),
    });
    assert.equal(publish.status, 200);
    const eventId = (await decodeBody(publish)).get(1);

    // The peer reads its own direction: a data slot it owns, plus the control
    // slot the acknowledgement was published to.
    const read = async (nonce, processedControlEventIds = []) => {
      const response = await fixture.route(
        await buildInboxRequest({
          nonce,
          tokenSecret: V2_TOKENS.peerRead,
          direction: 'invitee->inviter',
          slot: V2_CONTROL_SLOT,
          controlSlots: [
            {
              slot: V2_TARGET_SLOT,
              nonce: Uint8Array.from(nonce, (byte) => byte ^ 0xff),
            },
          ],
          processedControlEventIds,
        }),
        '/v2/inbox',
      );
      assert.equal(response.status, 200);
      return decodeV2InboxResponseFrame(
        new Uint8Array(await response.arrayBuffer()),
      );
    };

    // Reading alone never consumes: a reader that crashes before committing
    // the event locally must still see it on the next poll.
    for (const nonce of [fill(83), fill(84)]) {
      const events = (await read(nonce)).header.get(2);
      assert.equal(events.length, 1, 'the control event was consumed on read');
      assert.deepEqual(events[0].get(1), eventId);
    }

    // Naming the event as processed is what retires it.
    await read(fill(85), [eventId]);
    assert.equal(
      (await read(fill(86))).header.get(2).length,
      0,
      'a confirmed control event was served again',
    );
  });
}

test('a delivery frame tampered with after signing is refused', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND);
  const frame = await bodyOf(
    await buildDeliveryRequest({ nonce: fill(91), operationId: fill(92) }),
  );

  const truncated = await fixture.route(
    resend('/v2/deliveries', frame.subarray(0, frame.byteLength - 1)),
    '/v2/deliveries',
  );
  assert.equal(truncated.status, 400);
  assert.equal(await errorCode(truncated), MALFORMED_ERROR);

  const flipped = Uint8Array.from(frame);
  flipped[flipped.byteLength - 1] ^= 0x01;
  assert.equal(
    (await fixture.route(resend('/v2/deliveries', flipped), '/v2/deliveries'))
      .status,
    400,
  );

  // A frame whose declared payload length does not match its body.
  const relabelled = Uint8Array.from(frame);
  relabelled[6] = 0xff;
  assert.equal(
    (
      await fixture.route(
        resend('/v2/deliveries', relabelled),
        '/v2/deliveries',
      )
    ).status,
    400,
  );
});

test('a control envelope swapped after signing is refused', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND);
  const request = await buildControlEventRequest({
    nonce: fill(93),
    operationId: fill(94),
  });
  const header = new Map(
    decodeV2ControlEventRequest(await bodyOf(request)).header,
  );
  header.set(
    V2_CONTROL_EVENT_REQUEST_KEYS.encryptedEnvelope,
    Uint8Array.of(99, 99),
  );
  const response = await fixture.route(
    resend('/v2/control-events', encodeCbor(header)),
    '/v2/control-events',
  );
  assert.ok(response.status >= 400, 'a swapped control envelope was accepted');
});

test('a proof outside its acceptance window is refused at both ends', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND);
  assert.ok(
    (
      await fixture.deliver({
        nonce: fill(97),
        operationId: fill(98),
        proofExpiresAt: V2_NOW - 1,
      })
    ).status >= 400,
    'an expired proof was accepted',
  );

  // Further ahead than the five-minute proof lifetime allows, which is what
  // stops a stockpile of long-lived proofs being minted in advance.
  assert.ok(
    (
      await fixture.deliver({
        nonce: fill(99),
        operationId: fill(100),
        proofExpiresAt: V2_NOW + 5 * 60 + 1,
      })
    ).status >= 400,
    'an over-long proof lifetime was accepted',
  );

  // The boundary itself is inside the window.
  assert.equal(
    (
      await fixture.deliver({
        nonce: fill(101),
        operationId: fill(102),
        proofExpiresAt: V2_NOW + 5 * 60,
      })
    ).status,
    200,
  );
});

test('every unauthorized rejection is byte-identical to a caller', async (t) => {
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND);
  const foreign = Uint8Array.from(V2_TOKENS.write, (byte) => byte ^ 0xff);
  const describe = async (response) => [
    response.status,
    response.headers.get('content-type'),
    hex(new Uint8Array(await response.arrayBuffer())),
  ];
  const unregistered = await describe(
    await fixture.deliver({
      nonce: fill(111),
      operationId: fill(112),
      tokenSecret: foreign,
    }),
  );
  const forged = await describe(
    await fixture.deliver({
      nonce: fill(113),
      operationId: fill(114),
      tokenSecret: foreign,
      lookupSecret: V2_TOKENS.write,
    }),
  );
  const wrongScope = await describe(
    await fixture.deliver({
      nonce: fill(115),
      operationId: fill(116),
      tokenSecret: V2_TOKENS.read,
      scope: 'read',
    }),
  );
  assert.equal(unregistered[0], 401);
  assert.deepEqual(forged, unregistered);
  assert.deepEqual(wrongScope, unregistered);
});
