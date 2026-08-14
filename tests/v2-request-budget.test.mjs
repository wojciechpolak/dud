// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Request-count and latency gates. A send is one request and a receive two;
// these tests fail if any hot path grows a third.

import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeV2InboxResponseFrame } from '../dist/src/v2-delivery-frame.js';
import {
  createDeliveryFixture,
  decodeBody,
  fill,
  hex,
  V2_CONTROL_SLOT,
  V2_REPOSITORY_BACKENDS,
  V2_TARGET_SLOT,
  V2_TOKENS,
} from './v2-delivery-fixtures.mjs';

const SQLITE_BACKEND = V2_REPOSITORY_BACKENDS.find(
  ([name]) => name === 'sqlite',
)[1];

/** Counts every path a fixture routes, by endpoint rather than by instance. */
function counting(fixture, t) {
  const counts = new Map();
  const stop = fixture.observeRoutes((path) => {
    const key = /^\/v2\/deliveries\/[a-f0-9]{32}\/complete$/.test(path)
      ? '/v2/deliveries/:id/complete'
      : path;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  });
  t.after(stop);
  return {
    counts,
    total: () => Array.from(counts.values()).reduce((sum, n) => sum + n, 0),
    stop,
  };
}

test('a paired small send costs exactly one delivery request', async (t) => {
  const fixture = await createDeliveryFixture(t, SQLITE_BACKEND);
  const budget = counting(fixture, t);
  const response = await fixture.deliver({
    nonce: fill(11),
    operationId: fill(12),
  });
  assert.equal(response.status, 200);
  assert.deepEqual(
    Object.fromEntries(budget.counts),
    { '/v2/deliveries': 1 },
    'a send made more than one request',
  );
});

test('a receive costs one inbox request plus one completion', async (t) => {
  const fixture = await createDeliveryFixture(t, SQLITE_BACKEND);
  const published = await fixture.deliver({
    nonce: fill(21),
    operationId: fill(22),
  });
  assert.equal(published.status, 200);
  const id = hex((await decodeBody(published)).get(1));

  const budget = counting(fixture, t);
  const inbox = await fixture.inbox({ nonce: fill(23) });
  assert.equal(inbox.status, 200);
  const frame = decodeV2InboxResponseFrame(
    new Uint8Array(await inbox.arrayBuffer()),
  );
  // The payload and its descriptor arrive inside that one response, so nothing
  // else has to be fetched before the receiver can commit its output.
  assert.equal(hex(frame.header.get(3)), id);
  assert.ok(frame.payload.byteLength > 0);
  assert.ok(frame.header.get(5).byteLength > 0);

  const completed = await fixture.complete({
    deliveryId: id,
    ackNonce: fill(24),
    controlNonce: fill(25),
  });
  assert.equal(completed.status, 200);
  assert.deepEqual(
    Object.fromEntries(budget.counts),
    { '/v2/inbox': 1, '/v2/deliveries/:id/complete': 1 },
    'a receive made more than one inbox request and one completion',
  );
});

test('an empty and a full recovery each cost one inbox request', async (t) => {
  const fixture = await createDeliveryFixture(t, SQLITE_BACKEND);

  // Empty: nothing waiting anywhere.
  const empty = counting(fixture, t);
  const emptyResponse = await fixture.inbox({ nonce: fill(31) });
  assert.equal(emptyResponse.status, 200);
  assert.equal(empty.total(), 1, 'an empty recovery made extra requests');

  // Full: a delivery and a control event waiting at once. One inbox request
  // covering both slots is what stops recovery from scaling with history.
  await fixture.deliver({ nonce: fill(32), operationId: fill(33) });
  await fixture.control({ nonce: fill(34), operationId: fill(35) });

  const full = counting(fixture, t);
  const response = await fixture.route(
    await import('./v2-delivery-fixtures.mjs').then(({ buildInboxRequest }) =>
      buildInboxRequest({
        nonce: fill(36),
        tokenSecret: V2_TOKENS.peerRead,
        direction: 'invitee->inviter',
        slot: V2_CONTROL_SLOT,
        controlSlots: [{ slot: V2_TARGET_SLOT, nonce: fill(37) }],
      }),
    ),
    '/v2/inbox',
  );
  assert.equal(response.status, 200);
  const frame = decodeV2InboxResponseFrame(
    new Uint8Array(await response.arrayBuffer()),
  );
  assert.equal(
    frame.header.get(2).length,
    1,
    'the control event was not drained',
  );
  assert.equal(full.total(), 1, 'a full recovery made extra requests');
});

test('a send batching control queries still costs one request', async (t) => {
  const fixture = await createDeliveryFixture(t, SQLITE_BACKEND);
  await fixture.control({ nonce: fill(41), operationId: fill(42) });

  const budget = counting(fixture, t);
  const response = await fixture.deliver({
    nonce: fill(43),
    operationId: fill(44),
    controlQueries: [
      {
        slot: V2_TARGET_SLOT,
        nonce: fill(45),
        tokenSecret: V2_TOKENS.peerRead,
        direction: 'invitee->inviter',
      },
    ],
  });
  assert.equal(response.status, 200);
  const body = await decodeBody(response);
  // The batched control event rides back on the delivery response, which is
  // the whole point of allowing control queries on a send.
  assert.equal(
    body.get(5).length,
    1,
    'the batched control event was not returned',
  );
  assert.deepEqual(Object.fromEntries(budget.counts), { '/v2/deliveries': 1 });
});

test('no hot path touches capability discovery', async (t) => {
  const fixture = await createDeliveryFixture(t, SQLITE_BACKEND);
  const budget = counting(fixture, t);
  const published = await fixture.deliver({
    nonce: fill(51),
    operationId: fill(52),
  });
  const id = hex((await decodeBody(published)).get(1));
  await fixture.inbox({ nonce: fill(53) });
  await fixture.complete({
    deliveryId: id,
    ackNonce: fill(54),
    controlNonce: fill(55),
  });
  await fixture.control({ nonce: fill(56), operationId: fill(57) });
  for (const path of budget.counts.keys()) {
    assert.notEqual(
      path,
      '/v2/capabilities',
      'a hot path re-fetched the capability document',
    );
  }
  assert.equal(budget.total(), 4, `hot paths made ${budget.total()} requests`);
});

test('a warm send and receive cycle stays inside the 500ms gate', async (t) => {
  const fixture = await createDeliveryFixture(t, SQLITE_BACKEND, {
    capabilityExpiresAt: 1_800_000_000 + 600,
  });

  // One warm-up cycle so the measurement excludes first-statement preparation,
  // which a long-running deployment pays once rather than per message.
  const cycle = async (seed) => {
    const published = await fixture.deliver({
      nonce: fill(seed),
      operationId: fill(seed + 1),
    });
    assert.equal(published.status, 200);
    const id = hex((await decodeBody(published)).get(1));
    const inbox = await fixture.inbox({ nonce: fill(seed + 2) });
    assert.equal(inbox.status, 200);
    await inbox.arrayBuffer();
    const completed = await fixture.complete({
      deliveryId: id,
      ackNonce: fill(seed + 3),
      controlNonce: fill(seed + 4),
      operationId: fill(seed + 5),
    });
    assert.equal(completed.status, 200);
  };
  await cycle(60);

  const started = performance.now();
  await cycle(70);
  const elapsed = performance.now() - started;
  assert.ok(
    elapsed < 500,
    `a warm small-message send/receive cycle took ${elapsed.toFixed(1)}ms`,
  );
});
