// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Crash, restart and concurrency coverage for the durable backends, plus the
// filesystem body store's behaviour after an interrupted write.

import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { decodeV2InboxResponseFrame } from '../dist/src/v2-delivery-frame.js';
import { FilesystemV2BodyStore } from '../dist/src/v2-filesystem-body-store.js';
import { sha256 } from '../dist/src/sha256.js';
import {
  canReopen,
  createDeliveryFixture,
  decodeBody,
  fill,
  hex,
  requestedPolicy,
  V2_NOW,
  V2_REPOSITORY_BACKENDS,
} from './v2-delivery-fixtures.mjs';

const DELIVERY_KEY = `deliveries/${'a'.repeat(32)}.bin`;
const ORPHAN_KEY = `deliveries/${'b'.repeat(32)}.bin`;

const DURABLE_BACKENDS = V2_REPOSITORY_BACKENDS.filter(
  ([name]) => name !== 'memory',
);

async function publish(fixture, options) {
  const response = await fixture.deliver(options);
  assert.equal(response.status, 200, 'delivery was not accepted');
  return hex((await decodeBody(response)).get(1));
}

for (const [name, createRepository] of DURABLE_BACKENDS) {
  test(`${name} survives a restart with its delivery intact`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    assert.ok(canReopen(fixture.repository), `${name} cannot be reopened`);
    const id = await publish(fixture, {
      nonce: fill(11),
      operationId: fill(12),
    });

    const restarted = await fixture.restart();
    // The published delivery is still readable, and its retry is still
    // idempotent, from a repository instance that never saw the first request.
    const inbox = await restarted.inbox({ nonce: fill(13) });
    assert.equal(inbox.status, 200);
    const frame = decodeV2InboxResponseFrame(
      new Uint8Array(await inbox.arrayBuffer()),
    );
    assert.equal(hex(frame.header.get(3)), id);
    assert.deepEqual(frame.payload, Uint8Array.of(7, 8, 9));

    const retry = await restarted.deliver({
      nonce: fill(14),
      operationId: fill(12),
    });
    assert.equal(retry.status, 200);
    const retryBody = await decodeBody(retry);
    assert.equal(retryBody.get(3), true, 'the retry was not idempotent');
    assert.equal(hex(retryBody.get(1)), id);

    // A spent nonce stays spent across the restart, so a captured request
    // cannot be replayed by waiting for a redeploy.
    assert.ok(
      (await restarted.deliver({ nonce: fill(11), operationId: fill(15) }))
        .status >= 400,
      'a restart cleared the nonce record',
    );
  });

  test(`${name} keeps completion durable across a restart`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const id = await publish(fixture, {
      nonce: fill(21),
      operationId: fill(22),
    });
    const completed = await fixture.complete({
      deliveryId: id,
      ackNonce: fill(23),
      controlNonce: fill(24),
    });
    assert.equal(completed.status, 200);
    const controlEventId = (await decodeBody(completed)).get(2);

    const restarted = await fixture.restart();
    const retry = await restarted.complete({
      deliveryId: id,
      ackNonce: fill(25),
      controlNonce: fill(26),
    });
    assert.equal(retry.status, 200);
    const retryBody = await decodeBody(retry);
    assert.equal(retryBody.get(3), true, 'the completion replayed as new');
    assert.deepEqual(
      retryBody.get(2),
      controlEventId,
      'a restart minted a second control event',
    );
  });

  test(`${name} admits exactly one of two racing reservations`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const second = await fixture.restart();

    // Two independent handlers publishing the same operation concurrently.
    // Both may answer, but they must name one delivery, not two.
    const operationId = fill(31);
    const [left, right] = await Promise.all([
      fixture.deliver({ nonce: fill(32), operationId }),
      second.deliver({ nonce: fill(33), operationId }),
    ]);
    assert.equal(left.status, 200);
    assert.equal(right.status, 200);
    assert.equal(
      hex((await decodeBody(left)).get(1)),
      hex((await decodeBody(right)).get(1)),
      'a race produced two deliveries for one operation',
    );
  });

  test(`${name} charges a byte quota exactly once under a race`, async (t) => {
    // A quota of six bytes admits exactly two three-byte payloads, whether the
    // requests arrive one at a time or together.
    const fixture = await createDeliveryFixture(t, createRepository, {
      handler: { maximumTotalBytes: 6 },
    });
    const second = await fixture.restart();
    const responses = await Promise.all([
      fixture.deliver({ nonce: fill(41), operationId: fill(42) }),
      second.deliver({ nonce: fill(43), operationId: fill(44) }),
      fixture.deliver({ nonce: fill(45), operationId: fill(46) }),
      second.deliver({ nonce: fill(47), operationId: fill(48) }),
    ]);
    const accepted = responses.filter(({ status }) => status === 200);
    assert.equal(
      accepted.length,
      2,
      `quota admitted ${accepted.length} of four three-byte deliveries`,
    );
    const ids = new Set(
      await Promise.all(
        accepted.map(async (response) =>
          hex((await decodeBody(response)).get(1)),
        ),
      ),
    );
    assert.equal(ids.size, 2, 'two admissions shared one delivery ID');
  });

  test(`${name} fails closed when a delivery body has gone missing`, async (t) => {
    const fixture = await createDeliveryFixture(t, createRepository);
    const id = await publish(fixture, {
      nonce: fill(51),
      operationId: fill(52),
    });

    // Storage lost the object while its metadata survived. The reader must be
    // told the payload is unavailable rather than handed a short body.
    await fixture.bodyStore.delete(`deliveries/${id}.bin`);
    const response = await fixture.inbox({ nonce: fill(53) });
    assert.ok(
      response.status >= 400,
      'a missing body was served as a delivery',
    );
    assert.equal(
      (await decodeBody(response)).get(1),
      13,
      'a missing body was not reported as unavailable',
    );
  });

  test(`${name} returns every expired byte to the relationship quota`, async (t) => {
    // The capability outlives the deliveries, so after they expire the only
    // thing that can refuse a new send is stale quota accounting.
    const fixture = await createDeliveryFixture(t, createRepository, {
      handler: { maximumTotalBytes: 6 },
      capabilityExpiresAt: V2_NOW + 86_400,
    });
    await publish(fixture, { nonce: fill(61), operationId: fill(62) });
    await publish(fixture, { nonce: fill(63), operationId: fill(64) });
    assert.ok(
      (await fixture.deliver({ nonce: fill(65), operationId: fill(66) }))
        .status >= 400,
      'the six-byte quota did not fill',
    );

    // Restartable bounded batches must drain, releasing the exact byte count.
    const later = V2_NOW + 3600;
    let complete = false;
    for (let pass = 0; pass < 20 && !complete; pass++) {
      ({ complete } = await fixture.repository.runMaintenance(later, 4));
    }
    assert.equal(complete, true, 'maintenance did not drain');

    const restarted = await fixture.restart();
    restarted.setNow(later);
    const send = (seed) =>
      restarted.deliver({
        nonce: fill(seed),
        operationId: fill(seed + 1),
        policy: requestedPolicy(later + 60),
        proofExpiresAt: later + 60,
      });
    // Both three-byte slots are free again, and only both: a quota that leaked
    // would admit a third, and one that under-released would admit neither.
    assert.equal((await send(71)).status, 200);
    assert.equal((await send(73)).status, 200);
    assert.ok((await send(75)).status >= 400, 'the quota released too much');
  });
}

test('the filesystem body store publishes atomically and survives a restart', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-bodies-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new FilesystemV2BodyStore(directory);
  const payload = Uint8Array.of(1, 2, 3, 4);
  const stream = () =>
    new ReadableStream({
      start(controller) {
        controller.enqueue(payload);
        controller.close();
      },
    });

  const staged = await store.stage(
    stream(),
    payload.byteLength,
    sha256(payload),
  );
  await store.promote(staged, DELIVERY_KEY);
  assert.equal(await store.head(DELIVERY_KEY), true);

  // A crash between the temporary write and the rename leaves a partial file.
  // It must never be visible under a delivery key, and it must not stop a
  // fresh store instance from reading what was published.
  const before = await readdir(directory, { recursive: true });
  await writeFile(join(directory, 'orphan.tmp'), 'partial');
  const reopened = new FilesystemV2BodyStore(directory);
  const body = await reopened.get(DELIVERY_KEY);
  assert.ok(body, 'a published body was lost across a restart');
  assert.equal(body.size, payload.byteLength);
  assert.deepEqual(
    new Uint8Array(await new Response(body.body).arrayBuffer()),
    payload,
  );
  assert.equal(await reopened.head(ORPHAN_KEY), false);
  assert.ok(before.length > 0);
});

test('the filesystem body store refuses a body that does not match its digest', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-bodies-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new FilesystemV2BodyStore(directory);
  const payload = Uint8Array.of(9, 9, 9);
  const wrongDigest = sha256(Uint8Array.of(1));
  await assert.rejects(() =>
    store.put(
      DELIVERY_KEY,
      new ReadableStream({
        start(controller) {
          controller.enqueue(payload);
          controller.close();
        },
      }),
      payload.byteLength,
      wrongDigest,
    ),
  );
  // The failed write leaves nothing readable behind under the delivery key.
  assert.equal(await store.head(DELIVERY_KEY), false);
});
