// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  V2_TIMED_OPERATIONS,
  classifyV2Operation,
  startV2Timing,
} from '../dist/src/v2-timing.js';
import { MemoryV2Store } from '../dist/src/v2-memory.js';
import { makeContext } from './helpers.mjs';
import {
  V2_DATA_SLOT,
  V2_EPOCH,
  V2_REPOSITORY_BACKENDS,
  createDeliveryFixture,
  decodeBody,
  fill,
  hex,
} from './v2-delivery-fixtures.mjs';
import { V2_ORIGIN, createV2TestService } from './v2-helpers.mjs';

const MEMORY_BACKEND = V2_REPOSITORY_BACKENDS[0][1];

/** The exact shape a deployment may log. Anything else is a metadata leak. */
const TIMING_FIELDS = [
  'authorizationMs',
  'bodyMs',
  'metadataMs',
  'operation',
  'status',
  'totalMs',
];

function assertRedacted(record) {
  assert.deepEqual(Object.keys(record).sort(), TIMING_FIELDS);
  assert.ok(
    V2_TIMED_OPERATIONS.includes(record.operation),
    `unknown operation label ${record.operation}`,
  );
  assert.equal(typeof record.status, 'number');
  for (const field of ['authorizationMs', 'metadataMs', 'bodyMs', 'totalMs']) {
    assert.equal(typeof record[field], 'number', field);
    assert.ok(record[field] >= 0, `${field} = ${record[field]}`);
  }
}

/** A steppable clock, so a phase's duration is exactly what the test says. */
function scriptedClock() {
  let value = 0;
  return {
    now: () => value,
    advance: (milliseconds) => {
      value += milliseconds;
    },
  };
}

test('a timing recorder accumulates each phase separately', async () => {
  const clock = scriptedClock();
  const records = [];
  const timing = startV2Timing(
    'delivery-publish',
    (record) => records.push(record),
    clock.now,
  );
  clock.advance(1);
  await timing.measure('authorization', async () => clock.advance(4));
  await timing.measure('metadata', async () => clock.advance(2));
  await timing.measure('metadata', async () => clock.advance(3));
  await timing.measure('body', async () => clock.advance(10));
  clock.advance(5);
  timing.finish(200);
  // A second report would double-count the request in any aggregate.
  timing.finish(500);

  assert.equal(records.length, 1);
  assertRedacted(records[0]);
  assert.deepEqual(records[0], {
    operation: 'delivery-publish',
    status: 200,
    authorizationMs: 4,
    metadataMs: 5,
    bodyMs: 10,
    totalMs: 25,
  });
});

test('a phase is timed even when its work throws', async () => {
  const clock = scriptedClock();
  const records = [];
  const timing = startV2Timing(
    'delivery-inbox',
    (record) => records.push(record),
    clock.now,
  );
  await assert.rejects(
    timing.measure('metadata', async () => {
      clock.advance(7);
      throw new Error('repository failed');
    }),
    /repository failed/,
  );
  timing.finish(500);
  assert.equal(records[0].metadataMs, 7);
  assert.equal(records[0].status, 500);
});

test('timing costs nothing when no deployment is observing', async () => {
  const clock = scriptedClock();
  const timing = startV2Timing('capabilities', undefined, clock.now);
  assert.equal(await timing.measure('metadata', async () => 'value'), 'value');
  timing.finish(200);
  assert.equal(clock.now(), 0);
});

test('every v2 route maps to a fixed timing label', () => {
  const cases = [
    ['GET', '/v2/capabilities', 'capabilities'],
    ['POST', '/v2/capabilities/reissue', 'capability-reissue'],
    ['POST', '/v2/pairing/rendezvous', 'pairing'],
    ['GET', `/v2/pairing/rendezvous/${'a'.repeat(32)}`, 'pairing'],
    ['POST', '/v2/deliveries', 'delivery-publish'],
    ['POST', '/v2/inbox', 'delivery-inbox'],
    ['POST', `/v2/deliveries/${'a'.repeat(32)}/complete`, 'delivery-complete'],
    ['POST', '/v2/control-events', 'control-event'],
    ['POST', '/v2/admin/relationships/revoke', 'admin'],
    ['GET', '/v2/deliveries', 'unknown'],
    ['POST', '/v2/deliveries/short/complete', 'unknown'],
    ['DELETE', '/v2/nothing', 'unknown'],
  ];
  for (const [method, pathname, expected] of cases) {
    assert.equal(
      classifyV2Operation(method, pathname),
      expected,
      `${method} ${pathname}`,
    );
  }
});

test('a delivery reports authorization, metadata, and body separately', async (t) => {
  const clock = scriptedClock();
  const records = [];
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND, {
    handler: {
      observeTiming: (record) => records.push(record),
      monotonicMs: () => {
        clock.advance(1);
        return clock.now();
      },
    },
  });
  const operationId = fill(9);
  const response = await fixture.deliver({ operationId });
  assert.equal(response.status, 200);
  const deliveryId = hex((await decodeBody(response)).get(1));

  assert.equal(records.length, 1);
  const record = records[0];
  assertRedacted(record);
  assert.equal(record.operation, 'delivery-publish');
  assert.equal(record.status, 200);
  for (const field of ['authorizationMs', 'metadataMs', 'bodyMs']) {
    assert.ok(record[field] > 0, `${field} was not measured`);
  }
  assert.ok(
    record.totalMs >=
      record.authorizationMs + record.metadataMs + record.bodyMs,
    'phases exceed the total',
  );

  // The record must not describe the request it measured.
  const serialized = JSON.stringify(record);
  for (const secret of [
    deliveryId,
    hex(operationId),
    hex(V2_DATA_SLOT),
    String(V2_EPOCH),
    fixture.relationshipId,
  ]) {
    assert.ok(
      !serialized.includes(secret),
      `timing record leaked ${secret}: ${serialized}`,
    );
  }

  const inbox = await fixture.inbox({});
  assert.equal(inbox.status, 200);
  assert.equal(records.length, 2);
  assert.equal(records[1].operation, 'delivery-inbox');
  assertRedacted(records[1]);
  assert.ok(records[1].bodyMs > 0, 'inbox payload read was not measured');
});

test('a rejected delivery still reports its phases and status', async (t) => {
  const records = [];
  const fixture = await createDeliveryFixture(t, MEMORY_BACKEND, {
    handler: { observeTiming: (record) => records.push(record) },
  });
  const response = await fixture.deliver({ tokenSecret: fill(0xaa, 32) });
  assert.notEqual(response.status, 200);
  assert.equal(records.length, 1);
  assertRedacted(records[0]);
  assert.equal(records[0].operation, 'delivery-publish');
  assert.equal(records[0].status, response.status);
});

test('every v2 route reports one timing record through the service', async () => {
  const records = [];
  const { service } = await createV2TestService(new MemoryV2Store(), {
    observeTiming: (record) => records.push(record),
  });
  const requests = [
    ['capabilities', new Request(`${V2_ORIGIN}/v2/capabilities`)],
    [
      'pairing',
      new Request(`${V2_ORIGIN}/v2/pairing/rendezvous`, { method: 'POST' }),
    ],
    [
      'admin',
      new Request(`${V2_ORIGIN}/v2/admin/relationships/status`, {
        method: 'POST',
      }),
    ],
    [
      'capability-reissue',
      new Request(`${V2_ORIGIN}/v2/capabilities/reissue`, { method: 'POST' }),
    ],
    ['unknown', new Request(`${V2_ORIGIN}/v2/nothing`, { method: 'POST' })],
  ];
  for (const [operation, request] of requests) {
    records.length = 0;
    const response = await service.fetch(request, makeContext());
    assert.equal(records.length, 1, `${operation} reported ${records.length}`);
    assertRedacted(records[0]);
    assert.equal(records[0].operation, operation);
    assert.equal(records[0].status, response.status);
  }
});

test('a v1 request reports no v2 timing record', async () => {
  const records = [];
  const { service } = await createV2TestService(new MemoryV2Store(), {
    observeTiming: (record) => records.push(record),
  });
  const response = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/test`),
    makeContext(),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(records, []);
});
