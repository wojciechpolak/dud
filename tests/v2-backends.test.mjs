// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { decodeCbor } from '../dist/src/cbor.js';
import { DEFAULT_CONFIG } from '../dist/src/config.js';
import { encodeBase64Url } from '../dist/src/v2-auth.js';
import { FilesystemV2Store } from '../dist/src/v2-filesystem.js';
import { MemoryV2Store } from '../dist/src/v2-memory.js';
import {
  MemoryV2BodyStore,
  MemoryV2Repository,
} from '../dist/src/v2-memory-repository.js';
import { R2V2Store } from '../dist/src/v2-r2.js';
import { createV2Service } from '../dist/src/v2-service.js';
import { createWorker } from '../dist/src/index.js';
import { makeContext } from './helpers.mjs';
import {
  MockR2Bucket,
  V2_DEPLOYMENT_KEY,
  V2_NOW_MS,
  V2_ORIGIN,
} from './v2-helpers.mjs';

globalThis.FixedLengthStream ??= class FixedLengthStream extends (
  TransformStream
) {
  constructor() {
    super();
  }
};

function unusedD1Binding() {
  return {
    prepare() {
      const statement = {
        bind() {
          return statement;
        },
        async run() {
          return { meta: { changes: 0 } };
        },
        async first() {
          return null;
        },
        async all() {
          return { results: [] };
        },
      };
      return statement;
    },
    async batch(statements) {
      return Promise.all(statements.map((statement) => statement.run()));
    },
  };
}

async function decodeResponse(response) {
  return decodeCbor(new Uint8Array(await response.arrayBuffer()));
}

async function filesystemFactory(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'dud-v2-store-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return new FilesystemV2Store(directory);
}

const factories = [
  ['memory', async () => new MemoryV2Store()],
  ['filesystem', filesystemFactory],
  ['r2', async () => new R2V2Store(new MockR2Bucket())],
];

for (const [label, factory] of factories) {
  test(`${label} v2 whole-state store keeps nonce and relationship state`, async (t) => {
    const store = await factory(t);
    await store.initialize();
    const nonceKey = 'a'.repeat(64);
    const nonceNow = Math.floor(V2_NOW_MS / 1000);
    const nonceExpiry = nonceNow + 100;
    const claims = await Promise.all([
      store.claimNonce(nonceKey, nonceExpiry, nonceNow),
      store.claimNonce(nonceKey, nonceExpiry, nonceNow),
    ]);
    assert.deepEqual(claims.sort(), [false, true]);
    assert.equal(await store.deleteExpiredNonces(nonceExpiry, 10), 0);
    assert.equal(
      await store.claimNonce(nonceKey, nonceExpiry, nonceExpiry),
      false,
    );
    assert.equal(await store.deleteExpiredNonces(nonceExpiry + 1, 10), 1);
    assert.equal(
      await store.claimNonce(nonceKey, nonceExpiry + 200, nonceExpiry + 1),
      true,
    );

    const relationshipId = '12'.repeat(16);
    await store.transaction((state) => {
      state.relationships[relationshipId] = {
        relationshipId,
        canonicalOrigin: V2_ORIGIN,
        inviterSigningPublicKey: encodeBase64Url(new Uint8Array(32)),
        inviterAgeRecipient: encodeBase64Url(new Uint8Array(1216)),
        inviteeSigningPublicKey: encodeBase64Url(new Uint8Array(32)),
        inviteeAgeRecipient: encodeBase64Url(new Uint8Array(1216)),
        createdAt: nonceNow,
      };
    });
    const peerState = await store.readState();
    assert.equal(
      peerState.relationships[relationshipId].canonicalOrigin,
      V2_ORIGIN,
    );
    assert.equal(store.quotaEnforcement, 'atomic');
  });
}

test('filesystem v2 whole state survives restart with private modes', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'dud-v2-restart-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const firstStore = new FilesystemV2Store(directory);
  await firstStore.initialize();
  await firstStore.transaction((state) => {
    state.legacyCommittedBytes = 12;
  });

  const restarted = new FilesystemV2Store(directory);
  await restarted.initialize();
  assert.equal((await restarted.readState()).legacyCommittedBytes, 12);
  assert.equal(
    (await stat(path.join(directory, 'v2', 'state.json'))).mode & 0o777,
    0o600,
  );
  assert.deepEqual(
    (await readdir(path.join(directory, 'v2'))).filter((entry) =>
      entry.startsWith('state.json.tmp-'),
    ),
    [],
  );
});

test('worker v2 capability discovery does not initialize legacy state', async () => {
  const worker = createWorker({
    FILES: new MockR2Bucket(),
    DB: unusedD1Binding(),
    DUD_PEER_ENABLED: 'true',
    DUD_PEER_DEPLOYMENT_KEY: 'gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8',
    DUD_PEER_SECRET: 'squid-lantern-rotate-9-mango',
  });
  const response = await worker.fetch(
    new Request(`${V2_ORIGIN}/v2/capabilities`),
    makeContext(),
  );
  assert.equal(response.status, 200);
  assert.equal((await decodeResponse(response)).get(4).get(1), 2);
});

test('worker can expose a v2-only route surface', async () => {
  const worker = createWorker({
    FILES: new MockR2Bucket(),
    DB: unusedD1Binding(),
    DUD_DROP_ENABLED: 'false',
    DUD_PEER_ENABLED: 'true',
    DUD_PEER_DEPLOYMENT_KEY: 'gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8',
    DUD_PEER_SECRET: 'squid-lantern-rotate-9-mango',
  });
  assert.equal(
    (await worker.fetch(new Request(`${V2_ORIGIN}/v1/test`), makeContext()))
      .status,
    404,
  );
  const capabilities = await worker.fetch(
    new Request(`${V2_ORIGIN}/v2/capabilities`),
    makeContext(),
  );
  assert.deepEqual((await decodeResponse(capabilities)).get(1), [2]);
});

test('Worker V2 configuration requires the D1 metadata binding', () => {
  assert.throws(
    () =>
      createWorker({
        FILES: new MockR2Bucket(),
        DUD_PEER_ENABLED: 'true',
      }),
    /D1 DB binding is required/,
  );
});

test('independent R2 store instances preserve concurrent state updates', async () => {
  const bucket = new MockR2Bucket();
  const first = new R2V2Store(bucket);
  const second = new R2V2Store(bucket);
  await Promise.all([first.initialize(), second.initialize()]);
  await Promise.all([
    first.transaction((state) => {
      state.rateWindows.first = { minute: 1, count: 1 };
    }),
    second.transaction((state) => {
      state.rateWindows.second = { minute: 1, count: 1 };
    }),
  ]);
  const state = await first.readState();
  assert.equal(state.rateWindows.first.count, 1);
  assert.equal(state.rateWindows.second.count, 1);
  assert.equal(first.quotaEnforcement, 'atomic');
});

test('whole-state maintenance prunes stale windows, reservations and nonces', async () => {
  const store = new MemoryV2Store();
  await store.initialize();
  const current = Math.floor(V2_NOW_MS / 1000);
  await store.claimNonce('b'.repeat(64), current - 1, current - 100);
  await store.transaction((state) => {
    state.rateWindows.stale = {
      minute: Math.floor(current / 60) - 5,
      count: 3,
    };
    state.rateWindows.fresh = { minute: Math.floor(current / 60), count: 1 };
    state.reservations.expired = {
      id: 'expired',
      objectId: 'a'.repeat(32),
      reservedBytes: 10,
      expiresAt: current - 1,
    };
    state.legacyObjects.gone = {
      objectId: 'gone',
      ciphertextSize: 4,
      expiresAt: current - 1,
    };
    state.legacyCommittedBytes = 4;
  });
  const service = createV2Service({
    store,
    deploymentKey: V2_DEPLOYMENT_KEY,
    limits: DEFAULT_CONFIG.v2Limits,
    now: () => V2_NOW_MS,
  });
  await service.cleanup();
  const state = await store.readState();
  assert.deepEqual(Object.keys(state.rateWindows), ['fresh']);
  assert.deepEqual(state.reservations, {});
  assert.deepEqual(state.legacyObjects, {});
  assert.equal(state.legacyCommittedBytes, 0);
  assert.equal(
    await store.claimNonce('b'.repeat(64), current + 100, current),
    true,
  );
});

test('granular V2 service does not expose legacy object or slot delivery routes', async () => {
  const store = new MemoryV2Store();
  await store.initialize();
  const service = createV2Service({
    store,
    repository: new MemoryV2Repository(),
    bodyStore: new MemoryV2BodyStore(),
    deploymentKey: V2_DEPLOYMENT_KEY,
    limits: DEFAULT_CONFIG.v2Limits,
    now: () => V2_NOW_MS,
  });
  for (const [method, pathname] of [
    ['POST', '/v2/objects'],
    ['GET', `/v2/objects/${'a'.repeat(32)}`],
    ['DELETE', `/v2/objects/${'a'.repeat(32)}`],
    ['POST', `/v2/objects/${'a'.repeat(32)}/claim`],
    ['POST', `/v2/objects/${'a'.repeat(32)}/ack`],
    ['POST', `/v2/slots/${'a'.repeat(32)}/objects`],
    ['GET', `/v2/slots/${'a'.repeat(32)}/objects`],
    ['POST', `/v2/slots/${'a'.repeat(32)}/ack`],
  ]) {
    const response = await service.fetch(
      new Request(`${V2_ORIGIN}${pathname}`, { method }),
      false,
    );
    assert.equal(response.status, 404, `${method} ${pathname}`);
    assert.equal((await decodeResponse(response)).get(1), 4);
  }
});

test('a V2 service without a legacy store still answers every granular route', async () => {
  const { WorkerV2Store } = await import('../dist/src/v2-worker-store.js');
  const service = createV2Service({
    store: new WorkerV2Store(),
    repository: new MemoryV2Repository(),
    bodyStore: new MemoryV2BodyStore(),
    deploymentKey: V2_DEPLOYMENT_KEY,
    limits: DEFAULT_CONFIG.v2Limits,
    now: () => V2_NOW_MS,
  });
  // Discovery reads only the compile-time contract, never whole state.
  const capabilities = await service.fetch(
    new Request(`${V2_ORIGIN}/v2/capabilities`),
    true,
  );
  assert.equal(capabilities.status, 200);
  assert.deepEqual(
    (await decodeResponse(capabilities)).get(2),
    [2, 3, 5, 6, 9, 10, 11],
  );
});
