// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { FilesystemV2BodyStore } from '../dist/src/v2-filesystem-body-store.js';
import { MemoryV2BodyStore } from '../dist/src/v2-memory-body-store.js';
import { R2V2BodyStore } from '../dist/src/v2-r2.js';
import { sha256 } from '../dist/src/sha256.js';
import { MockR2Bucket } from './v2-helpers.mjs';

globalThis.FixedLengthStream ??= class FixedLengthStream extends (
  TransformStream
) {
  constructor() {
    super();
  }
};

function stream(bytes) {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

async function inventoryKeys(store) {
  if (typeof store.listBodies !== 'function') {
    return undefined;
  }
  const keys = [];
  let cursor;
  do {
    const page = await store.listBodies({ cursor, limit: 100 });
    keys.push(...page.entries.map((entry) => entry.key));
    cursor = page.cursor;
  } while (cursor !== undefined);
  return keys.sort();
}

const factories = [
  ['memory', async () => new MemoryV2BodyStore()],
  [
    'filesystem',
    async (t) => {
      const directory = await mkdtemp(join(tmpdir(), 'dud-v2-chunks-'));
      t.after(() => rm(directory, { recursive: true, force: true }));
      return new FilesystemV2BodyStore(directory);
    },
  ],
  ['r2', async () => new R2V2BodyStore(new MockR2Bucket())],
];

for (const [backend, createStore] of factories) {
  test(`${backend} body store commits verified delivery chunks idempotently`, async (t) => {
    const store = await createStore(t);
    const uploadId = 'a'.repeat(32);
    const deliveryId = 'b'.repeat(32);
    const bodies = [
      new TextEncoder().encode('first encrypted age file'),
      new TextEncoder().encode('second encrypted age file'),
    ];
    const parts = bodies.map((body, index) => ({
      id: String(index + 1).repeat(32),
      length: body.byteLength,
      digest: sha256(body),
    }));
    for (const [index, part] of parts.entries()) {
      const key = await store.stagePart(uploadId, part, stream(bodies[index]));
      assert.equal(key, `staging/uploads/${uploadId}/${part.id}.age`);
      await store.stagePart(uploadId, part, stream(bodies[index]));
    }
    assert.deepEqual(
      await inventoryKeys(store),
      typeof store.listBodies === 'function'
        ? parts
            .map((part) => `staging/uploads/${uploadId}/${part.id}.age`)
            .sort()
        : undefined,
    );
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    await assert.rejects(
      store.commitParts({
        uploadId,
        deliveryId,
        parts,
        expectedTotalLength: total + 1,
      }),
      /manifest total/,
    );
    const committed = await store.commitParts({
      uploadId,
      deliveryId,
      parts,
      expectedTotalLength: total,
    });
    assert.deepEqual(
      committed.map((part) => part.key),
      parts.map((part) => `deliveries/${deliveryId}/chunks/${part.id}.age`),
    );
    for (const [index, part] of committed.entries()) {
      assert.equal(
        await store.head(`staging/uploads/${uploadId}/${part.id}.age`),
        false,
      );
      assert.deepEqual(
        new Uint8Array(
          await new Response((await store.get(part.key)).body).arrayBuffer(),
        ),
        bodies[index],
      );
    }
    assert.deepEqual(
      await inventoryKeys(store),
      typeof store.listBodies === 'function'
        ? committed.map((part) => part.key).sort()
        : undefined,
    );
    await assert.doesNotReject(
      store.commitParts({
        uploadId,
        deliveryId,
        parts,
        expectedTotalLength: total,
      }),
    );
  });

  test(`${backend} body store rejects a substituted delivery chunk`, async (t) => {
    const store = await createStore(t);
    const expected = new TextEncoder().encode('expected encrypted chunk');
    const changed = new TextEncoder().encode('changed encrypted chunk');
    const part = {
      id: 'c'.repeat(32),
      length: expected.byteLength,
      digest: sha256(expected),
    };
    await assert.rejects(
      store.stagePart('d'.repeat(32), part, stream(changed)),
      /does not match|declaration/,
    );
    assert.equal(
      await store.head(`staging/uploads/${'d'.repeat(32)}/${part.id}.age`),
      false,
    );
  });
}
