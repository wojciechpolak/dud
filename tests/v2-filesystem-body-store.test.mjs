// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { sha256 } from '../dist/src/sha256.js';
import { FilesystemV2BodyStore } from '../dist/src/v2-filesystem-body-store.js';

function stream(bytes) {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

test('filesystem V2 body store verifies and atomically publishes an opaque delivery', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dud-v2-bodies-'));
  const store = new FilesystemV2BodyStore(root);
  const key = `deliveries/${'a'.repeat(32)}.bin`;
  const bytes = new TextEncoder().encode('opaque ciphertext');
  await store.put(key, stream(bytes), bytes.byteLength, sha256(bytes));

  const object = await store.get(key);
  assert.ok(object);
  assert.deepEqual(
    new Uint8Array(await new Response(object.body).arrayBuffer()),
    bytes,
  );
  assert.equal(await store.head(key), true);
  const info = await stat(
    join(root, 'v2', 'delivery-bodies', `${'a'.repeat(32)}.bin`),
  );
  assert.equal(info.mode & 0o777, 0o600);

  await store.delete(key);
  assert.equal(await store.get(key), null);
});

test('filesystem V2 body store removes a failed temporary upload', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dud-v2-bodies-'));
  const store = new FilesystemV2BodyStore(root);
  const key = `deliveries/${'b'.repeat(32)}.bin`;
  const bytes = new TextEncoder().encode('ciphertext');
  await assert.rejects(
    store.put(key, stream(bytes), bytes.byteLength, new Uint8Array(32)),
  );
  assert.equal(await store.head(key), false);
});

test('filesystem V2 body store stages then promotes a verified payload', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dud-v2-bodies-'));
  const store = new FilesystemV2BodyStore(root);
  const bytes = new TextEncoder().encode('staged ciphertext');
  const staged = await store.stage(
    stream(bytes),
    bytes.byteLength,
    sha256(bytes),
  );
  const key = `deliveries/${'c'.repeat(32)}.bin`;
  await store.promote(staged, key);
  assert.equal(await store.head(staged), false);
  assert.deepEqual(
    new Uint8Array(
      await new Response((await store.get(key)).body).arrayBuffer(),
    ),
    bytes,
  );

  const duplicate = await store.stage(
    stream(bytes),
    bytes.byteLength,
    sha256(bytes),
  );
  await store.promote(duplicate, key);
  assert.equal(await store.head(duplicate), false);

  const conflicting = new TextEncoder().encode('different ciphertext');
  const conflictingStage = await store.stage(
    stream(conflicting),
    conflicting.byteLength,
    sha256(conflicting),
  );
  await assert.rejects(store.promote(conflictingStage, key), /conflicts/);
  assert.equal(await store.head(conflictingStage), true);
});
