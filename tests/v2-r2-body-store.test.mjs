// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import { sha256 } from '../dist/src/sha256.js';
import { R2V2BodyStore } from '../dist/src/v2-r2.js';
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

test('R2 granular body store verifies, promotes, and reads opaque delivery bodies', async () => {
  const bucket = new MockR2Bucket();
  const store = new R2V2BodyStore(bucket);
  const bytes = new TextEncoder().encode('encrypted delivery payload');
  const digest = sha256(bytes);
  const staged = await store.stage(stream(bytes), bytes.byteLength, digest);

  assert.match(staged, /^staging\/[a-f0-9]{32}\.bin$/);
  assert.equal(
    bucket.objects.get(staged).customMetadata.dudSha256,
    Buffer.from(digest).toString('hex'),
  );

  const key = `deliveries/${'a'.repeat(32)}.bin`;
  await store.promote(staged, key);
  assert.equal(bucket.objects.has(staged), false);
  assert.equal(await store.head(key), true);
  assert.equal(
    await new Response((await store.get(key)).body).text(),
    'encrypted delivery payload',
  );
});

test('R2 granular body store permits an identical promotion retry but retains a conflict', async () => {
  const bucket = new MockR2Bucket();
  const store = new R2V2BodyStore(bucket);
  const key = `deliveries/${'b'.repeat(32)}.bin`;
  const first = new TextEncoder().encode('same payload');
  const firstDigest = sha256(first);
  const staged = await store.stage(
    stream(first),
    first.byteLength,
    firstDigest,
  );
  await store.promote(staged, key);

  const duplicate = await store.stage(
    stream(first),
    first.byteLength,
    firstDigest,
  );
  await store.promote(duplicate, key);
  assert.equal(bucket.objects.has(duplicate), false);

  const changed = new TextEncoder().encode('changed payload');
  const conflicting = await store.stage(
    stream(changed),
    changed.byteLength,
    sha256(changed),
  );
  await assert.rejects(store.promote(conflicting, key), /conflicts/);
  assert.equal(bucket.objects.has(conflicting), true);
});

test('R2 granular body store rejects a mismatched body before it is committed', async () => {
  const bucket = new MockR2Bucket();
  const store = new R2V2BodyStore(bucket);
  const expected = new TextEncoder().encode('expected');
  const actual = new TextEncoder().encode('actual');
  const key = `deliveries/${'c'.repeat(32)}.bin`;

  await assert.rejects(
    store.put(key, stream(actual), expected.byteLength, sha256(expected)),
    /does not match/,
  );
  assert.equal(await store.head(key), false);
});
