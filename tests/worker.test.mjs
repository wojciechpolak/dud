// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import { createDudService } from '../dist/src/service.js';

// Valid 32-char lowercase hex IDs used across tests
const ID_UPLOAD = 'a'.repeat(32);
const ID_EXPIRE = 'b'.repeat(32);
const ID_ONCE = 'c'.repeat(32);
const ID_CANCEL = 'd'.repeat(32);
const ID_FAIL = 'e'.repeat(32);
const ID_NEW = 'f'.repeat(32);
const PRETTY_ID_UPLOAD = 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa';

function textStream(text) {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

function makeContext() {
  const promises = [];
  return {
    waitUntil(promise) {
      promises.push(Promise.resolve(promise));
    },
    async flush() {
      await Promise.allSettled(promises);
    },
  };
}

class MemoryBlobStore {
  constructor() {
    this.objects = new Map();
    this.deletedKeys = [];
    this.failPut = false;
  }

  async put(key, body, metadata) {
    if (this.failPut) {
      throw new Error('put failed');
    }

    const bytes = new Uint8Array(await new Response(body).arrayBuffer());
    this.objects.set(key, {
      bytes,
      contentType: metadata.contentType,
      customMetadata: { ...(metadata.customMetadata ?? {}) },
    });
  }

  async get(key) {
    const entry = this.objects.get(key);
    if (!entry) {
      return null;
    }

    return {
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(entry.bytes);
          controller.close();
        },
      }),
      size: entry.bytes.byteLength,
      customMetadata: { ...entry.customMetadata },
    };
  }

  async head(key) {
    const entry = this.objects.get(key);
    if (!entry) {
      return null;
    }

    return {
      size: entry.bytes.byteLength,
      customMetadata: { ...entry.customMetadata },
    };
  }

  async list(prefix, limit) {
    return Array.from(this.objects.keys())
      .filter((key) => key.startsWith(prefix))
      .sort()
      .slice(0, limit)
      .map((key) => ({ key }));
  }

  async delete(key) {
    this.deletedKeys.push(key);
    this.objects.delete(key);
  }
}

test('GET /v1/test returns readiness JSON', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { version: '9.9.9' },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/test'),
    makeContext(),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    service: 'dud',
    host: 'dud.example.com',
    version: '9.9.9',
  });
});

test('upload returns 503 when R2 binding is missing', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: {
      secretToken: 'top-secret',
      storageConfigured: false,
    },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
      },
      body: textStream('ciphertext'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    error: 'Storage is not configured. Bind R2 as FILES.',
  });
});

test('upload then download returns the encrypted payload', async () => {
  const blobStore = new MemoryBlobStore();
  const service = createDudService({
    blobStore,
    now: () => 1_700_000_000_000,
    createId: () => ID_UPLOAD,
    config: { secretToken: 'top-secret' },
  });

  const uploadResponse = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
        'x-dud-ttl': '24h',
      },
      body: textStream('ciphertext'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(uploadResponse.status, 201);
  assert.deepEqual(await uploadResponse.json(), {
    id: PRETTY_ID_UPLOAD,
    expiresAt: '2023-11-15T22:13:20.000Z',
    deleteAfterRead: false,
  });

  const downloadResponse = await service.fetch(
    new Request(`https://dud.example.com/v1/files/${ID_UPLOAD}`),
    makeContext(),
  );

  assert.equal(downloadResponse.status, 200);
  assert.equal(await downloadResponse.text(), 'ciphertext');
  assert.equal(blobStore.objects.has(`files/${ID_UPLOAD}.age`), true);
});

test('download accepts dashed IDs and reads the raw stored object', async () => {
  const blobStore = new MemoryBlobStore();
  await blobStore.put(`files/${ID_UPLOAD}.age`, textStream('ciphertext'), {
    contentType: 'application/octet-stream',
    customMetadata: {
      dudId: ID_UPLOAD,
      createdAt: '1',
      expiresAt: String(Date.now() + 60_000),
      deleteAfterRead: 'false',
    },
  });

  const service = createDudService({ blobStore, now: () => 1_700_000_000_000 });

  const response = await service.fetch(
    new Request(`https://dud.example.com/v1/files/${PRETTY_ID_UPLOAD}`),
    makeContext(),
  );

  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'ciphertext');
});

test('upload schedules opportunistic cleanup of expired blobs', async () => {
  const blobStore = new MemoryBlobStore();
  await blobStore.put('files/old1.age', textStream('old'), {
    contentType: 'application/octet-stream',
    customMetadata: {
      dudId: 'old1',
      createdAt: '1',
      expiresAt: '2',
      deleteAfterRead: 'false',
    },
  });

  const service = createDudService({
    blobStore,
    now: () => 10_000,
    createId: () => ID_NEW,
    config: { secretToken: 'top-secret' },
  });
  const ctx = makeContext();

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
      },
      body: textStream('ciphertext'),
      duplex: 'half',
    }),
    ctx,
  );

  assert.equal(response.status, 201);
  await ctx.flush();
  assert.equal(blobStore.objects.has('files/old1.age'), false);
});

test('expired files return 410 and are replaced by tombstones', async () => {
  const blobStore = new MemoryBlobStore();
  const service = createDudService({
    blobStore,
    now: () => 1_700_000_000_000,
    createId: () => ID_EXPIRE,
    config: { secretToken: 'top-secret' },
  });

  await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
        'x-dud-ttl': '1s',
      },
      body: textStream('ciphertext'),
      duplex: 'half',
    }),
    makeContext(),
  );

  const expiredService = createDudService({
    blobStore,
    now: () => 1_700_000_002_000,
  });
  const ctx = makeContext();
  const response = await expiredService.fetch(
    new Request(`https://dud.example.com/v1/files/${ID_EXPIRE}`),
    ctx,
  );

  assert.equal(response.status, 410);
  await ctx.flush();
  assert.equal(blobStore.objects.has(`files/${ID_EXPIRE}.age`), false);
  assert.equal(blobStore.objects.has(`tombstones/${ID_EXPIRE}.json`), true);

  const second = await expiredService.fetch(
    new Request(`https://dud.example.com/v1/files/${ID_EXPIRE}`),
    makeContext(),
  );
  assert.equal(second.status, 410);
});

test('delete-after-read makes the second download unavailable', async () => {
  const blobStore = new MemoryBlobStore();
  const service = createDudService({
    blobStore,
    createId: () => ID_ONCE,
    config: { secretToken: 'top-secret' },
  });

  await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
        'x-dud-delete-after-read': 'true',
      },
      body: textStream('ciphertext'),
      duplex: 'half',
    }),
    makeContext(),
  );

  const firstCtx = makeContext();
  const first = await service.fetch(
    new Request(`https://dud.example.com/v1/files/${ID_ONCE}`),
    firstCtx,
  );
  assert.equal(first.status, 200);
  assert.equal(await first.text(), 'ciphertext');
  await firstCtx.flush();

  assert.equal(blobStore.objects.has(`files/${ID_ONCE}.age`), false);
  assert.equal(blobStore.objects.has(`tombstones/${ID_ONCE}.json`), true);

  const second = await service.fetch(
    new Request(`https://dud.example.com/v1/files/${ID_ONCE}`),
    makeContext(),
  );
  assert.equal(second.status, 410);
});

test('delete-after-read tombstone is written even when download is cancelled', async () => {
  const blobStore = new MemoryBlobStore();
  const service = createDudService({
    blobStore,
    createId: () => ID_CANCEL,
    config: { secretToken: 'top-secret' },
  });

  await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
        'x-dud-delete-after-read': 'true',
      },
      body: textStream('ciphertext'),
      duplex: 'half',
    }),
    makeContext(),
  );

  const ctx = makeContext();
  const response = await service.fetch(
    new Request(`https://dud.example.com/v1/files/${ID_CANCEL}`),
    ctx,
  );
  assert.equal(response.status, 200);

  await response.body.cancel();
  await ctx.flush();

  assert.equal(blobStore.objects.has(`files/${ID_CANCEL}.age`), false);
  assert.equal(blobStore.objects.has(`tombstones/${ID_CANCEL}.json`), true);
});

test('failed upload cleanup removes the partially written blob', async () => {
  const blobStore = new MemoryBlobStore();
  blobStore.failPut = true;
  const service = createDudService({
    blobStore,
    createId: () => ID_FAIL,
    config: { secretToken: 'top-secret' },
  });

  const originalError = console.error;
  console.error = () => {};
  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
      },
      body: textStream('ciphertext'),
      duplex: 'half',
    }),
    makeContext(),
  );
  console.error = originalError;

  assert.equal(response.status, 500);
  assert.equal(blobStore.objects.has(`files/${ID_FAIL}.age`), false);
});

test('upload rejects invalid secret tokens', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { secretToken: 'top-secret' },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'wrong',
      },
      body: textStream('ciphertext'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 403);
});

test('upload TTL error does not reveal the configured max duration', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { secretToken: 'top-secret', maxTtlMs: 86_400_000 },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
        'x-dud-ttl': '999d',
      },
      body: textStream('x'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 400);
  const body = await response.json();
  assert.equal(body.error, 'TTL exceeds the maximum allowed duration.');
  assert.ok(!body.error.includes('1d'), 'error must not reveal the max TTL');
});

test('upload rejects oversized payload via Content-Length header', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { secretToken: 'top-secret', maxUploadBytes: 10 },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
        'content-length': '11',
      },
      body: textStream('hello world'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 413);
});

test('upload forwards Content-Length to blobStore as length', async () => {
  let capturedLength;

  class CapturingBlobStore extends MemoryBlobStore {
    async put(key, body, metadata) {
      capturedLength = metadata.length;
      return super.put(key, body, metadata);
    }
  }

  const bodyText = 'hello';
  const byteLength = new TextEncoder().encode(bodyText).byteLength;

  const service = createDudService({
    blobStore: new CapturingBlobStore(),
    config: { secretToken: 'top-secret' },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
        'content-length': String(byteLength),
      },
      body: textStream(bodyText),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 201);
  assert.equal(capturedLength, byteLength);
});

test('upload rejects oversized payload via stream byte count', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { secretToken: 'top-secret', maxUploadBytes: 5 },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: { 'x-dud-secret-token': 'top-secret' },
      body: textStream('hello world'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 413);
});

test('upload rejects a token that is a prefix of the real token', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { secretToken: 'top-secret' },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: { 'x-dud-secret-token': 'top-secre' },
      body: textStream('x'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 403);
});

test('upload rejects a token that has the real token as a prefix', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { secretToken: 'top-secret' },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      headers: { 'x-dud-secret-token': 'top-secretX' },
      body: textStream('x'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 403);
});

test('upload rejects a missing token header', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { secretToken: 'top-secret' },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/files', {
      method: 'POST',
      body: textStream('x'),
      duplex: 'half',
    }),
    makeContext(),
  );

  assert.equal(response.status, 403);
});

test('download rejects IDs that are not raw hex after dash removal', async () => {
  const service = createDudService({ blobStore: new MemoryBlobStore() });

  const cases = [
    'short',
    'ABCDEF1234567890ABCDEF1234567890', // uppercase
    'ABCD-EF12-3456-7890-ABCD-EF12-3456-7890', // uppercase with dashes
    'zz' + 'a'.repeat(30), // non-hex chars
    'a'.repeat(33), // 33 chars (too long)
    'a'.repeat(31), // 31 chars (too short)
    'a'.repeat(16) + '-' + 'a'.repeat(17), // 33 chars after dash removal
  ];

  for (const badId of cases) {
    const response = await service.fetch(
      new Request(`https://dud.example.com/v1/files/${badId}`),
      makeContext(),
    );
    assert.equal(response.status, 400, `expected 400 for id: ${badId}`);
  }
});

test('flush endpoint removes expired blobs and expired tombstones', async () => {
  const blobStore = new MemoryBlobStore();
  await blobStore.put('files/old1.age', textStream('one'), {
    contentType: 'application/octet-stream',
    customMetadata: {
      dudId: 'old1',
      createdAt: '1',
      expiresAt: '2',
      deleteAfterRead: 'false',
    },
  });
  await blobStore.put('tombstones/old2.json', textStream('{}'), {
    contentType: 'application/json',
    customMetadata: {
      expiresAt: '5',
      reason: 'consumed',
    },
  });

  const service = createDudService({
    blobStore,
    now: () => 10_000,
    config: { secretToken: 'top-secret' },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/admin/flush', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
      },
    }),
    makeContext(),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    deletedCount: 2,
    partial: false,
  });
  assert.equal(blobStore.objects.size, 0);
});

test('flush returns partial:true when iteration cap is reached', async () => {
  const blobStore = new MemoryBlobStore();

  // Insert 3 expired files. With cleanupBatchSize=1 and flushMaxIterations=2,
  // only 2 will be deleted and partial should be true.
  for (let i = 0; i < 3; i++) {
    await blobStore.put(`files/${'0'.repeat(31)}${i}.age`, textStream('x'), {
      contentType: 'application/octet-stream',
      customMetadata: {
        dudId: `id${i}`,
        createdAt: '1',
        expiresAt: '2',
        deleteAfterRead: 'false',
      },
    });
  }

  const service = createDudService({
    blobStore,
    now: () => 10_000,
    config: {
      secretToken: 'top-secret',
      cleanupBatchSize: 1,
      flushMaxIterations: 2,
    },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/admin/flush', {
      method: 'POST',
      headers: { 'x-dud-secret-token': 'top-secret' },
    }),
    makeContext(),
  );

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.equal(body.deletedCount, 2);
  assert.equal(body.partial, true);
  assert.equal(blobStore.objects.size, 1);
});

test('all JSON responses include defensive security headers', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { version: '1.0.0' },
  });

  const endpoints = [
    new Request('https://dud.example.com/v1/test'),
    new Request('https://dud.example.com/v1/files/notfound', {
      method: 'GET',
    }),
    new Request('https://dud.example.com/v1/unknown'),
  ];

  for (const req of endpoints) {
    const response = await service.fetch(req, makeContext());
    assert.equal(
      response.headers.get('x-content-type-options'),
      'nosniff',
      `x-content-type-options missing for ${req.url}`,
    );
    assert.equal(
      response.headers.get('x-frame-options'),
      'DENY',
      `x-frame-options missing for ${req.url}`,
    );
    assert.equal(
      response.headers.get('cache-control'),
      'no-store',
      `cache-control missing for ${req.url}`,
    );
  }
});

test('flush endpoint rejects invalid secret tokens', async () => {
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    config: { secretToken: 'top-secret' },
  });

  const response = await service.fetch(
    new Request('https://dud.example.com/v1/admin/flush', {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'wrong',
      },
    }),
    makeContext(),
  );

  assert.equal(response.status, 403);
});
