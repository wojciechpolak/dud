// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { FilesystemBlobStore } from '../dist/src/filesystem.js';
import { createDudService } from '../dist/src/service.js';
import { makeContext, MemoryBlobStore, textStream } from './helpers.mjs';

const FILE_ID = '1'.repeat(32);
const DELETE_ID = '2'.repeat(32);
const EXPIRE_ID = '3'.repeat(32);

async function createFilesystemStore() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'dud-fs-store-'));
  return new FilesystemBlobStore(dir);
}

const storeFactories = [
  ['memory', async () => new MemoryBlobStore()],
  ['filesystem', createFilesystemStore],
];

for (const [label, createStore] of storeFactories) {
  test(`${label} blob store can upload and download through the shared service`, async () => {
    const blobStore = await createStore();
    const service = createDudService({
      blobStore,
      createId: () => FILE_ID,
      config: { secretToken: 'top-secret' },
    });

    const uploadResponse = await service.fetch(
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

    assert.equal(uploadResponse.status, 201);

    const downloadResponse = await service.fetch(
      new Request(`https://dud.example.com/v1/files/${FILE_ID}`),
      makeContext(),
    );

    assert.equal(downloadResponse.status, 200);
    assert.equal(await downloadResponse.text(), 'ciphertext');
  });

  test(`${label} blob store preserves delete-after-read behavior`, async () => {
    const blobStore = await createStore();
    const service = createDudService({
      blobStore,
      createId: () => DELETE_ID,
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
      new Request(`https://dud.example.com/v1/files/${DELETE_ID}`),
      firstCtx,
    );
    assert.equal(first.status, 200);
    assert.equal(await first.text(), 'ciphertext');
    await firstCtx.flush();

    const second = await service.fetch(
      new Request(`https://dud.example.com/v1/files/${DELETE_ID}`),
      makeContext(),
    );
    assert.equal(second.status, 410);
  });

  test(`${label} blob store preserves expiry handling`, async () => {
    const blobStore = await createStore();
    const service = createDudService({
      blobStore,
      now: () => 1_700_000_000_000,
      createId: () => EXPIRE_ID,
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
      new Request(`https://dud.example.com/v1/files/${EXPIRE_ID}`),
      ctx,
    );

    assert.equal(response.status, 410);
    await ctx.flush();

    const second = await expiredService.fetch(
      new Request(`https://dud.example.com/v1/files/${EXPIRE_ID}`),
      makeContext(),
    );
    assert.equal(second.status, 410);
  });
}
