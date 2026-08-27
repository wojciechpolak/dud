// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import test from 'node:test';

import { createDudService } from '../dist/src/service.js';
import { FilesystemBlobStore } from '../dist/src/filesystem.js';
import { FilesystemV2Store } from '../dist/src/v2-filesystem.js';
import { FilesystemV2BodyStore } from '../dist/src/v2-filesystem-body-store.js';
import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import { encodeBase64Url } from '../dist/src/v2-auth.js';
import { makeContext, textStream } from './helpers.mjs';
import {
  V2_ADMIN_SECRET,
  V2_DEPLOYMENT_KEY,
  V2_ENROLLMENT_SECRET,
  V2_ORIGIN,
  deterministicRandom,
} from './v2-helpers.mjs';

const LEGACY_SECRET = 'legacy-secret';
const NOW_MS = 1_700_000_000_000;
const NONCE_KEY = 'e'.repeat(64);

/**
 * Brings up the self-hosted stack over one data directory. Rolling the
 * deployment back and forward means tearing this down and building it again
 * with different feature flags over exactly the same files.
 */
async function deploy(dataDir, { v1Enabled, v2Enabled }, createId) {
  const parts = {};
  let repository;
  if (v2Enabled) {
    repository = new SQLiteV2Repository(dataDir);
    await repository.initialize();
    parts.v2Store = new FilesystemV2Store(dataDir);
    parts.v2Repository = repository;
    parts.v2PairingRepository = repository;
    parts.v2BodyStore = new FilesystemV2BodyStore(dataDir);
  }
  const service = createDudService({
    blobStore: new FilesystemBlobStore(dataDir),
    ...parts,
    now: () => NOW_MS,
    randomBytes: deterministicRandom(),
    ...(createId ? { createId } : {}),
    config: {
      secretToken: LEGACY_SECRET,
      v1Enabled,
      v2Enabled,
      ...(v2Enabled
        ? {
            v2DeploymentKey: encodeBase64Url(V2_DEPLOYMENT_KEY),
            v2AdminSecret: encodeBase64Url(V2_ADMIN_SECRET),
            v2Secret: V2_ENROLLMENT_SECRET,
          }
        : {}),
    },
  });
  return {
    service,
    v2Store: parts.v2Store,
    shutdown: () => repository?.close(),
  };
}

/** Content digest of the V2 state tree, ignoring transient SQLite journals. */
async function digestV2State(dataDir) {
  const root = join(dataDir, 'v2');
  const entries = [];
  const walk = async (directory) => {
    for (const item of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, item.name);
      if (item.isDirectory()) {
        await walk(path);
        continue;
      }
      if (item.name.endsWith('-wal') || item.name.endsWith('-shm')) {
        continue;
      }
      entries.push([
        relative(root, path),
        createHash('sha256')
          .update(await readFile(path))
          .digest('hex'),
      ]);
    }
  };
  await walk(root);
  entries.sort(([left], [right]) => left.localeCompare(right));
  return entries;
}

async function legacyUpload(service, body) {
  const ctx = makeContext();
  const response = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': LEGACY_SECRET,
        'x-dud-ttl': '24h',
      },
      body: textStream(body),
      duplex: 'half',
    }),
    ctx,
  );
  await ctx.flush();
  return response;
}

async function legacyDownload(service, id) {
  const ctx = makeContext();
  const response = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/files/${id}`),
    ctx,
  );
  const body = response.status === 200 ? await response.text() : undefined;
  await ctx.flush();
  return { status: response.status, body };
}

/**
 * Discovery can schedule a background maintenance pass, so the context is
 * flushed before the caller inspects or removes the data directory.
 */
async function discover(service) {
  const ctx = makeContext();
  const response = await service.fetch(
    new Request(`${V2_ORIGIN}/v2/capabilities`),
    ctx,
  );
  await ctx.flush();
  return response;
}

test('rolling a deployment back to v1 and forward again corrupts no state', async (t) => {
  const dataDir = await mkdtemp(join(tmpdir(), 'dud-rollback-'));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  const uploadedId = 'a'.repeat(32);
  const secondId = 'b'.repeat(32);
  const identifiers = [uploadedId, secondId];
  let issued = 0;
  const createId = () => identifiers[issued++];

  // Phase 1: dual-stack. One v1 object and one durable v2 replay claim.
  const dual = await deploy(
    dataDir,
    { v1Enabled: true, v2Enabled: true },
    createId,
  );
  assert.equal((await legacyUpload(dual.service, 'ciphertext')).status, 201);
  assert.equal((await discover(dual.service)).status, 200);
  assert.equal(
    await dual.v2Store.claimNonce(
      NONCE_KEY,
      NOW_MS / 1000 + 3600,
      NOW_MS / 1000,
    ),
    true,
  );
  dual.shutdown();
  const beforeRollback = await digestV2State(dataDir);
  assert.ok(beforeRollback.length > 0, 'phase 1 wrote no v2 state');

  // Phase 2: rolled back to v1-only. V1 keeps working and v2 is unreachable.
  const rolledBack = await deploy(
    dataDir,
    { v1Enabled: true, v2Enabled: false },
    createId,
  );
  assert.equal((await discover(rolledBack.service)).status, 404);
  assert.deepEqual(await legacyDownload(rolledBack.service, uploadedId), {
    status: 200,
    body: 'ciphertext',
  });
  assert.equal((await legacyUpload(rolledBack.service, 'second')).status, 201);
  const flush = await rolledBack.service.fetch(
    new Request(`${V2_ORIGIN}/v1/admin/flush`, {
      method: 'POST',
      headers: { 'x-dud-secret-token': LEGACY_SECRET },
    }),
    makeContext(),
  );
  assert.equal(flush.status, 200);
  assert.deepEqual(
    await digestV2State(dataDir),
    beforeRollback,
    'v1-only traffic modified v2 state at rest',
  );

  // Phase 3: rolled forward. The replay claim and both v1 objects survived.
  const restored = await deploy(dataDir, { v1Enabled: true, v2Enabled: true });
  t.after(() => restored.shutdown());
  assert.equal((await discover(restored.service)).status, 200);
  assert.equal(
    await restored.v2Store.claimNonce(
      NONCE_KEY,
      NOW_MS / 1000 + 3600,
      NOW_MS / 1000,
    ),
    false,
    'a rollback window erased v2 replay protection',
  );
  assert.deepEqual(await legacyDownload(restored.service, uploadedId), {
    status: 200,
    body: 'ciphertext',
  });
  assert.deepEqual(await legacyDownload(restored.service, secondId), {
    status: 200,
    body: 'second',
  });
});

test('a rolled-back deployment refuses to serve v2 from surviving state', async (t) => {
  const dataDir = await mkdtemp(join(tmpdir(), 'dud-rollback-'));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  const dual = await deploy(dataDir, { v1Enabled: true, v2Enabled: true });
  assert.equal((await discover(dual.service)).status, 200);
  dual.shutdown();

  const rolledBack = await deploy(dataDir, {
    v1Enabled: true,
    v2Enabled: false,
  });
  for (const path of [
    '/v2/capabilities',
    '/v2/deliveries',
    '/v2/inbox',
    '/v2/pairing/rendezvous',
    '/v2/admin/relationships/status',
  ]) {
    const ctx = makeContext();
    const response = await rolledBack.service.fetch(
      new Request(`${V2_ORIGIN}${path}`, {
        method: path === '/v2/capabilities' ? 'GET' : 'POST',
      }),
      ctx,
    );
    await ctx.flush();
    assert.equal(response.status, 404, `${path} survived the rollback`);
  }
});
