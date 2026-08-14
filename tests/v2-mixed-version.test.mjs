// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import { createDudService } from '../dist/src/service.js';
import { decodeCbor } from '../dist/src/cbor.js';
import { encodeBase64Url } from '../dist/src/v2-auth.js';
import { MemoryV2Store } from '../dist/src/v2-memory.js';
import { MemoryBlobStore, makeContext, textStream } from './helpers.mjs';
import {
  V2_ADMIN_SECRET,
  V2_DEPLOYMENT_KEY,
  V2_ENROLLMENT_SECRET,
  V2_ORIGIN,
  deterministicRandom,
} from './v2-helpers.mjs';

const LEGACY_SECRET = 'legacy-secret';
const NOW_MS = 1_700_000_000_000;
const RAW_ID = 'a'.repeat(32);
const DASHED_ID = 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa';
const ONCE_ID = 'b'.repeat(32);

/** Every V2 route the worker can answer, used to prove exposure per deployment. */
const V2_ROUTES = [
  ['GET', '/v2/capabilities'],
  ['POST', '/v2/capabilities/reissue'],
  ['POST', '/v2/pairing/rendezvous'],
  ['POST', '/v2/deliveries'],
  ['POST', '/v2/inbox'],
  ['POST', '/v2/control-events'],
  ['POST', '/v2/admin/relationships/revoke'],
  ['POST', '/v2/admin/relationships/rotate-capabilities'],
  ['POST', '/v2/admin/relationships/status'],
];

/**
 * Builds one deployment shape. The three shapes differ only in the two feature
 * flags, so any V1 behavior difference between them is a compatibility defect.
 */
async function createDeployment({ v1Enabled, v2Enabled }) {
  const blobStore = new MemoryBlobStore();
  const v2Store = v2Enabled ? new MemoryV2Store() : undefined;
  if (v2Store) {
    await v2Store.initialize();
  }
  const identifiers = [RAW_ID, ONCE_ID];
  let issued = 0;
  const service = createDudService({
    blobStore,
    ...(v2Store ? { v2Store } : {}),
    now: () => NOW_MS,
    randomBytes: deterministicRandom(),
    createId: () => identifiers[issued++] ?? `${issued}`.padStart(32, 'c'),
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
  return { blobStore, service };
}

function legacyUpload(body, headers = {}) {
  return new Request(`${V2_ORIGIN}/v1/files`, {
    method: 'POST',
    headers: {
      'content-type': 'application/octet-stream',
      'x-dud-secret-token': LEGACY_SECRET,
      ...headers,
    },
    body: textStream(body),
    duplex: 'half',
  });
}

/**
 * Replays the complete V1 client conversation and records only what a V1 client
 * can observe: status codes, JSON bodies, and payload bytes.
 */
async function observeLegacyConversation(deployment) {
  const { blobStore, service } = deployment;
  const observed = [];
  const record = async (name, request, ctx = makeContext()) => {
    const response = await service.fetch(request, ctx);
    await ctx.flush();
    const contentType = response.headers.get('content-type') ?? '';
    const body = contentType.startsWith('application/json')
      ? await response.json()
      : await response.text();
    observed.push({ name, status: response.status, body });
    return response;
  };

  await record('health', new Request(`${V2_ORIGIN}/v1/test`));
  await record('upload', legacyUpload('ciphertext', { 'x-dud-ttl': '24h' }));
  await record('download-raw', new Request(`${V2_ORIGIN}/v1/files/${RAW_ID}`));
  await record(
    'download-dashed',
    new Request(`${V2_ORIGIN}/v1/files/${DASHED_ID}`),
  );
  await record(
    'upload-once',
    legacyUpload('once', { 'x-dud-delete-after-read': 'true' }),
  );
  await record(
    'download-once',
    new Request(`${V2_ORIGIN}/v1/files/${ONCE_ID}`),
  );
  await record(
    'download-once-again',
    new Request(`${V2_ORIGIN}/v1/files/${ONCE_ID}`),
  );
  await record(
    'upload-without-token',
    new Request(`${V2_ORIGIN}/v1/files`, {
      method: 'POST',
      body: textStream('x'),
      duplex: 'half',
    }),
  );
  await record(
    'upload-with-wrong-token',
    legacyUpload('x', { 'x-dud-secret-token': 'wrong-secret' }),
  );
  await record(
    'upload-with-unsupported-ttl',
    legacyUpload('x', { 'x-dud-ttl': '400d' }),
  );
  await record(
    'download-malformed',
    new Request(`${V2_ORIGIN}/v1/files/short`),
  );
  await record(
    'download-missing',
    new Request(`${V2_ORIGIN}/v1/files/${'f'.repeat(32)}`),
  );
  await record(
    'flush',
    new Request(`${V2_ORIGIN}/v1/admin/flush`, {
      method: 'POST',
      headers: { 'x-dud-secret-token': LEGACY_SECRET },
    }),
  );
  await record(
    'flush-without-token',
    new Request(`${V2_ORIGIN}/v1/admin/flush`, { method: 'POST' }),
  );
  await record('unknown-path', new Request(`${V2_ORIGIN}/`));

  return {
    observed,
    storedKeys: Array.from(blobStore.objects.keys()).sort(),
  };
}

test('a dual-stack deployment preserves every observable v1 behavior', async () => {
  const legacyOnly = await observeLegacyConversation(
    await createDeployment({ v1Enabled: true, v2Enabled: false }),
  );
  const dualStack = await observeLegacyConversation(
    await createDeployment({ v1Enabled: true, v2Enabled: true }),
  );

  assert.deepEqual(dualStack.observed, legacyOnly.observed);
  assert.deepEqual(dualStack.storedKeys, legacyOnly.storedKeys);
  // Guard against both deployments failing identically for an unrelated reason.
  const statuses = Object.fromEntries(
    legacyOnly.observed.map((entry) => [entry.name, entry.status]),
  );
  assert.deepEqual(statuses, {
    health: 200,
    upload: 201,
    'download-raw': 200,
    'download-dashed': 200,
    'upload-once': 201,
    'download-once': 200,
    'download-once-again': 410,
    'upload-without-token': 403,
    'upload-with-wrong-token': 403,
    'upload-with-unsupported-ttl': 400,
    'download-malformed': 400,
    'download-missing': 404,
    flush: 200,
    'flush-without-token': 403,
    'unknown-path': 200,
  });
});

test('a v2-only deployment exposes no v1 route', async () => {
  const deployment = await createDeployment({
    v1Enabled: false,
    v2Enabled: true,
  });
  const { observed } = await observeLegacyConversation(deployment);
  for (const entry of observed) {
    if (entry.name === 'unknown-path') {
      continue;
    }
    assert.equal(entry.status, 404, `${entry.name} was reachable`);
    assert.deepEqual(entry.body, { error: 'Endpoint is not available.' });
  }
  assert.deepEqual(Array.from(deployment.blobStore.objects.keys()), []);
});

test('capability discovery advertises exactly the protocols a deployment serves', async () => {
  for (const [v1Enabled, expected] of [
    [true, [1, 2]],
    [false, [2]],
  ]) {
    const { service } = await createDeployment({ v1Enabled, v2Enabled: true });
    const response = await service.fetch(
      new Request(`${V2_ORIGIN}/v2/capabilities`),
      makeContext(),
    );
    assert.equal(response.status, 200);
    const document = decodeCbor(new Uint8Array(await response.arrayBuffer()));
    assert.deepEqual(document.get(1), expected);
  }
});

test('a v1-only deployment exposes no v2 route', async () => {
  const { service } = await createDeployment({
    v1Enabled: true,
    v2Enabled: false,
  });
  for (const [method, path] of V2_ROUTES) {
    const response = await service.fetch(
      new Request(`${V2_ORIGIN}${path}`, {
        method,
        ...(method === 'POST' ? { body: null } : {}),
      }),
      makeContext(),
    );
    assert.equal(response.status, 404, `${method} ${path} was reachable`);
    const document = decodeCbor(new Uint8Array(await response.arrayBuffer()));
    assert.equal(document.get(1), 4);
    assert.equal(document.get(2), 'V2 endpoint is not available.');
  }
});

test('a v2 deployment answers every v2 route without falling through to v1', async () => {
  const { service } = await createDeployment({
    v1Enabled: true,
    v2Enabled: true,
  });
  for (const [method, path] of V2_ROUTES) {
    const response = await service.fetch(
      new Request(`${V2_ORIGIN}${path}`, {
        method,
        ...(method === 'POST' ? { body: null } : {}),
      }),
      makeContext(),
    );
    assert.equal(
      response.headers.get('content-type'),
      'application/dud+cbor; version=2',
      `${method} ${path} did not answer as v2`,
    );
    if (path === '/v2/capabilities') {
      assert.equal(response.status, 200);
      continue;
    }
    // Unauthenticated probes must be rejected, never silently accepted.
    assert.notEqual(response.status, 200, `${method} ${path} accepted a probe`);
    const document = decodeCbor(new Uint8Array(await response.arrayBuffer()));
    assert.equal(typeof document.get(1), 'number');
  }
});
