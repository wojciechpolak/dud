// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  createNodeRequestHandler,
  loadNodeServerConfig,
  redactAccessPath,
  runNodeV2Maintenance,
  startNodeServer,
} from '../dist/src/node-server.js';
import {
  MAINTENANCE_MAX_BATCHES,
  runV2MaintenancePass,
} from '../dist/src/v2-maintenance.js';

test('v2 access paths redact complete delivery identifiers', () => {
  assert.equal(
    redactAccessPath(`/v2/deliveries/${'a'.repeat(32)}`),
    '/v2/deliveries/<redacted>',
  );
  assert.equal(
    redactAccessPath(`/v2/deliveries/${'b'.repeat(32)}/complete`),
    '/v2/deliveries/<redacted>/complete',
  );
  assert.equal(
    redactAccessPath(`/v2/pairing/rendezvous/${'d'.repeat(64)}/status`),
    '/v2/pairing/rendezvous/<redacted>/status',
  );
  assert.equal(
    redactAccessPath(`/v1/files/${'c'.repeat(32)}`),
    `/v1/files/${'c'.repeat(32)}`,
  );
});

test('Node v2 requires a configured canonical HTTPS public origin', () => {
  assert.throws(
    () =>
      createNodeRequestHandler({
        dataDir: '/tmp/dud-unused',
        v2Enabled: true,
      }),
    /DUD_PUBLIC_BASE_URL is required/,
  );
  assert.throws(
    () =>
      createNodeRequestHandler({
        dataDir: '/tmp/dud-unused',
        publicBaseUrl: 'http://dud.example.com',
        v2Enabled: true,
      }),
    /canonical HTTPS origin/,
  );
});

test('Node v2 configuration is explicit and validates limits', () => {
  const defaults = loadNodeServerConfig({});
  assert.equal(defaults.v1Enabled, true);
  assert.equal(defaults.v2Enabled, false);

  assert.equal(defaults.v2OpenEnrollment, false);

  const enabled = loadNodeServerConfig({
    DUD_PUBLIC_BASE_URL: 'https://dud.example.com',
    DUD_DROP_ENABLED: 'false',
    DUD_DROP_SECRET: 'shared',
    DUD_PEER_ENABLED: 'true',
    DUD_PEER_SECRET: 'squid-lantern-rotate-9-mango',
    DUD_PEER_MAX_OBJECT_BYTES: '4096',
  });
  assert.equal(enabled.v1Enabled, false);
  assert.equal(enabled.secretToken, 'shared');
  assert.equal(enabled.v2Enabled, true);
  assert.equal(enabled.v2Secret, 'squid-lantern-rotate-9-mango');
  assert.equal(enabled.v2Limits.maxObjectBytes, 4096);
  assert.equal(
    loadNodeServerConfig({ DUD_PEER_OPEN_ENROLLMENT: 'true' }).v2OpenEnrollment,
    true,
  );
  assert.throws(
    () => loadNodeServerConfig({ DUD_PEER_ENABLED: 'sometimes' }),
    /must be true, false, 1, or 0/,
  );
});

function maintenanceResult(overrides = {}) {
  return {
    expiredDeliveryIds: [],
    expiredBodyKeys: [],
    deletedNonces: 0,
    deletedControlEvents: 0,
    deletedRateWindows: 0,
    deletedInvitations: 0,
    complete: true,
    ...overrides,
  };
}

test('Node granular V2 maintenance removes only bodies named by its bounded metadata pass', async () => {
  const calls = [];
  const repository = {
    async runMaintenance(now, limit) {
      calls.push(['maintenance', now, limit]);
      return maintenanceResult({
        expiredDeliveryIds: ['delivery'],
        expiredBodyKeys: ['deliveries/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bin'],
        deletedNonces: 1,
      });
    },
  };
  const bodyStore = {
    async delete(key) {
      calls.push(['delete', key]);
    },
  };

  await runNodeV2Maintenance(
    repository,
    bodyStore,
    () => 1_800_000_123_999,
    64,
  );
  assert.deepEqual(calls, [
    ['maintenance', 1_800_000_123, 64],
    ['delete', 'deliveries/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bin'],
  ]);
});

test('Node granular V2 maintenance keeps batching until the backend is drained', async () => {
  const keys = Array.from(
    { length: 5 },
    (_, index) => `deliveries/${String(index).repeat(32)}.bin`,
  );
  const deleted = [];
  let batches = 0;
  const repository = {
    async runMaintenance() {
      const key = keys[batches++];
      return maintenanceResult(
        key === undefined
          ? {}
          : { expiredBodyKeys: [key], complete: batches === keys.length },
      );
    },
  };

  await runNodeV2Maintenance(
    repository,
    {
      async delete(key) {
        deleted.push(key);
      },
    },
    () => 1_800_000_123_999,
    64,
  );
  // The pass stops as soon as a batch reports the backend drained, and every
  // earlier batch contributed its own bounded page of body deletions.
  assert.equal(batches, keys.length);
  assert.deepEqual(deleted, keys);
});

test('Node granular V2 maintenance stops at its batch budget and resumes later', async () => {
  let batches = 0;
  const repository = {
    async runMaintenance() {
      batches++;
      return maintenanceResult({ complete: false });
    },
  };
  const result = await runV2MaintenancePass(
    repository,
    { async delete() {} },
    1_800_000_123,
    64,
  );
  assert.equal(batches, MAINTENANCE_MAX_BATCHES);
  assert.equal(result.batches, MAINTENANCE_MAX_BATCHES);
  assert.equal(result.complete, false);
});

test('Node granular V2 maintenance survives a body that cannot be deleted', async () => {
  let batches = 0;
  const repository = {
    async runMaintenance() {
      batches++;
      return maintenanceResult({
        expiredBodyKeys: [
          'deliveries/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bin',
          'deliveries/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bin',
        ],
      });
    },
  };
  const result = await runV2MaintenancePass(
    repository,
    {
      async delete(key) {
        if (key.includes('aaaa')) {
          throw new Error('storage is unavailable');
        }
      },
    },
    1_800_000_123,
    64,
  );
  assert.equal(batches, 1);
  assert.equal(result.deletedBodies, 1);
  assert.equal(result.complete, true);
});

async function closeServer(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function createCapturingLogger(messages) {
  return {
    error() {},
    log(...args) {
      messages.push(args.join(' '));
    },
  };
}

async function startTestServer(config = {}, options = {}) {
  const dataDir =
    config.dataDir ?? (await mkdtemp(path.join(os.tmpdir(), 'dud-node-data-')));
  const quietLogger = {
    error() {},
    log() {},
  };

  const server = await startNodeServer(
    {
      dataDir,
      listenHost: '127.0.0.1',
      listenPort: 0,
      secretToken: 'top-secret',
      ...config,
    },
    {
      logger: quietLogger,
      ...options,
    },
  );

  const address = server.address();
  const protocol = config.tlsCertFile && config.tlsKeyFile ? 'https' : 'http';
  const baseUrl = `${protocol}://127.0.0.1:${address.port}`;
  return { baseUrl, dataDir, server };
}

async function startLoggedTestServer(config = {}) {
  const messages = [];
  const serverState = await startTestServer(config, {
    logger: createCapturingLogger(messages),
  });

  return {
    ...serverState,
    messages,
  };
}

async function fetchTestEndpoint(baseUrl) {
  const response = await fetch(`${baseUrl}/v1/test`);
  assert.equal(response.status, 200);
  return response;
}

test('node server can upload and download ciphertext through the shared API', async () => {
  const { baseUrl, server } = await startTestServer();

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
      },
      body: 'ciphertext',
    });

    assert.equal(upload.status, 201);
    const uploadBody = await upload.json();

    const download = await fetch(`${baseUrl}/v1/files/${uploadBody.id}`);
    assert.equal(download.status, 200);
    assert.equal(await download.text(), 'ciphertext');
  } finally {
    await closeServer(server);
  }
});

test('node server enforces delete-after-read', async () => {
  const { baseUrl, server } = await startTestServer();

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
        'x-dud-delete-after-read': 'true',
      },
      body: 'ciphertext',
    });

    const { id } = await upload.json();
    const first = await fetch(`${baseUrl}/v1/files/${id}`);
    assert.equal(first.status, 200);
    assert.equal(await first.text(), 'ciphertext');

    const second = await fetch(`${baseUrl}/v1/files/${id}`);
    assert.equal(second.status, 410);
  } finally {
    await closeServer(server);
  }
});

test('node server handles expiry with the shared service logic', async () => {
  let currentTime = 1_700_000_000_000;
  const { baseUrl, server } = await startTestServer(
    {},
    {
      now: () => currentTime,
      createId: () => '4'.repeat(32),
    },
  );

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
        'x-dud-ttl': '1s',
      },
      body: 'ciphertext',
    });

    assert.equal(upload.status, 201);
    currentTime += 2_000;

    const download = await fetch(`${baseUrl}/v1/files/${'4'.repeat(32)}`);
    assert.equal(download.status, 410);
  } finally {
    await closeServer(server);
  }
});

test('node server rejects invalid secret tokens', async () => {
  const { baseUrl, server } = await startTestServer();

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'wrong',
      },
      body: 'ciphertext',
    });

    assert.equal(upload.status, 403);
  } finally {
    await closeServer(server);
  }
});

test('node server applies max upload size limits', async () => {
  const { baseUrl, server } = await startTestServer({
    maxUploadBytes: 4,
  });

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
      },
      body: 'hello world',
    });

    assert.equal(upload.status, 413);
  } finally {
    await closeServer(server);
  }
});

test('node server flush removes expired objects', async () => {
  let currentTime = 1_700_000_000_000;
  const { baseUrl, server } = await startTestServer(
    {},
    {
      now: () => currentTime,
      createId: () => '5'.repeat(32),
    },
  );

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
        'x-dud-ttl': '1s',
      },
      body: 'ciphertext',
    });
    assert.equal(upload.status, 201);

    currentTime += 2_000;

    const flush = await fetch(`${baseUrl}/v1/admin/flush`, {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
      },
    });
    assert.equal(flush.status, 200);

    const body = await flush.json();
    assert.equal(body.ok, true);
    assert.equal(body.deletedCount >= 1, true);
  } finally {
    await closeServer(server);
  }
});

test('node server exposes a middleware point for operator policy', async () => {
  const { baseUrl, server } = await startTestServer(
    {},
    {
      beforeRequest(request) {
        if (new URL(request.url).pathname === '/v1/files') {
          return new Response('rate limited', { status: 429 });
        }
        return null;
      },
    },
  );

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
      },
      body: 'ciphertext',
    });

    assert.equal(upload.status, 429);
    assert.equal(await upload.text(), 'rate limited');
  } finally {
    await closeServer(server);
  }
});

test('node server logs request summaries', async () => {
  const { baseUrl, messages, server } = await startLoggedTestServer();

  try {
    await fetchTestEndpoint(baseUrl);
    assert.equal(messages.length >= 1, true);
    assert.equal(
      messages.some((message) =>
        /127\.0\.0\.1 GET \/v1\/test -> 200 \d+ms/.test(message),
      ),
      true,
    );
  } finally {
    await closeServer(server);
  }
});

test('node server supports minimal request logging without client IPs', async () => {
  const { baseUrl, messages, server } = await startLoggedTestServer({
    logMode: 'minimal',
  });

  try {
    await fetchTestEndpoint(baseUrl);
    assert.equal(
      messages.some((message) => /GET \/v1\/test -> 200 \d+ms/.test(message)),
      true,
    );
    assert.equal(
      messages.some((message) =>
        /127\.0\.0\.1 GET \/v1\/test -> 200 \d+ms/.test(message),
      ),
      false,
    );
  } finally {
    await closeServer(server);
  }
});

test('node server silent log mode suppresses startup and access logs', async () => {
  const { baseUrl, messages, server } = await startLoggedTestServer({
    logMode: 'silent',
  });

  try {
    await fetchTestEndpoint(baseUrl);
    assert.deepEqual(messages, []);
  } finally {
    await closeServer(server);
  }
});
