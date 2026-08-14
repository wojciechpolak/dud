// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  formatAccessLog,
  formatEventLog,
  parseLogFormat,
  redactLogText,
} from '../dist/src/log.js';
import {
  loadNodeServerConfig,
  startNodeServer,
} from '../dist/src/node-server.js';
import { encodeBase64Url } from '../dist/src/v2-auth.js';

const DELIVERY_ID = 'a'.repeat(32);
const RENDEZVOUS_ID = 'd'.repeat(64);

function capturingLogger(lines) {
  return {
    error(...args) {
      lines.push(args.join(' '));
    },
    log(...args) {
      lines.push(args.join(' '));
    },
  };
}

async function startLoggingServer(t, config) {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'dud-node-log-'));
  const lines = [];
  const server = await startNodeServer(
    {
      dataDir,
      listenHost: '127.0.0.1',
      listenPort: 0,
      secretToken: 'top-secret',
      ...config,
    },
    { logger: capturingLogger(lines) },
  );
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await rm(dataDir, { recursive: true, force: true });
  });
  return { lines, baseUrl: `http://127.0.0.1:${server.address().port}` };
}

test('the log format is explicit and fails closed', () => {
  assert.equal(parseLogFormat(undefined), 'text');
  assert.equal(parseLogFormat(''), 'text');
  assert.equal(parseLogFormat('text'), 'text');
  assert.equal(parseLogFormat('json'), 'json');
  assert.throws(() => parseLogFormat('logfmt'), /must be one of: text, json/);
  assert.equal(loadNodeServerConfig({}).logFormat, 'text');
  assert.equal(
    loadNodeServerConfig({ DUD_LOG_FORMAT: 'json' }).logFormat,
    'json',
  );
});

test('log text drops identifier-shaped values', () => {
  assert.equal(
    redactLogText(`failed to read delivery ${DELIVERY_ID}`),
    'failed to read delivery <redacted>',
  );
  assert.equal(
    redactLogText(`rendezvous ${RENDEZVOUS_ID} expired`),
    'rendezvous <redacted> expired',
  );
  assert.equal(
    redactLogText(`token ${'A1_b-'.repeat(10)} rejected`),
    'token <redacted> rejected',
  );
  // Ordinary words and short values stay readable.
  assert.equal(
    redactLogText('capability is not active for epoch 20000'),
    'capability is not active for epoch 20000',
  );
});

test('the text access line is unchanged and the JSON line is structured', () => {
  const input = {
    method: 'POST',
    path: '/v2/deliveries',
    status: 200,
    durationMs: 12,
    client: '127.0.0.1',
    timing: {
      operation: 'delivery-publish',
      status: 200,
      authorizationMs: 1.5,
      metadataMs: 2.25,
      bodyMs: 3,
      totalMs: 9,
    },
  };
  assert.equal(
    formatAccessLog('text', input),
    '127.0.0.1 POST /v2/deliveries -> 200 12ms',
  );
  const at = new Date('2026-08-07T00:00:00.000Z');
  assert.deepEqual(JSON.parse(formatAccessLog('json', input, at)), {
    ts: '2026-08-07T00:00:00.000Z',
    level: 'info',
    event: 'request',
    method: 'POST',
    path: '/v2/deliveries',
    status: 200,
    duration_ms: 12,
    client: '127.0.0.1',
    operation: 'delivery-publish',
    authorization_ms: 1.5,
    metadata_ms: 2.25,
    body_ms: 3,
    handler_ms: 9,
  });
});

test('the JSON access line omits an absent client and absent timings', () => {
  const record = JSON.parse(
    formatAccessLog('json', {
      method: 'GET',
      path: '/v1/test',
      status: 200,
      durationMs: 1,
    }),
  );
  assert.deepEqual(Object.keys(record).sort(), [
    'duration_ms',
    'event',
    'level',
    'method',
    'path',
    'status',
    'ts',
  ]);
});

test('event logs are redacted in both formats', () => {
  const message = `Node server request failed: delivery ${DELIVERY_ID}`;
  assert.equal(
    formatEventLog('text', 'error', 'request_failed', message),
    'Node server request failed: delivery <redacted>',
  );
  const record = JSON.parse(
    formatEventLog(
      'json',
      'error',
      'request_failed',
      message,
      new Date('2026-08-07T00:00:00.000Z'),
    ),
  );
  assert.deepEqual(record, {
    ts: '2026-08-07T00:00:00.000Z',
    level: 'error',
    event: 'request_failed',
    message: 'Node server request failed: delivery <redacted>',
  });
});

test('a JSON-mode server logs one redacted record per request', async (t) => {
  const { lines, baseUrl } = await startLoggingServer(t, {
    logFormat: 'json',
  });
  const listening = JSON.parse(lines.at(-1));
  assert.equal(listening.event, 'listening');
  assert.equal(listening.level, 'info');

  lines.length = 0;
  const response = await fetch(`${baseUrl}/v1/files/${DELIVERY_ID}`);
  assert.equal(response.status, 404);
  await response.arrayBuffer();

  assert.equal(lines.length, 1);
  const record = JSON.parse(lines[0]);
  assert.equal(record.event, 'request');
  assert.equal(record.method, 'GET');
  assert.equal(record.status, 404);
  assert.equal(typeof record.duration_ms, 'number');
  assert.ok(Date.parse(record.ts) > 0);
});

test('v2 requests log their route class and phase timings', async (t) => {
  const { lines, baseUrl } = await startLoggingServer(t, {
    logFormat: 'json',
    logMode: 'minimal',
    publicBaseUrl: 'https://dud.example.com',
    v2Enabled: true,
    v2AdminSecret: encodeBase64Url(new Uint8Array(32).fill(0xc0)),
    v2DeploymentKey: encodeBase64Url(new Uint8Array(32).fill(0x80)),
    v2Secret: 'squid-lantern-rotate-9-mango',
  });
  lines.length = 0;
  const response = await fetch(
    `${baseUrl}/v2/deliveries/${DELIVERY_ID}/complete`,
    {
      method: 'POST',
    },
  );
  await response.arrayBuffer();

  const records = lines.map((line) => JSON.parse(line));
  // A refused request also names its reason for the operator; the access-log
  // entry is still exactly one line.
  const refusals = records.filter((entry) => entry.event === 'v2_rejected');
  assert.equal(refusals.length, 1);
  assert.match(refusals[0].message, /V2 request refused on/);
  const accessRecords = records.filter(
    (entry) => entry.event !== 'v2_rejected',
  );
  assert.equal(accessRecords.length, 1);
  const record = accessRecords[0];
  assert.equal(record.path, '/v2/deliveries/<redacted>/complete');
  assert.equal(record.operation, 'delivery-complete');
  for (const field of [
    'authorization_ms',
    'metadata_ms',
    'body_ms',
    'handler_ms',
  ]) {
    assert.equal(typeof record[field], 'number', field);
  }
  // minimal mode records no client address.
  assert.equal(record.client, undefined);
  assert.ok(
    !lines[0].includes(DELIVERY_ID),
    `access record leaked the delivery id: ${lines[0]}`,
  );
});

test('silent mode logs nothing at all', async (t) => {
  const { lines, baseUrl } = await startLoggingServer(t, {
    logFormat: 'json',
    logMode: 'silent',
  });
  lines.length = 0;
  const response = await fetch(`${baseUrl}/v1/test`);
  await response.arrayBuffer();
  assert.deepEqual(lines, []);
});
