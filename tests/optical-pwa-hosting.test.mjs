// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Readable, Writable } from 'node:stream';
import test from 'node:test';

import { createWorker } from '../dist/server/src/index.js';
import {
  createNodeRequestHandler,
  loadNodeServerConfig,
} from '../dist/server/src/node-server.js';
import { OPTICAL_PWA_BUILD } from '../dist/server/src/optical-pwa.js';
import { makeContext } from './helpers.mjs';

const SECURITY_HEADERS = {
  'content-security-policy':
    /connect-src 'none'.*script-src 'self'.*frame-ancestors 'none'/,
  'permissions-policy': 'camera=(self), geolocation=(), microphone=()',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
};

function storageTrap() {
  let calls = 0;
  const fail = () => {
    calls++;
    throw new Error('optical request reached payload storage');
  };
  return {
    blobStore: {
      put: fail,
      get: fail,
      head: fail,
      list: fail,
      delete: fail,
    },
    r2: {
      put: fail,
      get: fail,
      head: fail,
      list: fail,
      delete: fail,
    },
    get calls() {
      return calls;
    },
  };
}

function createOpticalNode(enabled) {
  const storage = storageTrap();
  const handler = createNodeRequestHandler(
    {
      dataDir: '/unused',
      opticalPwaEnabled: enabled,
    },
    {
      blobStore: storage.blobStore,
      logger: { error() {}, log() {} },
    },
  );
  return { handler, storage };
}

function createOpticalWorker(enabled) {
  const storage = storageTrap();
  return {
    storage,
    worker: createWorker({
      DUD_OPTICAL_PWA_ENABLED: String(enabled),
      FILES: storage.r2,
    }),
  };
}

function workerFetch(worker, pathname, init) {
  return worker.fetch(
    new Request(`https://dud.example.com${pathname}`, init),
    makeContext(),
  );
}

async function nodeFetch(handler, pathname, init = {}) {
  const requestHeaders = new Headers(init.headers);
  requestHeaders.set('host', 'dud.example.com');
  const body = init.body === undefined ? [] : [init.body];
  const request = Readable.from(body);
  request.method = init.method ?? 'GET';
  request.url = pathname;
  request.headers = Object.fromEntries(requestHeaders);
  request.rawHeaders = [...requestHeaders].flatMap(([name, value]) => [
    name,
    value,
  ]);
  request.socket = { remoteAddress: '127.0.0.1' };

  const chunks = [];
  const responseHeaders = new Headers();
  const response = new Writable({
    write(chunk, _encoding, done) {
      chunks.push(Buffer.from(chunk));
      done();
    },
  });
  response.statusCode = 200;
  response.setHeader = (name, value) =>
    responseHeaders.set(name, String(value));
  await handler(request, response);
  return new Response(Buffer.concat(chunks), {
    status: response.statusCode,
    headers: responseHeaders,
  });
}

function expectedBytes(asset) {
  return Buffer.from(asset.bytes, 'base64');
}

function assertSecurityHeaders(response) {
  for (const [name, expected] of Object.entries(SECURITY_HEADERS)) {
    const actual = response.headers.get(name);
    if (expected instanceof RegExp) {
      assert.match(actual ?? '', expected, name);
    } else {
      assert.equal(actual, expected, name);
    }
  }
}

test('Node and Worker serve byte-identical optical assets with exact metadata', async () => {
  const manifestBytes = readFileSync(
    new URL(
      '../server/optical-receiver/.work/pwa/build-manifest.json',
      import.meta.url,
    ),
  );
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifest.buildId, OPTICAL_PWA_BUILD.buildId);
  assert.equal(manifest.entrypoint, OPTICAL_PWA_BUILD.entrypoint);
  assert.deepEqual(
    Object.keys(OPTICAL_PWA_BUILD.assets).sort(),
    [
      ...manifest.assets.map((asset) => asset.path),
      'build-manifest.json',
    ].sort(),
  );
  const node = createOpticalNode(true);
  const { storage: workerStorage, worker } = createOpticalWorker(true);
  const paths = ['', ...Object.keys(OPTICAL_PWA_BUILD.assets)];

  for (const name of paths) {
    const pathname = `/optical/${name}`;
    const asset = OPTICAL_PWA_BUILD.assets[name || 'index.html'];
    const [nodeResponse, workerResponse] = await Promise.all([
      nodeFetch(node.handler, pathname),
      workerFetch(worker, pathname),
    ]);
    assert.equal(nodeResponse.status, 200, pathname);
    assert.equal(workerResponse.status, 200, pathname);
    assert.equal(nodeResponse.headers.get('content-type'), asset.contentType);
    assert.equal(workerResponse.headers.get('content-type'), asset.contentType);
    assert.equal(
      nodeResponse.headers.get('cache-control'),
      asset.immutable ? 'public, max-age=31536000, immutable' : 'no-store',
    );
    if (name === 'sw.js') {
      assert.equal(
        nodeResponse.headers.get('service-worker-allowed'),
        '/optical/',
      );
      assert.equal(
        workerResponse.headers.get('service-worker-allowed'),
        '/optical/',
      );
    }
    assertSecurityHeaders(nodeResponse);
    assertSecurityHeaders(workerResponse);
    const expected = expectedBytes(asset);
    assert.deepEqual(Buffer.from(await nodeResponse.arrayBuffer()), expected);
    assert.deepEqual(Buffer.from(await workerResponse.arrayBuffer()), expected);
    if (name === 'build-manifest.json') {
      assert.deepEqual(expected, manifestBytes);
    } else {
      const record = manifest.assets.find(
        (asset) => asset.path === (name || 'index.html'),
      );
      assert.ok(record, pathname);
      assert.equal(expected.length, record.bytes, pathname);
      assert.equal(
        createHash('sha256').update(expected).digest('hex'),
        record.sha256,
        pathname,
      );
      assert.equal(
        nodeResponse.headers.get('content-type'),
        record.contentType,
        pathname,
      );
    }
  }
  assert.equal(node.storage.calls, 0);
  assert.equal(workerStorage.calls, 0);
});

test('Node and Worker return headers without bodies for optical HEAD requests', async () => {
  const node = createOpticalNode(true);
  const { worker } = createOpticalWorker(true);

  for (const name of Object.keys(OPTICAL_PWA_BUILD.assets)) {
    const asset = OPTICAL_PWA_BUILD.assets[name];
    const pathname = `/optical/${name}`;
    const [nodeResponse, workerResponse] = await Promise.all([
      nodeFetch(node.handler, pathname, { method: 'HEAD' }),
      workerFetch(worker, pathname, { method: 'HEAD' }),
    ]);
    for (const response of [nodeResponse, workerResponse]) {
      assert.equal(response.status, 200, pathname);
      assert.equal(response.headers.get('content-type'), asset.contentType);
      assert.equal(
        response.headers.get('content-length'),
        String(expectedBytes(asset).byteLength),
      );
      assert.equal((await response.arrayBuffer()).byteLength, 0);
    }
  }
});

test('disabled optical hosting returns 404 for every optical request shape', async () => {
  const node = createOpticalNode(false);
  const { storage: workerStorage, worker } = createOpticalWorker(false);
  const requests = [
    ['/optical/', undefined],
    ['/optical/index.aaaaaaaaaaaa.html', undefined],
    ['/optical/manifest.webmanifest', undefined],
    [`/optical/${OPTICAL_PWA_BUILD.entrypoint}`, { method: 'HEAD' }],
    ['/optical/sw.js?build=wrong', undefined],
    ['/optical/index.html', { method: 'POST', body: 'ignored request body' }],
    ['/optical/index.html', { headers: { range: 'bytes=0-10' } }],
  ];

  for (const [pathname, init] of requests) {
    const [nodeResponse, workerResponse] = await Promise.all([
      nodeFetch(node.handler, pathname, init),
      workerFetch(worker, pathname, init),
    ]);
    assert.equal(nodeResponse.status, 404, pathname);
    assert.equal(workerResponse.status, 404, pathname);
    if (init?.method === 'HEAD') {
      assert.equal((await nodeResponse.arrayBuffer()).byteLength, 0);
      assert.equal((await workerResponse.arrayBuffer()).byteLength, 0);
    }
  }
  assert.equal(node.storage.calls, 0);
  assert.equal(workerStorage.calls, 0);
});

test('optical hosting rejects methods, query variants, ranges, and unknown paths', async () => {
  const node = createOpticalNode(true);
  const { storage: workerStorage, worker } = createOpticalWorker(true);
  const cases = [
    ['/optical', undefined, 404],
    ['/optical/missing.js', undefined, 404],
    ...['__proto__', 'constructor', 'toString', 'hasOwnProperty'].flatMap(
      (name) =>
        ['GET', 'HEAD'].map((method) => [`/optical/${name}`, { method }, 404]),
    ),
    ['/optical/index.html?build=anything', undefined, 404],
    ['/optical/index.html', { method: 'POST', body: 'not parsed' }, 405],
    ['/optical/index.html', { headers: { range: 'bytes=0-10' } }, 416],
    ['/optical/index.aaaaaaaaaaaa.html?build=anything', undefined, 404],
    ['/optical/index.AAAAAAAAAAAA.html', undefined, 404],
    ['/optical/index.aaaaaaaaaaa.html', undefined, 404],
    ['/optical/index.aaaaaaaaaaaaa.html', undefined, 404],
    ['/optical/nested/index.aaaaaaaaaaaa.html', undefined, 404],
    [
      '/optical/index.aaaaaaaaaaaa.html',
      { method: 'POST', body: 'not parsed' },
      405,
    ],
    [
      '/optical/index.aaaaaaaaaaaa.html',
      { headers: { range: 'bytes=0-10' } },
      416,
    ],
  ];

  for (const [pathname, init, status] of cases) {
    const [nodeResponse, workerResponse] = await Promise.all([
      nodeFetch(node.handler, pathname, init),
      workerFetch(worker, pathname, init),
    ]);
    assert.equal(nodeResponse.status, status, pathname);
    assert.equal(workerResponse.status, status, pathname);
    assertSecurityHeaders(nodeResponse);
    assertSecurityHeaders(workerResponse);
    if (status === 405) {
      assert.equal(nodeResponse.headers.get('allow'), 'GET, HEAD');
      assert.equal(workerResponse.headers.get('allow'), 'GET, HEAD');
    }
    if (status === 416) {
      assert.equal(nodeResponse.headers.get('accept-ranges'), 'none');
      assert.equal(workerResponse.headers.get('accept-ranges'), 'none');
    }
  }
  assert.equal(node.storage.calls, 0);
  assert.equal(workerStorage.calls, 0);
});

test('Node and Worker redirect missing fingerprinted indexes to the stable receiver URL', async () => {
  const node = createOpticalNode(true);
  const { storage: workerStorage, worker } = createOpticalWorker(true);
  for (const method of ['GET', 'HEAD']) {
    const pathname = '/optical/index.aaaaaaaaaaaa.html';
    const responses = await Promise.all([
      nodeFetch(node.handler, pathname, { method }),
      workerFetch(worker, pathname, { method }),
    ]);
    for (const response of responses) {
      assert.equal(response.status, 302);
      assert.equal(response.headers.get('location'), '/optical/');
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal((await response.arrayBuffer()).byteLength, 0);
      assertSecurityHeaders(response);
    }
  }
  assert.equal(node.storage.calls, 0);
  assert.equal(workerStorage.calls, 0);
});

test('optical hosting does not change Worker dead drop API responses', async () => {
  const disabled = createOpticalWorker(false).worker;
  const enabled = createOpticalWorker(true).worker;
  const responses = await Promise.all(
    [disabled, enabled].map((worker) => workerFetch(worker, '/v1/test')),
  );
  assert.equal(responses[0].status, 200);
  assert.equal(responses[1].status, 200);
  assert.deepEqual(await responses[0].json(), await responses[1].json());
});

test('optical hosting uses its own mode flag in Node and Worker', async () => {
  const cases = [
    [{}, false],
    [{ DUD_OPTICAL_PWA_ENABLED: '' }, false],
    [{ DUD_OPTICAL_PWA_ENABLED: 'true' }, true],
    [{ DUD_OPTICAL_PWA_ENABLED: '1' }, true],
    [{ DUD_OPTICAL_PWA_ENABLED: 'false' }, false],
    [{ DUD_OPTICAL_PWA_ENABLED: '0' }, false],
    [{ DUD_DROP_OPTICAL_PWA_ENABLED: 'true' }, false],
    [
      {
        DUD_OPTICAL_PWA_ENABLED: 'false',
        DUD_DROP_OPTICAL_PWA_ENABLED: 'true',
      },
      false,
    ],
    [
      {
        DUD_OPTICAL_PWA_ENABLED: 'true',
        DUD_DROP_OPTICAL_PWA_ENABLED: 'false',
      },
      true,
    ],
    [
      {
        DUD_OPTICAL_PWA_ENABLED: 'true',
        DUD_DROP_ENABLED: 'false',
        DUD_PEER_ENABLED: 'false',
      },
      true,
    ],
  ];
  for (const [env, enabled] of cases) {
    const config = loadNodeServerConfig(env);
    assert.equal(config.opticalPwaEnabled, enabled, JSON.stringify(env));
    const node = createOpticalNode(config.opticalPwaEnabled);
    const worker = createWorker(env);
    const responses = await Promise.all([
      nodeFetch(node.handler, '/optical/'),
      workerFetch(worker, '/optical/'),
    ]);
    for (const response of responses) {
      assert.equal(response.status, enabled ? 200 : 404, JSON.stringify(env));
    }
  }
});

test('Node and Worker reject invalid optical hosting boolean values', () => {
  for (const value of ['sometimes', 'TRUE', '2']) {
    const env = { DUD_OPTICAL_PWA_ENABLED: value };
    assert.throws(
      () => loadNodeServerConfig(env),
      /must be true, false, 1, or 0/,
    );
    assert.throws(
      () => createWorker(env),
      /Boolean environment value is invalid/,
    );
  }
});
