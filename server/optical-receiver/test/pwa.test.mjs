// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const pwa = new URL('../.work/pwa/', import.meta.url);

function read(name) {
  return readFileSync(new URL(name, pwa), 'utf8');
}

function buildManifest() {
  return JSON.parse(read('build-manifest.json'));
}

function assetPath(stem) {
  const match = buildManifest().assets.find(
    (asset) => asset.path === stem || asset.path.startsWith(`${stem}.`),
  );
  assert.ok(match, `${stem} is absent from the build manifest`);
  return match.path;
}

function serviceWorkerHarness(cacheNames = [], options = {}) {
  const listeners = new Map();
  const cached = new Map();
  const unrelated = new Map();
  const deleted = [];
  const scope = 'https://dud.example.com/optical/';
  const caches = {
    async open() {
      return {
        async put(url, response) {
          if (options.failPut) {
            throw new DOMException('quota exceeded', 'QuotaExceededError');
          }
          cached.set(String(url), response);
        },
        async match(url) {
          return cached.get(String(url));
        },
      };
    },
    async keys() {
      return cacheNames;
    },
    async delete(name) {
      deleted.push(name);
      if (name === `dud-optical-${buildManifest().buildId}`) {
        cached.clear();
      }
      return true;
    },
    async match(url) {
      return unrelated.get(String(url)) ?? cached.get(String(url));
    },
  };
  const self = {
    location: new URL(`${scope}sw.js`),
    registration: { scope },
    clients: { async claim() {} },
    async skipWaiting() {},
    addEventListener(name, listener) {
      listeners.set(name, listener);
    },
  };
  vm.runInNewContext(read('sw.js'), {
    URL,
    Response,
    Headers,
    atob,
    caches,
    Promise,
    self,
  });
  return { cached, deleted, listeners, unrelated };
}

async function dispatchWorkerEvent(listener, fields = {}) {
  let completion;
  let response;
  listener({
    ...fields,
    waitUntil(promise) {
      completion = promise;
    },
    respondWith(promise) {
      response = promise;
    },
  });
  await completion;
  return response ? await response : undefined;
}

test('service worker reports its immutable entrypoint through a local port', async () => {
  const harness = serviceWorkerHarness();
  const replies = [];
  await dispatchWorkerEvent(harness.listeners.get('message'), {
    data: { type: 'receiver-build' },
    ports: [
      {
        postMessage(value) {
          replies.push(JSON.parse(JSON.stringify(value)));
        },
      },
    ],
  });
  const manifest = buildManifest();
  assert.deepEqual(replies, [
    { buildID: manifest.buildId, entrypoint: `./${manifest.entrypoint}` },
  ]);
  assert.equal(harness.cached.size, 0);
});

test('receiver build contains only local repository JavaScript application and workers', () => {
  for (const name of ['app', 'decoder-worker', 'fountain-worker']) {
    const workerName = assetPath(name);
    const worker = read(workerName);
    assert.doesNotMatch(
      worker,
      /WebAssembly|ZBar|zbar|node_modules|filippo|age-encryption/,
    );
    assert.ok(
      statSync(new URL(workerName, pwa)).size <
        (name === 'app' ? 200_000 : 100_000),
    );
    assert.doesNotMatch(worker, /fetch\(|importScripts\(|https?:\/\//);
  }
});

test('receiver notices describe repository code and the dependency tree excludes QR packages', () => {
  for (const name of ['package.json', 'package-lock.json']) {
    const manifest = readFileSync(
      new URL(`../../../${name}`, import.meta.url),
      'utf8',
    );
    assert.doesNotMatch(manifest, /@undecaf\/zbar-wasm/);
  }
  const notices = read(assetPath('third-party-notices'));
  assert.match(notices, /MIT license/);
  assert.doesNotMatch(notices, /ZBar|zbar|LGPL/);
  assert.ok(read('index.html').includes(assetPath('third-party-notices')));
  assert.equal(
    buildManifest().assets.find(
      (asset) => asset.path === assetPath('third-party-notices'),
    ).contentType,
    'text/plain; charset=utf-8',
  );
});

test('decoder worker imports the repository image scanner without external QR runtimes', () => {
  const workerSource = readFileSync(
    new URL('../src/decoder-worker.ts', import.meta.url),
    'utf8',
  );
  assert.match(workerSource, /from '\.\/qr-image\.js'/);
  assert.doesNotMatch(workerSource, /ZBar|zbar|WebAssembly/);
});

test('decoder worker scans the bounded center square from the camera guide', () => {
  const workerSource = readFileSync(
    new URL('../src/decoder-worker.ts', import.meta.url),
    'utf8',
  );
  assert.match(workerSource, /scanRegion\(bitmap\.width, bitmap\.height\)/);
  assert.match(workerSource, /region\.scanSize/);
  assert.doesNotMatch(
    workerSource,
    /getImageData\(0, 0, bitmap\.width, bitmap\.height\)/,
  );
});

test('receiver document requests no decryption material', () => {
  const html = read('index.html');
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /script-src 'self'/);
  assert.match(html, /Start camera/);
  assert.match(html, /Stop/);
  assert.match(html, /DUD optical transfer receiver/);
  assert.doesNotMatch(html, /experiment|Prototype build/);
  assert.doesNotMatch(html, /type="password"|identity import|private key/i);
});

test('receiver offers only a user-initiated opaque capsule download', () => {
  const html = read('index.html');
  const applicationSource = readFileSync(
    new URL('../src/app.ts', import.meta.url),
    'utf8',
  );
  const receiptSource = readFileSync(
    new URL('../src/capsule-receipt.ts', import.meta.url),
    'utf8',
  );
  const fountainSource = [
    'fountain-client.ts',
    'fountain-worker.ts',
    'pipeline.ts',
    'codec.ts',
  ]
    .map((name) =>
      readFileSync(new URL(`../src/${name}`, import.meta.url), 'utf8'),
    )
    .join('\n');
  assert.match(
    html,
    /<button id="save-capsule" type="button" disabled>\s*Save encrypted capsule/,
  );
  assert.match(applicationSource, /saveButton\.addEventListener\('click'/);
  assert.match(applicationSource, /receipt\.accept\(value\.capsule\)/);
  assert.match(applicationSource, /URL\.createObjectURL\(receipt\.blob\(\)\)/);
  assert.match(receiptSource, /dud-encrypted-capsule\.age/);
  assert.match(receiptSource, /application\/octet-stream/);
  assert.doesNotMatch(
    `${applicationSource}\n${receiptSource}\n${fountainSource}`,
    /decrypt|passphrase|identity|TextDecoder|FileReader/i,
  );
  assert.doesNotMatch(
    `${applicationSource}\n${fountainSource}`,
    /indexedDB|localStorage|sessionStorage|caches\./,
  );
});

test('receiver enforces a fixed camera deadline', () => {
  const applicationSource = readFileSync(
    new URL('../src/app.ts', import.meta.url),
    'utf8',
  );
  assert.match(applicationSource, /MAX_TRANSFER_MILLISECONDS/);
  assert.match(applicationSource, /window\.setTimeout/);
  assert.match(applicationSource, /Camera time limit 15 minutes reached/);
  assert.match(applicationSource, /window\.clearTimeout/);
});

test('receiver interruption paths clear one in-memory run', () => {
  const applicationSource = readFileSync(
    new URL('../src/app.ts', import.meta.url),
    'utf8',
  );
  const interruptionSource = readFileSync(
    new URL('../src/capture-interruptions.ts', import.meta.url),
    'utf8',
  );
  assert.match(applicationSource, /watchCaptureInterruptions/);
  assert.match(applicationSource, /stopRun\(\)/);
  assert.match(applicationSource, /Incomplete encrypted bytes were cleared/);
  for (const event of [
    'visibilitychange',
    'freeze',
    'pagehide',
    'error',
    'unhandledrejection',
    'memorypressure',
    'change',
    'devicechange',
    'controllerchange',
    'ended',
    'mute',
  ]) {
    assert.ok(interruptionSource.includes(`'${event}'`), event);
  }
  assert.match(applicationSource, /camera\.disabled = true/);
});

test('receiver keeps one persistent progress row per stripe', () => {
  const html = read('index.html');
  const applicationSource = readFileSync(
    new URL('../src/app.ts', import.meta.url),
    'utf8',
  );
  assert.match(html, /id="stripe-progress"/);
  assert.match(html, /id="stripe-rows"/);
  assert.match(applicationSource, /Array\.from\(\{ length: count \}/);
  assert.match(applicationSource, /Stripe \$\{index \+ 1\}/);
  assert.match(applicationSource, /stopRun\(true\)/);
});

test('receiver offers full-frame and tracked camera scan profiles', () => {
  const html = read('index.html');
  const applicationSource = readFileSync(
    new URL('../src/app.ts', import.meta.url),
    'utf8',
  );
  assert.match(html, /30 FPS full frame/);
  assert.match(html, /60 FPS tracked four QR/);
  assert.match(
    applicationSource,
    /new ScanCadence\(activeCaptureProfile\.framesPerSecond\)/,
  );
  assert.match(applicationSource, /cadenceSkips/);
  assert.match(applicationSource, /cameraSettings\?\.frameRate/);
});

test('receiver displays the build identifier used by its service worker', () => {
  const html = read('index.html');
  const buildID = html.match(/data-build="([a-f0-9]{12})"/)?.[1];
  assert.ok(buildID, 'receiver document has no content-derived build ID');
  assert.equal(buildManifest().buildId, buildID);
  assert.ok(html.includes(`<code>${buildID}</code>`));
  assert.ok(read('sw.js').includes(`CACHE_PREFIX}${buildID}`));
  for (const asset of [
    'app',
    'styles',
    'receiver-icon',
    'third-party-notices',
  ]) {
    assert.ok(html.includes(assetPath(asset)));
  }
  assert.doesNotMatch(html, /__DUD_OPTICAL_BUILD__/);
  assert.doesNotMatch(read('sw.js'), /__DUD_OPTICAL_BUILD__/);
});

test('receiver installation uses a stable identity, launch URL, and manifest alias', () => {
  const manifest = JSON.parse(read('manifest.webmanifest'));
  assert.equal(manifest.id, '/optical/');
  assert.equal(manifest.start_url, './');
  assert.equal(manifest.scope, './');
  assert.equal(manifest.display, 'standalone');
  assert.match(
    read('index.html'),
    /rel="manifest" href="\.\/manifest.webmanifest"/,
  );
  assert.equal(read('manifest.webmanifest'), read(assetPath('manifest')));
  assert.equal(
    buildManifest().assets.find(
      (asset) => asset.path === 'manifest.webmanifest',
    ).immutable,
    false,
  );
});

test('service worker cache is restricted to receiver assets', () => {
  const serviceWorker = read('sw.js');
  const manifest = buildManifest();
  const immutable = manifest.assets.filter((asset) => asset.immutable);
  for (const asset of immutable) {
    assert.ok(
      serviceWorker.includes(`"./${asset.path}"`),
      `${asset.path} is absent from the offline cache`,
    );
  }
  assert.equal(serviceWorker.includes('"./index.html"'), false);
  assert.equal(serviceWorker.includes('"./sw.js"'), false);
  assert.equal(serviceWorker.includes('"./build-manifest.json"'), false);
  assert.match(serviceWorker, /requestURL\.origin !== self\.location\.origin/);
  assert.match(serviceWorker, /key\.startsWith\(CACHE_PREFIX\)/);
  assert.match(serviceWorker, /self\.skipWaiting\(\)/);
  assert.match(serviceWorker, /cache\.put\(/);
  assert.doesNotMatch(serviceWorker, /cache\.addAll\(/);
  assert.doesNotMatch(serviceWorker, /\bfetch\s*\(/);
});

test('application names its QR and fountain workers by content digest', () => {
  const application = read(assetPath('app'));
  assert.ok(application.includes(`./${assetPath('decoder-worker')}`));
  assert.doesNotMatch(application, /decoder-worker\.js/);
  assert.ok(application.includes(`./${assetPath('fountain-worker')}`));
  assert.doesNotMatch(application, /fountain-worker\.js/);
});

test('build manifest covers every shipped application asset', () => {
  const manifest = buildManifest();
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.basePath, '/optical/');
  assert.match(manifest.entrypoint, /^index\.[a-f0-9]{12}\.html$/);
  assert.deepEqual(manifest.browserCache, {
    bytes: manifest.assets
      .filter((asset) => asset.immutable)
      .reduce((total, asset) => total + asset.bytes, 0),
    limitBytes: 8 * 1024 * 1024,
  });
  assert.ok(manifest.browserCache.bytes <= manifest.browserCache.limitBytes);

  const shipped = readdirSync(pwa, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name !== 'build-manifest.json')
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual(manifest.assets.map((asset) => asset.path).sort(), shipped);
  for (const asset of manifest.assets) {
    const bytes = readFileSync(new URL(asset.path, pwa));
    assert.equal(asset.bytes, bytes.byteLength);
    assert.equal(
      asset.sha256,
      createHash('sha256').update(bytes).digest('hex'),
      asset.path,
    );
  }
});

test('receiver build is byte-reproducible', (t) => {
  const output = mkdtempSync(path.join(tmpdir(), 'dud-optical-pwa-'));
  t.after(() => rmSync(output, { recursive: true, force: true }));
  execFileSync(
    process.execPath,
    [
      fileURLToPath(new URL('../build.mjs', import.meta.url)),
      '--output',
      output,
    ],
    { stdio: 'pipe' },
  );

  const expected = readdirSync(pwa).sort();
  assert.deepEqual(readdirSync(output).sort(), expected);
  for (const name of expected) {
    assert.deepEqual(
      readFileSync(path.join(output, name)),
      readFileSync(new URL(name, pwa)),
      name,
    );
  }
});

test('service worker replaces only older optical build caches', async () => {
  const current = `dud-optical-${buildManifest().buildId}`;
  const old = 'dud-optical-old-build';
  const harness = serviceWorkerHarness([old, current, 'unrelated-cache']);
  await dispatchWorkerEvent(harness.listeners.get('activate'));
  assert.deepEqual(harness.deleted, [old]);
});

test('service worker restarts the receiver offline from its immutable index', async () => {
  const harness = serviceWorkerHarness();
  await dispatchWorkerEvent(harness.listeners.get('install'));
  const response = await dispatchWorkerEvent(harness.listeners.get('fetch'), {
    request: new Request('https://dud.example.com/optical/'),
  });
  assert.ok(response);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.equal(
    response.headers.get('permissions-policy'),
    'camera=(self), geolocation=(), microphone=()',
  );
  assert.match(
    response.headers.get('content-security-policy') ?? '',
    /connect-src 'none'.*frame-ancestors 'none'/,
  );
  assert.equal(
    createHash('sha256')
      .update(Buffer.from(await response.arrayBuffer()))
      .digest('hex'),
    buildManifest().assets.find(
      (asset) => asset.path === buildManifest().entrypoint,
    ).sha256,
  );
});

test('service worker ignores conflicting entries in unrelated caches', async () => {
  const harness = serviceWorkerHarness(['unrelated-cache']);
  const assetURL = `https://dud.example.com/optical/${buildManifest().entrypoint}`;
  harness.unrelated.set(assetURL, new Response('unrelated cache bytes'));
  await dispatchWorkerEvent(harness.listeners.get('install'));
  const response = await dispatchWorkerEvent(harness.listeners.get('fetch'), {
    request: new Request(assetURL),
  });
  assert.ok(response);
  assert.equal(
    createHash('sha256')
      .update(Buffer.from(await response.arrayBuffer()))
      .digest('hex'),
    buildManifest().assets.find(
      (asset) => asset.path === buildManifest().entrypoint,
    ).sha256,
  );
});

test('service worker serves public aliases from its pinned offline build without HTTP caching', async () => {
  const harness = serviceWorkerHarness(['unrelated-cache']);
  await dispatchWorkerEvent(harness.listeners.get('install'));
  for (const [name, target] of [
    ['', buildManifest().entrypoint],
    ['index.html', buildManifest().entrypoint],
    ['manifest.webmanifest', assetPath('manifest')],
  ]) {
    const response = await dispatchWorkerEvent(harness.listeners.get('fetch'), {
      request: new Request(`https://dud.example.com/optical/${name}`),
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(await response.text(), read(target));
  }
  const cachedIndex = harness.cached.get(
    `https://dud.example.com/optical/${buildManifest().entrypoint}`,
  );
  assert.equal(
    cachedIndex.headers.get('cache-control'),
    'public, max-age=31536000, immutable',
  );
});

test('service worker redirects stale index navigations locally and limits fallback to exact receiver addresses', async () => {
  const harness = serviceWorkerHarness();
  await dispatchWorkerEvent(harness.listeners.get('install'));
  const url = 'https://dud.example.com/optical/index.aaaaaaaaaaaa.html';
  const request = {
    url,
    method: 'GET',
    mode: 'navigate',
    headers: new Headers(),
  };
  const response = await dispatchWorkerEvent(harness.listeners.get('fetch'), {
    request,
  });
  assert.equal(response.status, 302);
  assert.equal(
    response.headers.get('location'),
    'https://dud.example.com/optical/',
  );
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.equal(await response.text(), '');
  const range = await dispatchWorkerEvent(harness.listeners.get('fetch'), {
    request: { ...request, headers: new Headers({ range: 'bytes=0-3' }) },
  });
  assert.equal(range.status, 416);
  for (const invalid of [
    { ...request, method: 'POST' },
    { ...request, mode: 'cors' },
    ...[
      `${url}?build=anything`,
      'https://other.example/optical/index.aaaaaaaaaaaa.html',
      'https://dud.example.com/other/index.aaaaaaaaaaaa.html',
      'https://dud.example.com/optical/nested/index.aaaaaaaaaaaa.html',
      'https://dud.example.com/optical/index.AAAAAAAAAAAA.html',
      'https://dud.example.com/optical/index.aaaaaaaaaaa.html',
      'https://dud.example.com/optical/index.aaaaaaaaaaaaa.html',
      'https://dud.example.com/optical/missing.js',
    ].map((url) => ({ ...request, url })),
  ]) {
    assert.equal(
      await dispatchWorkerEvent(harness.listeners.get('fetch'), {
        request: invalid,
      }),
      undefined,
    );
  }
});

test('service worker rejects ranges for immutable receiver assets', async () => {
  const harness = serviceWorkerHarness();
  await dispatchWorkerEvent(harness.listeners.get('install'));
  const asset = buildManifest().assets.find(
    (entry) => entry.path === buildManifest().entrypoint,
  );
  const response = await dispatchWorkerEvent(harness.listeners.get('fetch'), {
    request: new Request(`https://dud.example.com/optical/${asset.path}`, {
      headers: { range: 'bytes=0-3' },
    }),
  });
  assert.equal(response.status, 416);
  assert.equal(response.headers.get('accept-ranges'), 'none');
  assert.equal(response.headers.get('content-range'), `bytes */${asset.bytes}`);
  assert.equal((await response.arrayBuffer()).byteLength, 0);
});

test('service worker removes a partial cache after storage exhaustion', async () => {
  const current = `dud-optical-${buildManifest().buildId}`;
  const harness = serviceWorkerHarness([], { failPut: true });
  await assert.rejects(
    dispatchWorkerEvent(harness.listeners.get('install')),
    (error) => error?.name === 'QuotaExceededError',
  );
  assert.deepEqual(harness.deleted, [current]);
  assert.equal(harness.cached.size, 0);
});
