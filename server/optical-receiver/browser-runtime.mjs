// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import {
  accessSync,
  constants,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

import { createNodeRequestHandler } from '../../dist/server/src/node-server.js';

const repository = fileURLToPath(new URL('../..', import.meta.url));
const clientModule = path.join(repository, 'client');
const receiverSources = path.join(repository, 'server', 'optical-receiver');
const pwa = path.join(receiverSources, '.work', 'pwa');
const capsuleFilename = 'dud-encrypted-capsule.age';
const securityHeaders = {
  'permissions-policy': 'camera=(self), geolocation=(), microphone=()',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
};

function executable(candidates) {
  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Try the next platform-specific location.
    }
  }
  return undefined;
}

function pathExecutables(names) {
  return (process.env.PATH ?? '')
    .split(path.delimiter)
    .flatMap((directory) => names.map((name) => path.join(directory, name)));
}

function chromeExecutable() {
  return executable([
    process.env.DUD_CHROME_BIN,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    ...pathExecutables([
      'google-chrome',
      'google-chrome-stable',
      'chromium',
      'chromium-browser',
    ]),
  ]);
}

function ffmpegExecutable() {
  return executable([
    process.env.DUD_FFMPEG_BIN,
    ...pathExecutables(['ffmpeg']),
  ]);
}

function deterministicCapsule(length) {
  const bytes = Buffer.alloc(length);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = (index * 73 + Math.floor(index / 19) + 41) & 0xff;
  }
  return bytes;
}

function renderFakeCameraVideo(
  directory,
  ffmpeg,
  capsule = deterministicCapsule(2401),
  frameLimit,
) {
  const capsulePath = path.join(directory, 'opaque-capsule.age');
  const frames = path.join(directory, 'frames');
  const video = path.join(directory, 'camera.y4m');
  mkdirSync(frames);
  writeFileSync(capsulePath, capsule);
  const sourceBlocks = Math.ceil(capsule.length / 1600);
  const displayFrames = Math.ceil(
    (sourceBlocks + Math.ceil(sourceBlocks * 0.25)) / 4,
  );
  execFileSync(
    'go',
    [
      'run',
      './optical-sender/cmd/optical-sender',
      '--ciphertext',
      capsulePath,
      '--renderer',
      'frames',
      '--frame-limit',
      String(frameLimit ?? displayFrames),
      '--frames-dir',
      frames,
      '--block-size',
      '1600',
      '--qr-version',
      '30',
      '--error-correction',
      'low',
      '--quiet-zone',
      '4',
      '--scale',
      '2',
      '--qr-symbols',
      '4',
      '--fps',
      '30',
      '--repair-overhead',
      '25',
    ],
    {
      cwd: clientModule,
      env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
      stdio: 'pipe',
    },
  );
  encodeCameraVideo(frames, video, ffmpeg);
  return { capsule, video, frames };
}

function encodeCameraVideo(frames, video, ffmpeg) {
  execFileSync(
    ffmpeg,
    [
      '-loglevel',
      'error',
      '-y',
      '-framerate',
      '1',
      '-i',
      path.join(frames, 'frame-%08d.png'),
      '-r',
      '30',
      '-pix_fmt',
      'yuv420p',
      video,
    ],
    { stdio: 'pipe' },
  );
}

function storageTrap() {
  const fail = () => {
    throw new Error('browser optical receipt reached payload storage');
  };
  return { put: fail, get: fail, head: fail, list: fail, delete: fail };
}

async function alternateReceiver(directory) {
  const project = path.join(directory, 'alternate-project');
  const receiver = path.join(project, 'server', 'optical-receiver');
  mkdirSync(receiver, { recursive: true });
  symlinkSync(
    path.join(repository, 'node_modules'),
    path.join(project, 'node_modules'),
    'dir',
  );
  for (const name of ['src', 'public', 'build.mjs']) {
    cpSync(path.join(receiverSources, name), path.join(receiver, name), {
      recursive: true,
    });
  }
  const index = path.join(receiver, 'public', 'index.html');
  writeFileSync(
    index,
    `${readFileSync(index, 'utf8')}\n<!-- browser update fixture -->\n`,
  );
  const source = path.join(project, 'server', 'src');
  mkdirSync(source);
  cpSync(
    path.join(repository, 'server', 'src', 'optical-pwa.ts'),
    path.join(source, 'optical-pwa.ts'),
  );
  const output = path.join(project, 'pwa');
  execFileSync(
    process.execPath,
    [
      path.join(receiver, 'build.mjs'),
      '--output',
      output,
      '--embed-module',
      path.join(source, 'optical-pwa-assets.generated.ts'),
    ],
    { stdio: 'pipe' },
  );
  const hostModule = path.join(project, 'host.mjs');
  await build({
    entryPoints: [path.join(source, 'optical-pwa.ts')],
    bundle: true,
    platform: 'node',
    format: 'esm',
    outfile: hostModule,
  });
  return {
    manifest: JSON.parse(
      readFileSync(path.join(output, 'build-manifest.json'), 'utf8'),
    ),
    serve: (await import(pathToFileURL(hostModule).href)).serveOpticalPwa,
  };
}

async function startOpticalServer(directory) {
  const traffic = [];
  let alternate;
  let unavailable = false;
  const handler = createNodeRequestHandler(
    {
      dataDir: directory,
      opticalPwaEnabled: true,
      v1Enabled: false,
      v2Enabled: false,
      logMode: 'silent',
    },
    {
      blobStore: storageTrap(),
      logger: { error() {}, log() {} },
    },
  );
  const server = createServer((request, response) => {
    traffic.push({ method: request.method, url: request.url });
    if (unavailable && request.url === '/optical/sw.js') {
      response.writeHead(503, { 'cache-control': 'no-store' });
      response.end();
      return;
    }
    if (alternate) {
      const value = alternate(
        new Request(`http://localhost${request.url}`),
        true,
      );
      assert.ok(value);
      response.writeHead(value.status, Object.fromEntries(value.headers));
      void value
        .arrayBuffer()
        .then((bytes) => response.end(Buffer.from(bytes)));
      return;
    }
    void handler(request, response);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    origin: `http://127.0.0.1:${address.port}`,
    server,
    traffic,
    useBuild(serve) {
      alternate = serve;
    },
    rejectUpdates(value) {
      unavailable = value;
    },
  };
}

async function startOfflineProxy(origin) {
  let offline = false;
  const blocked = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url);
    if (url.origin !== origin) {
      response.writeHead(502);
      response.end();
      return;
    }
    if (offline) {
      blocked.push({
        method: request.method,
        path: `${url.pathname}${url.search}`,
      });
      response.writeHead(503);
      response.end();
      return;
    }
    const upstream = httpRequest(
      url,
      { method: request.method, headers: request.headers },
      (result) => {
        response.writeHead(result.statusCode, result.headers);
        result.pipe(response);
      },
    );
    upstream.on('error', () => {
      response.writeHead(502);
      response.end();
    });
    request.pipe(upstream);
  });
  server.on('connect', (_request, socket) => socket.end());
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    server,
    origin: `http://127.0.0.1:${address.port}`,
    blocked,
    disconnect() {
      offline = true;
    },
  };
}

class DevToolsClient {
  constructor(socket) {
    this.socket = socket;
    this.nextID = 1;
    this.pending = new Map();
    this.listeners = new Map();
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id !== undefined) {
        const pending = this.pending.get(message.id);
        if (!pending) {
          return;
        }
        this.pending.delete(message.id);
        if (message.error) {
          pending.reject(new Error(message.error.message));
        } else {
          pending.resolve(message.result ?? {});
        }
        return;
      }
      for (const listener of this.listeners.get(message.method) ?? []) {
        listener(message.params ?? {});
      }
    });
    socket.addEventListener('close', () => {
      for (const pending of this.pending.values()) {
        pending.reject(new Error('Chrome DevTools connection closed'));
      }
      this.pending.clear();
    });
  }

  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', reject, { once: true });
    });
    return new DevToolsClient(socket);
  }

  // fallow-ignore-next-line unused-class-member -- Browser measurements call this on clients returned by DevToolsClient.connect.
  send(method, params = {}, sessionId) {
    const id = this.nextID++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Chrome DevTools ${method} timed out`));
      }, 15_000);
      this.pending.set(id, {
        resolve(value) {
          clearTimeout(timer);
          resolve(value);
        },
        reject(error) {
          clearTimeout(timer);
          reject(error);
        },
      });
      this.socket.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }

  // fallow-ignore-next-line unused-class-member -- Browser measurements call this on clients returned by DevToolsClient.connect.
  on(method, listener) {
    const listeners = this.listeners.get(method) ?? [];
    listeners.push(listener);
    this.listeners.set(method, listeners);
  }

  // fallow-ignore-next-line unused-class-member -- Browser measurements call this on clients returned by DevToolsClient.connect.
  close() {
    this.socket.close();
  }
}

async function waitFor(predicate, description, timeout = 20_000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const value = await predicate();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(
    `Timed out waiting for ${description}${lastError ? `: ${lastError.message}` : ''}`,
  );
}

async function evaluate(client, expression, awaitPromise = false) {
  const response = await client.send('Runtime.evaluate', {
    expression,
    awaitPromise,
    returnByValue: true,
  });
  if (response.exceptionDetails) {
    throw new Error(
      response.exceptionDetails.exception?.description ??
        response.exceptionDetails.text,
    );
  }
  return response.result?.value;
}

async function waitForPage(client) {
  await waitFor(
    () => evaluate(client, "document.readyState === 'complete'"),
    'the receiver document',
  );
  const workerReady = await evaluate(
    client,
    `Promise.race([
      navigator.serviceWorker.ready.then(() => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 10000)),
    ])`,
    true,
  );
  if (!workerReady) {
    const state = await evaluate(
      client,
      `(async () => ({
        detail: document.querySelector('#status-detail')?.value,
        secureContext: isSecureContext,
        registrations: (await navigator.serviceWorker.getRegistrations()).map(
          (registration) => ({
            scope: registration.scope,
            active: registration.active?.state,
            installing: registration.installing?.state,
            waiting: registration.waiting?.state,
          }),
        ),
      }))()`,
      true,
    );
    assert.fail(
      `receiver service worker did not activate: ${JSON.stringify(state)}`,
    );
  }
  await waitFor(
    () => evaluate(client, "!document.querySelector('#start').disabled"),
    'receiver installation to release the camera button',
  );
}

async function waitForTrafficToSettle(traffic) {
  let previous = -1;
  await waitFor(
    async () => {
      if (traffic.length !== previous) {
        previous = traffic.length;
        await new Promise((resolve) => setTimeout(resolve, 250));
        return false;
      }
      return true;
    },
    'browser traffic to settle',
    5000,
  );
}

async function launchChrome(
  chrome,
  profile,
  video,
  automaticCameraPermission = true,
  proxy,
) {
  // A reused profile retains the debugger port from its previous process.
  rmSync(path.join(profile, 'DevToolsActivePort'), { force: true });
  const processHandle = spawn(
    chrome,
    [
      '--headless=new',
      '--remote-debugging-port=0',
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-networking',
      '--disable-breakpad',
      '--disable-client-side-phishing-detection',
      '--disable-component-update',
      '--disable-default-apps',
      '--disable-features=MediaRouter,OptimizationHints',
      '--disable-sync',
      '--metrics-recording-only',
      '--password-store=basic',
      '--use-mock-keychain',
      '--use-fake-device-for-media-stream',
      ...(automaticCameraPermission ? ['--use-fake-ui-for-media-stream'] : []),
      ...(proxy
        ? [`--proxy-server=${proxy}`, '--proxy-bypass-list=<-loopback>']
        : []),
      ...(video ? [`--use-file-for-fake-video-capture=${video}`] : []),
      'about:blank',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );
  let errors = '';
  processHandle.stderr.on('data', (chunk) => {
    errors = `${errors}${chunk}`.slice(-16_384);
  });
  const activePort = path.join(profile, 'DevToolsActivePort');
  const contents = await waitFor(() => {
    if (processHandle.exitCode !== null) {
      throw new Error(
        `Chrome exited with ${processHandle.exitCode}: ${errors.trim()}`,
      );
    }
    return existsSync(activePort) ? readFileSync(activePort, 'utf8') : false;
  }, 'Chrome DevTools endpoint');
  const [port, browserPath] = contents.trim().split('\n');
  return {
    browserURL: `ws://127.0.0.1:${port}${browserPath}`,
    debugOrigin: `http://127.0.0.1:${port}`,
    processHandle,
  };
}

async function stopChrome(processHandle) {
  if (processHandle.exitCode !== null) {
    return;
  }
  await new Promise((resolve) => {
    const force = setTimeout(() => processHandle.kill('SIGKILL'), 2000);
    processHandle.once('close', () => {
      clearTimeout(force);
      resolve();
    });
    processHandle.kill('SIGTERM');
  });
}

async function closeServer(server) {
  server.closeAllConnections();
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function assertOnlyOpticalTraffic(traffic, required = true) {
  if (required) {
    assert.ok(
      traffic.length > 0,
      'expected the static host to receive requests',
    );
  }
  for (const request of traffic) {
    assert.equal(request.method, 'GET');
    const url = new URL(request.url, 'http://dud.invalid');
    assert.match(url.pathname, /^\/optical\//);
    assert.equal(url.search, '');
  }
}

function assertNoExternalRequests(requests, origin) {
  const external = requests
    .map(({ request }) => request.url)
    .filter((url) => /^https?:/.test(url) && !url.startsWith(`${origin}/`));
  assert.deepEqual(external, []);
}

function assertCachedSecurityHeaders(response) {
  assert.ok(response, 'service worker response was not observed');
  for (const [name, expected] of Object.entries(securityHeaders)) {
    assert.equal(response.headers[name], expected, name);
  }
  assert.match(
    response.headers['content-security-policy'] ?? '',
    /connect-src 'none'.*frame-ancestors 'none'/,
  );
  assert.match(
    response.headers['content-security-policy'] ?? '',
    /script-src 'self'/,
  );
}

async function receiveFromFakeCamera(page) {
  await startFakeCamera(page);
  await waitForReceipt(page);
}

async function startFakeCamera(page) {
  assert.equal(
    await evaluate(
      page,
      `(() => {
      document.querySelector('#status').value = '';
      document.querySelector('#start').click();
      const update = document.querySelector('#receiver-update');
      update.click();
      return update.disabled && document.querySelector('#save-diagnostics').disabled;
    })()`,
    ),
    true,
  );
}

async function waitForReceipt(page) {
  await waitFor(
    async () => {
      const state = await evaluate(
        page,
        "({ status: document.querySelector('#status').value, detail: document.querySelector('#status-detail').value })",
      );
      if (/did not start|stopped/i.test(state.status)) {
        throw new Error(`${state.status}: ${state.detail}`);
      }
      return state.status === 'Optical receipt complete';
    },
    'optical receipt completion',
    45_000,
  );
  const finished = await evaluate(
    page,
    `(() => {
      const rows = [...document.querySelectorAll('#stripe-rows [role="listitem"]')];
      return {
        progress: document.querySelector('#progress').value,
        stripeCount: rows.length,
        incompleteStripes: rows.filter((row) => row.dataset.complete !== 'true').length,
        statistics: document.querySelector('#statistics').value,
      };
    })()`,
  );
  assert.equal(finished.progress, 100);
  assert.ok(finished.stripeCount > 0);
  assert.equal(finished.incompleteStripes, 0);
  assert.match(finished.statistics, /max progress gap/);
}

async function saveCapsule(page, download) {
  rmSync(download, { force: true });
  await evaluate(page, "document.querySelector('#save-capsule').click(); true");
  await waitFor(
    () =>
      existsSync(download) &&
      !existsSync(`${download}.crdownload`) &&
      statSync(download).size > 0,
    'encrypted capsule download',
  );
}

export {
  clientModule,
  receiverSources,
  pwa,
  capsuleFilename,
  chromeExecutable,
  ffmpegExecutable,
  deterministicCapsule,
  renderFakeCameraVideo,
  encodeCameraVideo,
  alternateReceiver,
  startOpticalServer,
  startOfflineProxy,
  DevToolsClient,
  waitFor,
  evaluate,
  waitForPage,
  waitForTrafficToSettle,
  launchChrome,
  stopChrome,
  closeServer,
  assertOnlyOpticalTraffic,
  assertNoExternalRequests,
  assertCachedSecurityHeaders,
  receiveFromFakeCamera,
  startFakeCamera,
  waitForReceipt,
  saveCapsule,
};
