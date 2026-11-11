#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { cpus, release, tmpdir } from 'node:os';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
import {
  chromeExecutable,
  DevToolsClient,
  evaluate,
  launchChrome,
  stopChrome,
  closeServer,
  waitFor,
} from './browser-runtime.mjs';

const receiver = import.meta.dirname;
const repository = path.resolve(receiver, '../..');
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

export async function runIsolatedMemory({
  bytes = 16 * 1024 * 1024,
  blockSize = 2860,
  input,
  downloadDirectory,
} = {}) {
  assert.ok(Number.isInteger(bytes) && bytes >= 1 && bytes <= 64 * 1024 * 1024);
  assert.ok([1600, 2860].includes(blockSize));
  const chrome = chromeExecutable();
  assert.ok(chrome, 'Chrome is required for isolated browser measurements');
  const directory = mkdtempSync(path.join(tmpdir(), 'dud-isolated-memory-'));
  const assets = new Map();
  for (const name of readdirSync(path.join(receiver, '.work/receiver')).filter(
    (name) => name.endsWith('.js'),
  )) {
    assets.set(
      `/${name}`,
      readFileSync(path.join(receiver, '.work/receiver', name)),
    );
  }
  for (const name of [
    'isolated-fountain-client.mjs',
    'isolated-fountain-producer.mjs',
    'isolated-fountain-receiver.mjs',
  ]) {
    assets.set(`/${name}`, readFileSync(path.join(receiver, name)));
  }
  assets.set(
    '/',
    Buffer.from(
      '<!doctype html><script type="module" src="/isolated-fountain-client.mjs"></script>',
    ),
  );
  if (input) {
    const ciphertext = readFileSync(input);
    assert.ok(ciphertext.length >= 1 && ciphertext.length <= 64 * 1024 * 1024);
    assets.set('/input.age', ciphertext);
  }
  let phase = 'preparing';
  const traffic = [];
  const server = createServer((request, response) => {
    traffic.push({ phase, method: request.method, url: request.url });
    const asset = assets.get(request.url);
    response.writeHead(asset ? 200 : 404, {
      'content-type':
        request.url === '/'
          ? 'text/html'
          : request.url === '/input.age'
            ? 'application/octet-stream'
            : 'text/javascript',
      'content-security-policy':
        "default-src 'none'; script-src 'self'; worker-src 'self'; connect-src 'self'; base-uri 'none'",
      'cache-control': 'no-store',
    });
    response.end(asset ?? '');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let launched, browser, page;
  let sampling;
  const sessions = new Map();
  const samples = [];
  const errors = [];
  const detached = new Set();
  const startedAt = performance.now();
  let samplingPromise = Promise.resolve();
  try {
    launched = await launchChrome(chrome, directory);
    browser = await DevToolsClient.connect(launched.browserURL);
    if (downloadDirectory) {
      await browser.send('Browser.setDownloadBehavior', {
        behavior: 'allow',
        downloadPath: downloadDirectory,
      });
    }
    const target = await fetch(`${launched.debugOrigin}/json/new?about:blank`, {
      method: 'PUT',
    }).then((r) => r.json());
    page = await DevToolsClient.connect(target.webSocketDebuggerUrl);
    await page.send('Runtime.enable');
    await page.send('Network.enable');
    page.on('Target.attachedToTarget', ({ sessionId, targetInfo }) => {
      void (async () => {
        if (targetInfo.type === 'worker') {
          sessions.set(
            sessionId,
            targetInfo.url.includes('producer') ? 'producer' : 'receiver',
          );
          await page.send('Runtime.enable', {}, sessionId);
        }
        await page.send('Runtime.runIfWaitingForDebugger', {}, sessionId);
      })().catch((error) => errors.push(String(error)));
    });
    page.on('Target.detachedFromTarget', ({ sessionId }) => {
      detached.add(sessionId);
      sessions.delete(sessionId);
    });
    await page.send('Target.setAutoAttach', {
      autoAttach: true,
      waitForDebuggerOnStart: true,
      flatten: true,
    });
    await page.send('Page.navigate', {
      url: `http://127.0.0.1:${server.address().port}/`,
    });
    await waitFor(
      () => evaluate(page, 'Boolean(globalThis.isolatedFountain)'),
      'isolated browser client',
    );
    const fixture = await evaluate(
      page,
      `isolatedFountain.prepare(${JSON.stringify({ bytes, blockSize, input: Boolean(input) })})`,
      true,
    );
    assert.equal(sessions.size, 2);
    const sample = async () => {
      const values = [];
      for (const [sessionId, role] of [...sessions]) {
        try {
          values.push({
            role,
            ...(await page.send('Runtime.getHeapUsage', {}, sessionId)),
          });
        } catch (error) {
          if (!detached.has(sessionId)) {
            throw error;
          }
        }
      }
      samples.push({
        offsetMilliseconds: performance.now() - startedAt,
        phase,
        page: await page.send('Runtime.getHeapUsage'),
        workers: values,
        queue: await evaluate(page, 'isolatedFountain.snapshot()'),
      });
    };
    phase = 'prepared';
    await sample();
    await page.send('Network.emulateNetworkConditions', {
      offline: true,
      latency: 0,
      downloadThroughput: 0,
      uploadThroughput: 0,
    });
    phase = 'receiving';
    let busy = false;
    sampling = setInterval(() => {
      if (busy) {
        return;
      }
      busy = true;
      samplingPromise = sample()
        .catch((error) => errors.push(String(error)))
        .finally(() => {
          busy = false;
        });
    }, 100);
    await evaluate(page, 'isolatedFountain.start(); true');
    const result = await evaluate(page, 'isolatedFountain.completion()', true);
    clearInterval(sampling);
    await samplingPromise;
    phase = 'completed';
    await sample();
    assert.equal(result.sha256, fixture.sha256);
    assert.equal(result.receivedSHA256, fixture.sha256);
    assert.ok(result.stats.maximumPendingFrames <= 32);
    assert.ok(result.maximumBufferedFrames <= 4);
    assert.deepEqual(errors, []);
    assert.deepEqual(
      traffic.filter((request) => request.phase === 'receiving'),
      [],
    );
    if (downloadDirectory) {
      await evaluate(page, 'isolatedFountain.save(); true');
      const saved = path.join(downloadDirectory, 'isolated-received.age');
      await waitFor(
        () => existsSync(saved) && !existsSync(`${saved}.crdownload`),
        'isolated ciphertext save',
      );
      assert.equal(hash(readFileSync(saved)), fixture.sha256);
    }
    await evaluate(page, 'isolatedFountain.reset(); true');
    assert.equal(
      await evaluate(page, 'isolatedFountain.snapshot().savedCiphertextBytes'),
      0,
    );
    await waitFor(
      () => sessions.size === 0,
      'terminated reconstruction workers',
    );
    phase = 'reset';
    await page.send('HeapProfiler.collectGarbage');
    await sample();
    const peaks = {};
    for (const role of ['page', 'producer', 'receiver']) {
      const heaps = samples.flatMap((s) =>
        role === 'page' ? [s.page] : s.workers.filter((w) => w.role === role),
      );
      peaks[role] = Object.fromEntries(
        ['usedSize', 'totalSize', 'backingStorageSize'].map((key) => [
          key,
          Math.max(...heaps.map((h) => h[key] ?? 0)),
        ]),
      );
    }
    return {
      schemaVersion: 1,
      recordedAt: new Date().toISOString(),
      revision: execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: repository,
        encoding: 'utf8',
      }).trim(),
      host: {
        platform: process.platform,
        arch: process.arch,
        release: release(),
        cpu: cpus()[0]?.model,
        cpuCount: cpus().length,
      },
      chrome: execFileSync(chrome, ['--version'], { encoding: 'utf8' }).trim(),
      node: process.version,
      sourceSHA256: Object.fromEntries(
        [
          'src/codec.ts',
          'src/pipeline.ts',
          'src/fountain-client.ts',
          'src/fountain-worker.ts',
          'src/fountain-messages.ts',
          'bench-isolated-memory.mjs',
          'isolated-fountain-client.mjs',
          'isolated-fountain-producer.mjs',
          'isolated-fountain-receiver.mjs',
        ].map((name) => [name, hash(readFileSync(path.join(receiver, name)))]),
      ),
      method:
        'Compiled production FountainFramePipeline and fountain-worker in real Chrome module workers. An independent producer worker holds the source, generates batches of four and transfers binary frames. DevTools carries only commands and sampled heap/queue metadata. No canvas, video, PNG, camera or QR worker is allocated. Compare full source length and SHA-256; omit one source block per stripe and recover with one maximum-degree repair.',
      limits: [
        'Runtime.getHeapUsage separates V8 heaps and backing storage; it excludes process, GPU, browser and camera memory.',
        'The 100 ms sampled maxima can miss transients and debugger sampling adds overhead.',
        'Producer generation and main-thread queueing affect elapsed throughput but producer memory is reported separately.',
        'This is synthetic desktop reconstruction, not PWA camera receipt, phone memory or plaintext goodput.',
      ],
      sampleIntervalMilliseconds: 100,
      peaks,
      result,
      transferTimeHostRequests: 0,
      phoneGatePassed: false,
      samples,
    };
  } finally {
    clearInterval(sampling);
    await samplingPromise;
    page?.close();
    browser?.close();
    if (launched) {
      await stopChrome(launched.processHandle);
    }
    await closeServer(server);
    rmSync(directory, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100,
    });
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  const [mib = '16', profile = 'high-rate', output] = process.argv.slice(2);
  assert.ok(
    ['1', '16', '64'].includes(mib) &&
      ['balanced', 'high-rate'].includes(profile) &&
      output,
    'usage: bench-isolated-memory.mjs 1|16|64 balanced|high-rate REPORT.json',
  );
  const report = await runIsolatedMemory({
    bytes: Number(mib) * 1024 * 1024,
    blockSize: profile === 'balanced' ? 1600 : 2860,
  });
  const { samples, ...summary } = report;
  const raw = gzipSync(JSON.stringify(samples));
  const rawPath = `${output}.samples.json.gz`;
  writeFileSync(rawPath, raw);
  writeFileSync(
    output,
    JSON.stringify(
      {
        ...summary,
        raw: {
          file: path.basename(rawPath),
          sha256: hash(raw),
          bytes: raw.length,
        },
      },
      null,
      2,
    ) + '\n',
  );
  console.log(JSON.stringify({ peaks: summary.peaks, result: summary.result }));
}
