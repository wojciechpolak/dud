// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { arch, cpus, platform, release, tmpdir, totalmem } from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { gzipSync } from 'node:zlib';

import { chromeProcessTree, summarizeMemory } from './memory-metrics.mjs';
import {
  clientModule,
  receiverSources,
  pwa,
  capsuleFilename,
  chromeExecutable,
  startOpticalServer,
  startOfflineProxy,
  DevToolsClient,
  evaluate,
  waitFor,
  waitForPage,
  waitForTrafficToSettle,
  launchChrome,
  stopChrome,
  closeServer,
  saveCapsule,
} from './browser-runtime.mjs';

const sourceBytes = Number(process.argv[2] ?? 64) * 1024 * 1024;
if (![1024 * 1024, 64 * 1024 * 1024].includes(sourceBytes)) {
  throw new Error('usage: bench-memory.mjs [1|64] [report.json]');
}
const reportPath = path.resolve(
  process.argv[3] ??
    path.join(
      receiverSources,
      '.work',
      `browser-memory-${sourceBytes / 1024 / 1024}mib.json`,
    ),
);
const sampleIntervalMilliseconds = 200;
const heapIntervalMilliseconds = 2000;
const displayHoldMilliseconds = 50;
const maximumFixtureBytes = 2 * 1024 * 1024 * 1024;
const senderProfile = {
  blockSize: 2860,
  qrVersion: 40,
  errorCorrection: 'low',
  quietZone: 4,
  scale: 2,
  qrSymbols: 4,
  framesPerSecond: 60,
  initialRepairPercent: 25,
  maximumRecoveryDegree: 31,
};
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const canvasCamera = `(() => {
  const canvas = document.createElement('canvas');
  canvas.width = 740;
  canvas.height = 740;
  const context = canvas.getContext('2d');
  context.fillStyle = 'white';
  context.fillRect(0, 0, 740, 740);
  const tracks = [];
  navigator.mediaDevices.getUserMedia = async () => {
    const stream = canvas.captureStream(60);
    tracks.push(...stream.getTracks());
    const timer = setInterval(() => {
      if (stream.getTracks().every((track) => track.readyState === 'ended')) {
        clearInterval(timer);
        return;
      }
      context.drawImage(canvas, 0, 0);
    }, 1000 / 60);
    return stream;
  };
  window.opticalMemoryCamera = {
    async show(base64) {
      const binary = atob(base64);
      const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      const bitmap = await createImageBitmap(new Blob([bytes], { type: 'image/png' }));
      if (bitmap.width !== 740 || bitmap.height !== 740) throw new Error('unexpected native QR raster');
      context.drawImage(bitmap, 0, 0);
      bitmap.close();
    },
    state: () => ({
      tracks: tracks.length,
      liveTracks: tracks.filter((track) => track.readyState === 'live').length,
      settings: tracks.map((track) => track.getSettings()),
    }),
  };
})()`;

const observeWasm = `(() => {
  const memories = new Set();
  const NativeMemory = WebAssembly.Memory;
  WebAssembly.Memory = class extends NativeMemory {
    constructor(...args) { super(...args); memories.add(this); }
  };
  for (const method of ['instantiate', 'instantiateStreaming']) {
    const native = WebAssembly[method].bind(WebAssembly);
    WebAssembly[method] = async (...args) => {
      const result = await native(...args);
      const instance = result.instance ?? result;
      for (const value of Object.values(instance.exports)) {
        if (value instanceof NativeMemory) memories.add(value);
      }
      return result;
    };
  }
  globalThis.opticalWasmMemory = () => ({
    memories: memories.size,
    linearCapacityBytes: [...memories].reduce((sum, memory) => sum + memory.buffer.byteLength, 0),
  });
})()`;

async function prepareFrames(input, sha256) {
  const directory = path.join(
    receiverSources,
    '.work',
    `memory-frames-${sourceBytes / 1024 / 1024}mib`,
  );
  const frames = path.join(directory, 'frames');
  const metadataPath = path.join(directory, 'fixture.json');
  const sourceFiles = [
    ...readdirSync(path.join(clientModule, 'optical-sender'), {
      recursive: true,
    })
      .filter((name) => name.endsWith('.go') && !name.endsWith('_test.go'))
      .map((name) => path.join(clientModule, 'optical-sender', name)),
    ...readdirSync(path.join(clientModule, 'drop'), { recursive: true })
      .filter((name) => name.endsWith('.go') && !name.endsWith('_test.go'))
      .map((name) => path.join(clientModule, 'drop', name)),
    path.join(clientModule, 'go.mod'),
    path.join(clientModule, 'go.sum'),
  ];
  const sourceDigest = digest(
    Buffer.concat(sourceFiles.sort().map((file) => readFileSync(file))),
  );
  const key = {
    sourceDigest,
    sha256,
    senderProfile,
    cycles: 'initial-and-one-recovery',
  };
  let repairFrames = 0;
  const sourceFrames = Math.ceil(sourceBytes / senderProfile.blockSize);
  for (let count = sourceFrames; count > 0; count -= 1024) {
    repairFrames += Math.ceil(Math.min(1024, count) / 4);
  }
  const initialDisplayFrames = Math.ceil((sourceFrames + repairFrames) / 4);
  const recoveryDisplayFrames = Math.ceil(repairFrames / 4);
  const displayFrames = initialDisplayFrames + recoveryDisplayFrames;
  assert.ok(displayFrames <= 10_000);
  let metadata = existsSync(metadataPath)
    ? JSON.parse(readFileSync(metadataPath, 'utf8'))
    : undefined;
  if (JSON.stringify(metadata?.key) !== JSON.stringify(key)) {
    rmSync(directory, { recursive: true, force: true });
    mkdirSync(frames, { recursive: true });
    console.log(
      `Rendering ${displayFrames} native four-QR PNGs for ${sourceBytes / 1024 / 1024} MiB.`,
    );
    const nativeSender = path.join(directory, 'optical-sender');
    execFileSync(
      'go',
      [
        'build',
        '-trimpath',
        '-o',
        nativeSender,
        './optical-sender/cmd/optical-sender',
      ],
      {
        cwd: clientModule,
        env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
        timeout: 120_000,
      },
    );
    const command = spawn(
      nativeSender,
      [
        '--ciphertext',
        input,
        '--renderer',
        'frames',
        '--frame-limit',
        String(displayFrames),
        '--frames-dir',
        frames,
        '--block-size',
        '2860',
        '--qr-version',
        '40',
        '--error-correction',
        'low',
        '--quiet-zone',
        '4',
        '--scale',
        '2',
        '--qr-symbols',
        '4',
        '--fps',
        '60',
        '--repair-overhead',
        '25',
      ],
      {
        cwd: clientModule,
        env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 20 * 60 * 1000,
      },
    );
    let output = '';
    let errors = '';
    command.stdout.on('data', (bytes) => {
      output = `${output}${bytes}`.slice(-8192);
    });
    command.stderr.on('data', (bytes) => {
      errors = `${errors}${bytes}`.slice(-8192);
    });
    const timer = setInterval(() => {
      const names = readdirSync(frames);
      const bytes = names.reduce(
        (sum, name) => sum + statSync(path.join(frames, name)).size,
        0,
      );
      console.log(
        `Native QR preparation: ${names.length}/${displayFrames}, ${(bytes / 1024 / 1024).toFixed(1)} MiB on disk.`,
      );
      if (bytes > maximumFixtureBytes) {
        command.kill('SIGTERM');
      }
    }, 15_000);
    try {
      const code = await new Promise((resolve, reject) => {
        command.once('error', reject);
        command.once('close', resolve);
      });
      if (code !== 0) {
        throw new Error(`native PNG preparation failed: ${errors}`);
      }
    } finally {
      clearInterval(timer);
    }
    metadata = {
      key,
      sourceFrames,
      repairFrames,
      initialDisplayFrames,
      recoveryDisplayFrames,
      displayFrames,
      nativeOutput: output,
      nativeSettings: errors,
      nativeSenderSHA256: digest(readFileSync(nativeSender)),
    };
  }
  const names = readdirSync(frames).sort();
  assert.equal(names.length, displayFrames);
  let bytes = 0;
  const hash = createHash('sha256');
  for (let index = 0; index < names.length; index++) {
    assert.equal(names[index], `frame-${String(index).padStart(8, '0')}.png`);
    const image = readFileSync(path.join(frames, names[index]));
    bytes += image.length;
    assert.ok(bytes <= maximumFixtureBytes);
    hash.update(image);
  }
  const pngSHA256 = hash.digest('hex');
  if (metadata.pngSHA256) {
    assert.equal(pngSHA256, metadata.pngSHA256);
  }
  metadata = { ...metadata, pngBytes: bytes, pngSHA256 };
  writeFileSync(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);
  return { frames, names, metadata };
}

function startSampler(rootPID, page, workerSessions) {
  const started = performance.now();
  const samples = [];
  const heapSamples = [];
  const errors = [];
  let phase = 'installed';
  let pendingHeap;
  let heapDue = 0;
  const sample = () => {
    try {
      const processes = chromeProcessTree(
        execFileSync('ps', ['-axo', 'pid=,ppid=,rss=,args='], {
          encoding: 'utf8',
        }),
        rootPID,
      );
      samples.push({
        offsetMilliseconds: performance.now() - started,
        phase,
        totalRSSBytes: processes.reduce(
          (sum, process) => sum + process.rssBytes,
          0,
        ),
        processes,
      });
    } catch (error) {
      errors.push(error.message);
    }
    if (!pendingHeap && performance.now() >= heapDue) {
      heapDue = performance.now() + heapIntervalMilliseconds;
      pendingHeap = (async () => {
        const value = {
          offsetMilliseconds: performance.now() - started,
          phase,
          page: await page.send('Runtime.getHeapUsage'),
          workers: [],
        };
        for (const [sessionId, target] of workerSessions) {
          try {
            const heap = await page.send('Runtime.getHeapUsage', {}, sessionId);
            const wasm = await page.send(
              'Runtime.evaluate',
              {
                expression: 'globalThis.opticalWasmMemory?.()',
                returnByValue: true,
              },
              sessionId,
            );
            value.workers.push({
              targetId: target.targetId,
              type: target.type,
              heap,
              wasm: wasm.result?.value ?? null,
            });
          } catch (error) {
            /* A completed receipt terminates its decoder workers. */
            if (workerSessions.has(sessionId)) {
              errors.push(error.message);
            }
          }
        }
        heapSamples.push(value);
      })()
        .catch((error) => errors.push(error.message))
        .finally(() => {
          pendingHeap = undefined;
        });
    }
  };
  const timer = setInterval(sample, sampleIntervalMilliseconds);
  sample();
  return {
    setPhase(value) {
      phase = value;
      sample();
    },
    samples,
    heapSamples,
    errors,
    async stop() {
      clearInterval(timer);
      await pendingHeap;
    },
  };
}

async function displayFrames(page, fixture) {
  const receiptStarted = performance.now();
  let displayed = 0;
  let status;
  let lastNotice = 0;
  while (performance.now() - receiptStarted < 14 * 60 * 1000) {
    const name = fixture.names[displayed % fixture.names.length];
    const base64 = readFileSync(path.join(fixture.frames, name)).toString(
      'base64',
    );
    await evaluate(
      page,
      `window.opticalMemoryCamera.show(${JSON.stringify(base64)})`,
      true,
    );
    displayed++;
    await pause(displayHoldMilliseconds);
    status = await evaluate(
      page,
      `({ status: document.querySelector('#status').value, detail: document.querySelector('#status-detail').value, progress: document.querySelector('#progress').value })`,
    );
    if (status.status === 'Optical receipt complete') {
      break;
    }
    if (/stopped|did not start/i.test(status.status)) {
      throw new Error(`${status.status}: ${status.detail}`);
    }
    if (performance.now() - lastNotice > 15_000) {
      console.log(
        `Receipt: ${status.progress.toFixed(1)}%, ${displayed} displayed images, ${((performance.now() - receiptStarted) / 1000).toFixed(1)} s.`,
      );
      lastNotice = performance.now();
    }
  }
  assert.equal(
    status?.status,
    'Optical receipt complete',
    `${sourceBytes / 1024 / 1024} MiB receipt must complete within the bounded measurement`,
  );
  const elapsedReceiptDriverMilliseconds = performance.now() - receiptStarted;
  return { receiptStarted, displayed, elapsedReceiptDriverMilliseconds };
}

function writeMeasurementReport(report, sampler, instrumentationErrors) {
  const samples = sampler?.samples ?? [];
  report.memory = samples.length ? summarizeMemory(samples) : null;
  report.instrumentationErrors = [
    ...instrumentationErrors,
    ...(sampler?.errors ?? []),
  ];
  if (report.instrumentationErrors.length > 0) {
    report.failure = report.failure ?? 'memory instrumentation reported errors';
    report.completion.success = false;
    process.exitCode = 1;
  }
  const raw = {
    processSamples: samples,
    heapSamples: sampler?.heapSamples ?? [],
  };
  report.heap = {
    sampleCount: raw.heapSamples.length,
    maximumObservedDecoderWorkers: Math.max(
      0,
      ...raw.heapSamples.map((sample) => sample.workers.length),
    ),
    peaksByPhase: Object.fromEntries(
      [...new Set(raw.heapSamples.map((sample) => sample.phase))].map(
        (phase) => {
          const values = raw.heapSamples.filter(
            (sample) => sample.phase === phase,
          );
          return [
            phase,
            {
              pageUsedBytes: Math.max(
                ...values.map((sample) => sample.page.usedSize),
              ),
              pageBackingStorageBytes: Math.max(
                ...values.map((sample) => sample.page.backingStorageSize ?? 0),
              ),
              decoderWorkerUsedBytesSum: Math.max(
                ...values.map((sample) =>
                  sample.workers.reduce(
                    (sum, worker) => sum + worker.heap.usedSize,
                    0,
                  ),
                ),
              ),
              decoderWorkerBackingStorageBytesSum: Math.max(
                ...values.map((sample) =>
                  sample.workers.reduce(
                    (sum, worker) =>
                      sum + (worker.heap.backingStorageSize ?? 0),
                    0,
                  ),
                ),
              ),
              decoderWorkerWASMCapacityBytesSum: Math.max(
                ...values.map((sample) =>
                  sample.workers.reduce(
                    (sum, worker) =>
                      sum + (worker.wasm?.linearCapacityBytes ?? 0),
                    0,
                  ),
                ),
              ),
            },
          ];
        },
      ),
    ),
  };
  const rawPath = reportPath.replace(/\.json$/, '') + '.samples.json.gz';
  mkdirSync(path.dirname(reportPath), { recursive: true });
  const compressed = gzipSync(JSON.stringify(raw));
  writeFileSync(rawPath, compressed);
  report.rawSamples = {
    file: path.basename(rawPath),
    sha256: digest(compressed),
    compressedBytes: compressed.length,
  };
  report.gate = {
    thresholdBytes: 256 * 1024 * 1024,
    observedProcessRSSComparison:
      report.memory?.peakRSSBytes <= 256 * 1024 * 1024
        ? 'at-or-below'
        : 'above',
    protocolGatePassed: false,
    reason:
      'sampled synthetic desktop process RSS is not a baseline-device or phone peak; shared-page accounting and sampling gaps limit interpretation',
  };
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  console.log(
    `Report ${reportPath}: success=${report.completion.success}, sampled Chrome RSS=${((report.memory?.peakRSSBytes ?? 0) / 1024 / 1024).toFixed(1)} MiB.`,
  );
}

async function run() {
  const chrome = chromeExecutable();
  if (!chrome) {
    throw new Error('Chrome is required for the memory measurement');
  }
  const corpusName = `random-${sourceBytes / 1024 / 1024}mib.bin`;
  const input = path.join(receiverSources, '.work', 'corpus', corpusName);
  const expected = JSON.parse(
    readFileSync(path.join(receiverSources, 'corpus', 'manifest.json'), 'utf8'),
  ).files.find((file) => file.name === corpusName);
  assert.equal(statSync(input).size, sourceBytes);
  assert.equal(digest(readFileSync(input)), expected.sha256);
  const fixture = await prepareFrames(input, expected.sha256);
  const work = mkdtempSync(path.join(tmpdir(), 'dud-optical-memory-'));
  const profile = path.join(work, 'profile');
  const downloads = path.join(work, 'downloads');
  mkdirSync(profile);
  mkdirSync(downloads);
  const hosted = await startOpticalServer(work);
  const proxy = await startOfflineProxy(hosted.origin);
  let launched;
  let browser;
  let page;
  let sampler;
  const workerSessions = new Map();
  const instrumentationErrors = [];
  const report = {
    schemaVersion: 1,
    method: 'native-qr-canvas-camera-process-rss',
    recordedAt: new Date().toISOString(),
    revision: execFileSync('git', ['rev-parse', 'HEAD'], {
      encoding: 'utf8',
    }).trim(),
    changedFiles: execFileSync('git', ['status', '--short'], {
      encoding: 'utf8',
    })
      .trim()
      .split('\n')
      .filter(Boolean),
    receiverBuild: JSON.parse(
      readFileSync(path.join(pwa, 'build-manifest.json'), 'utf8'),
    ).buildId,
    measurementSources: Object.fromEntries(
      ['bench-memory.mjs', 'browser-runtime.mjs', 'memory-metrics.mjs'].map(
        (name) => [
          name,
          digest(readFileSync(path.join(receiverSources, name))),
        ],
      ),
    ),
    host: {
      platform: platform(),
      arch: arch(),
      release: release(),
      cpu: cpus()[0]?.model,
      logicalCPUs: cpus().length,
      physicalMemoryBytes: totalmem(),
      osVersion:
        platform() === 'darwin'
          ? execFileSync('sw_vers', { encoding: 'utf8' }).trim()
          : null,
    },
    tools: {
      node: process.version,
      go: execFileSync('go', ['version'], { encoding: 'utf8' }).trim(),
    },
    corpus: expected,
    senderProfile,
    fixture: fixture.metadata,
    measurement: {
      requestedProcessIntervalMilliseconds: sampleIntervalMilliseconds,
      requestedHeapIntervalMilliseconds: heapIntervalMilliseconds,
      displayHoldMilliseconds,
      canvas: { width: 740, height: 740, requestedFPS: 60 },
      sourceTransport:
        'one PNG at a time over local DevTools, then canvas.captureStream(60)',
      processScope:
        'isolated Chrome PID and all observed descendants, including browser, renderers, GPU, and utilities; excludes the Node driver, native sender, static host, and PNG files',
      residentMetric:
        'sum of ps RSS KiB times 1024; shared resident pages can be counted in several processes; compressed and swapped pages are excluded',
      heapMetric:
        'Runtime.getHeapUsage per page and attached decoder worker; not total process memory',
      wasmMetric:
        'observed WebAssembly.Memory.buffer capacity per decoder worker; overlaps backing storage and RSS and must not be added to them',
      codecTypedStorageBoundBytes: 139_584_160,
    },
    completion: { success: false },
  };
  try {
    launched = await launchChrome(
      chrome,
      profile,
      undefined,
      false,
      proxy.origin,
    );
    browser = await DevToolsClient.connect(launched.browserURL);
    report.tools.chrome = await browser.send('Browser.getVersion');
    report.measurement.chromeArguments = launched.processHandle.spawnargs
      .slice(1)
      .map((argument) =>
        argument
          .replace(profile, '<isolated-profile>')
          .replace(proxy.origin, '<local-disconnecting-proxy>'),
      );
    report.measurement.rootPID = launched.processHandle.pid;
    await browser.send('Browser.setDownloadBehavior', {
      behavior: 'allow',
      downloadPath: downloads,
    });
    const target = await fetch(`${launched.debugOrigin}/json/new?about:blank`, {
      method: 'PUT',
    }).then((response) => response.json());
    page = await DevToolsClient.connect(target.webSocketDebuggerUrl);
    await Promise.all([
      page.send('Page.enable'),
      page.send('Runtime.enable'),
      page.send('Network.enable'),
    ]);
    await page.send('Page.addScriptToEvaluateOnNewDocument', {
      source: canvasCamera,
    });
    page.on('Target.attachedToTarget', (event) => {
      void (async () => {
        const { sessionId, targetInfo } = event;
        if (targetInfo.type === 'worker') {
          await page.send('Runtime.enable', {}, sessionId);
          await page.send(
            'Runtime.evaluate',
            { expression: observeWasm },
            sessionId,
          );
          workerSessions.set(sessionId, targetInfo);
        }
        await page.send('Runtime.runIfWaitingForDebugger', {}, sessionId);
      })().catch((error) => instrumentationErrors.push(error.message));
    });
    page.on('Target.detachedFromTarget', ({ sessionId }) =>
      workerSessions.delete(sessionId),
    );
    await page.send('Target.setAutoAttach', {
      autoAttach: true,
      waitForDebuggerOnStart: true,
      flatten: true,
    });
    const requests = [];
    page.on('Network.requestWillBeSent', (event) =>
      requests.push(event.request.url),
    );
    await page.send('Page.navigate', { url: `${hosted.origin}/optical/` });
    await waitForPage(page);
    await waitForTrafficToSettle(hosted.traffic);
    proxy.disconnect();
    hosted.traffic.length = 0;
    requests.length = 0;
    await page.send('Network.emulateNetworkConditions', {
      offline: true,
      latency: 0,
      downloadThroughput: 0,
      uploadThroughput: 0,
    });
    sampler = startSampler(launched.processHandle.pid, page, workerSessions);
    await pause(2000);
    sampler.setPhase('warm-camera');
    await evaluate(
      page,
      "document.querySelector('#capture-profile').value = 'tracked-60'; document.querySelector('#start').click(); true",
    );
    await waitFor(
      () =>
        evaluate(
          page,
          "document.querySelector('#status').value === 'Looking for frames'",
        ),
      'canvas camera start',
    );
    await waitFor(
      () =>
        sampler.heapSamples.some(
          (sample) =>
            sample.workers.length > 0 &&
            sample.workers.every(
              (worker) => worker.wasm?.linearCapacityBytes === 0,
            ),
        ),
      'observed JavaScript QR worker heaps without WASM memory',
    );
    await pause(2000);
    report.camera = await evaluate(page, 'window.opticalMemoryCamera.state()');
    sampler.setPhase('receiving');
    const { receiptStarted, displayed, elapsedReceiptDriverMilliseconds } =
      await displayFrames(page, fixture);
    sampler.setPhase('completed');
    await pause(2000);
    report.receipt = await evaluate(
      page,
      `({ detail: document.querySelector('#status-detail').value, statistics: document.querySelector('#statistics').value, camera: window.opticalMemoryCamera.state() })`,
    );
    sampler.setPhase('saving');
    const download = path.join(downloads, capsuleFilename);
    await saveCapsule(page, download);
    assert.equal(statSync(download).size, sourceBytes);
    const savedSHA256 = digest(readFileSync(download));
    assert.equal(savedSHA256, expected.sha256);
    assert.deepEqual(hosted.traffic, []);
    assert.deepEqual(
      requests.filter(
        (url) => /^https?:/.test(url) && new URL(url).origin !== hosted.origin,
      ),
      [],
    );
    for (const request of proxy.blocked) {
      assert.deepEqual(request, { method: 'GET', path: '/optical/sw.js' });
    }
    report.completion = {
      success: true,
      displayedImages: displayed,
      elapsedReceiptDriverMilliseconds,
      elapsedDriverMilliseconds: performance.now() - receiptStarted,
      savedBytes: sourceBytes,
      savedSHA256,
      hostRequests: hosted.traffic,
      cachedWorkerRequests: requests
        .filter((url) => /^https?:/.test(url))
        .map((url) => new URL(url).pathname),
      blockedWorkerUpdateAttempts: proxy.blocked.length,
    };
    await pause(2000);
    sampler.setPhase('cleared');
    await evaluate(
      page,
      "document.querySelector('#start').click(); document.querySelector('#stop').click(); true",
    );
    await pause(2000);
    assert.equal(
      await evaluate(page, 'window.opticalMemoryCamera.state().liveTracks'),
      0,
    );
  } catch (error) {
    report.failure = error.message;
    report.failureState = page
      ? await evaluate(
          page,
          `({ status: document.querySelector('#status')?.value, detail: document.querySelector('#status-detail')?.value, progress: document.querySelector('#progress')?.value, statistics: document.querySelector('#statistics')?.value, stripes: document.querySelector('#stripe-progress')?.textContent, camera: window.opticalMemoryCamera?.state() })`,
        ).catch(() => null)
      : null;
    process.exitCode = 1;
  } finally {
    await sampler?.stop();
    writeMeasurementReport(report, sampler, instrumentationErrors);
    page?.close();
    browser?.close();
    if (launched) {
      await stopChrome(launched.processHandle);
    }
    await closeServer(hosted.server);
    await closeServer(proxy.server);
    rmSync(work, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100,
    });
  }
}

await run();
