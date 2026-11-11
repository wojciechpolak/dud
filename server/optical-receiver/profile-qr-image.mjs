#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import { PerformanceObserver } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { qrFixture, renderQR } from './test/qr-image-fixtures.mjs';

const iterations = Number(process.argv[2] ?? 1000);
const output = process.argv[3];
const mode = process.argv[4] ?? 'plain';
if (!Number.isInteger(iterations) || iterations < 1 || iterations > 10_000) {
  throw new RangeError('iterations must be an integer from 1 through 10000');
}
if (!['plain', 'stages'].includes(mode) || !output) {
  throw new Error(
    'Usage: profile-qr-image.mjs ITERATIONS OUTPUT [plain|stages]',
  );
}

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const measureKey = Symbol.for('dud.qr.profile.measure');
let stages;
const stack = [];
globalThis[measureKey] = (name, operation) => {
  const frame = { started: performance.now(), child: 0 };
  stack.push(frame);
  try {
    return operation();
  } finally {
    const elapsed = performance.now() - frame.started;
    stack.pop();
    if (stack.length) {
      stack.at(-1).child += elapsed;
    }
    const stage = (stages[name] ??= { calls: 0, inclusive: 0, exclusive: 0 });
    stage.calls++;
    stage.inclusive += elapsed;
    stage.exclusive += elapsed - frame.child;
  }
};

const temporary = mkdtempSync(join(os.tmpdir(), 'dud-qr-profile-'));
const gc = [];
const observer = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    gc.push({
      start: entry.startTime,
      duration: entry.duration,
      ...entry.detail,
    });
  }
});
observer.observe({ entryTypes: ['gc'] });

try {
  let scanner;
  if (mode === 'plain') {
    scanner = await import('./.work/receiver/qr-image.js');
  } else {
    // Instrument a disposable bundle; production sources and worker stay intact.
    const functions = {
      'qr-image.ts': ['binarize', 'finders', 'triples', 'alignment', 'sample'],
      'qr-matrix.ts': ['decodeQRMatrix', 'readWords', 'recover'],
      'qr-reed-solomon.ts': ['correctQRBlock', 'syndromes'],
    };
    const bundle = join(temporary, 'scanner.mjs');
    await build({
      entryPoints: [fileURLToPath(new URL('src/qr-image.ts', import.meta.url))],
      outfile: bundle,
      bundle: true,
      format: 'esm',
      platform: 'node',
      plugins: [
        {
          name: 'qr-stage-timing',
          setup(builder) {
            builder.onLoad(
              { filter: /qr-(image|matrix|reed-solomon)\.ts$/ },
              (args) => {
                let contents = readFileSync(args.path, 'utf8');
                for (const name of functions[args.path.split('/').at(-1)]) {
                  const declaration = new RegExp(
                    `(export )?function ${name}\\(`,
                    'g',
                  );
                  assert.equal([...contents.matchAll(declaration)].length, 1);
                  const exported = contents.includes(
                    `export function ${name}(`,
                  );
                  contents = contents.replace(
                    declaration,
                    `function measured_${name}(`,
                  );
                  contents += `\n${exported ? 'export ' : ''}function ${name}(...args) {
                return globalThis[Symbol.for('dud.qr.profile.measure')](
                  '${name}', () => measured_${name}(...args));
              }\n`;
                }
                return { contents, loader: 'ts' };
              },
            );
          },
        },
      ],
    });
    scanner = await import(pathToFileURL(bundle).href);
  }
  const oracle = process.env.DUD_QR_IMAGE_ORACLE
    ? await import(pathToFileURL(process.env.DUD_QR_IMAGE_ORACLE).href)
    : undefined;
  const oracleName = process.env.DUD_QR_IMAGE_ORACLE_NAME ?? 'zbar-public-api';
  if (oracleName === 'repository' || !/^[a-z0-9-]{1,48}$/.test(oracleName)) {
    throw new Error(
      'Oracle name must be distinct and contain lowercase letters, digits or hyphens',
    );
  }
  const inputs = [30, 40].map((version) => {
    const fixtures = ['zero', 'cycle', 'random', 'capacity'].map((name) =>
      qrFixture(version, name),
    );
    const side = (fixtures[0].rows.length + 8) * 4;
    const rgba = new Uint8Array(side * side * 4).fill(255);
    for (let i = 0; i < fixtures.length; i++) {
      const half = side / 2;
      const image = renderQR(
        fixtures[i],
        [2, 0, 8 + (i % 2) * half, 0, 2, 8 + Math.floor(i / 2) * half, 0, 0, 1],
        side,
      );
      for (let p = 0; p < rgba.length; p += 4) {
        if (image.rgba[p] === 0) {
          rgba[p] = rgba[p + 1] = rgba[p + 2] = 0;
        }
      }
    }
    return {
      version,
      side,
      rgba,
      expected: fixtures.map((f) => f.payload.toString('base64')).sort(),
    };
  });
  const results = [];
  const implementations = ['repository', ...(oracle ? [oracleName] : [])];
  for (let round = -50; round < iterations; round++) {
    // Alternate versions and implementations to distribute time-varying host load.
    const order = round % 2 ? [...inputs].reverse() : inputs;
    const decoders =
      round % 2 ? [...implementations].reverse() : implementations;
    for (const input of order) {
      for (const implementation of decoders) {
        stages = {};
        const cpuStart = process.threadCpuUsage();
        const processStart = process.cpuUsage();
        const started = performance.now();
        let work;
        let exhausted;
        let symbols;
        if (implementation === 'repository') {
          const decoded = scanner.scanQRImage(
            input.rgba,
            input.side,
            input.side,
          );
          work = decoded.work;
          exhausted = decoded.exhausted;
          symbols = decoded.symbols.map((symbol) => Buffer.from(symbol.data));
        } else {
          symbols = await oracle.decode(input.rgba, input.side, input.side);
        }
        const ended = performance.now();
        const cpu = process.threadCpuUsage(cpuStart);
        const processCPU = process.cpuUsage(processStart);
        assert.deepEqual(
          symbols.map((data) => data.toString('base64')).sort(),
          input.expected,
        );
        if (round >= 0) {
          const memory = process.memoryUsage();
          results.push({
            round,
            implementation,
            version: input.version,
            started,
            ended,
            milliseconds: ended - started,
            threadCPUMilliseconds: (cpu.user + cpu.system) / 1000,
            processCPUMilliseconds:
              (processCPU.user + processCPU.system) / 1000,
            heapUsed: memory.heapUsed,
            arrayBuffers: memory.arrayBuffers,
            work,
            exhausted,
            stages: mode === 'stages' ? stages : undefined,
          });
        }
        // Deliver GC observations outside the measured decode interval.
        await new Promise(setImmediate);
      }
    }
  }
  await new Promise(setImmediate);
  gc.push(
    ...observer.takeRecords().map((entry) => ({
      start: entry.startTime,
      duration: entry.duration,
      ...entry.detail,
    })),
  );
  for (const sample of results) {
    const overlapping = gc.filter(
      (entry) =>
        entry.start < sample.ended &&
        entry.start + entry.duration > sample.started,
    );
    sample.gcMilliseconds = overlapping.reduce(
      (sum, entry) =>
        sum +
        Math.max(
          0,
          Math.min(sample.ended, entry.start + entry.duration) -
            Math.max(sample.started, entry.start),
        ),
      0,
    );
    sample.gcCount = overlapping.length;
  }
  const summary = [];
  for (const version of [30, 40]) {
    for (const implementation of implementations) {
      const samples = results.filter(
        (s) => s.version === version && s.implementation === implementation,
      );
      const percentile = (key, fraction) =>
        samples.map((s) => s[key]).sort((a, b) => a - b)[
          Math.ceil(samples.length * fraction) - 1
        ];
      summary.push({
        version,
        implementation,
        medianMilliseconds: percentile('milliseconds', 0.5),
        p95Milliseconds: percentile('milliseconds', 0.95),
        maxMilliseconds: percentile('milliseconds', 1),
        medianThreadCPUMilliseconds: percentile('threadCPUMilliseconds', 0.5),
        p95ThreadCPUMilliseconds: percentile('threadCPUMilliseconds', 0.95),
        maxGCMilliseconds: percentile('gcMilliseconds', 1),
        samplesOver50Milliseconds: samples.filter((s) => s.milliseconds > 50)
          .length,
        workCounts: [...new Set(samples.map((s) => JSON.stringify(s.work)))],
      });
    }
  }
  const sources = Object.fromEntries(
    [
      'src/qr-image.ts',
      'src/qr-matrix.ts',
      'src/qr-reed-solomon.ts',
      'src/qr-gf256.ts',
      'test/qr-image-fixtures.mjs',
      'profile-qr-image.mjs',
    ].map((name) => [name, hash(readFileSync(new URL(name, import.meta.url)))]),
  );
  const report = {
    schemaVersion: 1,
    runtime: process.version,
    mode,
    iterations,
    warmupRounds: 50,
    recordedAt: new Date().toISOString(),
    host: {
      platform: process.platform,
      arch: process.arch,
      release: os.release(),
      cpu: os.cpus()[0]?.model,
    },
    method:
      'Alternate profile and decoder order each round. Decode interval excludes rendering, payload assertions, memory sampling and event-loop yields. Every decode verifies all four binary payloads. Thread CPU measures the calling thread; process CPU includes other runtime threads. Stage times are nested wall times with child durations subtracted for exclusive time.',
    limits: [
      'Static Node fixtures do not establish camera or phone performance.',
      'Host load is not isolated. Instrumentation, CPU clocks and GC observation affect timings.',
      'GC observations do not reconstruct the archived run.',
    ],
    sources,
    inputs: inputs.map((i) => ({
      version: i.version,
      width: i.side,
      height: i.side,
      inputSHA256: hash(i.rgba),
    })),
    summary,
    gc,
    results,
  };
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(summary, null, 2));
} finally {
  observer.disconnect();
  delete globalThis[measureKey];
  rmSync(temporary, { recursive: true, force: true });
}
