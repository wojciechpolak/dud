#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { scanQRImage } from './.work/receiver/qr-image.js';
import { qrFixture, renderQR } from './test/qr-image-fixtures.mjs';

const iterations = Number(process.argv[2] ?? 1000);
const output = process.argv[3];
if (!Number.isInteger(iterations) || iterations < 1 || iterations > 10_000) {
  throw new RangeError('iterations must be an integer from 1 through 10000');
}
const oracle = process.env.DUD_QR_IMAGE_ORACLE
  ? await import(pathToFileURL(process.env.DUD_QR_IMAGE_ORACLE).href)
  : undefined;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const report = {
  schemaVersion: 1,
  runtime: process.version,
  host: {
    platform: process.platform,
    arch: process.arch,
    release: os.release(),
    cpu: os.cpus()[0]?.model,
  },
  iterations,
  warmupIterations: 50,
  method:
    'Sequential same-host RGBA decoding of fixed four-symbol images, byte-verified each iteration. Input rendering is excluded; decoder allocations, detection, sampling and correction are included.',
  limits: [
    'Repeated static fixtures are not camera frames or display cadence measurements.',
    'Node timings do not establish browser or phone performance.',
    'No physical camera, memory, battery, thermal or release gate is passed by this measurement.',
  ],
  sources: {},
  results: [],
};
for (const name of [
  'src/qr-image.ts',
  'src/qr-matrix.ts',
  'src/qr-reed-solomon.ts',
  'src/qr-gf256.ts',
  'test/qr-image-fixtures.mjs',
  'bench-qr-image.mjs',
]) {
  report.sources[name] = hash(readFileSync(new URL(name, import.meta.url)));
}

for (const version of [30, 40]) {
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
  const expected = fixtures.map((f) => f.payload.toString('base64')).sort();
  const implementations = [
    [
      'repository',
      (data) =>
        scanQRImage(data, side, side).symbols.map((symbol) =>
          Buffer.from(symbol.data),
        ),
    ],
  ];
  if (oracle) {
    implementations.unshift([
      'zbar-public-api',
      (data) => oracle.decode(data, side, side),
    ]);
  }
  for (const [implementation, decode] of implementations) {
    const samples = [];
    for (let i = -50; i < iterations; i++) {
      const started = performance.now();
      const symbols = await decode(rgba);
      const milliseconds = performance.now() - started;
      assert.deepEqual(
        symbols.map((data) => data.toString('base64')).sort(),
        expected,
      );
      if (i >= 0) {
        samples.push(milliseconds);
      }
    }
    const sorted = [...samples].sort((a, b) => a - b);
    const total = samples.reduce((a, b) => a + b, 0);
    report.results.push({
      implementation,
      version,
      symbolsPerImage: 4,
      width: side,
      height: side,
      inputSHA256: hash(rgba),
      medianMilliseconds: sorted[Math.ceil(iterations * 0.5) - 1],
      p95Milliseconds: sorted[Math.ceil(iterations * 0.95) - 1],
      meanMilliseconds: total / iterations,
      imagesPerSecond: (iterations * 1000) / total,
      samplesMilliseconds: samples,
    });
    console.log(
      JSON.stringify({
        ...report.results.at(-1),
        samplesMilliseconds: undefined,
      }),
    );
  }
}
if (output) {
  writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
}
