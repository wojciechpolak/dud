#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
import { build } from 'esbuild';
import {
  qrFixture,
  fourQR,
  phoneRaster,
  renderQR,
} from './test/qr-image-fixtures.mjs';
import { trackedRegion } from './.work/receiver/tracked-regions.js';

const [reference, countText = '1000', output] = process.argv.slice(2);
const iterations = Number(countText);
if (
  !reference ||
  !output ||
  !Number.isInteger(iterations) ||
  iterations < 1 ||
  iterations > 10000
) {
  throw new Error(
    'Usage: bench-qr-scan-cost.mjs BASELINE_REF ITERATIONS OUTPUT.json',
  );
}
const root = fileURLToPath(new URL('../../', import.meta.url));
const sourceRoot = fileURLToPath(new URL('src/', import.meta.url));
const baselineCommit = execFileSync(
  'git',
  ['rev-parse', '--verify', `${reference}^{commit}`],
  { cwd: root, encoding: 'utf8' },
).trim();
const sourcePrefix = relative(root, sourceRoot) + '/';
const baselinePrefixes = [sourcePrefix, 'receiver/optical/src/'];
const baselineEntries = execFileSync(
  'git',
  [
    'ls-tree',
    '-r',
    '--name-only',
    baselineCommit,
    '--',
    ...baselinePrefixes.map((prefix) => prefix + 'qr-image.ts'),
  ],
  { cwd: root, encoding: 'utf8' },
)
  .trim()
  .split('\n');
const baselinePrefix = baselinePrefixes.find((prefix) =>
  baselineEntries.includes(prefix + 'qr-image.ts'),
);
if (!baselinePrefix) {
  throw new Error('Git baseline must contain optical QR decoder sources');
}
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const temporary = mkdtempSync(join(os.tmpdir(), 'dud-scan-cost-'));
const sources = { before: {}, after: {} };
const bundles = {};
function baselineSource(path) {
  const baselinePath = baselinePrefix + path.slice(sourcePrefix.length);
  return execFileSync('git', ['show', `${baselineCommit}:${baselinePath}`], {
    cwd: root,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

try {
  for (const implementation of ['before', 'after']) {
    const outfile = join(temporary, implementation + '.mjs');
    await build({
      entryPoints: [join(sourceRoot, 'qr-image.ts')],
      outfile,
      bundle: true,
      platform: 'node',
      format: 'esm',
      plugins: [
        {
          name: 'repository-snapshot',
          setup(builder) {
            builder.onLoad({ filter: /\.ts$/ }, (args) => {
              const path = relative(root, args.path);
              const contents =
                implementation === 'before'
                  ? baselineSource(path)
                  : readFileSync(args.path);
              sources[implementation][path] = hash(contents);
              return { contents: contents.toString(), loader: 'ts' };
            });
          },
        },
      ],
    });
    bundles[implementation] = {
      sha256: hash(readFileSync(outfile)),
      module: await import(pathToFileURL(outfile).href),
    };
  }
  const cases = [];
  const crop = (image, region) => {
    const rgba = new Uint8Array(region.width * region.height * 4);
    for (let y = 0; y < region.height; y++) {
      const start = ((region.y + y) * image.width + region.x) * 4;
      rgba.set(
        image.rgba.subarray(start, start + region.width * 4),
        y * region.width * 4,
      );
    }
    return { rgba, width: region.width, height: region.height };
  };
  const fullCase = (name, version, image, expected, count = iterations) => {
    const entry = {
      name,
      version,
      regions: [image],
      expected: expected.map(hash).sort(),
      count,
      tracked: false,
    };
    cases.push(entry);
    return entry;
  };
  for (const version of [30, 40]) {
    const fixtures = ['zero', 'cycle', 'random', 'capacity'].map((n) =>
      qrFixture(version, n),
    );
    const width = 960,
      rgba = new Uint8Array(width * width * 4).fill(255);
    for (let i = 0; i < 4; i++) {
      const image = renderQR(
        fixtures[i],
        [
          2.4,
          0,
          20 + (i % 2) * 480,
          0,
          2.4,
          20 + Math.floor(i / 2) * 480,
          0,
          0,
          1,
        ],
        width,
      );
      for (let p = 0; p < rgba.length; p += 4) {
        rgba[p] = rgba[p + 1] = rgba[p + 2] = Math.min(rgba[p], image.rgba[p]);
      }
    }
    fullCase(
      `clean-full-v${version}`,
      version,
      { rgba, width, height: width },
      fixtures.map((f) => f.payload),
    );
    const image = fourQR(fixtures, version === 30 ? 3 : 2.4);
    const symbols = bundles.before.module.scanQRImage(
      image.rgba,
      image.width,
      image.height,
    ).symbols;
    assert.equal(symbols.length, 4);
    const regions = symbols.map((s) =>
      crop(image, trackedRegion(s.points, image.width, image.height)),
    );
    cases.push({
      name: `blurred-tracked-four-v${version}`,
      version,
      regions,
      expected: fixtures.map((f) => hash(f.payload)).sort(),
      count: iterations,
      tracked: true,
    });
  }
  const phone = phoneRaster();
  fullCase(
    'submitted-jpeg-full',
    40,
    phone,
    [phone.payload],
    Math.min(iterations, 100),
  );
  const symbol = bundles.before.module.scanQRImage(
    phone.rgba,
    phone.width,
    phone.height,
  ).symbols[0];
  assert.deepEqual(Buffer.from(symbol.data), phone.payload);
  cases.push({
    name: 'submitted-jpeg-tracked-single',
    version: 40,
    regions: [
      crop(phone, trackedRegion(symbol.points, phone.width, phone.height)),
    ],
    expected: [hash(phone.payload)],
    count: Math.min(iterations, 100),
    tracked: true,
  });
  const samples = [],
    summary = [];
  const decode = (entry, implementation) => {
    const work = {
      finderChecks: 0,
      candidates: 0,
      triples: 0,
      alignmentChecks: 0,
      matrixAttempts: 0,
    };
    let exhaustedScans = 0;
    const symbols = [];
    for (const image of entry.regions) {
      const result = bundles[implementation].module.scanQRImage(
        image.rgba,
        image.width,
        image.height,
        entry.tracked && implementation === 'after' ? 1 : 4,
      );
      for (const key of Object.keys(work)) {
        work[key] += result.work[key];
      }
      exhaustedScans += Number(result.exhausted);
      symbols.push(...result.symbols);
    }
    return { symbols, work, exhaustedScans };
  };
  for (const entry of cases) {
    const warmup = Math.min(entry.count, entry.tracked ? 20 : 50);
    for (let round = -warmup; round < entry.count; round++) {
      for (const implementation of round % 2
        ? ['after', 'before']
        : ['before', 'after']) {
        const started = performance.now();
        const result = decode(entry, implementation);
        const milliseconds = performance.now() - started;
        assert.deepEqual(
          result.symbols.map((s) => hash(s.data)).sort(),
          entry.expected,
        );
        if (round >= 0) {
          samples.push({
            scene: entry.name,
            implementation,
            round,
            milliseconds,
            work: result.work,
            exhaustedScans: result.exhaustedScans,
          });
        }
      }
      await new Promise(setImmediate);
    }
    for (const implementation of ['before', 'after']) {
      const values = samples.filter(
        (s) => s.scene === entry.name && s.implementation === implementation,
      );
      const times = values.map((v) => v.milliseconds).sort((a, b) => a - b);
      summary.push({
        scene: entry.name,
        implementation,
        samples: values.length,
        warmup,
        medianMilliseconds: times[Math.ceil(times.length / 2) - 1],
        p95Milliseconds: times[Math.ceil(times.length * 0.95) - 1],
        imagesPerSecond:
          (1000 * values.length) /
          values.reduce((sum, v) => sum + v.milliseconds, 0),
        workCounts: [...new Set(values.map((v) => JSON.stringify(v.work)))],
        exhaustedScanCounts: [...new Set(values.map((v) => v.exhaustedScans))],
      });
    }
    console.log(JSON.stringify(summary.filter((s) => s.scene === entry.name)));
  }
  const rawFile = output.replace(/\.json$/, '.samples.json.gz');
  const raw = gzipSync(JSON.stringify(samples) + '\n');
  writeFileSync(rawFile, raw);
  const report = {
    schemaVersion: 1,
    baselineCommit,
    recordedAt: new Date().toISOString(),
    host: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cpu: os.cpus()[0]?.model,
    },
    method:
      'Alternate baseline and working-source bundles each round on identical static RGBA inputs. Track crops are fixed from baseline symbol geometry. Tracked cases compare four-symbol search per crop with a one-symbol stop. Detection, sampling, correction, allocations and scan-work aggregation are timed; input rendering, cropping, payload SHA-256 comparison and event-loop yields are excluded. Every complete recovered payload is checked.',
    sources,
    bundles: Object.fromEntries(
      Object.entries(bundles).map(([key, value]) => [
        key,
        { sha256: value.sha256 },
      ]),
    ),
    inputs: cases.map((c) => ({
      scene: c.name,
      version: c.version,
      tracked: c.tracked,
      regions: c.regions.map((r) => ({
        width: r.width,
        height: r.height,
        rgbaSHA256: hash(r.rgba),
      })),
      expectedPayloadSHA256: c.expected,
    })),
    summary,
    raw: {
      file: rawFile.split('/').at(-1),
      sha256: hash(raw),
      samples: samples.length,
    },
    limits: [
      'Static Node measurements do not establish phone latency, battery, thermal behavior or camera throughput.',
      'The submitted JPEG has one recoverable frame; its tracked case covers one crop rather than four readable regions.',
      'Host CPU load and memory pressure are not isolated.',
      'No physical-phone or release gate is passed.',
    ],
  };
  writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
