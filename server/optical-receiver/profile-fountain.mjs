#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
import { build } from 'esbuild';

const sizeMiB = Number(process.argv[2] ?? 16);
const output = process.argv[3];
if (![1, 16, 64].includes(sizeMiB) || !output) {
  throw new Error('Usage: profile-fountain.mjs [1|16|64] REPORT.json');
}
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const measureKey = Symbol.for('dud.fountain.profile.measure');
let phases;
globalThis[measureKey] = (name, operation) => {
  const started = performance.now();
  try {
    return operation();
  } finally {
    phases[name] = (phases[name] ?? 0) + performance.now() - started;
  }
};
const temporary = mkdtempSync(join(os.tmpdir(), 'dud-fountain-profile-'));
try {
  const sourceURL = new URL('src/codec.ts', import.meta.url);
  const source = readFileSync(sourceURL, 'utf8');
  let instrumented = source;
  for (const [name, signature, argument, phase] of [
    ['add', 'row: Equation', 'row', 'elimination'],
    ['solve', '', '', 'solve'],
  ]) {
    const declaration = `  ${name}(${signature}): ${name === 'add' ? 'boolean' : 'Uint8Array'} {`;
    assert.equal(instrumented.split(declaration).length, 2);
    instrumented = instrumented.replace(
      declaration,
      `${declaration}
      return globalThis[Symbol.for('dud.fountain.profile.measure')](
        '${phase}', () => this.measured_${name}(${argument}));
    }
    ${declaration.trimStart().replace(`${name}(`, `measured_${name}(`)}`,
    );
  }
  const bundle = join(temporary, 'codec.mjs');
  await build({
    stdin: {
      contents: instrumented,
      loader: 'ts',
      resolveDir: fileURLToPath(new URL('src/', import.meta.url)),
    },
    outfile: bundle,
    bundle: true,
    format: 'esm',
    platform: 'node',
  });
  const { OpticalEncoder, OpticalDecoder, selectBlocks } = await import(
    pathToFileURL(bundle).href
  );
  const capsule = Uint8Array.from(
    { length: sizeMiB * 1024 * 1024 },
    (_, i) => (Math.imul(i, 73) + Math.imul(i >>> 8, 19) + 41) & 255,
  );
  const session = Uint8Array.from({ length: 16 }, (_, i) => 13 + i);
  const patterns = [
    { name: 'all', keep: () => true },
    { name: 'every-second', keep: (position) => position % 2 === 0 },
    { name: 'every-ninth', keep: (position) => position % 9 === 0 },
    {
      name: 'burst-eight-of-thirty-two',
      keep: (position) => position % 32 < 8,
    },
  ];
  const runs = [];
  for (const blockSize of [1600, 2860]) {
    const encoder = await OpticalEncoder.create(capsule, session, blockSize);
    for (const pattern of patterns) {
      const decoder = new OpticalDecoder();
      const samples = [];
      const completions = [];
      let progress;
      let previousWork = 0;
      for (let stripe = 0; stripe < encoder.stripeCount; stripe++) {
        progress = undefined;
        const sources = encoder.getSourceCount(stripe);
        const repairs = Math.ceil(sources / 4);
        const cycle = sources + repairs;
        const add = (sequence, kind) => {
          const frame = encoder.frame(stripe, sequence);
          const previousRows = progress?.independentRows ?? 0;
          phases = {};
          const cpu = process.threadCpuUsage();
          const started = performance.now();
          progress = decoder.add(frame);
          const milliseconds = performance.now() - started;
          const used = process.threadCpuUsage(cpu);
          const sample = {
            stripe,
            sequence,
            kind,
            milliseconds,
            threadCPUMilliseconds: (used.user + used.system) / 1000,
            ...phases,
            workBytes: progress.workBytes - previousWork,
            independent: progress.independentRows > previousRows,
          };
          samples.push(sample);
          previousWork = progress.workBytes;
          if (progress.independentRows === sources) {
            completions.push(sample);
          }
        };
        for (let position = 0; position < cycle; position++) {
          const before = Math.floor((position * repairs) / cycle);
          const through = Math.floor(((position + 1) * repairs) / cycle);
          const sequence =
            through > before ? sources + through - 1 : position - before;
          if (pattern.keep(position) && progress?.independentRows !== sources) {
            add(sequence, 'initial');
          }
        }
        let sequence = sources + repairs;
        let attempts = 0;
        while ((progress?.independentRows ?? 0) < sources && attempts < 2000) {
          if (
            selectBlocks(session, stripe, sequence, sources).length ===
            Math.min(31, sources)
          ) {
            add(sequence, 'recovery');
            attempts++;
          }
          sequence++;
        }
        assert.equal(
          progress.independentRows,
          sources,
          `${blockSize}/${pattern.name}/${stripe}`,
        );
      }
      const digestStarted = performance.now();
      const result = await decoder.result();
      const digestMilliseconds = performance.now() - digestStarted;
      assert.deepEqual(result, capsule);
      const percentile = (name, fraction) =>
        samples.map((s) => s[name] ?? 0).sort((a, b) => a - b)[
          Math.ceil(samples.length * fraction) - 1
        ];
      const sum = (name) =>
        samples.reduce((total, s) => total + (s[name] ?? 0), 0);
      const run = {
        blockSize,
        lossPattern: pattern.name,
        sourceBytes: capsule.length,
        frameCount: samples.length,
        stripeCount: encoder.stripeCount,
        countedWorkBytes: progress.workBytes,
        medianAddMilliseconds: percentile('milliseconds', 0.5),
        p95AddMilliseconds: percentile('milliseconds', 0.95),
        p99AddMilliseconds: percentile('milliseconds', 0.99),
        maximumAddMilliseconds: percentile('milliseconds', 1),
        maximumEliminationMilliseconds: percentile('elimination', 1),
        maximumSolveMilliseconds: percentile('solve', 1),
        totalAddMilliseconds: sum('milliseconds'),
        totalEliminationMilliseconds: sum('elimination'),
        totalSolveMilliseconds: sum('solve'),
        digestMilliseconds,
        completions,
        samples,
      };
      runs.push(run);
      console.log(
        JSON.stringify({ ...run, samples: undefined, completions: undefined }),
      );
      decoder.clear();
    }
  }
  const rawPath = output.replace(/\.json$/, '') + '.samples.json.gz';
  const raw = gzipSync(JSON.stringify(runs), { level: 9 });
  writeFileSync(rawPath, raw);
  writeFileSync(
    output,
    JSON.stringify(
      {
        schemaVersion: 1,
        recordedAt: new Date().toISOString(),
        runtime: process.version,
        host: {
          platform: process.platform,
          arch: process.arch,
          cpu: os.cpus()[0]?.model,
        },
        sources: {
          'src/codec.ts': hash(source),
          'profile-fountain.mjs': hash(
            readFileSync(new URL('profile-fountain.mjs', import.meta.url)),
          ),
        },
        corpusSHA256: hash(capsule),
        sessionHex: Buffer.from(session).toString('hex'),
        method:
          'Per-frame synchronous decoder.add, StripeDecoder.add elimination and StripeDecoder.solve wall times in a disposable instrumented bundle. Rendering, QR, frame generation and output assertion are excluded. Initial cycle interleaves 25% repair. Recovery admits only degree min(31,sourceCount), bounded to 2000 attempts per stripe. Every run verifies exact reconstructed bytes and digest.',
        limits: [
          'Static Node streams do not establish browser or phone performance.',
          'Host load and thermal state are not isolated.',
          'Stage wrappers alter JIT call boundaries.',
          'Profiles and loss patterns run sequentially; comparisons do not isolate time-varying host load.',
        ],
        raw: {
          file: rawPath.split('/').at(-1),
          bytes: raw.length,
          sha256: hash(raw),
        },
        runs: runs.map(({ samples: _samples, ...r }) => r),
      },
      null,
      2,
    ) + '\n',
  );
} finally {
  delete globalThis[measureKey];
  rmSync(temporary, { recursive: true, force: true });
}
