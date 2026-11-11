#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve, basename } from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';
import { OpticalEncoder } from './.work/receiver/codec.js';
import { FountainFramePipeline } from './.work/receiver/fountain-client.js';
import { createFountainNodeWorker } from './fountain-node-worker.mjs';

const input = process.argv[2],
  output = process.argv[3];
if (!input || !output) {
  throw new Error(
    'Usage: profile-fountain-worker.mjs FOUNTAIN_REPORT.json OUTPUT.json',
  );
}
const baseline = JSON.parse(readFileSync(input));
const streams = JSON.parse(
  gunzipSync(readFileSync(resolve(dirname(input), baseline.raw.file))),
);
const hash = (b) => createHash('sha256').update(b).digest('hex');
const capsule = Uint8Array.from(
  { length: streams[0].sourceBytes },
  (_, i) => (Math.imul(i, 73) + Math.imul(i >>> 8, 19) + 41) & 255,
);
assert.equal(hash(capsule), baseline.corpusSHA256);
const session = Uint8Array.from(Buffer.from(baseline.sessionHex, 'hex'));
const results = [];
for (const stream of streams) {
  const encoder = await OpticalEncoder.create(
    capsule,
    session,
    stream.blockSize,
  );
  const durations = [];
  const heartbeat = [];
  let client;
  let index = 0;
  let scheduling = false;
  let finished = false;
  let previous = performance.now();
  let done;
  const completed = new Promise((resolve) => {
    done = resolve;
  });
  const timer = setInterval(() => {
    const now = performance.now();
    heartbeat.push(now - previous);
    previous = now;
  }, 5);
  const timeout = setTimeout(() => done({ timeout: true }), 120000);
  const pump = () => {
    if (scheduling || finished) {
      return;
    }
    scheduling = true;
    setImmediate(() => {
      scheduling = false;
      if (finished) {
        return;
      }
      let sent = 0;
      while (index < stream.samples.length && client.canAccept && sent < 4) {
        const { stripe, sequence } = stream.samples[index++];
        const frame = encoder.frame(stripe, sequence);
        const start = performance.now();
        client.accept(frame);
        durations.push(performance.now() - start);
        sent++;
      }
      if (index < stream.samples.length && client.canAccept) {
        pump();
      }
    });
  };
  client = new FountainFramePipeline(
    {
      onProgress: pump,
      onFrameDisposition: () => {},
      onComplete: (v) => {
        finished = true;
        done({ completion: v });
      },
      onFatal: (v) => {
        finished = true;
        done({ fatal: v });
      },
      onRejected: (v) => {
        finished = true;
        done({ rejected: v });
      },
      onUnsupported: (v) => {
        finished = true;
        done({ unsupported: v });
      },
      onSessionChange: () => {
        finished = true;
        done({ session: true });
      },
    },
    createFountainNodeWorker,
  );
  try {
    pump();
    const result = await completed;
    assert.ok(
      result.completion,
      JSON.stringify({
        fatal: result.fatal,
        timeout: result.timeout,
        rejected: result.rejected,
        unsupported: result.unsupported,
        session: result.session,
      }),
    );
    assert.deepEqual(result.completion.capsule, capsule);
    assert.equal(index, stream.samples.length);
    const sorted = [...durations].sort((a, b) => a - b);
    const summary = {
      blockSize: stream.blockSize,
      lossPattern: stream.lossPattern,
      frameCount: index,
      callerMedianMilliseconds: sorted[Math.ceil(sorted.length * 0.5) - 1],
      callerP95Milliseconds: sorted[Math.ceil(sorted.length * 0.95) - 1],
      callerMaximumMilliseconds: sorted.at(-1),
      heartbeatCount: heartbeat.length,
      maximumHeartbeatGapMilliseconds: Math.max(...heartbeat),
      stats: client.snapshot(),
      verifiedBytes: result.completion.byteLength,
    };
    results.push({
      ...summary,
      callerSamplesMilliseconds: durations,
      heartbeatSamplesMilliseconds: heartbeat,
    });
    console.log(JSON.stringify(summary));
  } finally {
    finished = true;
    clearInterval(timer);
    clearTimeout(timeout);
    client.reset();
  }
}
const raw = gzipSync(JSON.stringify(results), { level: 9 });
const rawPath = output.replace(/\.json$/, '') + '.samples.json.gz';
writeFileSync(rawPath, raw);
writeFileSync(
  output,
  JSON.stringify(
    {
      schemaVersion: 1,
      clientDate: '2026-10-03',
      recordedAt: new Date().toISOString(),
      runtime: process.version,
      baseline: { file: basename(input), sha256: hash(readFileSync(input)) },
      corpusSHA256: baseline.corpusSHA256,
      method:
        'Replay the exact per-stripe/sequence schedules from the synchronous profile through the shipped fountain worker using real Node message ports and transfer lists. Generate each sender frame outside the measured enqueue interval, send batches of at most four, verify every reconstructed byte and digest. A 5 ms main-thread heartbeat runs through queueing, worker processing and digest completion.',
      sources: Object.fromEntries(
        [
          'src/codec.ts',
          'src/pipeline.ts',
          'src/fountain-client.ts',
          'src/fountain-messages.ts',
          'src/fountain-worker.ts',
          'fountain-node-worker.mjs',
          'profile-fountain-worker.mjs',
        ].map((n) => [n, hash(readFileSync(new URL(n, import.meta.url)))]),
      ),
      build: JSON.parse(
        readFileSync(
          new URL('./.work/pwa/build-manifest.json', import.meta.url),
        ),
      ),
      raw: { file: basename(rawPath), bytes: raw.length, sha256: hash(raw) },
      results: results.map(
        ({
          callerSamplesMilliseconds: _callerSamples,
          heartbeatSamplesMilliseconds: _heartbeatSamples,
          ...r
        }) => r,
      ),
      limits: [
        'Node message ports are a main-thread isolation check, not browser or phone timing.',
        'Heartbeat includes sender frame generation, callbacks, worker startup and scheduler delays.',
        'Host CPU load and thermal state are not isolated.',
        'Caller enqueue time excludes fountain computation; worker processing and round-trip counters retain that work.',
      ],
    },
    null,
    2,
  ) + '\n',
);
