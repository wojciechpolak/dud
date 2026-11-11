// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';
import { FountainFramePipeline } from '../.work/receiver/fountain-client.js';
import {
  MAX_FOUNTAIN_PENDING_FRAMES,
  MAX_FOUNTAIN_FRAME_BYTES,
} from '../.work/receiver/fountain-messages.js';
import { OpticalEncoder, recomputeCrc } from '../.work/receiver/codec.js';
import { createFountainNodeWorker } from '../fountain-node-worker.mjs';

function callbacks(events) {
  return {
    onFrameDisposition: (v) => events.push(['disposition', v]),
    onProgress: (v) => events.push(['progress', v]),
    onComplete: (v) => events.push(['complete', v]),
    onSessionChange: () => events.push(['session']),
    onUnsupported: (v) => events.push(['unsupported', v]),
    onRejected: (v) => events.push(['rejected', v]),
    onFatal: (v) => events.push(['fatal', v]),
  };
}

function mockHarness() {
  const workers = [];
  const events = [];
  const client = new FountainFramePipeline(
    callbacks(events),
    () => {
      const listeners = new Map();
      const worker = {
        messages: [],
        terminated: false,
        addEventListener(type, handler) {
          listeners.set(type, handler);
        },
        postMessage(data, transfer) {
          this.messages.push(structuredClone(data, { transfer }));
        },
        terminate() {
          this.terminated = true;
        },
        emit(data) {
          listeners.get('message')({ data });
        },
        error() {
          listeners.get('error')();
        },
      };
      workers.push(worker);
      return worker;
    },
    () => 100,
  );
  return { client, workers, events };
}

test('fountain client transfers owned frames and copies only subarray bounds', () => {
  const { client, workers } = mockHarness();
  const owned = Uint8Array.of(1, 2, 3);
  client.accept(owned);
  assert.equal(owned.byteLength, 0);
  const backing = Uint8Array.of(9, 8, 7, 6, 5);
  client.accept(backing.subarray(1, 4));
  assert.deepEqual(backing, Uint8Array.of(9, 8, 7, 6, 5));
  assert.deepEqual(
    new Uint8Array(workers[0].messages[1].frame),
    Uint8Array.of(8, 7, 6),
  );
  client.reset();
  assert.ok(workers[0].terminated);
});

test('fountain acknowledgement restores headroom and the frame queue has a hard ceiling', () => {
  const { client, workers, events } = mockHarness();
  for (let i = 0; i < 17; i++) {
    client.accept(Uint8Array.of(i));
  }
  assert.equal(client.canAccept, false);
  workers[0].emit({
    type: 'processed',
    id: 0,
    disposition: 'repeated',
    processingMilliseconds: 4,
  });
  assert.equal(client.canAccept, true);
  assert.equal(client.snapshot().processedFrames, 1);
  for (let i = 16; i < MAX_FOUNTAIN_PENDING_FRAMES; i++) {
    client.accept(Uint8Array.of(i));
  }
  assert.equal(client.snapshot().pendingFrames, 32);
  client.accept(Uint8Array.of(1));
  assert.equal(events.at(-1)[0], 'fatal');
  assert.ok(workers[0].terminated);
  assert.equal(client.snapshot().pendingFrames, 0);
  assert.equal(workers[0].messages.length, 33);
});

test('fountain input bounds reject before allocating a worker or copying a payload', () => {
  const { client, workers, events } = mockHarness();
  client.accept(new Uint8Array(MAX_FOUNTAIN_FRAME_BYTES + 1));
  assert.equal(workers.length, 0);
  assert.equal(events.at(-1)[0], 'fatal');
});

test('reset ignores stale worker replies and clears stale completion bytes', () => {
  const { client, workers, events } = mockHarness();
  client.accept(Uint8Array.of(1));
  const old = workers[0];
  client.reset();
  client.accept(Uint8Array.of(2));
  old.emit({
    type: 'processed',
    id: 0,
    disposition: 'useful',
    progress: {},
    processingMilliseconds: 1,
  });
  const capsule = Uint8Array.of(1, 2, 3);
  old.emit({ type: 'complete', capsule: capsule.buffer, completion: {} });
  assert.equal(events.length, 0);
  assert.deepEqual(capsule, new Uint8Array(3));
  assert.equal(client.snapshot().pendingFrames, 1);
  client.reset();
});

test('worker exceptions stop a bounded fountain session once', () => {
  const { client, workers, events } = mockHarness();
  client.accept(Uint8Array.of(1));
  workers[0].error();
  workers[0].error();
  assert.equal(events.filter((v) => v[0] === 'fatal').length, 1);
  assert.equal(client.canAccept, false);
  client.reset();
  assert.equal(client.canAccept, true);
});

async function realRun(capsule, mutate = (frame) => frame, timestamps) {
  const encoder = await OpticalEncoder.create(
    capsule,
    new Uint8Array(16),
    1600,
  );
  const frames = Array.from({ length: encoder.getSourceCount(0) }, (_, i) =>
    mutate(encoder.frame(0, i)),
  );
  let client;
  let next = 0;
  const events = [];
  let done;
  const completed = new Promise((resolve) => {
    done = resolve;
  });
  const timeout = setTimeout(() => done({ timeout: true }), 10000);
  const pump = () => {
    while (next < frames.length && client.canAccept) {
      client.accept(frames[next++]);
    }
  };
  client = new FountainFramePipeline(
    {
      ...callbacks(events),
      onProgress: (p) => {
        events.push(['progress', p]);
        pump();
      },
      onComplete: (v) => done({ completion: v }),
      onFatal: (message) => done({ fatal: message }),
    },
    createFountainNodeWorker,
    timestamps ?? (() => performance.now()),
  );
  try {
    pump();
    const result = await completed;
    assert.equal(result.timeout, undefined);
    return { ...result, events, stats: client.snapshot() };
  } finally {
    clearTimeout(timeout);
    client.reset();
  }
}

test('shipped fountain worker returns exact opaque binary bytes through transfer lists', async () => {
  const capsule = Uint8Array.from({ length: 100000 }, (_, i) => (i * 73) & 255);
  const result = await realRun(capsule);
  assert.deepEqual(result.completion.capsule, capsule);
  assert.equal(
    result.completion.usefulFrames,
    Math.ceil(capsule.length / 1600),
  );
  assert.ok(result.stats.maximumPendingFrames <= 32);
  assert.ok(result.stats.maximumProcessingMilliseconds > 0);
});

test('asynchronous digest failure in the shipped worker exposes no completion', async () => {
  const capsule = new Uint8Array(3200);
  const result = await realRun(capsule, (frame) => {
    frame[56] ^= 1;
    recomputeCrc(frame);
    return frame;
  });
  assert.match(result.fatal, /digest/);
  assert.equal(result.completion, undefined);
});

test('fountain worker uses arrival timestamps for the transfer deadline', async () => {
  let i = 0;
  const result = await realRun(new Uint8Array(3200), undefined, () =>
    i++ === 0 ? 10 : 1000000,
  );
  assert.match(result.fatal, /Transfer time limit/);
  assert.equal(result.completion, undefined);
  assert.deepEqual(
    result.events
      .filter(([type]) => type === 'disposition')
      .map(([_type, value]) => value),
    ['useful', 'rejected'],
  );
});
