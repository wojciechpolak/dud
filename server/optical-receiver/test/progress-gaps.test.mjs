// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BLOCK_SIZE,
  MAX_STRIPE_SIZE,
  OpticalEncoder,
  selectBlocks,
} from '../.work/receiver/codec.js';
import { OpticalFramePipeline } from '../.work/receiver/pipeline.js';
import {
  ProgressGapMeter,
  MAX_RECORDED_PROGRESS_GAPS,
  formatProgressGaps,
} from '../.work/receiver/progress-gaps.js';
import { CaptureLifecycle } from '../.work/receiver/lifecycle.js';
import { QRWorkerPool } from '../.work/receiver/worker-pool.js';

for (const mode of ['empty', 'repeated', 'dependent']) {
  test(`progress gap observations distinguish ${mode} input before exact recovery`, async () => {
    const capsule = Uint8Array.from(
      { length: BLOCK_SIZE * 8 },
      (_, index) => index % 251,
    );
    const session = new Uint8Array(16);
    const encoder = await OpticalEncoder.create(capsule, session);
    const meter = new ProgressGapMeter();
    let now = 0;
    let complete;
    const completion = new Promise((resolve) => {
      complete = resolve;
    });
    const pipeline = new OpticalFramePipeline(
      {
        onFrameDisposition: (value) => meter.count(value),
        onProgress: (value) => {
          meter.usefulProgress(now, value.usefulFrames);
          if (value.usefulFrames === value.requiredFrames) {
            meter.finish();
          }
        },
        onComplete: complete,
        onFatal: assert.fail,
        onRejected: assert.fail,
        onUnsupported: assert.fail,
        onSessionChange: assert.fail,
      },
      () => now,
    );
    const image = (frames) => {
      meter.image({
        symbolCount: frames.length,
        decodeMilliseconds: 8,
        roundTripMilliseconds: 12,
      });
      for (const frame of frames) {
        pipeline.accept(frame);
      }
    };
    for (let index = 0; index < 7; index++) {
      image([encoder.frame(0, index)]);
    }
    let sequence = 8;
    for (now = 20; now <= 6200; now += 20) {
      meter.count('cameraCallbacks');
      if (now % 100 !== 0) {
        continue;
      }
      let frames = [];
      if (mode === 'repeated') {
        frames = [encoder.frame(0, 0)];
      }
      if (mode === 'dependent') {
        while (selectBlocks(session, 0, sequence, 8).includes(7)) {
          sequence++;
        }
        frames = [encoder.frame(0, sequence++)];
      }
      image(frames);
    }
    now = 6201;
    meter.count('cameraCallbacks');
    image([encoder.frame(0, 7)]);
    const result = await completion;
    assert.deepEqual(result.capsule, capsule);
    assert.equal(result.rejectedFrames, 0);
    const snapshot = meter.snapshot(now + 5000);
    assert.equal(
      snapshot.ongoingGap,
      undefined,
      'verification time is outside recovery gaps',
    );
    assert.equal(snapshot.gaps.length, 1);
    const gap = snapshot.gaps[0];
    assert.equal(gap.durationMilliseconds, 6201);
    assert.equal(gap.startOffsetMilliseconds, 0);
    assert.equal(gap.activity.decodedImages, 63);
    assert.equal(gap.activity.emptyImages, mode === 'empty' ? 62 : 0);
    assert.equal(gap.activity.repeated, mode === 'repeated' ? 62 : 0);
    assert.equal(gap.activity.dependent, mode === 'dependent' ? 62 : 0);
    assert.equal(gap.activity.qrSymbols, mode === 'empty' ? 1 : 63);
    assert.equal(gap.activity.maximumWorkerRoundTripMilliseconds, 12);
    assert.equal(snapshot.totals.useful, 8);
    assert.match(formatProgressGaps(snapshot), /Longest observed gap 6.2 s/);
    assert.ok(
      Object.values(gap.activity).every((value) => typeof value === 'number'),
    );
  });
}

test('frame observations separate other streams, invalid frames, and completed stripes', async () => {
  const encoder = await OpticalEncoder.create(
    new Uint8Array(MAX_STRIPE_SIZE + 1),
    new Uint8Array(16),
  );
  const other = await OpticalEncoder.create(
    new Uint8Array(MAX_STRIPE_SIZE + 1),
    new Uint8Array(16).fill(1),
  );
  const dispositions = [];
  const pipeline = new OpticalFramePipeline({
    onFrameDisposition: (value) => dispositions.push(value),
    onProgress() {},
    onComplete() {},
    onSessionChange() {},
    onUnsupported() {},
    onRejected() {},
    onFatal: assert.fail,
  });
  pipeline.accept(new Uint8Array(0));
  pipeline.accept(new Uint8Array(100));
  for (let index = 0; index < 1024; index++) {
    pipeline.accept(encoder.frame(0, index));
  }
  assert.ok(dispositions.slice(2).every((value) => value === 'useful'));
  pipeline.accept(encoder.frame(0, 0));
  pipeline.accept(encoder.frame(0, 1024));
  pipeline.accept(other.frame(0, 0));
  assert.deepEqual(dispositions.slice(0, 2), ['rejected', 'unsupported']);
  assert.deepEqual(dispositions.slice(-3), [
    'repeated',
    'completed-stripe',
    'other-session',
  ]);
  pipeline.reset();
  pipeline.accept(encoder.frame(0, 0));
  assert.equal(dispositions.at(-1), 'useful');
  pipeline.reset();
});

test('gap recording excludes intervals of 250 ms and includes an unfinished interval', () => {
  const meter = new ProgressGapMeter();
  meter.usefulProgress(100, 1);
  meter.usefulProgress(350, 2);
  assert.deepEqual(meter.snapshot(350).gaps, []);
  meter.count('repeated');
  assert.equal(meter.snapshot(600).ongoingGap.activity.repeated, 1);
  meter.usefulProgress(601, 3);
  assert.equal(meter.snapshot(601).gaps[0].durationMilliseconds, 251);
  assert.equal(meter.snapshot(601).gaps[0].startOffsetMilliseconds, 250);
});

test('gap records keep the longest bounded observations and isolate snapshots and runs', () => {
  const meter = new ProgressGapMeter();
  meter.usefulProgress(0, 1);
  let now = 0;
  for (let index = 1; index <= MAX_RECORDED_PROGRESS_GAPS + 10; index++) {
    now += 250 + index;
    meter.count('busyDrops');
    meter.bitmap(index);
    meter.usefulProgress(now, index + 1);
  }
  const snapshot = meter.snapshot(now + 6201);
  assert.equal(snapshot.gaps.length, MAX_RECORDED_PROGRESS_GAPS);
  assert.equal(
    snapshot.completedGapsOverThreshold,
    MAX_RECORDED_PROGRESS_GAPS + 10,
  );
  assert.equal(snapshot.omittedGaps, 10);
  assert.equal(snapshot.gaps[0].durationMilliseconds, 261);
  assert.equal(snapshot.ongoingGap.durationMilliseconds, 6201);
  assert.equal(snapshot.ongoingGap.activity.busyDrops, 0);
  snapshot.gaps[0].activity.busyDrops = 999;
  snapshot.totals.busyDrops = 999;
  assert.equal(meter.snapshot(now).gaps[0].activity.busyDrops, 1);
  meter.reset();
  const clean = meter.snapshot(now);
  assert.equal(clean.usefulFrames, 0);
  assert.equal(clean.completedGapsOverThreshold, 0);
  assert.equal(clean.omittedGaps, 0);
  assert.equal(clean.ongoingGap, undefined);
  assert.deepEqual(clean.gaps, []);
  assert.ok(Object.values(clean.totals).every((value) => value === 0));
});

test('worker observations measure empty replies and delayed delivery before frame callbacks', async (t) => {
  const workers = [];
  class FakeWorker extends EventTarget {
    constructor() {
      super();
      workers.push(this);
    }
    postMessage() {}
    terminate() {}
    reply(data) {
      this.dispatchEvent(new MessageEvent('message', { data }));
    }
  }
  const original = globalThis.Worker;
  globalThis.Worker = FakeWorker;
  t.after(() => {
    globalThis.Worker = original;
  });
  const lifecycle = new CaptureLifecycle();
  t.after(() => lifecycle.stop());
  let now = 0;
  const observations = [];
  const pool = new QRWorkerPool(
    1,
    lifecycle,
    {
      onImage: (image) => observations.push(image),
      onStats() {},
      onFrame: () => observations.push('frame'),
      onError: assert.fail,
    },
    'tracked-four',
    () => now,
  );
  workers[0].reply({ type: 'ready' });
  await pool.ready;
  assert.deepEqual(observations, []);
  pool.submit({ close() {} });
  now = 6201;
  workers[0].reply({ type: 'result', frames: [], decodeMilliseconds: 12 });
  assert.deepEqual(observations, [
    { symbolCount: 0, decodeMilliseconds: 12, roundTripMilliseconds: 6201 },
  ]);
  pool.submit({ close() {} });
  now += 20;
  workers[0].reply({
    type: 'result',
    frames: [new ArrayBuffer(1)],
    decodeMilliseconds: 8,
  });
  assert.deepEqual(observations.slice(1), [
    { symbolCount: 1, decodeMilliseconds: 8, roundTripMilliseconds: 20 },
    'frame',
  ]);
});
