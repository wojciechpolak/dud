// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { CaptureLifecycle } from '../.work/receiver/lifecycle.js';
import { watchCaptureInterruptions } from '../.work/receiver/capture-interruptions.js';
import {
  captureProfile,
  DEFAULT_CAPTURE_PROFILE,
} from '../.work/receiver/capture-profile.js';
import {
  CapsuleReceipt,
  ENCRYPTED_CAPSULE_FILENAME,
} from '../.work/receiver/capsule-receipt.js';
import {
  BLOCK_SIZE,
  MAX_STRIPE_SIZE,
  OpticalEncoder,
  recomputeCrc,
} from '../.work/receiver/codec.js';
import {
  MAX_PIPELINE_FRAMES,
  MAX_TRANSFER_MILLISECONDS,
  OpticalFramePipeline,
} from '../.work/receiver/pipeline.js';
import { PresentationCadence } from '../.work/receiver/presentation-cadence.js';
import {
  MAX_SCAN_DIMENSION,
  scanRegion,
} from '../.work/receiver/scan-region.js';
import {
  decodeReplayPNG,
  MAX_REPLAY_IMAGE_PIXELS,
  MAX_REPLAY_IMAGE_SIDE,
  MAX_REPLAY_PNG_BYTES,
  validateReplayPNGHeader,
} from '../.work/receiver/replay-image.js';
import {
  CAMERA_SCAN_FPS,
  ScanCadence,
} from '../.work/receiver/scan-cadence.js';
import { playSyntheticVideo } from '../.work/receiver/synthetic-video.js';
import {
  ReceiverTimingMeter,
  STALL_THRESHOLD_MILLISECONDS,
} from '../.work/receiver/timing-metrics.js';
import {
  mergeTrackedRegions,
  trackedRegion,
  translatedPoints,
} from '../.work/receiver/tracked-regions.js';
import {
  recommendedQRWorkerCount,
  recordDecodedImage,
} from '../.work/receiver/worker-pool.js';

const vectors = JSON.parse(
  readFileSync(
    new URL(
      '../../../client/optical-sender/testdata/format1/go-vectors.json',
      import.meta.url,
    ),
    'utf8',
  ),
);

function bytes(hex) {
  return Uint8Array.from({ length: hex.length / 2 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}

function vectorCapsule(length) {
  return Uint8Array.from(
    { length },
    (_, index) =>
      (Math.imul(index, 73) + Math.imul(index >>> 8, 19) + 41) & 0xff,
  );
}

function callbacks(overrides = {}) {
  return {
    onProgress() {},
    onComplete() {},
    onSessionChange() {},
    onUnsupported() {},
    onRejected() {},
    onFatal() {},
    ...overrides,
  };
}

function pngHeader(width, height) {
  const header = new Uint8Array(24);
  header.set([137, 80, 78, 71, 13, 10, 26, 10]);
  const view = new DataView(header.buffer);
  view.setUint32(8, 13);
  header.set([73, 72, 68, 82], 12);
  view.setUint32(16, width);
  view.setUint32(20, height);
  return header;
}

function bitmap(width, height) {
  return {
    width,
    height,
    closed: false,
    close() {
      this.closed = true;
    },
  };
}

test('camera scan uses the visible center square with a bounded pixel count', () => {
  assert.equal(MAX_SCAN_DIMENSION, 960);
  assert.deepEqual(scanRegion(1920, 1080), {
    sourceX: 420,
    sourceY: 0,
    sourceSize: 1080,
    scanSize: 960,
  });
  assert.deepEqual(scanRegion(1080, 1920), {
    sourceX: 0,
    sourceY: 420,
    sourceSize: 1080,
    scanSize: 960,
  });
  assert.deepEqual(scanRegion(640, 480), {
    sourceX: 80,
    sourceY: 0,
    sourceSize: 480,
    scanSize: 480,
  });
  assert.throws(() => scanRegion(0, 1080), RangeError);
});

test('recorded PNG validation bounds encoded and decoded input before decode', () => {
  assert.equal(MAX_REPLAY_IMAGE_SIDE, 6688);
  assert.equal(MAX_REPLAY_IMAGE_PIXELS, 44_729_344);
  assert.deepEqual(
    validateReplayPNGHeader(
      pngHeader(MAX_REPLAY_IMAGE_SIDE, MAX_REPLAY_IMAGE_SIDE),
      MAX_REPLAY_PNG_BYTES,
    ),
    { width: MAX_REPLAY_IMAGE_SIDE, height: MAX_REPLAY_IMAGE_SIDE },
  );
  assert.throws(
    () => validateReplayPNGHeader(pngHeader(MAX_REPLAY_IMAGE_SIDE + 1, 1), 24),
    /decoded pixel limit/,
  );
  assert.throws(
    () => validateReplayPNGHeader(pngHeader(1, 1), MAX_REPLAY_PNG_BYTES + 1),
    /encoded byte limit/,
  );
  assert.throws(
    () => validateReplayPNGHeader(new Uint8Array(24), 24),
    /not a PNG/,
  );
  const nonIHDR = pngHeader(1, 1);
  nonIHDR.set([73, 68, 65, 84], 12);
  assert.throws(
    () => validateReplayPNGHeader(nonIHDR, 24),
    /does not begin with IHDR/,
  );
  assert.throws(
    () => validateReplayPNGHeader(pngHeader(0, 1), 24),
    /dimensions must be positive/,
  );
});

test('recorded PNG encoded limit rejects before reading or decoding', async () => {
  let sliced = false;
  let decoded = false;
  const oversized = {
    size: MAX_REPLAY_PNG_BYTES + 1,
    slice() {
      sliced = true;
      return new Blob();
    },
  };
  await assert.rejects(
    decodeReplayPNG(oversized, async () => {
      decoded = true;
      return bitmap(1, 1);
    }),
    /encoded byte limit/,
  );
  assert.equal(sliced, false);
  assert.equal(decoded, false);
});

test('recorded PNG decode crops and resizes before returning a bitmap', async () => {
  const source = new Blob([pngHeader(4096, 4096)]);
  let call;
  const decoded = bitmap(960, 960);
  const result = await decodeReplayPNG(source, async (...args) => {
    call = args;
    return decoded;
  });
  assert.equal(result, decoded);
  assert.equal(decoded.closed, false);
  assert.deepEqual(call.slice(1, 5), [0, 0, 4096, 4096]);
  assert.deepEqual(call[5], {
    resizeWidth: 960,
    resizeHeight: 960,
    resizeQuality: 'low',
  });
});

test('recorded PNG decode closes a decoder result outside its bound', async () => {
  const source = new Blob([pngHeader(1920, 1080)]);
  const decoded = bitmap(961, 960);
  await assert.rejects(
    decodeReplayPNG(source, async () => decoded),
    /decoder exceeded its pixel limit/,
  );
  assert.equal(decoded.closed, true);
});

test('camera scan cadence selects every frame from a thirty FPS source', () => {
  assert.equal(CAMERA_SCAN_FPS, 30);
  const cadence = new ScanCadence();
  const cameraFrameTimestamps = Array.from(
    { length: 31 },
    (_, index) => (index * 1000) / 30,
  );
  const selected = cameraFrameTimestamps.filter((timestamp) =>
    cadence.shouldScan(timestamp),
  );

  assert.equal(selected.length, 31);
  assert.deepEqual(
    selected.map((timestamp) => Math.round(timestamp)),
    Array.from({ length: 31 }, (_, index) => Math.round((index * 1000) / 30)),
  );
});

test('capture profiles use tracked high-rate scanning by default', () => {
  assert.deepEqual(DEFAULT_CAPTURE_PROFILE, {
    id: 'tracked-60',
    framesPerSecond: 60,
    scanMode: 'tracked-four',
  });
  assert.deepEqual(captureProfile('balanced'), {
    id: 'balanced',
    framesPerSecond: 30,
    scanMode: 'full-frame',
  });
  assert.equal(captureProfile('unknown'), DEFAULT_CAPTURE_PROFILE);
});

test('tracked QR regions are padded, bounded, and translated', () => {
  const region = trackedRegion(
    [
      { x: 4, y: 8 },
      { x: 104, y: 8 },
      { x: 104, y: 108 },
      { x: 4, y: 108 },
    ],
    960,
    960,
  );
  assert.deepEqual(region, { x: 0, y: 0, width: 120, height: 124 });
  assert.deepEqual(translatedPoints([{ x: 3, y: 7 }], region), [
    { x: 3, y: 7 },
  ]);
  assert.equal(trackedRegion([], 960, 960), undefined);
});

test('tracked QR regions accumulate across partial full-frame scans', () => {
  const topLeft = { x: 80, y: 80, width: 300, height: 300 };
  const topRight = { x: 580, y: 80, width: 300, height: 300 };
  const bottomLeft = { x: 80, y: 580, width: 300, height: 300 };
  const bottomRight = { x: 580, y: 580, width: 300, height: 300 };
  const first = mergeTrackedRegions([], [topLeft, bottomRight], 960, 960);
  assert.deepEqual(first, [topLeft, bottomRight]);

  const complete = mergeTrackedRegions(first, [topRight, bottomLeft], 960, 960);
  assert.deepEqual(complete, [topLeft, topRight, bottomLeft, bottomRight]);

  const refreshedTopLeft = { x: 84, y: 82, width: 302, height: 298 };
  assert.deepEqual(
    mergeTrackedRegions(complete, [refreshedTopLeft], 960, 960),
    [refreshedTopLeft, topRight, bottomLeft, bottomRight],
  );
  assert.deepEqual(mergeTrackedRegions(complete, [], 960, 960), complete);
  assert.deepEqual(mergeTrackedRegions(complete, [], 0, 960), []);
});

test('camera scan cadence catches up once after a delayed callback', () => {
  const cadence = new ScanCadence();
  assert.equal(cadence.shouldScan(0), true);
  assert.equal(cadence.shouldScan(17), false);
  assert.equal(cadence.shouldScan(500), true);
  assert.equal(cadence.shouldScan(501), false);
  assert.throws(() => cadence.shouldScan(Number.NaN), RangeError);
  assert.throws(() => new ScanCadence(0), RangeError);
});

test('display cadence keeps the latest progress and flushes completion', () => {
  const rendered = [];
  const display = new PresentationCadence(100, (value) => {
    rendered.push(value);
  });
  display.offer(1, 0);
  display.offer(2, 40);
  display.offer(3, 99);
  assert.deepEqual(rendered, [1]);
  display.offer(4, 100);
  assert.deepEqual(rendered, [1, 4]);
  display.offer(5, 150);
  display.flush();
  assert.deepEqual(rendered, [1, 4, 5]);
  display.reset();
  display.offer(6, 151);
  assert.deepEqual(rendered, [1, 4, 5, 6]);
  assert.throws(() => display.offer(7, Number.NaN), RangeError);
});

test('display cadence retains every stripe completion in one interval and renders latest totals last', () => {
  const rows = new Map();
  const updates = [];
  const display = new PresentationCadence(
    100,
    (value) => {
      rows.set(value.stripeIndex, value);
      updates.push(value);
    },
    (value) => value.stripeIndex,
  );
  const counts = [1024, 1024, 1024, 1024, 1024, 747];
  const observedPartialRows = [1016, 1014, 1024, 1024, 1024, 729];
  let total = 0;
  // Partial rows reproduce the submitted screenshot before a burst of final
  // updates for different stripes shares one presentation interval.
  for (let index = 0; index < counts.length; index++) {
    display.offer(
      {
        stripeIndex: index,
        independentRows: observedPartialRows[index],
        sourceCount: counts[index],
        usefulFrames: total,
      },
      index * 100,
    );
  }
  for (const index of [0, 1, 3, 4, 5, 2]) {
    total += counts[index];
    display.offer(
      {
        stripeIndex: index,
        independentRows: counts[index],
        sourceCount: counts[index],
        usefulFrames: total,
      },
      510,
    );
  }
  assert.ok(
    [...rows.values()].some(
      (value) => value.independentRows < value.sourceCount,
    ),
  );
  display.flush();
  assert.equal(rows.size, 6);
  for (const value of rows.values()) {
    assert.equal(value.independentRows, value.sourceCount);
  }
  assert.equal(updates.at(-1).usefulFrames, 5867);
  assert.equal(updates.at(-1).stripeIndex, 2);
  display.flush();
  assert.equal(updates.length, 12);
});

test('verified multi-stripe pipeline completion flushes every pending stripe without manufacturing progress', async () => {
  const capsule = vectorCapsule(MAX_STRIPE_SIZE + BLOCK_SIZE);
  const encoder = await OpticalEncoder.create(capsule, new Uint8Array(16));
  const rows = new Map();
  const display = new PresentationCadence(
    100,
    (value) => rows.set(value.stripeIndex, value),
    (value) => value.stripeIndex,
  );
  let finish;
  const finished = new Promise((resolve) => {
    finish = resolve;
  });
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onProgress(value) {
        display.offer(value, 0);
      },
      onComplete(value) {
        display.flush();
        finish(value);
      },
      onFatal(message) {
        assert.fail(message);
      },
    }),
  );
  for (let stripe = 0; stripe < 2; stripe++) {
    for (
      let sequence = 0;
      sequence < encoder.getSourceCount(stripe);
      sequence++
    ) {
      pipeline.accept(encoder.frame(stripe, sequence));
    }
  }
  const completion = await finished;
  assert.deepEqual(completion.capsule, capsule);
  assert.equal(completion.usefulFrames, 1025);
  assert.equal(rows.size, 2);
  for (const row of rows.values()) {
    assert.equal(row.independentRows, row.sourceCount);
  }
  pipeline.reset();
});

test('keyed display cadence coalesces a stripe without regressing totals and clears all keys on reset', () => {
  const rendered = [];
  const display = new PresentationCadence(
    100,
    (value) => rendered.push(value),
    (value) => value.stripeIndex,
  );
  display.offer({ stripeIndex: 0, usefulFrames: 1 }, 0);
  display.offer({ stripeIndex: 0, usefulFrames: 2 }, 1);
  display.offer({ stripeIndex: 1, usefulFrames: 3 }, 2);
  display.offer({ stripeIndex: 0, usefulFrames: 4 }, 3);
  display.flush();
  assert.deepEqual(
    rendered.map((value) => value.usefulFrames),
    [1, 3, 4],
  );
  display.offer({ stripeIndex: 1, usefulFrames: 5 }, 4);
  display.offer({ stripeIndex: 2, usefulFrames: 6 }, 5);
  display.reset();
  display.flush();
  display.offer({ stripeIndex: 0, usefulFrames: 1 }, 0);
  assert.deepEqual(
    rendered.map((value) => value.usefulFrames),
    [1, 3, 4, 1],
  );
});

test('decoder statistics distinguish multi-symbol camera images', () => {
  const initial = {
    submitted: 2,
    dropped: 0,
    decodedImages: 0,
    decodedFrames: 0,
    multiSymbolImages: 0,
    maximumSymbolsPerImage: 0,
    decodeMilliseconds: 0,
    maximumDecodeMilliseconds: 0,
    decodesOverThreshold: 0,
    scanDimension: 0,
    fullScans: 0,
    trackedScans: 0,
    trackedSymbols: 0,
  };
  const oneSymbol = recordDecodedImage(initial, 1, 30, 960, {
    fullScans: 1,
    trackedScans: 0,
    trackedSymbols: 0,
  });
  const fourSymbols = recordDecodedImage(oneSymbol, 4, 50, 960, {
    fullScans: 0,
    trackedScans: 4,
    trackedSymbols: 4,
  });

  assert.deepEqual(fourSymbols, {
    submitted: 2,
    dropped: 0,
    decodedImages: 2,
    decodedFrames: 5,
    multiSymbolImages: 1,
    maximumSymbolsPerImage: 4,
    decodeMilliseconds: 80,
    maximumDecodeMilliseconds: 50,
    decodesOverThreshold: 0,
    scanDimension: 960,
    fullScans: 1,
    trackedScans: 4,
    trackedSymbols: 4,
  });
  assert.throws(() => recordDecodedImage(initial, -1, 0, 960), RangeError);
  assert.throws(
    () => recordDecodedImage(initial, 1, Number.NaN, 960),
    RangeError,
  );
  const slowDecode = recordDecodedImage(fourSymbols, 1, 251, 960);
  assert.equal(slowDecode.maximumDecodeMilliseconds, 251);
  assert.equal(slowDecode.decodesOverThreshold, 1);
  const emptyScan = {
    finderChecks: 8192,
    finderCandidates: 0,
    alignmentChecks: 0,
    matrixAttempts: 0,
    exhaustedScans: 1,
  };
  const noSymbols = recordDecodedImage(initial, 0, 75, 960, {
    fullScans: 1,
    trackedScans: 0,
    trackedSymbols: 0,
    scanDiagnostics: emptyScan,
  });
  assert.equal(noSymbols.decodedImages, 1);
  assert.equal(noSymbols.decodedFrames, 0);
  assert.deepEqual(noSymbols.scanDiagnostics, emptyScan);
  const nextScan = recordDecodedImage(noSymbols, 1, 5, 960, {
    fullScans: 1,
    trackedScans: 0,
    trackedSymbols: 0,
    scanDiagnostics: {
      finderChecks: 10,
      finderCandidates: 3,
      alignmentChecks: 2,
      matrixAttempts: 1,
      exhaustedScans: 0,
    },
  });
  assert.deepEqual(nextScan.scanDiagnostics, {
    finderChecks: 8202,
    finderCandidates: 3,
    alignmentChecks: 2,
    matrixAttempts: 1,
    exhaustedScans: 1,
  });
  assert.equal(nextScan.decodedFrames, 1);
  assert.equal(initial.scanDiagnostics, undefined);
});

test('receiver timing counters count long gaps and reset between receipts', () => {
  const meter = new ReceiverTimingMeter();
  meter.cameraCallback(10);
  meter.cameraCallback(10 + STALL_THRESHOLD_MILLISECONDS);
  meter.cameraCallback(11 + STALL_THRESHOLD_MILLISECONDS * 2);
  meter.usefulProgress(20, 1);
  meter.usefulProgress(21 + STALL_THRESHOLD_MILLISECONDS, 2);
  meter.usefulProgress(22 + STALL_THRESHOLD_MILLISECONDS * 2, 2);
  meter.frameHandler(STALL_THRESHOLD_MILLISECONDS);
  meter.frameHandler(STALL_THRESHOLD_MILLISECONDS + 1);

  assert.deepEqual(meter.snapshot(), {
    cameraCallbacks: 3,
    cameraGapsOverThreshold: 1,
    maximumCameraGapMilliseconds: 251,
    usefulGapsOverThreshold: 1,
    maximumUsefulGapMilliseconds: 251,
    frameHandlersOverThreshold: 1,
    maximumFrameHandlerMilliseconds: 251,
  });
  meter.reset();
  assert.deepEqual(meter.snapshot(), {
    cameraCallbacks: 0,
    cameraGapsOverThreshold: 0,
    maximumCameraGapMilliseconds: 0,
    usefulGapsOverThreshold: 0,
    maximumUsefulGapMilliseconds: 0,
    frameHandlersOverThreshold: 0,
    maximumFrameHandlerMilliseconds: 0,
  });
  assert.throws(() => meter.cameraCallback(Number.NaN), RangeError);
});

test('deliberate camera pauses separate timing intervals and keep observation counts', () => {
  const meter = new ReceiverTimingMeter();
  meter.cameraCallback(10);
  meter.cameraCallback(30);
  meter.usefulProgress(20, 1);
  meter.usefulProgress(60, 2);
  meter.breakInterval();
  meter.cameraCallback(60_000);
  meter.usefulProgress(60_010, 3);
  assert.equal(meter.snapshot().cameraCallbacks, 3);
  assert.equal(meter.snapshot().maximumCameraGapMilliseconds, 20);
  assert.equal(meter.snapshot().maximumUsefulGapMilliseconds, 40);
  assert.equal(meter.snapshot().usefulGapsOverThreshold, 0);
  meter.usefulProgress(60_900, 3);
  meter.usefulProgress(61_000, 4);
  assert.equal(meter.snapshot().usefulGapsOverThreshold, 1);
  assert.equal(meter.snapshot().maximumUsefulGapMilliseconds, 990);
});

test('duplicate frames leave progress idle while camera callbacks remain frequent', async () => {
  const encoder = await OpticalEncoder.create(
    vectorCapsule(BLOCK_SIZE + 1),
    new Uint8Array(16),
  );
  const timing = new ReceiverTimingMeter();
  let atMilliseconds = 0;
  let resolveCompletion;
  const completed = new Promise((resolve) => {
    resolveCompletion = resolve;
  });
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onProgress(value) {
        timing.usefulProgress(atMilliseconds, value.usefulFrames);
      },
      onComplete: resolveCompletion,
    }),
    () => atMilliseconds,
  );
  const repeated = encoder.frame(0, 0);
  timing.cameraCallback(0);
  pipeline.accept(repeated);
  for (atMilliseconds = 20; atMilliseconds <= 6200; atMilliseconds += 20) {
    timing.cameraCallback(atMilliseconds);
    if (atMilliseconds % 100 === 0) {
      pipeline.accept(repeated);
    }
  }
  atMilliseconds = 6201;
  timing.cameraCallback(atMilliseconds);
  pipeline.accept(encoder.frame(0, 1));
  const completion = await completed;
  assert.equal(completion.usefulFrames, 2);
  assert.equal(completion.rejectedFrames, 0);
  assert.deepEqual(completion.capsule, vectorCapsule(BLOCK_SIZE + 1));
  assert.equal(timing.snapshot().maximumUsefulGapMilliseconds, 6201);
  assert.equal(timing.snapshot().usefulGapsOverThreshold, 1);
  assert.equal(timing.snapshot().maximumCameraGapMilliseconds, 20);
  assert.equal(timing.snapshot().cameraGapsOverThreshold, 0);
});

test('decoder worker count uses available cores within a fixed bound', () => {
  assert.equal(recommendedQRWorkerCount(Number.NaN), 2);
  assert.equal(recommendedQRWorkerCount(1), 2);
  assert.equal(recommendedQRWorkerCount(3), 3);
  assert.equal(recommendedQRWorkerCount(8), 4);
});

test('camera and synthetic input share one frame-to-capsule pipeline', async () => {
  const completeCase = vectors.cases.find(
    (entry) => entry.name === 'complete-capsule',
  );
  let completion;
  let resolveCompletion;
  const completed = new Promise((resolve) => {
    resolveCompletion = resolve;
  });
  const progress = [];
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onProgress(value) {
        progress.push(value.percent);
      },
      onComplete(value) {
        completion = value;
        resolveCompletion();
      },
    }),
  );
  for (const frame of completeCase.frames) {
    pipeline.accept(bytes(frame.bytes));
  }
  await completed;
  assert.equal(completion.byteLength, completeCase.capsuleLength);
  assert.deepEqual(
    completion.capsule,
    vectorCapsule(completeCase.capsuleLength),
  );
  assert.equal(
    completion.usefulFrames,
    Math.ceil(completeCase.capsuleLength / BLOCK_SIZE),
  );
  assert.ok(progress.every((value) => value >= 0 && value <= 100));
  assert.equal(progress.at(-1), 99.9);
});

test('unsupported format leaves the receiver ready for a valid stream', async () => {
  const completeCase = vectors.cases.find(
    (entry) => entry.name === 'complete-capsule',
  );
  const unsupported = bytes(completeCase.frames[0].bytes);
  unsupported[8] = 0;
  recomputeCrc(unsupported);
  const events = [];
  let resolveCompletion;
  const completed = new Promise((resolve) => {
    resolveCompletion = resolve;
  });
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onUnsupported(message) {
        events.push(message);
      },
      onComplete(value) {
        events.push(value.capsule);
        resolveCompletion();
      },
    }),
  );

  pipeline.accept(unsupported);
  assert.match(events[0], /expected dud\/optical\/1, received format 0/);
  assert.equal(events.length, 1);
  for (const frame of completeCase.frames) {
    pipeline.accept(bytes(frame.bytes));
  }
  await completed;
  assert.deepEqual(events[1], vectorCapsule(completeCase.capsuleLength));
});

test('encrypted capsule receipt saves exact opaque bytes and clears its buffer', async () => {
  const source = Uint8Array.from([0, 255, 65, 71, 69, 0, 23]);
  const expected = new Uint8Array(source);
  const receipt = new CapsuleReceipt();
  assert.equal(receipt.available, false);
  assert.throws(() => receipt.blob(), /no encrypted capsule/);

  receipt.accept(source);
  assert.equal(receipt.available, true);
  const blob = receipt.blob();
  assert.equal(blob.type, 'application/octet-stream');
  assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), expected);
  assert.equal(ENCRYPTED_CAPSULE_FILENAME, 'dud-encrypted-capsule.age');

  receipt.clear();
  assert.equal(receipt.available, false);
  assert.deepEqual(source, new Uint8Array(source.byteLength));
  assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), expected);
});

test('digest failure exposes no encrypted capsule receipt', async () => {
  const completeCase = vectors.cases.find(
    (entry) => entry.name === 'complete-capsule',
  );
  const receipt = new CapsuleReceipt();
  let completions = 0;
  let resolveFailure;
  const failed = new Promise((resolve) => {
    resolveFailure = resolve;
  });
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onComplete(value) {
        completions++;
        receipt.accept(value.capsule);
      },
      onFatal(code) {
        resolveFailure(code);
      },
    }),
  );
  for (const encoded of completeCase.frames) {
    const frame = bytes(encoded.bytes);
    frame[56] ^= 1;
    recomputeCrc(frame);
    pipeline.accept(frame);
  }
  await failed;
  assert.equal(completions, 0);
  assert.equal(receipt.available, false);
});

test('stopping during digest verification cannot complete or fail a stale run', async () => {
  const encoder = await OpticalEncoder.create(
    new Uint8Array(BLOCK_SIZE * 2),
    new Uint8Array(16),
  );
  const events = [];
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onComplete() {
        events.push('complete');
      },
      onFatal() {
        events.push('fatal');
      },
    }),
  );
  pipeline.accept(encoder.frame(0, 0));
  pipeline.accept(encoder.frame(0, 1));
  pipeline.reset();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(events, []);
});

test('pipeline progress and useful-frame count stay global across stripes', async () => {
  const encoder = await OpticalEncoder.create(
    new Uint8Array(MAX_STRIPE_SIZE + BLOCK_SIZE),
    new Uint8Array(16),
  );
  const progress = [];
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onProgress(value) {
        progress.push(value);
      },
    }),
  );
  for (let sequence = 0; sequence < 181; sequence++) {
    pipeline.accept(encoder.frame(0, sequence));
  }
  pipeline.accept(encoder.frame(1, 0));
  pipeline.accept(encoder.frame(0, 0));

  assert.deepEqual(
    progress.map((value) => value.percent),
    progress
      .map((value) => value.percent)
      .toSorted((left, right) => left - right),
  );
  assert.equal(progress.at(-1).usefulFrames, 182);
  assert.equal(progress.at(-1).requiredFrames, 1025);
  assert.equal(progress.at(-1).percent, (182 / 1025) * 100);
});

test('pipeline measures from the first valid frame to the completing frame', async () => {
  const encoder = await OpticalEncoder.create(
    new Uint8Array(BLOCK_SIZE * 2),
    new Uint8Array(16),
  );
  let completion;
  let resolveCompletion;
  const completed = new Promise((resolve) => {
    resolveCompletion = resolve;
  });
  const times = [1000, 3500];
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onComplete(value) {
        completion = value;
        resolveCompletion();
      },
    }),
    () => times.shift(),
  );

  pipeline.accept(encoder.frame(0, 0));
  pipeline.accept(encoder.frame(0, 1));
  await completed;

  assert.equal(completion.elapsedMilliseconds, 2500);
});

test('pipeline reports a sender restart without merging sessions', () => {
  const completeCase = vectors.cases.find(
    (entry) => entry.name === 'complete-capsule',
  );
  const first = bytes(completeCase.frames[0].bytes);
  const restarted = new Uint8Array(first);
  restarted[12] ^= 1;
  recomputeCrc(restarted);
  let changes = 0;
  const pipeline = new OpticalFramePipeline(
    callbacks({
      onSessionChange() {
        changes++;
      },
    }),
  );
  pipeline.accept(first);
  pipeline.accept(restarted);
  assert.equal(changes, 1);
});

test('pipeline stops at total-frame and transfer-time bounds', async () => {
  assert.equal(MAX_PIPELINE_FRAMES, 216_000);
  assert.equal(MAX_TRANSFER_MILLISECONDS, 900_000);
  const encoder = await OpticalEncoder.create(
    new Uint8Array(BLOCK_SIZE * 2),
    new Uint8Array(16),
  );
  const frame = encoder.frame(0, 0);

  const frameFailures = [];
  const framePipeline = new OpticalFramePipeline(
    callbacks({ onFatal: (message) => frameFailures.push(message) }),
    () => 0,
    { maxFrames: 2, maxTransferMilliseconds: 10_000 },
  );
  framePipeline.accept(frame);
  framePipeline.accept(frame);
  framePipeline.accept(frame);
  framePipeline.accept(frame);
  assert.deepEqual(frameFailures, [
    'Frame processing limit 2 reached. Restart the receiver and use one sender stream.',
  ]);

  const timeFailures = [];
  const times = [0, 1001];
  const timePipeline = new OpticalFramePipeline(
    callbacks({ onFatal: (message) => timeFailures.push(message) }),
    () => times.shift(),
    { maxFrames: 10, maxTransferMilliseconds: 1000 },
  );
  timePipeline.accept(frame);
  timePipeline.accept(frame);
  assert.deepEqual(timeFailures, [
    'Transfer time limit 1 second reached. Restart the receiver and sender.',
  ]);
});

test('capture lifecycle releases tracks, workers, and callbacks once', () => {
  const calls = { tracks: 0, workers: 0, cleanups: 0 };
  const lifecycle = new CaptureLifecycle();
  lifecycle.addTrack({ stop: () => calls.tracks++ });
  lifecycle.addWorker({ terminate: () => calls.workers++ });
  lifecycle.addCleanup(() => calls.cleanups++);
  lifecycle.stop();
  lifecycle.stop();
  assert.deepEqual(calls, { tracks: 1, workers: 1, cleanups: 1 });
});

test('capture lifecycle attempts every release after one resource fails', () => {
  const calls = [];
  const lifecycle = new CaptureLifecycle();
  lifecycle.addTrack({
    stop() {
      calls.push('track');
      throw new Error('track failed');
    },
  });
  lifecycle.addWorker({ terminate: () => calls.push('worker') });
  lifecycle.addCleanup(() => calls.push('cleanup'));
  lifecycle.stop();
  assert.deepEqual(calls, ['cleanup', 'track', 'worker']);
});

test('capture interruptions converge on one cleanup path', () => {
  const cases = [
    ['background', 'document', 'visibilitychange'],
    ['suspension', 'page', 'freeze'],
    ['page-exit', 'page', 'pagehide'],
    ['renderer-loss', 'page', 'error'],
    ['renderer-loss', 'page', 'unhandledrejection'],
    ['memory-pressure', 'page', 'memorypressure'],
    ['rotation', 'orientation', 'change'],
    ['camera-change', 'mediaDevices', 'devicechange'],
    ['service-worker-change', 'serviceWorker', 'controllerchange'],
    ['camera-ended', 'track', 'ended'],
    ['camera-muted', 'track', 'mute'],
  ];

  for (const [expected, sourceName, eventName] of cases) {
    const lifecycle = new CaptureLifecycle();
    const sources = {
      page: new EventTarget(),
      document: Object.assign(new EventTarget(), {
        visibilityState: 'visible',
      }),
      orientation: new EventTarget(),
      mediaDevices: new EventTarget(),
      serviceWorker: Object.assign(new EventTarget(), {
        controller: { id: 'active' },
      }),
      track: Object.assign(new EventTarget(), { readyState: 'live' }),
    };
    const reasons = [];
    const watchTracks = watchCaptureInterruptions(
      lifecycle,
      sources,
      (reason) => {
        reasons.push(reason);
        lifecycle.stop();
      },
    );
    watchTracks([sources.track]);
    if (sourceName === 'document') {
      sources.document.visibilityState = 'hidden';
    }
    if (sourceName === 'serviceWorker') {
      sources.serviceWorker.controller = { id: 'replacement' };
    }
    if (sourceName === 'mediaDevices') {
      sources.track.readyState = 'ended';
    }
    sources[sourceName].dispatchEvent(new Event(eventName));
    sources[sourceName].dispatchEvent(new Event(eventName));
    assert.deepEqual(reasons, [expected], expected);
  }
});

test('camera enumeration changes leave a live camera run active', () => {
  const lifecycle = new CaptureLifecycle();
  const mediaDevices = new EventTarget();
  const track = Object.assign(new EventTarget(), { readyState: 'live' });
  const reasons = [];
  const watchTracks = watchCaptureInterruptions(
    lifecycle,
    {
      page: new EventTarget(),
      document: Object.assign(new EventTarget(), {
        visibilityState: 'visible',
      }),
      mediaDevices,
    },
    (reason) => reasons.push(reason),
  );

  mediaDevices.dispatchEvent(new Event('devicechange'));
  watchTracks([track]);
  mediaDevices.dispatchEvent(new Event('devicechange'));
  assert.deepEqual(reasons, []);

  track.readyState = 'ended';
  mediaDevices.dispatchEvent(new Event('devicechange'));
  assert.deepEqual(reasons, ['camera-change']);
  lifecycle.stop();
});

test('initial service worker claim keeps the camera run active', () => {
  const lifecycle = new CaptureLifecycle();
  const serviceWorker = Object.assign(new EventTarget(), {
    controller: null,
  });
  const reasons = [];
  watchCaptureInterruptions(
    lifecycle,
    {
      page: new EventTarget(),
      document: Object.assign(new EventTarget(), {
        visibilityState: 'visible',
      }),
      serviceWorker,
    },
    (reason) => reasons.push(reason),
  );

  const firstController = { id: 'first' };
  serviceWorker.controller = firstController;
  serviceWorker.dispatchEvent(new Event('controllerchange'));
  assert.deepEqual(reasons, []);

  serviceWorker.dispatchEvent(new Event('controllerchange'));
  assert.deepEqual(reasons, []);

  serviceWorker.controller = { id: 'replacement' };
  serviceWorker.dispatchEvent(new Event('controllerchange'));
  assert.deepEqual(reasons, ['service-worker-change']);
  lifecycle.stop();
});

test('synthetic video obeys the same bounded drop policy', async () => {
  async function* frames() {
    for (let index = 0; index < 8; index++) {
      yield index;
    }
  }
  const accepted = [];
  const result = await playSyntheticVideo(
    frames(),
    {
      submit(frame) {
        if (frame % 3 === 0) {
          return false;
        }
        accepted.push(frame);
        return true;
      },
    },
    new AbortController().signal,
    async () => {},
  );
  assert.deepEqual(accepted, [1, 2, 4, 5, 7]);
  assert.deepEqual(result, { submitted: 5, dropped: 3 });
});

test('synthetic video releases an image delivered after cancellation', async () => {
  const controller = new AbortController();
  const frame = { id: 1 };
  const discarded = [];
  async function* frames() {
    controller.abort();
    yield frame;
  }
  const result = await playSyntheticVideo(
    frames(),
    {
      submit() {
        assert.fail('cancelled frame reached the decoder');
      },
      discard(value) {
        discarded.push(value);
      },
    },
    controller.signal,
  );
  assert.deepEqual(discarded, [frame]);
  assert.deepEqual(result, { submitted: 0, dropped: 0 });
});
