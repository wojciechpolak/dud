// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';

import {
  HIGH_DENSITY_BLOCK_SIZE,
  OpticalDecoder,
  OpticalEncoder,
  selectBlocks,
} from './.work/receiver/codec.js';

const stride = Number(process.argv[2] ?? 9);
if (!Number.isInteger(stride) || stride < 1 || stride > 9) {
  throw new RangeError('initial-frame stride must be an integer from 1 to 9');
}

const capsule = Uint8Array.from(
  { length: 16 * 1024 * 1024 },
  (_, index) => (Math.imul(index, 73) + Math.imul(index >>> 8, 19) + 41) & 0xff,
);
const sessionId = new Uint8Array(16);
const encoder = await OpticalEncoder.create(
  capsule,
  sessionId,
  HIGH_DENSITY_BLOCK_SIZE,
);
const decoder = new OpticalDecoder();
const addDurations = [];
const completionDurations = [];
let progress;

for (let stripe = 0; stripe < encoder.stripeCount; stripe++) {
  progress = undefined;
  const sourceCount = encoder.getSourceCount(stripe);
  const repairCount = Math.ceil(sourceCount / 4);
  const cycleLength = sourceCount + repairCount;
  const add = (sequence) => {
    const frame = encoder.frame(stripe, sequence);
    const started = performance.now();
    progress = decoder.add(frame);
    const milliseconds = performance.now() - started;
    addDurations.push(milliseconds);
    if (progress.independentRows === sourceCount) {
      completionDurations.push({ stripe, milliseconds });
    }
  };

  for (let position = 0; position < cycleLength; position++) {
    const repairsBefore = Math.floor((position * repairCount) / cycleLength);
    const repairsThrough = Math.floor(
      ((position + 1) * repairCount) / cycleLength,
    );
    const sequence =
      repairsThrough > repairsBefore
        ? sourceCount + repairsThrough - 1
        : position - repairsBefore;
    if (position % stride === 0 && progress?.independentRows !== sourceCount) {
      add(sequence);
    }
  }

  let sequence = sourceCount + repairCount;
  let repairAttempts = 0;
  while (progress.independentRows < sourceCount && repairAttempts < 2000) {
    if (
      selectBlocks(sessionId, stripe, sequence, sourceCount).length ===
      Math.min(31, sourceCount)
    ) {
      add(sequence);
      repairAttempts++;
    }
    sequence++;
  }
  assert.equal(progress.independentRows, sourceCount, `stripe ${stripe}`);
}

assert.ok(decoder.complete);
assert.deepEqual(await decoder.result(), capsule);
addDurations.sort((a, b) => a - b);
const percentile = (fraction) =>
  addDurations[Math.floor((addDurations.length - 1) * fraction)];

console.log(
  JSON.stringify(
    {
      sourceBytes: capsule.byteLength,
      sourceBlockBytes: HIGH_DENSITY_BLOCK_SIZE,
      initialFrameStride: stride,
      decodedFrames: addDurations.length,
      countedWorkBytes: progress.workBytes,
      totalDecoderAddMilliseconds: addDurations.reduce(
        (sum, duration) => sum + duration,
        0,
      ),
      medianDecoderAddMilliseconds: percentile(0.5),
      p99DecoderAddMilliseconds: percentile(0.99),
      maximumDecoderAddMilliseconds: addDurations.at(-1),
      stripeCompletionAddMilliseconds: completionDurations,
    },
    null,
    2,
  ),
);
