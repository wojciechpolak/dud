// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// fallow-ignore-next-line unresolved-import -- The isolated benchmark serves compiled receiver modules beside this script.
import { OpticalEncoder, selectBlocks } from './codec.js';

let encoder;
let stripe = 0;
let sequence = 0;
let count = 0;
let exhausted = false;
async function prepare(data) {
  const source = data.input
    ? new Uint8Array(await (await fetch('./input.age')).arrayBuffer())
    : Uint8Array.from(
        { length: data.bytes },
        (_, i) => (Math.imul(i, 73) + Math.imul(i >>> 8, 19) + 41) & 255,
      );
  encoder = await OpticalEncoder.create(
    source,
    new Uint8Array(16),
    data.blockSize,
  );
  count = encoder.getSourceCount(0);
  const sha256 = Array.from(
    new Uint8Array(await crypto.subtle.digest('SHA-256', source)),
    (b) => b.toString(16).padStart(2, '0'),
  ).join('');
  self.postMessage({
    type: 'ready',
    bytes: source.length,
    sha256,
    blockSize: data.blockSize,
    lossPattern:
      'omit last systematic block in each stripe, replace with one degree-31 repair',
  });
}

function nextSequence() {
  let chosen = sequence;
  if (sequence === count - 1 && count > 1) {
    chosen = count;
    while (true) {
      const selected = selectBlocks(encoder.sessionId, stripe, chosen, count);
      if (
        selected.length === Math.min(31, count) &&
        selected.includes(count - 1)
      ) {
        break;
      }
      chosen++;
    }
  }
  return chosen;
}

self.onmessage = async ({ data }) => {
  try {
    if (data.type === 'prepare') {
      await prepare(data);
      return;
    }
    if (data.type !== 'next' || !encoder) {
      throw new Error('invalid producer request');
    }
    const frames = [];
    while (frames.length < 4 && !exhausted) {
      const chosen = nextSequence();
      frames.push(encoder.frame(stripe, chosen).buffer);
      sequence++;
      if (sequence === count) {
        sequence = 0;
        stripe++;
        exhausted = stripe === encoder.stripeCount;
        if (!exhausted) {
          count = encoder.getSourceCount(stripe);
        }
      }
    }
    self.postMessage({ type: 'frames', frames, exhausted }, frames);
  } catch (error) {
    self.postMessage({ type: 'failed', message: String(error) });
  }
};
