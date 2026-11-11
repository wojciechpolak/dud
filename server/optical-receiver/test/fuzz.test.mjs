// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  HEADER_SIZE,
  HIGH_DENSITY_FRAME_SIZE,
  MAX_SOURCE_BLOCKS,
  OpticalCodecError,
  parseFrame,
} from '../.work/receiver/codec.js';

const vectors = JSON.parse(
  readFileSync(
    new URL(
      '../../../client/optical-sender/testdata/format1/go-vectors.json',
      import.meta.url,
    ),
    'utf8',
  ),
);

function decode(value) {
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

function parserSeeds() {
  return [
    ...vectors.cases.flatMap((entry) =>
      entry.frames.map((frame) => decode(frame.bytes)),
    ),
    ...vectors.invalid.map((entry) => decode(entry.bytes)),
    ...vectors.hostile.flatMap((entry) => entry.frames.map(decode)),
  ];
}

function nextRandom(state) {
  state ^= state << 13;
  state ^= state >>> 17;
  state ^= state << 5;
  return state >>> 0;
}

function mutate(seed, mode, random) {
  if (mode === 0) {
    return seed.subarray(0, random() % (seed.byteLength + 1));
  }
  if (mode === 1) {
    const value = new Uint8Array(seed);
    const changes = 1 + (random() % 8);
    for (let index = 0; index < changes && value.byteLength > 0; index++) {
      value[random() % value.byteLength] ^= 1 << (random() % 8);
    }
    return value;
  }
  if (mode === 2) {
    const extra = random() % 65;
    const value = new Uint8Array(seed.byteLength + extra);
    value.set(seed);
    for (let index = seed.byteLength; index < value.byteLength; index++) {
      value[index] = random() & 0xff;
    }
    return value;
  }
  const value = new Uint8Array(random() % (HIGH_DENSITY_FRAME_SIZE + 65));
  for (let index = 0; index < value.byteLength; index++) {
    value[index] = random() & 0xff;
  }
  return value;
}

function assertParserResult(input) {
  let frame;
  try {
    frame = parseFrame(input);
  } catch (error) {
    assert.ok(error instanceof OpticalCodecError, String(error));
    return;
  }
  assert.equal(frame.payload.byteLength, frame.blockSize);
  assert.ok(frame.sourceCount >= 1 && frame.sourceCount <= MAX_SOURCE_BLOCKS);
  assert.ok(frame.degree >= 1 && frame.degree <= 31);
  if (frame.payload.byteLength > 0) {
    const first = frame.payload[0];
    input[HEADER_SIZE] ^= 0xff;
    assert.equal(frame.payload[0], first, 'parsed payload aliases its input');
  }
}

test('TypeScript parser survives deterministic mutations of the shared Go corpus', () => {
  const seeds = parserSeeds();
  for (const seed of seeds) {
    assertParserResult(new Uint8Array(seed));
  }

  let state = 0xd0d0_5eed;
  const random = () => {
    state = nextRandom(state);
    return state;
  };
  for (let iteration = 0; iteration < 4096; iteration++) {
    const seed = seeds[random() % seeds.length];
    assertParserResult(mutate(seed, random() % 4, random));
  }
});
