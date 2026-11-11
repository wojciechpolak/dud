// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// fallow-ignore-next-line unresolved-import -- The isolated benchmark serves compiled receiver modules beside this script.
import { FountainFramePipeline } from './fountain-client.js';

const producer = new Worker('./isolated-fountain-producer.mjs', {
  type: 'module',
});
const receiver = new Worker('./isolated-fountain-receiver.mjs', {
  type: 'module',
});
let producerReady;
let receiverReady;
const ready = Promise.all([
  new Promise((resolve) => {
    producerReady = resolve;
  }),
  new Promise((resolve) => {
    receiverReady = resolve;
  }),
]);
let frames = [];
let requesting = false;
let exhausted = false;
let started = false;
let finished = false;
let maximumBufferedFrames = 0;
let startedAt;
let expected;
let result;
let savedCapsule;
let fail;
const completion = new Promise((resolve, reject) => {
  result = resolve;
  fail = reject;
});
// Keep failures observable through the explicit completion request.
completion.catch(() => {});
function pump() {
  if (!started || finished) {
    return;
  }
  while (frames.length && client.canAccept) {
    client.accept(frames.shift());
  }
  if (!frames.length && !requesting && !exhausted && client.canAccept) {
    requesting = true;
    producer.postMessage({ type: 'next' });
  }
}
const client = new FountainFramePipeline(
  {
    onFrameDisposition: pump,
    onProgress: pump,
    onComplete: async ({ capsule }) => {
      finished = true;
      producer.terminate();
      const receivedSHA256 = Array.from(
        new Uint8Array(await crypto.subtle.digest('SHA-256', capsule)),
        (b) => b.toString(16).padStart(2, '0'),
      ).join('');
      const elapsedMilliseconds = performance.now() - startedAt;
      if (
        receivedSHA256 !== expected.sha256 ||
        capsule.length !== expected.bytes
      ) {
        fail(new Error('reconstructed ciphertext differs'));
        return;
      }
      result({
        ...expected,
        receivedSHA256,
        elapsedMilliseconds,
        reconstructionBytesPerSecond:
          (capsule.length * 1000) / elapsedMilliseconds,
        stats: client.snapshot(),
        maximumBufferedFrames,
      });
      savedCapsule = capsule;
    },
    onFatal: (value) => fail(new Error(value)),
    onRejected: (value) => fail(new Error(value)),
    onUnsupported: (value) => fail(new Error(value)),
    onSessionChange: () => fail(new Error('session conflict')),
  },
  () => receiver,
);
producer.onmessage = ({ data }) => {
  if (data.type === 'ready') {
    expected = data;
    producerReady();
  } else if (data.type === 'frames') {
    requesting = false;
    exhausted = data.exhausted;
    frames.push(...data.frames.map((buffer) => new Uint8Array(buffer)));
    maximumBufferedFrames = Math.max(maximumBufferedFrames, frames.length);
    pump();
  } else if (data.type === 'failed') {
    fail(new Error(data.message));
  }
};
receiver.addEventListener('message', ({ data }) => {
  if (data.benchmarkReady) {
    receiverReady();
  }
});
producer.onerror = receiver.onerror = (event) => fail(new Error(event.message));
globalThis.isolatedFountain = {
  async prepare(config) {
    producer.postMessage({ type: 'prepare', ...config });
    await ready;
    return expected;
  },
  start() {
    started = true;
    startedAt = performance.now();
    pump();
  },
  snapshot() {
    return {
      stats: client.snapshot(),
      bufferedFrames: frames.length,
      savedCiphertextBytes: savedCapsule?.byteLength ?? 0,
      finished,
    };
  },
  completion: () => completion,
  save() {
    if (!savedCapsule) {
      throw new Error('receipt is incomplete');
    }
    const url = URL.createObjectURL(
      new Blob([savedCapsule], { type: 'application/octet-stream' }),
    );
    const link = document.createElement('a');
    link.href = url;
    link.download = 'isolated-received.age';
    link.click();
    URL.revokeObjectURL(url);
    savedCapsule.fill(0);
    savedCapsule = undefined;
  },
  reset() {
    finished = true;
    frames = [];
    savedCapsule?.fill(0);
    savedCapsule = undefined;
    producer.terminate();
    client.reset();
  },
};
