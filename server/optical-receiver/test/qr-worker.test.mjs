// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import { qrFixture, renderQR, cameraRaster } from './qr-image-fixtures.mjs';
import { OpticalFramePipeline } from '../.work/receiver/pipeline.js';

const pwa = new URL('../.work/pwa/', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('build-manifest.json', pwa)));
const workerPath = manifest.assets.find((asset) =>
  asset.path.startsWith('decoder-worker.'),
).path;
const workerSource = readFileSync(new URL(workerPath, pwa), 'utf8');

function workerHarness(image, unavailableContext = false) {
  let handler;
  let receive;
  const pending = [];
  class Canvas {
    constructor(width, height) {
      this.width = width;
      this.height = height;
    }
    getContext() {
      if (unavailableContext) {
        return null;
      }
      const canvas = this;
      return {
        canvas,
        drawImage(
          bitmap,
          sx,
          sy,
          sourceWidth,
          sourceHeight,
          dx,
          dy,
          width,
          height,
        ) {
          assert.equal(sourceWidth, width);
          assert.equal(sourceHeight, height);
          assert.equal(dx, 0);
          assert.equal(dy, 0);
          this.sourceX = sx;
          this.sourceY = sy;
        },
        getImageData(x, y, width, height) {
          assert.ok(
            x >= 0 &&
              y >= 0 &&
              x + width <= canvas.width &&
              y + height <= canvas.height,
          );
          const data = new Uint8ClampedArray(width * height * 4);
          for (let row = 0; row < height; row++) {
            const start =
              ((this.sourceY + y + row) * image.width + this.sourceX + x) * 4;
            data.set(
              image.rgba.subarray(start, start + width * 4),
              row * width * 4,
            );
          }
          return { data, width, height };
        },
      };
    }
  }
  const context = vm.createContext(
    {
      Uint8Array,
      Uint8ClampedArray,
      Uint32Array,
      Float32Array,
      OffscreenCanvas: Canvas,
      performance,
      self: {
        addEventListener(type, callback) {
          assert.equal(type, 'message');
          handler = callback;
        },
        postMessage(message, options) {
          if (message.type === 'result') {
            assert.deepEqual(options.transfer, message.frames);
          }
          if (receive) {
            const callback = receive;
            receive = undefined;
            callback(message);
          } else {
            pending.push(message);
          }
        },
      },
    },
    { microtaskMode: 'afterEvaluate' },
  );
  // Local intrinsic bindings avoid context-proxy lookup for each sampled pixel.
  const intrinsics =
    'Math,Number,Array,Map,Set,Error,RangeError,Uint8Array,Uint8ClampedArray,Uint32Array,Float32Array,self,performance,OffscreenCanvas';
  vm.runInContext(
    `(function(${intrinsics}) {\n${workerSource}\n})(${intrinsics});`,
    context,
  );
  context.dispatch = handler;
  return async (data) => {
    let timer;
    const response = new Promise((resolve, reject) => {
      timer = setTimeout(
        () => reject(new Error('Worker did not reply')),
        10_000,
      );
      if (pending.length) {
        resolve(pending.shift());
      } else {
        receive = resolve;
      }
    });
    context.message = data;
    vm.runInContext('dispatch({ data: message })', context);
    try {
      return await response;
    } finally {
      clearTimeout(timer);
    }
  };
}

for (const version of [30, 40]) {
  test(`built QR worker tracks four Version ${version} regions and periodically refreshes exact bytes`, async () => {
    const fixtures = ['zero', 'cycle', 'random', 'capacity'].map((name) =>
      qrFixture(version, name),
    );
    const width = (fixtures[0].rows.length + 8) * 4;
    const rgba = new Uint8Array(width * width * 4).fill(255);
    for (let i = 0; i < 4; i++) {
      const image = renderQR(
        fixtures[i],
        [
          2,
          0,
          8 + ((i % 2) * width) / 2,
          0,
          2,
          8 + (Math.floor(i / 2) * width) / 2,
          0,
          0,
          1,
        ],
        width,
      );
      for (let pixel = 0; pixel < rgba.length; pixel += 4) {
        if (image.rgba[pixel] === 0) {
          rgba[pixel] = rgba[pixel + 1] = rgba[pixel + 2] = 0;
        }
      }
    }
    const send = workerHarness({ width, height: width, rgba });
    assert.equal((await send({ type: 'warmup' })).type, 'ready');
    const expected = fixtures
      .map((fixture) => fixture.payload.toString('base64'))
      .sort();
    let closed = 0;
    for (let iteration = 0; iteration < 16; iteration++) {
      const reply = await send({
        type: 'decode',
        scanMode: 'tracked-four',
        bitmap: {
          width,
          height: width,
          close() {
            closed++;
          },
        },
      });
      assert.equal(reply.type, 'result');
      assert.deepEqual(
        Array.from(reply.frames, (frame) =>
          Buffer.from(frame).toString('base64'),
        ).sort(),
        expected,
      );
      assert.equal(reply.fullScans, iteration % 15 === 0 ? 1 : 0);
      assert.equal(reply.trackedScans, iteration % 15 === 0 ? 0 : 4);
      assert.equal(reply.trackedSymbols, iteration % 15 === 0 ? 0 : 4);
      assert.equal(reply.scanDimension, width);
      assert.ok(reply.scanDiagnostics.finderCandidates >= 12);
      assert.ok(reply.scanDiagnostics.matrixAttempts >= 4);
      assert.ok(reply.scanDiagnostics.exhaustedScans >= 0);
      assert.ok(
        reply.scanDiagnostics.exhaustedScans <= (reply.fullScans ? 1 : 4),
      );
    }
    assert.equal(closed, 16);
  });
}

test('built QR worker preserves camera frame bytes for format-0 rejection', async () => {
  const image = cameraRaster();
  const send = workerHarness(image);
  let closed = 0;
  const reply = await send({
    type: 'decode',
    scanMode: 'tracked-four',
    bitmap: {
      width: image.width,
      height: image.height,
      close() {
        closed++;
      },
    },
  });
  assert.equal(reply.type, 'result');
  assert.equal(reply.frames.length, 1);
  assert.deepEqual(Buffer.from(reply.frames[0]), image.payload);
  assert.equal(reply.fullScans, 1);
  assert.equal(closed, 1);
  const progress = [];
  const dispositions = [];
  const unsupported = [];
  const unexpected = (message) => assert.fail(String(message));
  const pipeline = new OpticalFramePipeline({
    onProgress: (value) => progress.push(value),
    onFrameDisposition: (value) => dispositions.push(value),
    onComplete: unexpected,
    onSessionChange: unexpected,
    onUnsupported: (message) => unsupported.push(message),
    onRejected: unexpected,
    onFatal: unexpected,
  });
  pipeline.accept(new Uint8Array(reply.frames[0]));
  assert.deepEqual(dispositions, ['unsupported']);
  assert.equal(progress.length, 0);
  assert.deepEqual(unsupported, [
    'version: unsupported optical sender; expected dud/optical/1, received format 0',
  ]);
  pipeline.reset();
});

test('built QR worker closes bitmaps after image failures and rejects missing images', async () => {
  const send = workerHarness(
    { width: 1, height: 1, rgba: new Uint8Array(4) },
    true,
  );
  assert.equal((await send({ type: 'decode' })).type, 'error');
  let closed = 0;
  const reply = await send({
    type: 'decode',
    bitmap: {
      width: 1,
      height: 1,
      close() {
        closed++;
      },
    },
  });
  assert.equal(reply.type, 'error');
  assert.equal(closed, 1);
});
