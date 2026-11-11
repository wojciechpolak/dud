// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';
import { parseFrame } from '../.work/receiver/codec.js';
import { scanQRImage, QR_IMAGE_LIMITS } from '../.work/receiver/qr-image.js';
import {
  qrFixture,
  renderQR,
  rotatedQR,
  blur,
  fourQR,
  cameraWarp,
  cameraRaster,
} from './qr-image-fixtures.mjs';
import { trackedRegion } from '../.work/receiver/tracked-regions.js';

function recovered(image, fixture) {
  const input = image.rgba.slice();
  const result = scanQRImage(image.rgba, image.width, image.height);
  assert.equal(result.symbols.length, 1, JSON.stringify(result.work));
  assert.deepEqual(Buffer.from(result.symbols[0].data), fixture.payload);
  assert.equal(result.exhausted, false);
  assert.deepEqual(image.rgba, input);
  return result;
}

function crop(image, region) {
  const rgba = new Uint8Array(region.width * region.height * 4);
  for (let y = 0; y < region.height; y++) {
    const start = ((region.y + y) * image.width + region.x) * 4;
    rgba.set(
      image.rgba.subarray(start, start + region.width * 4),
      y * region.width * 4,
    );
  }
  return { rgba, width: region.width, height: region.height };
}

for (const version of [30, 40]) {
  const fixture = qrFixture(version);
  for (const angle of [0, 15, 30, 45, 90, 135, 180, 270]) {
    test(`Version ${version} image at ${angle} degrees preserves binary bytes`, () => {
      recovered(
        rotatedQR(fixture, angle, version === 30 ? 3 : 2.4, {
          antialias: true,
        }),
        fixture,
      );
    });
  }
  test(`Version ${version} projective image uses alignment to recover modules`, () => {
    const result = recovered(
      renderQR(
        fixture,
        [3, 0.12, 40, 0.08, 3, 40, 0.0008, 0.0004, 1],
        640,
        640,
        { antialias: true },
      ),
      fixture,
    );
    assert.ok(result.work.alignmentChecks > 0);
  });
  for (const [p, q] of [
    [-0.0004, 0.0008],
    [0.001, -0.0003],
  ]) {
    test(`Version ${version} asymmetric perspective ${p},${q} recovers bytes`, () => {
      recovered(
        renderQR(fixture, [3, 0.18, 90, 0.1, 3, 90, p, q, 1], 800),
        fixture,
      );
    });
  }
  for (const effect of ['gradient', 'glare', 'blur']) {
    test(`Version ${version} ${effect} image preserves binary bytes`, () => {
      let image = rotatedQR(fixture, 0, 3, { antialias: true, [effect]: true });
      if (effect === 'blur') {
        image = blur(image);
      }
      recovered(image, fixture);
    });
  }
  for (const scale of [2.25, 2.4, 2.5]) {
    test(`Version ${version} blurred fractional-pixel grid at ${scale} preserves bytes`, () => {
      recovered(
        blur(
          renderQR(
            fixture,
            [scale, 0.025, 31.2, 0.01, scale, 29.4, 0.00008, 0.00004, 1],
            640,
            640,
            { antialias: true },
          ),
        ),
        fixture,
      );
    });
  }
  for (const [curvature, gamma] of [
    [0.02, 0.8],
    [0.04, 1],
  ]) {
    test(`Version ${version} radial curvature ${curvature} and gamma ${gamma} preserve binary bytes`, () => {
      const image = cameraWarp(
        blur(
          rotatedQR(fixture, 0, version === 30 ? 3 : 2.4, { antialias: true }),
        ),
        curvature,
        gamma,
      );
      const result = recovered(image, fixture);
      for (const [name, count] of Object.entries(result.work)) {
        assert.ok(count <= QR_IMAGE_LIMITS[name]);
      }
    });
  }
}

test('blurred four-symbol camera image recovers exact independent payloads within shared bounds', () => {
  const fixtures = ['zero', 'cycle', 'random', 'capacity'].map((name) =>
    qrFixture(40, name),
  );
  const width = 960;
  const rgba = new Uint8Array(width * width * 4).fill(255);
  for (let i = 0; i < fixtures.length; i++) {
    const part = renderQR(
      fixtures[i],
      [
        2.25,
        0.01,
        40 + (i % 2) * 480,
        0.01,
        2.25,
        40 + Math.floor(i / 2) * 480,
        0,
        0,
        1,
      ],
      width,
      width,
      { antialias: true },
    );
    for (let p = 0; p < rgba.length; p += 4) {
      if (part.rgba[p] < 255) {
        rgba[p] = part.rgba[p];
        rgba[p + 1] = part.rgba[p + 1];
        rgba[p + 2] = part.rgba[p + 2];
      }
    }
  }
  const image = blur({ rgba, width, height: width });
  const result = scanQRImage(image.rgba, width, width);
  assert.ok(result.symbols.length >= 2, JSON.stringify(result.work));
  assert.equal(result.exhausted, false);
  const expected = new Set(fixtures.map((f) => f.payload.toString('base64')));
  const recovered = result.symbols.map((s) =>
    Buffer.from(s.data).toString('base64'),
  );
  assert.equal(new Set(recovered).size, recovered.length);
  for (const payload of recovered) {
    assert.ok(expected.has(payload));
  }
  for (const [name, count] of Object.entries(result.work)) {
    assert.ok(count <= QR_IMAGE_LIMITS[name]);
  }
});

for (const [scale, perspective, count] of [
  [2.25, 0, 4],
  [2.4, 0, 4],
  [2.4, 0.0002, 4],
]) {
  test(`four blurred Version 40 symbols at ${scale},${perspective} share geometry work without starvation`, () => {
    const fixtures = ['zero', 'cycle', 'random', 'capacity'].map((name) =>
      qrFixture(40, name),
    );
    const image = fourQR(fixtures, scale, perspective);
    const result = scanQRImage(image.rgba, image.width, image.height);
    assert.equal(result.symbols.length, count, JSON.stringify(result.work));
    assert.equal(result.exhausted, false);
    const expected = new Set(fixtures.map((f) => f.payload.toString('base64')));
    const decoded = result.symbols.map((s) =>
      Buffer.from(s.data).toString('base64'),
    );
    assert.equal(new Set(decoded).size, decoded.length);
    for (const payload of decoded) {
      assert.ok(expected.has(payload));
    }
    for (const [name, work] of Object.entries(result.work)) {
      assert.ok(work <= QR_IMAGE_LIMITS[name]);
    }
  });
}

test('four symbol image produces four independent binary payloads', () => {
  const fixtures = ['zero', 'cycle', 'random', 'capacity'].map((name) =>
    qrFixture(40, name),
  );
  const image = {
    rgba: new Uint8Array(960 * 960 * 4).fill(255),
    width: 960,
    height: 960,
  };
  for (let i = 0; i < fixtures.length; i++) {
    const x = 20 + (i % 2) * 480;
    const y = 20 + Math.floor(i / 2) * 480;
    const part = renderQR(fixtures[i], [2.4, 0, x, 0, 2.4, y, 0, 0, 1], 960);
    for (let p = 0; p < image.rgba.length; p += 4) {
      if (part.rgba[p] === 0) {
        image.rgba[p] = image.rgba[p + 1] = image.rgba[p + 2] = 0;
      }
    }
  }
  const result = scanQRImage(image.rgba, image.width, image.height);
  assert.equal(result.symbols.length, 4, JSON.stringify(result.work));
  assert.deepEqual(
    result.symbols
      .map((symbol) => Buffer.from(symbol.data).toString('base64'))
      .sort(),
    fixtures.map((fixture) => fixture.payload.toString('base64')).sort(),
  );
});

test('four-symbol camera raster preserves exact format-0 frame bytes', () => {
  const { rgba, payload: expected } = cameraRaster();
  const before = rgba.slice();
  const result = scanQRImage(rgba, 960, 960);
  assert.equal(result.symbols.length, 1, JSON.stringify(result.work));
  assert.deepEqual(Buffer.from(result.symbols[0].data), expected);
  assert.throws(
    () => parseFrame(result.symbols[0].data),
    /expected dud\/optical\/1, received format 0/,
  );
  const header = new DataView(
    expected.buffer,
    expected.byteOffset,
    expected.byteLength,
  );
  assert.equal(header.getUint32(28), 813712);
  assert.equal(header.getUint16(38), 2860);
  assert.equal(header.getUint32(40), 1048576);
  assert.deepEqual(rgba, before);
  for (const [name, count] of Object.entries(result.work)) {
    assert.ok(count <= QR_IMAGE_LIMITS[name]);
  }
});

test('one-symbol tracked crop stops after verified payload despite neighboring finder candidates', () => {
  const fixtures = ['zero', 'cycle', 'random', 'capacity'].map((name) =>
    qrFixture(40, name),
  );
  const image = fourQR(fixtures, 2.4);
  const full = scanQRImage(image.rgba, image.width, image.height);
  const symbol = full.symbols.find((s) =>
    Buffer.from(s.data).equals(fixtures[0].payload),
  );
  assert.ok(symbol);
  const region = trackedRegion(symbol.points, image.width, image.height);
  assert.ok(region);
  const { rgba } = crop(image, region);
  const unrestricted = scanQRImage(rgba, region.width, region.height);
  const tracked = scanQRImage(rgba, region.width, region.height, 1);
  assert.equal(tracked.symbols.length, 1);
  assert.deepEqual(Buffer.from(tracked.symbols[0].data), fixtures[0].payload);
  assert.ok(tracked.work.candidates > 3);
  assert.ok(tracked.work.matrixAttempts < unrestricted.work.matrixAttempts);
  assert.ok(tracked.work.alignmentChecks < unrestricted.work.alignmentChecks);
  assert.equal(tracked.exhausted, false);
});

test('one-symbol tracked JPEG crop preserves the complete native frame under adaptive sampling', () => {
  const image = cameraRaster();
  const full = scanQRImage(image.rgba, image.width, image.height);
  const region = trackedRegion(
    full.symbols[0].points,
    image.width,
    image.height,
  );
  assert.ok(region);
  const cropped = crop(image, region);
  const before = cropped.rgba.slice();
  const result = scanQRImage(cropped.rgba, cropped.width, cropped.height, 1);
  assert.equal(result.symbols.length, 1, JSON.stringify(result.work));
  assert.deepEqual(Buffer.from(result.symbols[0].data), image.payload);
  assert.deepEqual(cropped.rgba, before);
  assert.ok(result.work.alignmentChecks > 0);
  for (const [name, count] of Object.entries(result.work)) {
    assert.ok(count <= QR_IMAGE_LIMITS[name]);
  }
});

test('symbol limit preserves the first verified payloads and rejects invalid limits', () => {
  const fixtures = ['zero', 'cycle', 'random', 'capacity'].map((name) =>
    qrFixture(30, name),
  );
  const image = fourQR(fixtures, 3);
  const full = scanQRImage(image.rgba, image.width, image.height);
  assert.equal(full.symbols.length, 4);
  for (const limit of [1, 2, 3, 4]) {
    const result = scanQRImage(image.rgba, image.width, image.height, limit);
    assert.deepEqual(
      result.symbols.map((s) => Buffer.from(s.data)),
      full.symbols.slice(0, limit).map((s) => Buffer.from(s.data)),
    );
    assert.equal(result.exhausted, false);
  }
  for (const limit of [0, 5, 1.5, NaN, Infinity, null]) {
    assert.throws(
      () => scanQRImage(image.rgba, image.width, image.height, limit),
      RangeError,
    );
  }
});

test('blank, transparent and random images return no symbol within work bounds', () => {
  let state = 0x137294ac;
  for (const kind of ['white', 'black', 'transparent', 'noise']) {
    const rgba = new Uint8Array(960 * 960 * 4);
    for (let i = 0; i < rgba.length; i += 4) {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      const value = kind === 'white' ? 255 : kind === 'noise' ? state & 255 : 0;
      rgba[i] = rgba[i + 1] = rgba[i + 2] = value;
      rgba[i + 3] = kind === 'transparent' ? 0 : 255;
    }
    const result = scanQRImage(rgba, 960, 960);
    assert.equal(result.symbols.length, 0);
    for (const [name, count] of Object.entries(result.work)) {
      assert.ok(count <= QR_IMAGE_LIMITS[name]);
    }
  }
});

test('repeated finder-like scanlines exhaust a fixed work budget without output', () => {
  const rgba = new Uint8Array(960 * 960 * 4).fill(255);
  const pattern = [0, 255, 0, 0, 0, 255, 0, 255];
  for (let y = 0; y < 960; y++) {
    for (let x = 0; x < 960; x++) {
      const index = (y * 960 + x) * 4;
      rgba[index] =
        rgba[index + 1] =
        rgba[index + 2] =
          pattern[x % pattern.length];
    }
  }
  const result = scanQRImage(rgba, 960, 960);
  assert.deepEqual(result.symbols, []);
  assert.equal(result.exhausted, true);
  assert.equal(result.work.finderChecks, QR_IMAGE_LIMITS.finderChecks);
});

function drawFinderImitation(rgba, width, top, left) {
  for (let y = 0; y < 21; y++) {
    for (let x = 0; x < 21; x++) {
      const radius = Math.max(
        Math.abs(Math.floor(x / 3) - 3),
        Math.abs(Math.floor(y / 3) - 3),
      );
      if (radius === 2) {
        continue;
      }
      const index = ((top + y) * width + left + x) * 4;
      rgba[index] = rgba[index + 1] = rgba[index + 2] = 0;
    }
  }
}

test('dense independent finder imitations stop before unbounded matrix or alignment work', () => {
  const width = 960;
  const rgba = new Uint8Array(width * width * 4).fill(255);
  for (let top = 4; top + 21 < width; top += 32) {
    for (let left = 4; left + 21 < width; left += 32) {
      drawFinderImitation(rgba, width, top, left);
    }
  }
  const result = scanQRImage(rgba, width, width);
  assert.deepEqual(result.symbols, []);
  for (const [name, count] of Object.entries(result.work)) {
    assert.ok(count <= QR_IMAGE_LIMITS[name]);
  }
});

test('clipped and severely compressed symbols expose no partial payload', () => {
  const fixture = qrFixture(40);
  for (const transform of [
    [3, 0, -30, 0, 3, -30, 0, 0, 1],
    [3, 0.18, 90, 0.1, 3, 90, 0.0012, 0.0008, 1],
  ]) {
    const image = renderQR(fixture, transform, 800);
    const result = scanQRImage(image.rgba, image.width, image.height);
    assert.deepEqual(result.symbols, []);
  }
});

test('RGBA input dimensions and byte allocation are bounded', () => {
  for (const [width, height] of [
    [0, 1],
    [1, 0],
    [961, 1],
    [1, 961],
    [1.5, 1],
    [NaN, 1],
    [Infinity, 1],
  ]) {
    assert.throws(
      () => scanQRImage(new Uint8Array(), width, height),
      RangeError,
    );
  }
  for (const data of [null, [], new Uint8Array(3), new Uint8Array(5)]) {
    assert.throws(() => scanQRImage(data, 1, 1), RangeError);
  }
});
