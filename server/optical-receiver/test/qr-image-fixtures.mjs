// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';

export function cameraRaster() {
  const gray = gunzipSync(
    readFileSync(
      new URL('../testdata/qr/camera-v40-format0.gray.gz', import.meta.url),
    ),
  );
  const rgba = new Uint8Array(gray.length * 4).fill(255);
  for (let i = 0; i < gray.length; i++) {
    rgba[i * 4] = rgba[i * 4 + 1] = rgba[i * 4 + 2] = gray[i];
  }
  const payload = readFileSync(
    new URL('../testdata/qr/camera-v40-format0.frame.bin', import.meta.url),
  );
  return { rgba, width: 960, height: 960, payload };
}

export function qrFixture(version, name = 'random') {
  const record = JSON.parse(
    readFileSync(
      new URL(
        `../../../client/optical-sender/testdata/qr/oracle-v${version}-${name}.json`,
        import.meta.url,
      ),
    ),
  );
  return { rows: record.rows, payload: Buffer.from(record.payload, 'base64') };
}

// The renderer uses a direct 3x3 inverse, independent of the detector's solver.
function inverse(m) {
  const [a, b, c, d, e, f, g, h, i] = m;
  const values = [
    e * i - f * h,
    c * h - b * i,
    b * f - c * e,
    f * g - d * i,
    a * i - c * g,
    c * d - a * f,
    d * h - e * g,
    b * g - a * h,
    a * e - b * d,
  ];
  const determinant = a * values[0] + b * values[3] + c * values[6];
  return values.map((value) => value / determinant);
}

function sampledLuminance(fixture, matrix, samples, x, y) {
  let sum = 0;
  for (const [dx, dy] of samples) {
    const divisor = matrix[6] * (x + dx) + matrix[7] * (y + dy) + matrix[8];
    const sx = Math.floor(
      (matrix[0] * (x + dx) + matrix[1] * (y + dy) + matrix[2]) / divisor,
    );
    const sy = Math.floor(
      (matrix[3] * (x + dx) + matrix[4] * (y + dy) + matrix[5]) / divisor,
    );
    sum += fixture.rows[sy]?.[sx] === '1' ? 0 : 255;
  }
  return sum;
}

export function renderQR(
  fixture,
  transform,
  width = 640,
  height = width,
  options = {},
) {
  const rgba = new Uint8Array(width * height * 4).fill(255);
  const matrix = inverse(transform);
  const samples = options.antialias
    ? [
        [0.25, 0.25],
        [0.75, 0.25],
        [0.25, 0.75],
        [0.75, 0.75],
      ]
    : [[0.5, 0.5]];
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const sum = sampledLuminance(fixture, matrix, samples, x, y);
      let value = sum / samples.length;
      if (options.gradient) {
        value = 20 + value * (0.5 + (0.45 * x) / width);
      }
      if (options.glare) {
        value = Math.min(
          255,
          value +
            80 *
              Math.exp(
                -((x - width * 0.6) ** 2 + (y - height * 0.6) ** 2) /
                  (width * width * 0.025),
              ),
        );
      }
      const offset = (y * width + x) * 4;
      rgba[offset] = rgba[offset + 1] = rgba[offset + 2] = value;
    }
  }
  return { rgba, width, height };
}

export function rotatedQR(fixture, degrees, scale = 3, options = {}) {
  const angle = (degrees * Math.PI) / 180;
  const a = scale * Math.cos(angle),
    b = scale * Math.sin(angle);
  const center = fixture.rows.length / 2;
  return renderQR(
    fixture,
    [a, -b, 320 - (a - b) * center, b, a, 320 - (a + b) * center, 0, 0, 1],
    640,
    640,
    options,
  );
}

export function blur(image) {
  const rgba = image.rgba.slice();
  for (let y = 1; y < image.height - 1; y++) {
    for (let x = 1; x < image.width - 1; x++) {
      let value = 0;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          value += image.rgba[((y + dy) * image.width + x + dx) * 4];
        }
      }
      const index = (y * image.width + x) * 4;
      rgba[index] = rgba[index + 1] = rgba[index + 2] = value / 9;
    }
  }
  return { ...image, rgba };
}

export function fourQR(fixtures, scale, perspective = 0) {
  const width = 960;
  const rgba = new Uint8Array(width * width * 4).fill(255);
  for (let i = 0; i < fixtures.length; i++) {
    const part = renderQR(
      fixtures[i],
      [
        scale,
        0.025,
        35 + (i % 2) * 480,
        0.01,
        scale,
        35 + Math.floor(i / 2) * 480,
        perspective,
        perspective / 2,
        1,
      ],
      width,
      width,
      { antialias: true },
    );
    for (let p = 0; p < rgba.length; p += 4) {
      rgba[p] = rgba[p + 1] = rgba[p + 2] = Math.min(rgba[p], part.rgba[p]);
    }
  }
  return blur({ rgba, width, height: width });
}

export function cameraWarp(image, curvature, gamma) {
  const { width, height } = image;
  const rgba = new Uint8Array(image.rgba.length).fill(255);
  const cx = width / 2,
    cy = height / 2,
    radius = Math.min(width, height) / 2;
  const at = (x, y) =>
    image.rgba[
      (Math.max(0, Math.min(height - 1, y)) * width +
        Math.max(0, Math.min(width - 1, x))) *
        4
    ];
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const factor =
        1 + (curvature * ((x - cx) ** 2 + (y - cy) ** 2)) / radius ** 2;
      const sx = cx + (x - cx) * factor,
        sy = cy + (y - cy) * factor;
      const ix = Math.floor(sx),
        iy = Math.floor(sy),
        dx = sx - ix,
        dy = sy - iy;
      const value =
        at(ix, iy) * (1 - dx) * (1 - dy) +
        at(ix + 1, iy) * dx * (1 - dy) +
        at(ix, iy + 1) * (1 - dx) * dy +
        at(ix + 1, iy + 1) * dx * dy;
      rgba[(y * width + x) * 4] =
        rgba[(y * width + x) * 4 + 1] =
        rgba[(y * width + x) * 4 + 2] =
          255 * (value / 255) ** gamma;
    }
  }
  return { rgba, width, height };
}
