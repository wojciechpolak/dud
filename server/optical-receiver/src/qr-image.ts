// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { decodeQRMatrix, readQRMetadata, QRDecodeError } from './qr-matrix.js';
import type { ScanPoint } from './tracked-regions.js';
import { MAX_SCAN_DIMENSION } from './scan-region.js';

export const QR_IMAGE_LIMITS = Object.freeze({
  dimension: MAX_SCAN_DIMENSION,
  finderChecks: 8192,
  candidates: 48,
  triples: 128,
  alignmentChecks: 100_000,
  matrixAttempts: 32,
  symbols: 4,
});

export interface QRImageSymbol {
  data: Uint8Array;
  points: ScanPoint[];
}

export interface QRImageResult {
  symbols: QRImageSymbol[];
  work: {
    finderChecks: number;
    candidates: number;
    triples: number;
    alignmentChecks: number;
    matrixAttempts: number;
  };
  exhausted: boolean;
}

interface BinaryImage {
  pixels: Uint8Array;
  gray: Uint8Array;
  thresholds: Uint8Array;
  thresholdColumns: number;
  width: number;
  height: number;
}

interface Finder extends ScanPoint {
  module: number;
  hits: number;
}

interface Triple {
  tl: Finder;
  tr: Finder;
  bl: Finder;
  score: number;
}

interface MatrixRetry {
  finders: Finder[];
  read(): QRImageSymbol | undefined;
}

function binarize(
  data: Uint8ClampedArray | Uint8Array,
  width: number,
  height: number,
): BinaryImage {
  const gray = new Uint8Array(width * height);
  let minimum = 255;
  let maximum = 0;
  for (let i = 0; i < gray.length; i++) {
    // Transparent input is composited on white, matching the sender's quiet zone.
    const alpha = data[i * 4 + 3];
    const luminance =
      (77 * data[i * 4] + 150 * data[i * 4 + 1] + 29 * data[i * 4 + 2]) >>> 8;
    const value = Math.round((luminance * alpha + 255 * (255 - alpha)) / 255);
    gray[i] = value;
    minimum = Math.min(minimum, value);
    maximum = Math.max(maximum, value);
  }
  const pixels = new Uint8Array(gray.length);
  const tile = 16;
  const columns = Math.ceil(width / tile);
  const rows = Math.ceil(height / tile);
  const thresholds = new Uint8Array(columns * rows);
  if (maximum - minimum < 24) {
    thresholds.fill((minimum + maximum) / 2);
    return {
      pixels,
      gray,
      thresholds,
      thresholdColumns: columns,
      width,
      height,
    };
  }
  for (let ty = 0; ty < rows; ty++) {
    for (let tx = 0; tx < columns; tx++) {
      const { low, high } = tileRange(gray, width, height, tx, ty, tile);
      thresholds[ty * columns + tx] =
        high - low >= 24 ? (low + high) / 2 : (minimum + maximum) / 2;
    }
  }
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      pixels[y * width + x] = Number(
        gray[y * width + x] <
          thresholds[Math.floor(y / tile) * columns + Math.floor(x / tile)],
      );
    }
  }
  return { pixels, gray, thresholds, thresholdColumns: columns, width, height };
}

function tileRange(
  gray: Uint8Array,
  width: number,
  height: number,
  tx: number,
  ty: number,
  tile: number,
): { low: number; high: number } {
  let low = 255;
  let high = 0;
  for (let y = ty * tile; y < Math.min(height, (ty + 1) * tile); y++) {
    for (let x = tx * tile; x < Math.min(width, (tx + 1) * tile); x++) {
      const value = gray[y * width + x];
      low = Math.min(low, value);
      high = Math.max(high, value);
    }
  }
  return { low, high };
}

function ratio(runs: number[]): boolean {
  const module = runs.reduce((sum, value) => sum + value, 0) / 7;
  return (
    module >= 1 &&
    runs.every(
      (value, index) =>
        Math.abs(value - module * (index === 2 ? 3 : 1)) <=
        module * (index === 2 ? 1.2 : 0.75),
    )
  );
}

function cross(
  image: BinaryImage,
  x: number,
  y: number,
  vertical: boolean,
  module: number,
): { center: number; module: number } | undefined {
  const fixed = Math.floor(vertical ? x : y);
  const center = Math.floor(vertical ? y : x);
  const size = vertical ? image.height : image.width;
  const at = (position: number) =>
    image.pixels[
      vertical ? position * image.width + fixed : fixed * image.width + position
    ];
  if (
    fixed < 0 ||
    fixed >= (vertical ? image.width : image.height) ||
    center < 0 ||
    center >= size ||
    !at(center)
  ) {
    return;
  }
  const runs = [0, 0, 0, 0, 0];
  const limit = Math.ceil(module * 5);
  const left = crossRuns(at, center, -1, size, [2, 1, 0], runs, limit);
  if (left === undefined) {
    return;
  }
  const right = crossRuns(at, center + 1, 1, size, [2, 3, 4], runs, limit);
  if (right === undefined) {
    return;
  }
  if (!ratio(runs)) {
    return;
  }
  return {
    center: left + 1 + runs[0] + runs[1] + runs[2] / 2,
    module: runs.reduce((a, b) => a + b, 0) / 7,
  };
}

function crossRuns(
  at: (position: number) => number,
  position: number,
  direction: number,
  size: number,
  indices: number[],
  runs: number[],
  limit: number,
): number | undefined {
  for (const index of indices) {
    const color = index === 1 || index === 3 ? 0 : 1;
    while (
      position >= 0 &&
      position < size &&
      at(position) === color &&
      runs[index] <= limit
    ) {
      runs[index]++;
      position += direction;
    }
    if (runs[index] === 0 || runs[index] > limit) {
      return;
    }
  }
  return position;
}

function recordFinder(
  image: BinaryImage,
  found: Finder[],
  x: number,
  y: number,
  runs: number[],
): void {
  const total = runs.reduce((a, b) => a + b, 0);
  const cx = x - runs[4] - runs[3] - runs[2] / 2;
  const vertical = cross(image, cx, y, true, total / 7);
  if (!vertical) {
    return;
  }
  const horizontal = cross(image, cx, vertical.center, false, vertical.module);
  if (!horizontal || Math.abs(horizontal.center - cx) > (total / 7) * 2) {
    return;
  }
  const module = finderPattern(
    image,
    horizontal.center,
    vertical.center,
    horizontal.module,
    vertical.module,
  );
  if (module === undefined) {
    return;
  }
  const match = found.find(
    (candidate) =>
      Math.hypot(
        candidate.x - horizontal.center,
        candidate.y - vertical.center,
      ) <=
      module * 2,
  );
  if (match) {
    match.x = (match.x * match.hits + horizontal.center) / (match.hits + 1);
    match.y = (match.y * match.hits + vertical.center) / (match.hits + 1);
    match.module = (match.module * match.hits + module) / (match.hits + 1);
    match.hits++;
  } else if (found.length < QR_IMAGE_LIMITS.candidates) {
    found.push({ x: horizontal.center, y: vertical.center, module, hits: 1 });
  }
}

function scanFinderRow(
  image: BinaryImage,
  y: number,
  found: Finder[],
  result: QRImageResult,
): void {
  const runs: number[] = [];
  let start = 0;
  let color = image.pixels[y * image.width];
  for (let x = 1; x <= image.width; x++) {
    const next =
      x < image.width ? image.pixels[y * image.width + x] : 1 - color;
    if (next === color) {
      continue;
    }
    runs.push(x - start);
    if (runs.length > 5) {
      runs.shift();
    }
    if (color === 1 && runs.length === 5 && ratio(runs)) {
      if (result.work.finderChecks >= QR_IMAGE_LIMITS.finderChecks) {
        result.exhausted = true;
        return;
      }
      result.work.finderChecks++;
      recordFinder(image, found, x, y, runs);
    }
    color = next;
    start = x;
  }
}

function finders(image: BinaryImage, result: QRImageResult): Finder[] {
  const found: Finder[] = [];
  for (let y = 0; y < image.height; y++) {
    scanFinderRow(image, y, found, result);
    if (result.exhausted) {
      return [];
    }
  }
  return found
    .filter((candidate) => candidate.hits >= 2)
    .sort((a, b) => b.hits - a.hits);
}

function finderPattern(
  image: BinaryImage,
  x: number,
  y: number,
  horizontal: number,
  vertical: number,
): number | undefined {
  for (let angle = 0; angle < Math.PI / 2; angle += Math.PI / 12) {
    const cosine = Math.cos(angle);
    const sine = Math.sin(angle);
    const scale = Math.max(cosine, sine);
    let matching = 0;
    for (let dy = -3; dy <= 3; dy++) {
      for (let dx = -3; dx <= 3; dx++) {
        const px = Math.floor(
          x + scale * (dx * horizontal * cosine - dy * vertical * sine),
        );
        const py = Math.floor(
          y + scale * (dx * horizontal * sine + dy * vertical * cosine),
        );
        if (px < 0 || py < 0 || px >= image.width || py >= image.height) {
          continue;
        }
        const dark = Number(Math.max(Math.abs(dx), Math.abs(dy)) !== 2);
        matching += Number(image.pixels[py * image.width + px] === dark);
      }
    }
    if (matching >= 44) {
      return ((horizontal + vertical) * scale) / 2;
    }
  }
  return undefined;
}

function triples(points: Finder[]): Triple[] {
  const found: Triple[] = [];
  for (let i = 0; i < points.length; i++) {
    for (let j = i + 1; j < points.length; j++) {
      for (let k = j + 1; k < points.length; k++) {
        const three = [points[i], points[j], points[k]];
        const lengths = three.map((_, index) =>
          Math.hypot(
            three[(index + 1) % 3].x - three[(index + 2) % 3].x,
            three[(index + 1) % 3].y - three[(index + 2) % 3].y,
          ),
        );
        const corner = lengths.indexOf(Math.max(...lengths));
        const tl = three[corner];
        let tr = three[(corner + 1) % 3];
        let bl = three[(corner + 2) % 3];
        const ax = tr.x - tl.x,
          ay = tr.y - tl.y;
        const bx = bl.x - tl.x,
          by = bl.y - tl.y;
        const a = Math.hypot(ax, ay),
          b = Math.hypot(bx, by);
        const angle = Math.abs(ax * bx + ay * by) / (a * b);
        const module = (tl.module + tr.module + bl.module) / 3;
        if (
          angle > 0.35 ||
          a / b < 0.65 ||
          a / b > 1.55 ||
          Math.min(a, b) < module * 95 ||
          Math.max(a, b) > module * 215 ||
          Math.max(...three.map((p) => p.module)) >
            Math.min(...three.map((p) => p.module)) * 1.7
        ) {
          continue;
        }
        if (ax * by - ay * bx < 0) {
          [tr, bl] = [bl, tr];
        }
        // Finder triples spanning separate symbols have plausible angles but
        // imply more modules than either supported version.
        found.push({
          tl,
          tr,
          bl,
          score:
            tl.hits +
            tr.hits +
            bl.hits -
            angle * 20 -
            100 *
              Math.min(
                ...[137, 177].map(
                  (size) => Math.abs((a + b) / (2 * module) + 7 - size) / size,
                ),
              ),
        });
      }
    }
  }
  return found
    .sort((a, b) => b.score - a.score)
    .slice(0, QR_IMAGE_LIMITS.triples);
}

type Transform = (x: number, y: number) => ScanPoint;

// Four noncollinear correspondences determine the eight homography coefficients.
function homography(
  source: ScanPoint[],
  target: ScanPoint[],
): Transform | undefined {
  const rows: number[][] = [];
  for (let i = 0; i < 4; i++) {
    const { x, y } = source[i];
    const { x: u, y: v } = target[i];
    rows.push([x, y, 1, 0, 0, 0, -u * x, -u * y, u]);
    rows.push([0, 0, 0, x, y, 1, -v * x, -v * y, v]);
  }
  for (let column = 0; column < 8; column++) {
    let pivot = column;
    for (let i = column + 1; i < 8; i++) {
      if (Math.abs(rows[i][column]) > Math.abs(rows[pivot][column])) {
        pivot = i;
      }
    }
    if (Math.abs(rows[pivot][column]) < 1e-8) {
      return;
    }
    [rows[column], rows[pivot]] = [rows[pivot], rows[column]];
    const divisor = rows[column][column];
    for (let j = column; j <= 8; j++) {
      rows[column][j] /= divisor;
    }
    eliminateColumn(rows, column);
  }
  const c = rows.map((row) => row[8]);
  return (x, y) => {
    const divisor = c[6] * x + c[7] * y + 1;
    return {
      x: (c[0] * x + c[1] * y + c[2]) / divisor,
      y: (c[3] * x + c[4] * y + c[5]) / divisor,
    };
  };
}

function eliminateColumn(rows: number[][], column: number): void {
  for (let i = 0; i < 8; i++) {
    if (i === column) {
      continue;
    }
    const factor = rows[i][column];
    for (let j = column; j <= 8; j++) {
      rows[i][j] -= factor * rows[column][j];
    }
  }
}

function affine(t: Triple, size: number): Transform {
  return (x, y) => ({
    x:
      t.tl.x +
      ((x - 3.5) * (t.tr.x - t.tl.x)) / (size - 7) +
      ((y - 3.5) * (t.bl.x - t.tl.x)) / (size - 7),
    y:
      t.tl.y +
      ((x - 3.5) * (t.tr.y - t.tl.y)) / (size - 7) +
      ((y - 3.5) * (t.bl.y - t.tl.y)) / (size - 7),
  });
}

function alignmentMatching(
  image: BinaryImage,
  x: number,
  y: number,
  ux: number,
  uy: number,
  vx: number,
  vy: number,
  scale: number,
): number {
  let matching = 0;
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      const px = Math.floor(x + scale * (dx * ux + dy * vx));
      const py = Math.floor(y + scale * (dx * uy + dy * vy));
      if (px < 0 || py < 0 || px >= image.width || py >= image.height) {
        continue;
      }
      const dark = Number(Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      matching += Number(image.pixels[py * image.width + px] === dark);
    }
  }
  return matching;
}

function searchAlignmentRings(
  cx: number,
  cy: number,
  step: number,
  radius: number,
  visit: (x: number, y: number) => boolean,
): void {
  visit(cx, cy);
  for (let ring = step; ring <= radius; ring += step) {
    for (let offset = -ring; offset <= ring; offset += step) {
      if (!visit(cx + offset, cy - ring) || !visit(cx + offset, cy + ring)) {
        return;
      }
      if (
        Math.abs(offset) !== ring &&
        (!visit(cx - ring, cy + offset) || !visit(cx + ring, cy + offset))
      ) {
        return;
      }
    }
  }
}

function refineAlignment(
  center: ScanPoint,
  step: number,
  stopAt: number,
  result: QRImageResult,
  score: (x: number, y: number) => void,
): void {
  for (let y = center.y - step; y <= center.y + step; y++) {
    for (let x = center.x - step; x <= center.x + step; x++) {
      if (result.work.alignmentChecks >= stopAt) {
        break;
      }
      score(x, y);
    }
  }
}

function centeredAlignment(
  image: BinaryImage,
  point: ScanPoint,
  module: number,
): ScanPoint {
  const horizontal = darkCenter(image, point.x, point.y, false, module);
  const vertical =
    horizontal === undefined
      ? undefined
      : darkCenter(image, horizontal, point.y, true, module);
  return horizontal === undefined || vertical === undefined
    ? point
    : { x: horizontal, y: vertical };
}

function alignment(
  image: BinaryImage,
  t: Triple,
  size: number,
  result: QRImageResult,
): ScanPoint[] {
  const initial = affine(t, size);
  const expected = initial(size - 6.5, size - 6.5);
  const ux = (t.tr.x - t.tl.x) / (size - 7),
    uy = (t.tr.y - t.tl.y) / (size - 7);
  const vx = (t.bl.x - t.tl.x) / (size - 7),
    vy = (t.bl.y - t.tl.y) / (size - 7);
  const module = (Math.hypot(ux, uy) + Math.hypot(vx, vy)) / 2;
  const radius = Math.ceil(module * size * 0.2);
  const step = Math.max(1, Math.floor(module / 2));
  let best: ScanPoint | undefined;
  let bestScore = -Infinity;
  const alternatives: { point: ScanPoint; score: number }[] = [];
  // Reserve alignment work for both version hypotheses of every visible symbol.
  // Search outward from the affine prediction so a local quota retains nearby
  // matches instead of spending it on one edge of the search square.
  const stopAt = Math.min(
    QR_IMAGE_LIMITS.alignmentChecks,
    result.work.alignmentChecks +
      Math.floor(
        QR_IMAGE_LIMITS.alignmentChecks /
          (Math.min(
            QR_IMAGE_LIMITS.symbols,
            Math.ceil(result.work.candidates / 3),
          ) *
            2),
      ),
  );
  const score = (x: number, y: number) => {
    if (result.work.alignmentChecks >= QR_IMAGE_LIMITS.alignmentChecks) {
      result.exhausted = true;
      return;
    }
    result.work.alignmentChecks++;
    for (const scale of [1, 0.85, 1.15]) {
      const matching = alignmentMatching(image, x, y, ux, uy, vx, vy, scale);
      const value =
        matching - Math.hypot(x - expected.x, y - expected.y) / (radius * 5);
      if (matching >= 24) {
        const nearby = alternatives.find(
          (candidate) =>
            Math.hypot(candidate.point.x - x, candidate.point.y - y) <
            module * 4,
        );
        if (nearby && value > nearby.score) {
          nearby.point = { x, y };
          nearby.score = value;
        }
        if (!nearby) {
          alternatives.push({ point: { x, y }, score: value });
        }
        alternatives.sort((a, b) => b.score - a.score);
        alternatives.splice(4);
      }
      if (matching >= 24 && value > bestScore) {
        best = { x, y };
        bestScore = value;
      }
    }
  };
  const cx = Math.floor(expected.x),
    cy = Math.floor(expected.y);
  const visit = (x: number, y: number): boolean => {
    if (result.work.alignmentChecks >= stopAt) {
      return false;
    }
    if (x >= 0 && y >= 0 && x < image.width && y < image.height) {
      score(x + 0.5, y + 0.5);
    }
    return true;
  };
  searchAlignmentRings(cx, cy, step, radius, visit);
  if (best) {
    refineAlignment(best, step, stopAt, result, score);
    // Pattern scores have a flat maximum inside the central dark module.
    // Run boundaries locate its center without favoring the affine prediction.
    best = centeredAlignment(image, best, module);
  }
  if (!best) {
    return [];
  }
  const points = [best];
  for (const candidate of alternatives) {
    if (
      Math.hypot(candidate.point.x - best.x, candidate.point.y - best.y) <
      module * 4
    ) {
      continue;
    }
    points.push(centeredAlignment(image, candidate.point, module));
  }
  return points;
}

function darkCenter(
  image: BinaryImage,
  x: number,
  y: number,
  vertical: boolean,
  module: number,
): number | undefined {
  const fixed = Math.floor(vertical ? x : y);
  const start = Math.floor(vertical ? y : x);
  const length = vertical ? image.height : image.width;
  const at = (position: number) =>
    image.pixels[
      vertical ? position * image.width + fixed : fixed * image.width + position
    ];
  if (
    start < 0 ||
    start >= length ||
    fixed < 0 ||
    fixed >= (vertical ? image.width : image.height) ||
    !at(start)
  ) {
    return;
  }
  let left = start;
  let right = start + 1;
  const limit = Math.ceil(module * 3);
  while (left >= 0 && at(left) && start - left <= limit) {
    left--;
  }
  while (right < length && at(right) && right - start <= limit) {
    right++;
  }
  if (left < 0 || right >= length || right - left - 1 > limit) {
    return;
  }
  return (left + 1 + right) / 2;
}

function sample(
  image: BinaryImage,
  transform: Transform,
  size: number,
  interpolate = false,
  sharpen = false,
): Uint8Array | undefined {
  // The BCH fields use the same sampling rule as payload modules. Rejecting an
  // unreadable grid here avoids sampling thousands of unrelated data modules.
  readQRMetadata(
    size,
    (x, y) => sampleModule(image, transform, x, y, interpolate, sharpen) ?? 2,
  );
  const modules = new Uint8Array(size * size);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const value = sampleModule(image, transform, x, y, interpolate, sharpen);
      if (value === undefined) {
        return;
      }
      modules[y * size + x] = value;
    }
  }
  return modules;
}

function sampleModule(
  image: BinaryImage,
  transform: Transform,
  x: number,
  y: number,
  interpolate: boolean,
  sharpen: boolean,
): number | undefined {
  const point = transform(x + 0.5, y + 0.5);
  if (!pointInImage(image, point)) {
    return;
  }
  if (!interpolate) {
    return image.pixels[
      Math.floor(point.y) * image.width + Math.floor(point.x)
    ];
  }
  // Pixel centers are half-integer coordinates. Interpolate luminance relative
  // to its local threshold to retain contrast under camera blur.
  const px = point.x - 0.5,
    py = point.y - 0.5;
  const ix = Math.floor(px),
    iy = Math.floor(py);
  const dx = px - ix,
    dy = py - iy;
  const contrast =
    localContrast(image, ix, iy, sharpen) * (1 - dx) * (1 - dy) +
    localContrast(image, ix + 1, iy, sharpen) * dx * (1 - dy) +
    localContrast(image, ix, iy + 1, sharpen) * (1 - dx) * dy +
    localContrast(image, ix + 1, iy + 1, sharpen) * dx * dy;
  return Number(contrast < 0);
}

function localContrast(
  image: BinaryImage,
  x: number,
  y: number,
  sharpen: boolean,
): number {
  x = Math.max(0, Math.min(image.width - 1, x));
  y = Math.max(0, Math.min(image.height - 1, y));
  const center = image.gray[y * image.width + x];
  const value = sharpen
    ? 2 * center -
      (image.gray[y * image.width + Math.max(0, x - 1)] +
        image.gray[y * image.width + Math.min(image.width - 1, x + 1)] +
        image.gray[Math.max(0, y - 1) * image.width + x] +
        image.gray[Math.min(image.height - 1, y + 1) * image.width + x]) /
        4
    : center;
  return (
    value - image.thresholds[(y >>> 4) * image.thresholdColumns + (x >>> 4)]
  );
}

function grayAt(image: BinaryImage, x: number, y: number): number {
  const px = x - 0.5,
    py = y - 0.5;
  const ix = Math.floor(px),
    iy = Math.floor(py);
  const dx = px - ix,
    dy = py - iy;
  const x0 = Math.max(0, Math.min(image.width - 1, ix)),
    x1 = Math.max(0, Math.min(image.width - 1, ix + 1));
  const y0 = Math.max(0, Math.min(image.height - 1, iy)) * image.width,
    y1 = Math.max(0, Math.min(image.height - 1, iy + 1)) * image.width;
  return (
    image.gray[y0 + x0] * (1 - dx) * (1 - dy) +
    image.gray[y0 + x1] * dx * (1 - dy) +
    image.gray[y1 + x0] * (1 - dx) * dy +
    image.gray[y1 + x1] * dx * dy
  );
}

function refinedGrid(
  image: BinaryImage,
  initial: Transform,
  size: number,
  result: QRImageResult,
): Transform | undefined {
  const centers = (
    size === 137 ? [6, 26, 52, 78, 104, 130] : [6, 30, 58, 86, 114, 142, 170]
  ).map((v) => v + 0.5);
  const last = centers.length - 1;
  // A 5x5 alignment pattern has 17 dark and eight light modules. Equal class
  // weights keep the center estimate independent of surrounding brightness.
  // Each center uses 121 coarse positions and nine quarter-pixel refinements.
  if (
    result.work.alignmentChecks + (centers.length ** 2 - 3) * 130 >
    QR_IMAGE_LIMITS.alignmentChecks
  ) {
    return;
  }
  let accepted = 0;
  const grid = centers.map((ay, row) =>
    centers.map((ax, column) => {
      if (
        (row === 0 && (column === 0 || column === last)) ||
        (row === last && column === 0)
      ) {
        return { dx: 0, dy: 0 };
      }
      const predicted = initial(ax, ay),
        right = initial(ax + 1, ay),
        down = initial(ax, ay + 1);
      const ux = right.x - predicted.x,
        uy = right.y - predicted.y;
      const vx = down.x - predicted.x,
        vy = down.y - predicted.y;
      let best = { score: Infinity, dx: 0, dy: 0 };
      const score = (dx: number, dy: number) => {
        result.work.alignmentChecks++;
        let dark = 0,
          light = 0;
        for (let y = -2; y <= 2; y++) {
          for (let x = -2; x <= 2; x++) {
            const value = grayAt(
              image,
              predicted.x + dx + x * ux + y * vx,
              predicted.y + dy + x * uy + y * vy,
            );
            if (Math.max(Math.abs(x), Math.abs(y)) === 1) {
              light += value;
            } else {
              dark += value;
            }
          }
        }
        const value = dark / 17 - light / 8;
        if (value < best.score) {
          best = { score: value, dx, dy };
        }
      };
      for (let dy = -2.5; dy <= 2.5; dy += 0.5) {
        for (let dx = -2.5; dx <= 2.5; dx += 0.5) {
          score(dx, dy);
        }
      }
      const coarse = best;
      for (let dy = coarse.dy - 0.25; dy <= coarse.dy + 0.25; dy += 0.25) {
        for (let dx = coarse.dx - 0.25; dx <= coarse.dx + 0.25; dx += 0.25) {
          score(dx, dy);
        }
      }
      if (best.score > -24) {
        return { dx: 0, dy: 0 };
      }
      accepted++;
      return best;
    }),
  );
  if (accepted < (centers.length ** 2 - 3) / 2) {
    return;
  }
  const interval = (value: number) => {
    let index = 0;
    while (index < last - 1 && value > centers[index + 1]) {
      index++;
    }
    return {
      index,
      weight: (value - centers[index]) / (centers[index + 1] - centers[index]),
    };
  };
  return (x, y) => {
    const a = interval(x),
      b = interval(y),
      point = initial(x, y);
    for (const key of ['dx', 'dy'] as const) {
      point[key === 'dx' ? 'x' : 'y'] +=
        grid[b.index][a.index][key] * (1 - a.weight) * (1 - b.weight) +
        grid[b.index][a.index + 1][key] * a.weight * (1 - b.weight) +
        grid[b.index + 1][a.index][key] * (1 - a.weight) * b.weight +
        grid[b.index + 1][a.index + 1][key] * a.weight * b.weight;
    }
    return point;
  };
}

function pointInImage(image: BinaryImage, point: ScanPoint): boolean {
  return (
    Number.isFinite(point.x) &&
    Number.isFinite(point.y) &&
    point.x >= 0 &&
    point.y >= 0 &&
    point.x < image.width &&
    point.y < image.height
  );
}

function adaptiveSamples(
  image: BinaryImage,
  transform: Transform,
  size: number,
): { values: Float32Array; thresholds: number[] } | undefined {
  const values = new Float32Array(size * size),
    histogram = new Uint32Array(256);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const point = transform(x + 0.5, y + 0.5);
      if (!pointInImage(image, point)) {
        return;
      }
      const value = grayAt(image, point.x, point.y);
      values[y * size + x] = value;
      histogram[Math.floor(value)]++;
    }
  }
  let total = 0;
  for (let i = 0; i < 256; i++) {
    total += i * histogram[i];
  }
  let weight = 0,
    sum = 0,
    best = -1,
    threshold = 0,
    separation = 0;
  // Otsu's between-class variance separates module-center luminance, rather
  // than the darkest and lightest camera pixels in a tile. Nearby cutoffs cover
  // class asymmetry under blur without relaxing BCH or parity verification.
  for (let i = 0; i < 256; i++) {
    weight += histogram[i];
    sum += i * histogram[i];
    if (weight === 0 || weight === values.length) {
      continue;
    }
    const difference = (total - sum) / (values.length - weight) - sum / weight;
    const variance = weight * (values.length - weight) * difference ** 2;
    if (variance > best) {
      best = variance;
      threshold = i + 0.5;
      separation = difference;
    }
  }
  if (best < 0 || separation < 24) {
    return;
  }
  return {
    values,
    thresholds: [
      threshold + separation / 8,
      threshold,
      threshold - separation / 8,
    ],
  };
}

function decode(
  image: BinaryImage,
  t: Triple,
  size: number,
  result: QRImageResult,
  retries: MatrixRetry[],
  alignments: MatrixRetry[],
): QRImageSymbol | undefined {
  const a = Math.hypot(t.tr.x - t.tl.x, t.tr.y - t.tl.y);
  const b = Math.hypot(t.bl.x - t.tl.x, t.bl.y - t.tl.y);
  const observed = (t.tl.module + t.tr.module + t.bl.module) / 3;
  const estimate = (a + b) / (2 * (size - 7));
  if (estimate / observed < 0.7 || estimate / observed > 1.3) {
    return;
  }
  let failure: string | undefined;
  const tryMatrix = (
    read: () => Uint8Array | undefined,
    transform: Transform,
  ): QRImageSymbol | undefined => {
    failure = undefined;
    if (result.work.matrixAttempts >= QR_IMAGE_LIMITS.matrixAttempts) {
      result.exhausted = true;
      return;
    }
    result.work.matrixAttempts++;
    try {
      const modules = read();
      if (!modules) {
        return;
      }
      const decoded = decodeQRMatrix(modules, size);
      return {
        data: decoded.payload,
        points: [
          transform(0, 0),
          transform(size, 0),
          transform(size, size),
          transform(0, size),
        ],
      };
    } catch (error) {
      if (!(error instanceof QRDecodeError)) {
        throw error;
      }
      failure = error.code;
    }
  };
  const trySample = (
    transform: Transform,
    interpolate: boolean,
    sharpen = false,
  ) =>
    tryMatrix(
      () => sample(image, transform, size, interpolate, sharpen),
      transform,
    );
  const tryRefined = (transform: Transform): QRImageSymbol | undefined => {
    const mesh = refinedGrid(image, transform, size, result);
    const samples = mesh && adaptiveSamples(image, mesh, size);
    if (mesh && samples) {
      for (const threshold of samples.thresholds) {
        const symbol = tryMatrix(
          () =>
            Uint8Array.from(samples.values, (value) =>
              Number(value < threshold),
            ),
          mesh,
        );
        if (symbol || result.exhausted) {
          return symbol;
        }
      }
    }
  };
  const tryTransform = (
    transform: Transform,
    refine = false,
  ): QRImageSymbol | undefined => {
    const found = trySample(transform, false);
    // Valid BCH fields identify a plausible QR grid before blur retries spend
    // matrix work. Invalid format/version guesses stay behind the clean search.
    if (!found && !result.exhausted && failure === 'qr-reed-solomon') {
      const recovered =
        trySample(transform, true) ??
        (result.exhausted ? undefined : trySample(transform, true, true));
      if (recovered || result.exhausted || !refine) {
        return recovered;
      }
      return tryRefined(transform);
    }
    if (
      !found &&
      !result.exhausted &&
      retries.length < QR_IMAGE_LIMITS.matrixAttempts
    ) {
      retries.push({
        finders: [t.tl, t.tr, t.bl],
        read: () =>
          trySample(transform, true) ??
          (result.exhausted ? undefined : trySample(transform, true, true)),
      });
    }
    return found;
  };
  // QR BCH and parity disambiguate nearby alignment patterns under perspective.
  const simple = tryTransform(affine(t, size));
  if (simple || result.exhausted) {
    return simple;
  }
  const readAlignment = (): QRImageSymbol | undefined => {
    for (const point of alignment(image, t, size, result)) {
      const transform = homography(
        [
          { x: 3.5, y: 3.5 },
          { x: size - 3.5, y: 3.5 },
          { x: 3.5, y: size - 3.5 },
          { x: size - 6.5, y: size - 6.5 },
        ],
        [t.tl, t.tr, t.bl, point],
      );
      if (!transform) {
        continue;
      }
      const found = tryTransform(transform, true);
      if (found || result.exhausted) {
        return found;
      }
    }
  };
  if (alignments.length < QR_IMAGE_LIMITS.matrixAttempts) {
    alignments.push({ finders: [t.tl, t.tr, t.bl], read: readAlignment });
  }
}

function validateImage(
  data: Uint8ClampedArray | Uint8Array,
  width: number,
  height: number,
  maximumSymbols: number,
): void {
  if (
    !Number.isInteger(width) ||
    !Number.isInteger(height) ||
    width < 1 ||
    height < 1 ||
    width > QR_IMAGE_LIMITS.dimension ||
    height > QR_IMAGE_LIMITS.dimension ||
    !(data instanceof Uint8Array || data instanceof Uint8ClampedArray) ||
    data.length !== width * height * 4 ||
    !Number.isInteger(maximumSymbols) ||
    maximumSymbols < 1 ||
    maximumSymbols > QR_IMAGE_LIMITS.symbols
  ) {
    throw new RangeError(
      'QR image dimensions, RGBA bytes or symbol count exceed the scan bounds',
    );
  }
}

function tryPrimarySizes(
  image: BinaryImage,
  t: Triple,
  result: QRImageResult,
  retries: MatrixRetry[],
  alignments: MatrixRetry[],
): QRImageSymbol | 'budget' | 'exhausted' | undefined {
  const inferred =
    ((Math.hypot(t.tr.x - t.tl.x, t.tr.y - t.tl.y) +
      Math.hypot(t.bl.x - t.tl.x, t.bl.y - t.tl.y)) *
      1.5) /
      (t.tl.module + t.tr.module + t.bl.module) +
    7;
  for (const size of [137, 177].sort(
    (a, b) => Math.abs(a - inferred) - Math.abs(b - inferred),
  )) {
    if (result.work.matrixAttempts >= QR_IMAGE_LIMITS.symbols * 3) {
      return 'budget';
    }
    const symbol = decode(image, t, size, result, retries, alignments);
    if (symbol) {
      return symbol;
    }
    if (result.exhausted) {
      return 'exhausted';
    }
  }
}

/** Find at most four bounded binary QR symbols in local RGBA pixels. */
export function scanQRImage(
  data: Uint8ClampedArray | Uint8Array,
  width: number,
  height: number,
  maximumSymbols: number = QR_IMAGE_LIMITS.symbols,
): QRImageResult {
  validateImage(data, width, height, maximumSymbols);
  const result: QRImageResult = {
    symbols: [],
    work: {
      finderChecks: 0,
      candidates: 0,
      triples: 0,
      alignmentChecks: 0,
      matrixAttempts: 0,
    },
    exhausted: false,
  };
  const image = binarize(data, width, height);
  const found = finders(image, result);
  result.work.candidates = found.length;
  const candidates = triples(found);
  const consumed = new Set<Finder>();
  const retries: MatrixRetry[] = [];
  const alignments: MatrixRetry[] = [];
  // Give affine grids and contrast retries a bounded first pass before any
  // alignment search. Unsuccessful guesses cannot consume the entire budget
  // before the other symbols receive a matrix attempt.
  for (const t of candidates) {
    if ([t.tl, t.tr, t.bl].some((finder) => consumed.has(finder))) {
      continue;
    }
    result.work.triples++;
    const symbol = tryPrimarySizes(image, t, result, retries, alignments);
    if (symbol === 'budget') {
      break;
    }
    if (symbol === 'exhausted') {
      return result;
    }
    if (symbol) {
      result.symbols.push(symbol);
      for (const finder of [t.tl, t.tr, t.bl]) {
        consumed.add(finder);
      }
    }
    if (result.symbols.length === maximumSymbols) {
      break;
    }
  }
  // Guesses without valid BCH fields stay behind the clean search. All retries
  // share the same matrix budget, including retries of plausible QR grids.
  const readQueued = (
    queue: MatrixRetry[],
    start = 0,
    allowance: number = QR_IMAGE_LIMITS.matrixAttempts,
  ): number => {
    const matrixStart = result.work.matrixAttempts;
    let cursor = start;
    for (; cursor < queue.length; cursor++) {
      if (
        result.symbols.length === maximumSymbols ||
        result.exhausted ||
        result.work.matrixAttempts - matrixStart >= allowance
      ) {
        break;
      }
      const attempt = queue[cursor];
      if (attempt.finders.some((finder) => consumed.has(finder))) {
        continue;
      }
      const symbol = attempt.read();
      if (symbol) {
        result.symbols.push(symbol);
        for (const finder of attempt.finders) {
          consumed.add(finder);
        }
      }
    }
    return cursor;
  };
  const retryCursor = readQueued(retries, 0, QR_IMAGE_LIMITS.symbols * 2);
  readQueued(alignments);
  readQueued(retries, retryCursor);
  result.exhausted ||=
    result.work.alignmentChecks >= QR_IMAGE_LIMITS.alignmentChecks;
  return result;
}
