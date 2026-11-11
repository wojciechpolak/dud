// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { decodeQRMatrix } from '../.work/receiver/qr-matrix.js';
import { scanQRImage } from '../.work/receiver/qr-image.js';

test('Go QR profiles preserve binary bytes at every mask and capacity boundary', async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'dud-qr-decoder-'));
  try {
    execFileSync(
      'go',
      ['test', './optical-sender', '-run=^TestQRDecoderVectors$', '-count=1'],
      {
        cwd: fileURLToPath(new URL('../../../client/', import.meta.url)),
        env: {
          ...process.env,
          GOCACHE: '/tmp/dud-optical-go-build-cache',
          DUD_QR_TEST_OUTPUT: directory,
        },
      },
    );
    const vectors = JSON.parse(
      readFileSync(path.join(directory, 'vectors.json'), 'utf8'),
    );
    assert.equal(vectors.length, 72);
    for (const vector of vectors) {
      const pixels = readFileSync(path.join(directory, `${vector.file}.rgba`));
      // Go's test raster has a four-module margin and two pixels per module.
      const size = vector.side / 2 - 8;
      const modules = new Uint8Array(size * size);
      for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
          modules[y * size + x] = Number(
            pixels[((y + 4) * 2 * vector.side + (x + 4) * 2) * 4] === 0,
          );
        }
      }
      const decoded = decodeQRMatrix(modules, size);
      assert.deepEqual(
        Buffer.from(decoded.payload),
        Buffer.from(vector.payload, 'base64'),
        vector.file,
      );
      assert.equal(decoded.correctedCodewords, 0, vector.file);
      const scanned = scanQRImage(pixels, vector.side, vector.side);
      assert.equal(scanned.symbols.length, 1, vector.file);
      assert.deepEqual(
        Buffer.from(scanned.symbols[0].data),
        Buffer.from(vector.payload, 'base64'),
        vector.file,
      );
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
