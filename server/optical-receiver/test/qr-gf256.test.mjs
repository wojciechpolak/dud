// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';
import { multiplyQRField } from '../.work/receiver/qr-gf256.js';

// Reduce the complete carryless polynomial product without logarithm tables.
function polynomialProduct(a, b) {
  let product = 0;
  for (let bit = 0; bit < 8; bit++) {
    if (b & (1 << bit)) {
      product ^= a << bit;
    }
  }
  for (let bit = 14; bit >= 8; bit--) {
    if (product & (1 << bit)) {
      product ^= 0x11d << (bit - 8);
    }
  }
  return product;
}

test('QR field multiplication matches polynomial reduction for every byte pair', () => {
  for (let a = 0; a < 256; a++) {
    for (let b = 0; b < 256; b++) {
      assert.equal(multiplyQRField(a, b), polynomialProduct(a, b), `${a},${b}`);
    }
  }
});
