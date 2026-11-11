// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { multiplyQRField as multiply } from './qr-gf256.js';

function power(value: number, exponent: number): number {
  let result = 1;
  while (exponent > 0) {
    if (exponent & 1) {
      result = multiply(result, value);
    }
    value = multiply(value, value);
    exponent >>>= 1;
  }
  return result;
}

function divide(a: number, b: number): number {
  if (b === 0) {
    throw new Error('Zero Reed-Solomon divisor');
  }
  return multiply(a, power(b, 254));
}

function syndromes(words: Uint8Array): Uint8Array {
  const result = new Uint8Array(30);
  let root = 1;
  for (let i = 0; i < result.length; i++) {
    for (const word of words) {
      result[i] = multiply(result[i], root) ^ word;
    }
    root = multiply(root, 2);
  }
  return result;
}

// Berlekamp-Massey finds the shortest recurrence for the syndrome sequence.
// Coefficients are in ascending order; roots are inverse error locations.
function locator(s: Uint8Array): { coefficients: Uint8Array; degree: number } {
  const coefficients = new Uint8Array(31);
  let previous = new Uint8Array(31);
  coefficients[0] = previous[0] = 1;
  let degree = 0;
  let shift = 1;
  let discrepancy = 1;
  for (let n = 0; n < s.length; n++) {
    let delta = s[n];
    for (let i = 1; i <= degree; i++) {
      delta ^= multiply(coefficients[i], s[n - i]);
    }
    if (delta === 0) {
      shift++;
      continue;
    }
    const saved = coefficients.slice();
    const factor = divide(delta, discrepancy);
    for (let i = 0; i + shift < coefficients.length; i++) {
      coefficients[i + shift] ^= multiply(factor, previous[i]);
    }
    if (2 * degree <= n) {
      degree = n + 1 - degree;
      previous = saved;
      discrepancy = delta;
      shift = 1;
    } else {
      shift++;
    }
  }
  return { coefficients, degree };
}

function errorPositions(
  coefficients: Uint8Array,
  degree: number,
  length: number,
): number[] {
  const positions: number[] = [];
  for (let position = 0; position < length; position++) {
    const inverse = power(2, (255 - (length - 1 - position)) % 255);
    let value = coefficients[degree];
    for (let i = degree - 1; i >= 0; i--) {
      value = multiply(value, inverse) ^ coefficients[i];
    }
    if (value === 0) {
      positions.push(position);
    }
  }
  return positions;
}

// Annex B's syndrome equations form a Vandermonde system for error magnitudes.
function magnitudes(
  positions: number[],
  s: Uint8Array,
  length: number,
): Uint8Array {
  const count = positions.length;
  const rows = Array.from({ length: count }, (_, row) => {
    const values = new Uint8Array(count + 1);
    for (let column = 0; column < count; column++) {
      values[column] = power(2, (row * (length - 1 - positions[column])) % 255);
    }
    values[count] = s[row];
    return values;
  });
  for (let column = 0; column < count; column++) {
    const pivot = rows.findIndex(
      (row, index) => index >= column && row[column] !== 0,
    );
    if (pivot < 0) {
      throw new Error('Singular Reed-Solomon equations');
    }
    [rows[column], rows[pivot]] = [rows[pivot], rows[column]];
    const divisor = rows[column][column];
    for (let j = column; j <= count; j++) {
      rows[column][j] = divide(rows[column][j], divisor);
    }
    for (let i = 0; i < count; i++) {
      if (i === column) {
        continue;
      }
      const factor = rows[i][column];
      for (let j = column; j <= count; j++) {
        rows[i][j] ^= multiply(factor, rows[column][j]);
      }
    }
  }
  return Uint8Array.from(rows, (row) => row[count]);
}

export interface CorrectedQRBlock {
  words: Uint8Array;
  correctedCodewords: number;
}

/** Correct a shortened QR block with 30 parity bytes, without mutating input. */
export function correctQRBlock(input: Uint8Array): CorrectedQRBlock {
  if (
    !(input instanceof Uint8Array) ||
    input.length < 31 ||
    input.length > 255
  ) {
    throw new Error('Invalid Reed-Solomon block length');
  }
  const words = input.slice();
  const s = syndromes(words);
  if (s.every((value) => value === 0)) {
    return { words, correctedCodewords: 0 };
  }
  const { coefficients, degree } = locator(s);
  if (degree < 1 || degree > 15) {
    throw new Error('Uncorrectable Reed-Solomon block');
  }
  const positions = errorPositions(coefficients, degree, words.length);
  if (positions.length !== degree) {
    throw new Error('Reed-Solomon roots do not match block');
  }
  const errors = magnitudes(positions, s, words.length);
  for (let i = 0; i < positions.length; i++) {
    words[positions[i]] ^= errors[i];
  }
  if (syndromes(words).some((value) => value !== 0)) {
    throw new Error('Reed-Solomon verification failed');
  }
  return { words, correctedCodewords: degree };
}
