// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

/**
 * Normalizes a binary column read back from D1, which hands BLOB values to the
 * Worker as `Array<number>` rather than the `Uint8Array` a SQLite driver bound
 * to the same column returns. `ArrayBuffer` costs one branch and keeps the
 * repositories working if D1 ever returns bytes directly.
 */
export function d1Bytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return Uint8Array.from(value);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value)) {
    return Uint8Array.from(value as readonly number[]);
  }
  throw new Error('D1 returned an invalid binary value.');
}
