// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(
    parts.reduce((length, part) => length + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

/**
 * Copies a view into a standalone ArrayBuffer. Web Crypto accepts only
 * ArrayBuffer-backed sources under strict typing, and a copy keeps a subarray
 * from exposing the bytes outside its window.
 */
export function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}
