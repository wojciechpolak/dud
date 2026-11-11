// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { correctQRBlock } from './qr-reed-solomon.js';

export class QRDecodeError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'QRDecodeError';
  }
}

function reject(code: string, message: string): never {
  throw new QRDecodeError(code, message);
}

interface Profile {
  version: 30 | 40;
  size: number;
  dataWords: number;
  shortBlocks: number;
  longBlocks: number;
  shortData: number;
  alignment: number[];
}

function profile(size: number): Profile {
  if (size === 137) {
    return {
      version: 30,
      size,
      dataWords: 1735,
      shortBlocks: 5,
      longBlocks: 10,
      shortData: 115,
      alignment: [6, 26, 52, 78, 104, 130],
    };
  }
  if (size === 177) {
    return {
      version: 40,
      size,
      dataWords: 2956,
      shortBlocks: 19,
      longBlocks: 6,
      shortData: 118,
      alignment: [6, 30, 58, 86, 114, 142, 170],
    };
  }
  return reject('qr-version', 'Expected a Version 30 or 40 matrix');
}

function bch(data: number, degree: number, generator: number): number {
  let remainder = data << degree;
  for (let bit = 17; bit >= degree; bit--) {
    if (remainder & (1 << bit)) {
      remainder ^= generator << (bit - degree);
    }
  }
  return (data << degree) | remainder;
}

function distance(a: number, b: number): number {
  let value = a ^ b;
  let count = 0;
  while (value !== 0) {
    value &= value - 1;
    count++;
  }
  return count;
}

function nearest(
  bits: number,
  candidates: number[],
  degree: number,
  generator: number,
  xor: number,
): number | undefined {
  return candidates.find(
    (data) => distance(bits, bch(data, degree, generator) ^ xor) <= 3,
  );
}

function copies(
  first: number | undefined,
  second: number | undefined,
  code: string,
): number {
  if (first === undefined && second === undefined) {
    return reject(code, 'Both BCH copies are unreadable');
  }
  if (first !== undefined && second !== undefined && first !== second) {
    return reject(code, 'BCH copies disagree');
  }
  return (first ?? second)!;
}

function readFormat(
  read: (x: number, y: number) => number,
  size: number,
): number {
  let first = 0;
  let second = 0;
  for (let bit = 0; bit < 15; bit++) {
    const x = bit < 8 ? 8 : bit === 8 ? 7 : 14 - bit;
    const y = bit < 6 ? bit : bit < 8 ? bit + 1 : 8;
    first |= read(x, y) << bit;
    second |=
      (bit < 8 ? read(size - 1 - bit, 8) : read(8, size - 15 + bit)) << bit;
  }
  // Decode all levels before enforcing L, so another level cannot be mistaken for L.
  const candidates = Array.from({ length: 32 }, (_, index) => index);
  const data = copies(
    nearest(first, candidates, 10, 0x537, 0x5412),
    nearest(second, candidates, 10, 0x537, 0x5412),
    'qr-format',
  );
  if (data >>> 3 !== 1) {
    return reject('qr-error-correction', 'Expected level L');
  }
  return data & 7;
}

function checkVersion(
  read: (x: number, y: number) => number,
  p: Profile,
): void {
  let first = 0;
  let second = 0;
  for (let bit = 0; bit < 18; bit++) {
    const x = p.size - 11 + (bit % 3);
    const y = Math.floor(bit / 3);
    first |= read(x, y) << bit;
    second |= read(y, x) << bit;
  }
  const candidates = Array.from({ length: 34 }, (_, index) => index + 7);
  const value = copies(
    nearest(first, candidates, 12, 0x1f25, 0),
    nearest(second, candidates, 12, 0x1f25, 0),
    'qr-version',
  );
  if (value !== p.version) {
    reject(
      'qr-version',
      'Version information disagrees with matrix dimensions',
    );
  }
}

/** Validate both BCH fields using only their 66 module positions. */
export function readQRMetadata(
  size: number,
  read: (x: number, y: number) => number,
): { version: 30 | 40; mask: number } {
  const p = profile(size);
  const binary = (x: number, y: number): number => {
    const value = read(x, y);
    if (value !== 0 && value !== 1) {
      return reject('qr-matrix', 'Expected binary metadata modules');
    }
    return value;
  };
  checkVersion(binary, p);
  return { version: p.version, mask: readFormat(binary, size) };
}

function functionModules(p: Profile): Uint8Array {
  const reserved = new Uint8Array(p.size * p.size);
  const mark = (x: number, y: number) => {
    reserved[y * p.size + x] = 1;
  };
  const rectangle = (
    left: number,
    top: number,
    width: number,
    height: number,
  ) => {
    for (let y = top; y < top + height; y++) {
      for (let x = left; x < left + width; x++) {
        mark(x, y);
      }
    }
  };
  rectangle(0, 0, 9, 9);
  rectangle(p.size - 8, 0, 8, 9);
  rectangle(0, p.size - 8, 9, 8);
  for (let i = 0; i < p.size; i++) {
    mark(6, i);
    mark(i, 6);
  }
  const last = p.alignment.length - 1;
  for (let y = 0; y <= last; y++) {
    for (let x = 0; x <= last; x++) {
      if (
        (x === 0 && y === 0) ||
        (x === last && y === 0) ||
        (x === 0 && y === last)
      ) {
        continue;
      }
      rectangle(p.alignment[x] - 2, p.alignment[y] - 2, 5, 5);
    }
  }
  rectangle(p.size - 11, 0, 3, 6);
  rectangle(0, p.size - 11, 6, 3);
  return reserved;
}

function masked(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    case 7:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return false;
  }
}

function appendWordBit(words: Uint8Array, bit: number, value: number): void {
  if (bit < words.length * 8) {
    words[bit >>> 3] |= value << (7 - (bit & 7));
  }
}

function readWords(modules: Uint8Array, p: Profile, mask: number): Uint8Array {
  const reserved = functionModules(p);
  const words = new Uint8Array(
    p.dataWords + 30 * (p.shortBlocks + p.longBlocks),
  );
  let bit = 0;
  let upward = true;
  for (let right = p.size - 1; right > 0; right -= 2) {
    if (right === 6) {
      right--;
    }
    for (let row = 0; row < p.size; row++) {
      const y = upward ? p.size - 1 - row : row;
      for (let x = right; x >= right - 1; x--) {
        const index = y * p.size + x;
        if (reserved[index]) {
          continue;
        }
        appendWordBit(words, bit, modules[index] ^ Number(masked(mask, x, y)));
        bit++;
      }
    }
    upward = !upward;
  }
  return words;
}

function recover(
  words: Uint8Array,
  p: Profile,
): { data: Uint8Array; correctedCodewords: number } {
  const blocks = Array.from(
    { length: p.shortBlocks + p.longBlocks },
    (_, index) =>
      new Uint8Array(p.shortData + Number(index >= p.shortBlocks) + 30),
  );
  let offset = 0;
  for (let column = 0; column <= p.shortData; column++) {
    for (const block of blocks) {
      if (column < block.length - 30) {
        block[column] = words[offset++];
      }
    }
  }
  for (let column = 0; column < 30; column++) {
    for (const block of blocks) {
      block[block.length - 30 + column] = words[offset++];
    }
  }
  const data = new Uint8Array(p.dataWords);
  let correctedCodewords = 0;
  offset = 0;
  for (const block of blocks) {
    let corrected;
    try {
      corrected = correctQRBlock(block);
    } catch {
      return reject('qr-reed-solomon', 'Uncorrectable codeword block');
    }
    const payload = corrected.words.subarray(0, block.length - 30);
    data.set(payload, offset);
    offset += payload.length;
    correctedCodewords += corrected.correctedCodewords;
  }
  return { data, correctedCodewords };
}

function byteSegment(data: Uint8Array): Uint8Array {
  let bit = 0;
  const read = (count: number) => {
    if (bit + count > data.length * 8) {
      return reject('qr-capacity', 'Segment exceeds data capacity');
    }
    let value = 0;
    for (let i = 0; i < count; i++, bit++) {
      value = (value << 1) | ((data[bit >>> 3] >>> (7 - (bit & 7))) & 1);
    }
    return value;
  };
  if (read(4) !== 4) {
    return reject('qr-mode', 'Expected one byte-mode segment');
  }
  const length = read(16);
  if (20 + length * 8 + 4 > data.length * 8) {
    return reject('qr-capacity', 'Byte count exceeds profile capacity');
  }
  const payload = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    payload[i] = read(8);
  }
  if (read(4) !== 0) {
    return reject('qr-mode', 'Expected byte segment terminator');
  }
  let pad = 0xec;
  while (bit < data.length * 8) {
    if (read(8) !== pad) {
      return reject('qr-padding', 'Invalid byte segment padding');
    }
    pad ^= 0xfd;
  }
  return payload;
}

export interface DecodedQRMatrix {
  payload: Uint8Array;
  version: 30 | 40;
  mask: number;
  correctedCodewords: number;
}

/** Decode a row-major binary matrix with top-left, top-right and bottom-left finders. */
export function decodeQRMatrix(
  modules: Uint8Array,
  size: number,
): DecodedQRMatrix {
  const p = profile(size);
  if (
    !(modules instanceof Uint8Array) ||
    modules.length !== size * size ||
    modules.some((value) => value > 1)
  ) {
    return reject('qr-matrix', 'Expected exactly one binary value per module');
  }
  const { mask } = readQRMetadata(size, (x, y) => modules[y * size + x]);
  const { data, correctedCodewords } = recover(readWords(modules, p, mask), p);
  return {
    payload: byteSegment(data),
    version: p.version,
    mask,
    correctedCodewords,
  };
}
