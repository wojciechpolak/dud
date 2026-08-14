// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export type CborValue =
  | boolean
  | number
  | string
  | Uint8Array
  | CborValue[]
  | Map<number, CborValue>;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

function encodeLength(major: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('CBOR unsigned integer is outside the safe range.');
  }
  if (value < 24) {
    return Uint8Array.of((major << 5) | value);
  }
  if (value <= 0xff) {
    return Uint8Array.of((major << 5) | 24, value);
  }
  if (value <= 0xffff) {
    return Uint8Array.of((major << 5) | 25, value >>> 8, value);
  }
  if (value <= 0xffffffff) {
    return Uint8Array.of(
      (major << 5) | 26,
      value / 0x1000000,
      value >>> 16,
      value >>> 8,
      value,
    );
  }

  const high = Math.floor(value / 0x100000000);
  const low = value >>> 0;
  return Uint8Array.of(
    (major << 5) | 27,
    high >>> 24,
    high >>> 16,
    high >>> 8,
    high,
    low >>> 24,
    low >>> 16,
    low >>> 8,
    low,
  );
}

function concat(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function compareEncoded(a: Uint8Array, b: Uint8Array): number {
  if (a.byteLength !== b.byteLength) {
    return a.byteLength - b.byteLength;
  }
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return 0;
}

export function encodeCbor(value: CborValue): Uint8Array {
  if (typeof value === 'boolean') {
    return Uint8Array.of(value ? 0xf5 : 0xf4);
  }
  if (typeof value === 'number') {
    return encodeLength(0, value);
  }
  if (typeof value === 'string') {
    const bytes = textEncoder.encode(value);
    return concat([encodeLength(3, bytes.byteLength), bytes]);
  }
  if (value instanceof Uint8Array) {
    return concat([encodeLength(2, value.byteLength), value]);
  }
  if (Array.isArray(value)) {
    return concat([
      encodeLength(4, value.length),
      ...value.map((entry) => encodeCbor(entry)),
    ]);
  }
  if (value instanceof Map) {
    const entries = Array.from(value.entries()).map(([key, entry]) => {
      if (!Number.isSafeInteger(key) || key < 0) {
        throw new Error('CBOR protocol map keys must be unsigned integers.');
      }
      return {
        key: encodeCbor(key),
        value: encodeCbor(entry),
      };
    });
    entries.sort((a, b) => compareEncoded(a.key, b.key));
    return concat([
      encodeLength(5, entries.length),
      ...entries.flatMap((entry) => [entry.key, entry.value]),
    ]);
  }
  throw new Error('Unsupported CBOR value.');
}

export interface CborDecodeOptions {
  maxArrayElements?: number;
  maxBytes?: number;
  maxDepth?: number;
  maxMapPairs?: number;
  requireDeterministic?: boolean;
}

class Decoder {
  private offset = 0;

  constructor(
    private readonly input: Uint8Array,
    private readonly options: Required<CborDecodeOptions>,
  ) {}

  decode(): CborValue {
    const value = this.decodeValue(0);
    if (this.offset !== this.input.byteLength) {
      throw new Error('CBOR body has trailing bytes.');
    }
    if (
      this.options.requireDeterministic &&
      !bytesEqual(encodeCbor(value), this.input)
    ) {
      throw new Error('CBOR body is not deterministic.');
    }
    return value;
  }

  private take(length: number): Uint8Array {
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      this.offset + length > this.input.byteLength
    ) {
      throw new Error('CBOR item is truncated.');
    }
    const value = this.input.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  private readLength(additional: number): number {
    if (additional < 24) {
      return additional;
    }
    let length: number;
    if (additional === 24) {
      length = this.take(1)[0];
      if (length < 24) {
        throw new Error('CBOR integer is not minimally encoded.');
      }
      return length;
    }
    if (additional === 25) {
      const bytes = this.take(2);
      length = bytes[0] * 0x100 + bytes[1];
      if (length <= 0xff) {
        throw new Error('CBOR integer is not minimally encoded.');
      }
      return length;
    }
    if (additional === 26) {
      const bytes = this.take(4);
      length =
        bytes[0] * 0x1000000 + bytes[1] * 0x10000 + bytes[2] * 0x100 + bytes[3];
      if (length <= 0xffff) {
        throw new Error('CBOR integer is not minimally encoded.');
      }
      return length;
    }
    if (additional === 27) {
      const bytes = this.take(8);
      const high =
        bytes[0] * 0x1000000 + bytes[1] * 0x10000 + bytes[2] * 0x100 + bytes[3];
      const low =
        bytes[4] * 0x1000000 + bytes[5] * 0x10000 + bytes[6] * 0x100 + bytes[7];
      length = high * 0x100000000 + low;
      if (!Number.isSafeInteger(length) || length <= 0xffffffff) {
        throw new Error('CBOR integer is invalid or not minimally encoded.');
      }
      return length;
    }
    if (additional === 31) {
      throw new Error('Indefinite-length CBOR items are forbidden.');
    }
    throw new Error('Reserved CBOR additional information.');
  }

  private decodeValue(depth: number): CborValue {
    if (depth >= this.options.maxDepth) {
      throw new Error('CBOR nesting exceeds the configured limit.');
    }
    const initial = this.take(1)[0];
    const major = initial >>> 5;
    const additional = initial & 0x1f;

    if (major === 0) {
      return this.readLength(additional);
    }
    if (major === 2 || major === 3) {
      const length = this.readLength(additional);
      if (length > this.options.maxBytes) {
        throw new Error('CBOR string exceeds the configured limit.');
      }
      const bytes = this.take(length);
      if (major === 2) {
        return new Uint8Array(bytes);
      }
      return textDecoder.decode(bytes);
    }
    if (major === 4) {
      const length = this.readLength(additional);
      if (length > this.options.maxArrayElements) {
        throw new Error('CBOR array exceeds the configured limit.');
      }
      const values: CborValue[] = [];
      for (let i = 0; i < length; i++) {
        values.push(this.decodeValue(depth + 1));
      }
      return values;
    }
    if (major === 5) {
      const length = this.readLength(additional);
      if (length > this.options.maxMapPairs) {
        throw new Error('CBOR map exceeds the configured limit.');
      }
      const values = new Map<number, CborValue>();
      for (let i = 0; i < length; i++) {
        const key = this.decodeValue(depth + 1);
        if (typeof key !== 'number') {
          throw new Error('CBOR protocol map key is not an unsigned integer.');
        }
        if (values.has(key)) {
          throw new Error('CBOR map contains a duplicate key.');
        }
        values.set(key, this.decodeValue(depth + 1));
      }
      return values;
    }
    if (major === 7 && additional === 20) {
      return false;
    }
    if (major === 7 && additional === 21) {
      return true;
    }
    throw new Error('Unsupported CBOR type.');
  }
}

export function decodeCbor(
  input: Uint8Array,
  options: CborDecodeOptions = {},
): CborValue {
  if (input.byteLength > (options.maxBytes ?? 262_144)) {
    throw new Error('CBOR body exceeds the configured limit.');
  }
  return new Decoder(input, {
    maxArrayElements: options.maxArrayElements ?? 4096,
    maxBytes: options.maxBytes ?? 262_144,
    maxDepth: options.maxDepth ?? 8,
    maxMapPairs: options.maxMapPairs ?? 128,
    requireDeterministic: options.requireDeterministic ?? true,
  }).decode();
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  const length = Math.max(a.byteLength, b.byteLength);
  let difference = a.byteLength ^ b.byteLength;
  for (let i = 0; i < length; i++) {
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return difference === 0;
}

export function requireCborMap(
  value: CborValue,
  allowedKeys: readonly number[],
  requiredKeys: readonly number[],
): Map<number, CborValue> {
  if (!(value instanceof Map)) {
    throw new Error('CBOR body must be a map.');
  }
  const allowed = new Set(allowedKeys);
  for (const key of value.keys()) {
    if (!allowed.has(key)) {
      throw new Error(`CBOR map contains unknown core key ${key}.`);
    }
  }
  for (const key of requiredKeys) {
    if (!value.has(key)) {
      throw new Error(`CBOR map is missing required key ${key}.`);
    }
  }
  return value;
}
