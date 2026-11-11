// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export const FORMAT_VERSION = 1;
export const HEADER_SIZE = 88;
export const BLOCK_SIZE = 1600;
export const HIGH_DENSITY_BLOCK_SIZE = 2860;
export const FRAME_SIZE = HEADER_SIZE + BLOCK_SIZE + 4;
export const HIGH_DENSITY_FRAME_SIZE =
  HEADER_SIZE + HIGH_DENSITY_BLOCK_SIZE + 4;
export const MAX_SOURCE_BLOCKS = 1024;
export const MAX_STRIPE_SIZE = BLOCK_SIZE * MAX_SOURCE_BLOCKS;
export const MAX_CAPSULE_SIZE = 64 * 1024 * 1024;
export const MAX_STRIPE_COUNT = Math.ceil(MAX_CAPSULE_SIZE / MAX_STRIPE_SIZE);
export const MAX_ACTIVE_STRIPES = MAX_STRIPE_COUNT;
export const MAX_ACTIVE_SESSIONS = 1;
export const MAX_DISTINCT_FRAMES = 131_072;
export const MAX_RETAINED_EQUATIONS = Math.ceil(MAX_CAPSULE_SIZE / BLOCK_SIZE);
// Repair-heavy elimination can process hundreds of bytes per source byte.
// Each stripe gets 512 times its padded source size; the total also has a
// ceiling of 512 times the maximum capsule size.
const WORK_BYTES_PER_SOURCE_BYTE = 512;
export const MAX_DECODER_WORK_BYTES =
  MAX_CAPSULE_SIZE * WORK_BYTES_PER_SOURCE_BYTE;
const SESSION_ID_SIZE = 16;

function maximumEquationStorageBytes(): number {
  let total = 0;
  for (let offset = 0; offset < MAX_CAPSULE_SIZE; offset += MAX_STRIPE_SIZE) {
    const length = Math.min(MAX_STRIPE_SIZE, MAX_CAPSULE_SIZE - offset);
    const count = Math.ceil(length / BLOCK_SIZE);
    const coefficientBytes =
      Math.ceil(count / 32) * Uint32Array.BYTES_PER_ELEMENT;
    total += count * (BLOCK_SIZE + coefficientBytes);
  }
  return total;
}

export const MAX_EQUATION_STORAGE_BYTES = maximumEquationStorageBytes();
export const MAX_DECODER_TYPED_STORAGE_BYTES =
  MAX_EQUATION_STORAGE_BYTES + MAX_CAPSULE_SIZE;

const FRAME_MAGIC = Uint8Array.of(0x44, 0x55, 0x44, 0x4f, 0x50, 0x54, 0x31, 0);

const FORMAT_ZERO_MAGIC = Uint8Array.of(
  0x44,
  0x55,
  0x44,
  0x4f,
  0x50,
  0x54,
  0x30,
  0,
);

export class OpticalCodecError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = 'OpticalCodecError';
    this.code = code;
  }
}

function reject(code: string, message: string): never {
  throw new OpticalCodecError(code, message);
}

export interface OpticalFrame {
  sessionId: Uint8Array;
  sequence: number;
  stripeIndex: number;
  stripeCount: number;
  sourceCount: number;
  blockSize: number;
  capsuleLength: number;
  stripeLength: number;
  degree: number;
  digest: Uint8Array;
  payload: Uint8Array;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

function copyBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

function validBlockSize(blockSize: number): boolean {
  return blockSize === BLOCK_SIZE || blockSize === HIGH_DENSITY_BLOCK_SIZE;
}

function stripeSize(blockSize: number): number {
  return blockSize * MAX_SOURCE_BLOCKS;
}

function stripeCount(capsuleLength: number, blockSize: number): number {
  return Math.ceil(capsuleLength / stripeSize(blockSize));
}

function sourceCount(stripeLength: number, blockSize: number): number {
  return Math.ceil(stripeLength / blockSize);
}

function mix32(value: number): number {
  value = (value ^ (value >>> 16)) >>> 0;
  value = Math.imul(value, 0x21f0_aaad) >>> 0;
  value = (value ^ (value >>> 15)) >>> 0;
  value = Math.imul(value, 0x735a_2d97) >>> 0;
  return (value ^ (value >>> 15)) >>> 0;
}

function selectionDegree(draw: number, count: number): number {
  let degree = 31;
  if (draw < 500) {
    degree = 2;
  } else if (draw < 750) {
    degree = 3;
  } else if (draw < 875) {
    degree = 4;
  } else if (draw < 938) {
    degree = 5;
  } else if (draw < 969) {
    degree = 6;
  } else if (draw < 985) {
    degree = 7;
  }
  return Math.min(degree, count);
}

function drawDistinctBlocks(
  next: () => number,
  count: number,
  degree: number,
): number[] {
  const selected: number[] = [];
  while (selected.length < degree) {
    const candidate = next() % count;
    let position = 0;
    while (position < selected.length && selected[position] < candidate) {
      position++;
    }
    if (selected[position] === candidate) {
      continue;
    }
    selected.splice(position, 0, candidate);
  }
  return selected;
}

export function selectBlocks(
  sessionId: Uint8Array,
  stripeIndex: number,
  sequence: number,
  count: number,
): number[] {
  if (sessionId.byteLength !== SESSION_ID_SIZE) {
    throw new RangeError('session ID must contain 16 bytes');
  }
  if (!Number.isInteger(count) || count < 1 || count > 1024) {
    throw new RangeError('source-block count is outside the optical bound');
  }
  if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffff_ffff) {
    throw new RangeError('frame sequence is outside uint32');
  }
  if (sequence < count) {
    return [sequence];
  }

  let state = 0x6d2b_79f5;
  for (const value of sessionId) {
    state = mix32((state ^ value) >>> 0);
  }
  state = mix32((state ^ stripeIndex) >>> 0);
  state = mix32((state ^ sequence) >>> 0);
  const next = (): number => {
    state = (state + 0x9e37_79b9) >>> 0;
    state = mix32(state);
    return state;
  };

  const degree = selectionDegree(next() % 1000, count);
  return drawDistinctBlocks(next, count, degree);
}

const crcTable = new Uint32Array(256);
for (let index = 0; index < crcTable.length; index++) {
  let value = index;
  for (let bit = 0; bit < 8; bit++) {
    value = value & 1 ? 0xedb8_8320 ^ (value >>> 1) : value >>> 1;
  }
  crcTable[index] = value >>> 0;
}

function crc32(data: Uint8Array): number {
  let value = 0xffff_ffff;
  for (const byte of data) {
    value = crcTable[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffff_ffff) >>> 0;
}

export function recomputeCrc(frame: Uint8Array): void {
  if (frame.byteLength < HEADER_SIZE + 4) {
    return;
  }
  new DataView(frame.buffer, frame.byteOffset, frame.byteLength).setUint32(
    frame.byteLength - 4,
    crc32(frame.subarray(0, frame.byteLength - 4)),
  );
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data);
  try {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', copy.buffer));
  } finally {
    copy.fill(0);
  }
}

export class OpticalEncoder {
  readonly capsule: Uint8Array;
  readonly sessionId: Uint8Array;
  readonly digest: Uint8Array;
  readonly stripeCount: number;
  readonly blockSize: number;
  readonly stripeSize: number;

  private constructor(
    capsule: Uint8Array,
    sessionId: Uint8Array,
    digest: Uint8Array,
    blockSize: number,
  ) {
    this.capsule = copyBytes(capsule);
    this.sessionId = copyBytes(sessionId);
    this.digest = copyBytes(digest);
    this.blockSize = blockSize;
    this.stripeSize = stripeSize(blockSize);
    this.stripeCount = stripeCount(capsule.byteLength, blockSize);
  }

  static async create(
    capsule: Uint8Array,
    sessionId: Uint8Array,
    blockSize = BLOCK_SIZE,
  ): Promise<OpticalEncoder> {
    if (capsule.byteLength < 1 || capsule.byteLength > MAX_CAPSULE_SIZE) {
      reject(
        'capsule-length',
        `capsule length ${capsule.byteLength} is outside 1..${MAX_CAPSULE_SIZE}`,
      );
    }
    if (sessionId.byteLength !== SESSION_ID_SIZE) {
      throw new RangeError('session ID must contain 16 bytes');
    }
    if (!validBlockSize(blockSize)) {
      reject('block-size', `source block size ${blockSize} is unsupported`);
    }
    return new OpticalEncoder(
      capsule,
      sessionId,
      await sha256(capsule),
      blockSize,
    );
  }

  // Receiver tests call this through the compiled codec module.
  // fallow-ignore-next-line unused-class-member
  getSourceCount(stripeIndex: number): number {
    return sourceCount(this.stripeBounds(stripeIndex).length, this.blockSize);
  }

  // Receiver tests call this through the compiled codec module.
  // fallow-ignore-next-line unused-class-member
  frame(stripeIndex: number, sequence: number): Uint8Array {
    const { offset, length } = this.stripeBounds(stripeIndex);
    const count = sourceCount(length, this.blockSize);
    const indexes = selectBlocks(this.sessionId, stripeIndex, sequence, count);
    const payload = new Uint8Array(this.blockSize);
    for (const blockIndex of indexes) {
      const blockStart = offset + blockIndex * this.blockSize;
      const blockEnd = Math.min(blockStart + this.blockSize, offset + length);
      for (
        let sourceOffset = blockStart;
        sourceOffset < blockEnd;
        sourceOffset++
      ) {
        payload[sourceOffset - blockStart] ^= this.capsule[sourceOffset];
      }
    }

    const frameSize = HEADER_SIZE + this.blockSize + 4;
    const frame = new Uint8Array(frameSize);
    const view = new DataView(frame.buffer);
    frame.set(FRAME_MAGIC, 0);
    frame[8] = FORMAT_VERSION;
    frame[9] = 0;
    view.setUint16(10, HEADER_SIZE);
    frame.set(this.sessionId, 12);
    view.setUint32(28, sequence);
    view.setUint16(32, stripeIndex);
    view.setUint16(34, this.stripeCount);
    view.setUint16(36, count);
    view.setUint16(38, this.blockSize);
    view.setUint32(40, this.capsule.byteLength);
    view.setUint32(44, offset);
    view.setUint32(48, length);
    view.setUint16(52, this.blockSize);
    view.setUint16(54, indexes.length);
    frame.set(this.digest, 56);
    frame.set(payload, HEADER_SIZE);
    view.setUint32(frameSize - 4, crc32(frame.subarray(0, frameSize - 4)));
    return frame;
  }

  private stripeBounds(stripeIndex: number): {
    offset: number;
    length: number;
  } {
    if (
      !Number.isInteger(stripeIndex) ||
      stripeIndex < 0 ||
      stripeIndex >= this.stripeCount
    ) {
      reject(
        'stripe-index',
        `stripe index ${stripeIndex} is outside 0..${this.stripeCount - 1}`,
      );
    }
    const offset = stripeIndex * this.stripeSize;
    return {
      offset,
      length: Math.min(this.stripeSize, this.capsule.byteLength - offset),
    };
  }
}

function validatedFrameHeader(data: Uint8Array): {
  view: DataView;
  blockSize: number;
} {
  if (data.byteLength < HEADER_SIZE + 4) {
    reject(
      'frame-length',
      `frame length ${data.byteLength} is shorter than the fixed framing`,
    );
  }
  if (equalBytes(data.subarray(0, 8), FORMAT_ZERO_MAGIC)) {
    reject(
      'version',
      'unsupported optical sender; expected dud/optical/1, received format 0',
    );
  }
  if (!equalBytes(data.subarray(0, 8), FRAME_MAGIC)) {
    reject('magic', 'frame magic is invalid');
  }
  if (data[8] !== FORMAT_VERSION) {
    reject(
      'version',
      `unsupported optical sender; expected dud/optical/1, received format ${data[8]}`,
    );
  }
  if (data[9] !== 0) {
    reject('features', 'must-understand feature bits are set');
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint16(10) !== HEADER_SIZE) {
    reject('header-length', 'header length is invalid');
  }
  const blockSize = view.getUint16(38);
  if (!validBlockSize(blockSize)) {
    reject('block-size', 'source block size is invalid');
  }
  const frameSize = HEADER_SIZE + blockSize + 4;
  if (data.byteLength !== frameSize) {
    reject(
      'frame-length',
      `frame length ${data.byteLength} does not equal ${frameSize}`,
    );
  }
  if (view.getUint16(52) !== blockSize) {
    reject('payload-length', 'QR payload length is invalid');
  }
  if (
    view.getUint32(frameSize - 4) !== crc32(data.subarray(0, frameSize - 4))
  ) {
    reject('crc', 'frame CRC-32 is invalid');
  }
  return { view, blockSize };
}

export function parseFrame(data: Uint8Array): OpticalFrame {
  const { view, blockSize } = validatedFrameHeader(data);
  const frame: OpticalFrame = {
    sessionId: copyBytes(data.subarray(12, 28)),
    sequence: view.getUint32(28),
    stripeIndex: view.getUint16(32),
    stripeCount: view.getUint16(34),
    sourceCount: view.getUint16(36),
    blockSize,
    capsuleLength: view.getUint32(40),
    stripeLength: view.getUint32(48),
    degree: view.getUint16(54),
    digest: copyBytes(data.subarray(56, 88)),
    payload: new Uint8Array(0),
  };
  const stripeOffset = view.getUint32(44);
  if (frame.capsuleLength < 1 || frame.capsuleLength > MAX_CAPSULE_SIZE) {
    reject(
      'capsule-length',
      `declared capsule length ${frame.capsuleLength} is outside the optical bound`,
    );
  }
  const frameStripeSize = stripeSize(blockSize);
  const expectedStripes = stripeCount(frame.capsuleLength, blockSize);
  if (
    frame.stripeCount !== expectedStripes ||
    expectedStripes > MAX_STRIPE_COUNT
  ) {
    reject('stripe-count', 'stripe count is inconsistent with capsule length');
  }
  if (frame.stripeIndex >= expectedStripes) {
    reject('stripe-index', 'stripe index is outside the capsule');
  }
  const expectedOffset = frame.stripeIndex * frameStripeSize;
  const expectedLength = Math.min(
    frameStripeSize,
    frame.capsuleLength - expectedOffset,
  );
  if (stripeOffset !== expectedOffset) {
    reject('stripe-offset', 'stripe offset is inconsistent with stripe index');
  }
  if (frame.stripeLength !== expectedLength) {
    reject(
      'stripe-length',
      'stripe length is inconsistent with capsule length',
    );
  }
  const expectedSources = sourceCount(expectedLength, blockSize);
  if (frame.sourceCount !== expectedSources) {
    reject(
      'source-count',
      'source-block count is inconsistent with stripe length',
    );
  }
  const indexes = selectBlocks(
    frame.sessionId,
    frame.stripeIndex,
    frame.sequence,
    expectedSources,
  );
  if (frame.degree !== indexes.length) {
    reject('degree', 'fountain degree is inconsistent with frame sequence');
  }
  frame.payload = copyBytes(
    data.subarray(HEADER_SIZE, HEADER_SIZE + blockSize),
  );
  return frame;
}

interface Equation {
  coefficients: Uint32Array;
  payload: Uint8Array;
  payloadWords: Uint32Array;
}

class StripeDecoder {
  readonly sourceCount: number;
  readonly stripeLength: number;
  readonly blockSize: number;
  readonly basis = new Map<number, Equation>();
  private workBytes = 0;
  private readonly workLimitBytes: number;

  constructor(
    count: number,
    length: number,
    blockSize: number,
    private readonly spendGlobalWork: (bytes: number) => void,
    private readonly retainEquation: () => void,
  ) {
    this.sourceCount = count;
    this.stripeLength = length;
    this.blockSize = blockSize;
    this.workLimitBytes = count * blockSize * WORK_BYTES_PER_SOURCE_BYTE;
  }

  add(row: Equation): boolean {
    for (;;) {
      const pivot = firstSet(row.coefficients);
      if (pivot < 0) {
        if (row.payload.some((value) => value !== 0)) {
          reject('contradiction', 'dependent equation has a nonzero payload');
        }
        return false;
      }
      const existing = this.basis.get(pivot);
      if (!existing) {
        this.retainEquation();
        this.basis.set(pivot, row);
        return true;
      }
      this.spendWork(equationBytes(row));
      xorEquation(row, existing);
    }
  }

  solve(): Uint8Array {
    const blocks = Array.from(
      { length: this.sourceCount },
      () => new Uint8Array(this.blockSize),
    );
    const blockWords = blocks.map(wordsForPayload);
    for (let pivot = this.sourceCount - 1; pivot >= 0; pivot--) {
      const row = this.basis.get(pivot);
      if (!row) {
        reject('incomplete', `missing pivot ${pivot}`);
      }
      blocks[pivot].set(row.payload);
      for (let index = pivot + 1; index < this.sourceCount; index++) {
        if ((row.coefficients[index >>> 5] & (1 << (index & 31))) !== 0) {
          this.spendWork(this.blockSize);
          xorWords(blockWords[pivot], blockWords[index]);
        }
      }
    }
    const result = new Uint8Array(this.stripeLength);
    for (let index = 0; index < blocks.length; index++) {
      const offset = index * this.blockSize;
      result.set(
        blocks[index].subarray(
          0,
          Math.min(this.blockSize, result.length - offset),
        ),
        offset,
      );
    }
    return result;
  }

  clear(): void {
    for (const row of this.basis.values()) {
      row.coefficients.fill(0);
      row.payload.fill(0);
    }
    this.basis.clear();
    this.workBytes = 0;
  }

  private spendWork(bytes: number): void {
    if (this.workBytes + bytes > this.workLimitBytes) {
      reject(
        'decoder-work',
        `decoder stripe work limit ${this.workLimitBytes} byte operations reached`,
      );
    }
    this.spendGlobalWork(bytes);
    this.workBytes += bytes;
  }
}

export interface DecoderProgress {
  stripeIndex: number;
  independentRows: number;
  sourceCount: number;
  independentFrameCount: number;
  requiredFrameCount: number;
  stripeCount: number;
  distinctFrameCount: number;
  retainedEquationCount: number;
  workBytes: number;
}

export interface DecoderLimits {
  maxDistinctFrames: number;
  maxRetainedEquations: number;
  maxWorkBytes: number;
}

const DEFAULT_DECODER_LIMITS: Readonly<DecoderLimits> = {
  maxDistinctFrames: MAX_DISTINCT_FRAMES,
  maxRetainedEquations: MAX_RETAINED_EQUATIONS,
  maxWorkBytes: MAX_DECODER_WORK_BYTES,
};

export class OpticalDecoder {
  private initialized = false;
  private sessionId: Uint8Array = new Uint8Array(0);
  private digest: Uint8Array = new Uint8Array(0);
  private capsuleLength = 0;
  private stripeCount = 0;
  private blockSize = 0;
  private workBytes = 0;
  private workLimitBytes: number;
  private retainedEquationCount = 0;
  private readonly distinctFrames = new Set<number>();
  private readonly active = new Map<number, StripeDecoder>();
  private readonly recovered = new Map<number, Uint8Array>();

  constructor(
    private readonly limits: Readonly<DecoderLimits> = DEFAULT_DECODER_LIMITS,
  ) {
    this.workLimitBytes = limits.maxWorkBytes;
  }

  get complete(): boolean {
    return this.initialized && this.recovered.size === this.stripeCount;
  }

  add(data: Uint8Array): DecoderProgress {
    this.spendWork(data.byteLength);
    const frame = parseFrame(data);
    if (!this.initialized) {
      this.workLimitBytes = Math.min(
        this.limits.maxWorkBytes,
        Math.ceil(frame.capsuleLength / frame.blockSize) *
          frame.blockSize *
          WORK_BYTES_PER_SOURCE_BYTE,
      );
      if (this.workBytes > this.workLimitBytes) {
        reject(
          'decoder-work',
          `decoder work limit ${this.workLimitBytes} byte operations reached`,
        );
      }
      this.initialized = true;
      this.sessionId = frame.sessionId;
      this.digest = frame.digest;
      this.capsuleLength = frame.capsuleLength;
      this.stripeCount = frame.stripeCount;
      this.blockSize = frame.blockSize;
    } else if (
      !equalBytes(frame.sessionId, this.sessionId) ||
      !equalBytes(frame.digest, this.digest) ||
      frame.capsuleLength !== this.capsuleLength ||
      frame.stripeCount !== this.stripeCount ||
      frame.blockSize !== this.blockSize
    ) {
      reject('session', 'frame belongs to a different or inconsistent session');
    }

    const frameKey = frame.stripeIndex * 0x1_0000_0000 + frame.sequence;
    if (!this.distinctFrames.has(frameKey)) {
      if (this.distinctFrames.size >= this.limits.maxDistinctFrames) {
        reject(
          'distinct-frames',
          `distinct optical frame limit ${this.limits.maxDistinctFrames} reached`,
        );
      }
      this.distinctFrames.add(frameKey);
    }

    if (this.recovered.has(frame.stripeIndex)) {
      return this.progress(
        frame.stripeIndex,
        frame.sourceCount,
        frame.sourceCount,
      );
    }
    let stripe = this.active.get(frame.stripeIndex);
    if (!stripe) {
      if (this.active.size >= MAX_ACTIVE_STRIPES) {
        reject(
          'active-stripes',
          `unfinished stripe count exceeds ${MAX_ACTIVE_STRIPES}`,
        );
      }
      stripe = new StripeDecoder(
        frame.sourceCount,
        frame.stripeLength,
        frame.blockSize,
        (bytes) => this.spendWork(bytes),
        () => this.retainEquation(),
      );
      this.active.set(frame.stripeIndex, stripe);
    }
    const coefficients = new Uint32Array(Math.ceil(stripe.sourceCount / 32));
    for (const index of selectBlocks(
      frame.sessionId,
      frame.stripeIndex,
      frame.sequence,
      stripe.sourceCount,
    )) {
      coefficients[index >>> 5] |= 1 << (index & 31);
    }
    const independent = stripe.add({
      coefficients,
      payload: frame.payload,
      payloadWords: wordsForPayload(frame.payload),
    });
    const independentRows = stripe.basis.size;
    if (independent && stripe.basis.size === stripe.sourceCount) {
      this.recovered.set(frame.stripeIndex, stripe.solve());
      this.active.delete(frame.stripeIndex);
      this.retainedEquationCount -= stripe.basis.size;
      stripe.clear();
    }
    return this.progress(
      frame.stripeIndex,
      independentRows,
      stripe.sourceCount,
    );
  }

  clear(): void {
    for (const stripe of this.active.values()) {
      stripe.clear();
    }
    for (const bytes of this.recovered.values()) {
      bytes.fill(0);
    }
    this.active.clear();
    this.recovered.clear();
    this.distinctFrames.clear();
    this.sessionId.fill(0);
    this.digest.fill(0);
    this.initialized = false;
    this.capsuleLength = 0;
    this.stripeCount = 0;
    this.blockSize = 0;
    this.workBytes = 0;
    this.workLimitBytes = this.limits.maxWorkBytes;
    this.retainedEquationCount = 0;
  }

  async result(): Promise<Uint8Array> {
    if (!this.complete) {
      reject('incomplete', 'not every stripe has been recovered');
    }
    const result = new Uint8Array(this.capsuleLength);
    for (let index = 0; index < this.stripeCount; index++) {
      const stripe = this.recovered.get(index);
      if (!stripe) {
        reject('incomplete', `stripe ${index} has not been recovered`);
      }
      result.set(stripe, index * stripeSize(this.blockSize));
    }
    if (!equalBytes(await sha256(result), this.digest)) {
      result.fill(0);
      reject('digest', 'reconstructed capsule digest does not match');
    }
    return result;
  }

  private progress(
    stripeIndex: number,
    rows: number,
    sources: number,
  ): DecoderProgress {
    let independentFrameCount = 0;
    for (const stripe of this.active.values()) {
      independentFrameCount += stripe.basis.size;
    }
    for (const stripe of this.recovered.values()) {
      independentFrameCount += sourceCount(stripe.byteLength, this.blockSize);
    }
    return {
      stripeIndex,
      independentRows: rows,
      sourceCount: sources,
      independentFrameCount,
      requiredFrameCount: sourceCount(this.capsuleLength, this.blockSize),
      stripeCount: this.stripeCount,
      distinctFrameCount: this.distinctFrames.size,
      retainedEquationCount: this.retainedEquationCount,
      workBytes: this.workBytes,
    };
  }

  private spendWork(bytes: number): void {
    if (this.workBytes + bytes > this.workLimitBytes) {
      reject(
        'decoder-work',
        `decoder work limit ${this.workLimitBytes} byte operations reached`,
      );
    }
    this.workBytes += bytes;
  }

  private retainEquation(): void {
    if (this.retainedEquationCount >= this.limits.maxRetainedEquations) {
      reject(
        'retained-equations',
        `retained equation limit ${this.limits.maxRetainedEquations} reached`,
      );
    }
    this.retainedEquationCount++;
  }
}

function equationBytes(equation: Equation): number {
  return equation.coefficients.byteLength + equation.payload.byteLength;
}

function firstSet(coefficients: Uint32Array): number {
  for (let wordIndex = 0; wordIndex < coefficients.length; wordIndex++) {
    const word = coefficients[wordIndex];
    if (word !== 0) {
      return wordIndex * 32 + (31 - Math.clz32(word & -word));
    }
  }
  return -1;
}

function xorEquation(target: Equation, source: Equation): void {
  for (let index = 0; index < target.coefficients.length; index++) {
    target.coefficients[index] ^= source.coefficients[index];
  }
  xorWords(target.payloadWords, source.payloadWords);
}

function wordsForPayload(payload: Uint8Array): Uint32Array {
  // Both frame block sizes are multiples of four, and parsed payloads and solve
  // blocks own aligned buffers. Wordwise XOR preserves bytewise XOR on either
  // host byte order and reuses the payload allocation.
  return new Uint32Array(
    payload.buffer,
    payload.byteOffset,
    payload.byteLength / Uint32Array.BYTES_PER_ELEMENT,
  );
}

function xorWords(target: Uint32Array, source: Uint32Array): void {
  for (let index = 0; index < target.length; index++) {
    target[index] ^= source[index];
  }
}
