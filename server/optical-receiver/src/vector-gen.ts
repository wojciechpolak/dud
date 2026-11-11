// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { writeFileSync } from 'node:fs';

import {
  FORMAT_VERSION,
  BLOCK_SIZE,
  HEADER_SIZE,
  HIGH_DENSITY_BLOCK_SIZE,
  MAX_CAPSULE_SIZE,
  MAX_STRIPE_SIZE,
  OpticalDecoder,
  OpticalEncoder,
  recomputeCrc,
  selectBlocks,
} from './codec.js';

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

function vectorCapsule(length: number): Uint8Array {
  return Uint8Array.from(
    { length },
    (_, index) =>
      (Math.imul(index, 73) + Math.imul(index >>> 8, 19) + 41) & 0xff,
  );
}

function setUint32(
  frame: Uint8Array,
  offset: number,
  value: number,
): Uint8Array {
  const copy = new Uint8Array(frame);
  new DataView(copy.buffer).setUint32(offset, value);
  recomputeCrc(copy);
  return copy;
}

function setUint16(
  frame: Uint8Array,
  offset: number,
  value: number,
): Uint8Array {
  const copy = new Uint8Array(frame);
  new DataView(copy.buffer).setUint16(offset, value);
  recomputeCrc(copy);
  return copy;
}

async function frameCase(
  name: string,
  length: number,
  sessionId: Uint8Array,
  requested: ReadonlyArray<readonly [number, number]>,
  blockSize = BLOCK_SIZE,
) {
  const capsule = vectorCapsule(length);
  const encoder = await OpticalEncoder.create(capsule, sessionId, blockSize);
  const frames = requested.map(([stripe, sequence]) => {
    const bytes = encoder.frame(stripe, sequence);
    return {
      stripe,
      sequence,
      selected: selectBlocks(
        sessionId,
        stripe,
        sequence,
        encoder.getSourceCount(stripe),
      ),
      bytes: hex(bytes),
    };
  });
  const decoder = new OpticalDecoder();
  if (name === 'complete-capsule' || name === 'high-density-complete') {
    for (let sequence = 0; sequence < encoder.getSourceCount(0); sequence++) {
      decoder.add(encoder.frame(0, sequence));
    }
    await decoder.result();
  }
  return {
    name,
    recipe: 'index-73-page-19-plus-41',
    capsuleLength: length,
    blockSize,
    digest: hex(encoder.digest),
    frames,
  };
}

const sessionId = Uint8Array.from({ length: 16 }, (_, index) => index * 17);
const complete = await frameCase('complete-capsule', 2401, sessionId, [
  [0, 0],
  [0, 1],
  [0, 2],
  [0, 3],
  [0, 4],
  [0, 17],
]);
const boundary = await frameCase(
  'stripe-boundary',
  MAX_STRIPE_SIZE + 1,
  sessionId,
  [
    [0, 0],
    [0, 1024],
    [0, 1030],
    [1, 0],
    [1, 1],
  ],
);
const highDensity = await frameCase(
  'high-density-complete',
  HIGH_DENSITY_BLOCK_SIZE * 2 + 1,
  sessionId,
  [
    [0, 0],
    [0, 1],
    [0, 2],
    [0, 17],
  ],
  HIGH_DENSITY_BLOCK_SIZE,
);
const base = Uint8Array.from(BufferFromHex(complete.frames[0].bytes));
const invalid = [
  { name: 'empty', code: 'frame-length', bytes: '' },
  {
    name: 'truncated-header',
    code: 'frame-length',
    bytes: hex(base.subarray(0, HEADER_SIZE)),
  },
  {
    name: 'truncated-qr-payload',
    code: 'frame-length',
    bytes: hex(base.subarray(0, base.length - 1)),
  },
  { name: 'magic', code: 'magic', bytes: hex(mutate(base, 0, 0xff)) },
  { name: 'version', code: 'version', bytes: hex(mutate(base, 8, 1)) },
  { name: 'features', code: 'features', bytes: hex(mutate(base, 9, 1)) },
  {
    name: 'header-length',
    code: 'header-length',
    bytes: hex(mutate(base, 11, 87)),
  },
  {
    name: 'block-size',
    code: 'block-size',
    bytes: hex(mutate(base, 39, 1)),
  },
  {
    name: 'payload-length',
    code: 'payload-length',
    bytes: hex(mutate(base, 53, 1)),
  },
  {
    name: 'payload-length-maximum',
    code: 'payload-length',
    bytes: hex(setUint16(base, 52, 0xffff)),
  },
  { name: 'crc', code: 'crc', bytes: hex(mutate(base, 100, 0x80)) },
  {
    name: 'capsule-length-over-limit',
    code: 'capsule-length',
    bytes: hex(setUint32(base, 40, MAX_CAPSULE_SIZE + 1)),
  },
  {
    name: 'capsule-length-uint32-maximum',
    code: 'capsule-length',
    bytes: hex(setUint32(base, 40, 0xffff_ffff)),
  },
  {
    name: 'stripe-count',
    code: 'stripe-count',
    bytes: hex(setUint16(base, 34, 2)),
  },
  {
    name: 'stripe-count-maximum',
    code: 'stripe-count',
    bytes: hex(setUint16(base, 34, 0xffff)),
  },
  {
    name: 'stripe-index-maximum',
    code: 'stripe-index',
    bytes: hex(setUint16(base, 32, 0xffff)),
  },
  {
    name: 'stripe-offset',
    code: 'stripe-offset',
    bytes: hex(setUint32(base, 44, 1)),
  },
  {
    name: 'stripe-offset-uint32-maximum',
    code: 'stripe-offset',
    bytes: hex(setUint32(base, 44, 0xffff_ffff)),
  },
  {
    name: 'stripe-length',
    code: 'stripe-length',
    bytes: hex(setUint32(base, 48, 2400)),
  },
  {
    name: 'stripe-length-uint32-maximum',
    code: 'stripe-length',
    bytes: hex(setUint32(base, 48, 0xffff_ffff)),
  },
  {
    name: 'source-count',
    code: 'source-count',
    bytes: hex(setUint16(base, 36, 3)),
  },
  {
    name: 'source-count-maximum',
    code: 'source-count',
    bytes: hex(setUint16(base, 36, 0xffff)),
  },
  {
    name: 'impossible-fountain-degree',
    code: 'degree',
    bytes: hex(setUint16(base, 54, 0xffff)),
  },
  {
    name: 'sequence-uint32-maximum',
    code: 'degree',
    bytes: hex(setUint32(base, 28, 0xffff_ffff)),
  },
];
const collidingSession = mutateWithCrc(base, 12, 0xff);
const digestSubstitution = mutateWithCrc(base, 56, 0xff);
const inconsistentMetadata = setUint32(setUint32(base, 40, 2402), 48, 2402);
const encodedBase = hex(base);
const hostile = [
  {
    name: 'duplicate-equation',
    frames: [encodedBase],
    repeat: 2,
    independentRows: 1,
  },
  {
    name: 'endless-duplicate-stream',
    frames: [encodedBase],
    repeat: 16384,
    independentRows: 1,
  },
  {
    name: 'colliding-session',
    frames: [encodedBase, hex(collidingSession)],
    repeat: 1,
    code: 'session',
    independentRows: 1,
  },
  {
    name: 'digest-substitution',
    frames: [encodedBase, hex(digestSubstitution)],
    repeat: 1,
    code: 'session',
    independentRows: 1,
  },
  {
    name: 'inconsistent-session-metadata',
    frames: [encodedBase, hex(inconsistentMetadata)],
    repeat: 1,
    code: 'session',
    independentRows: 1,
  },
];
// Development-only vectors construct private bytes outside the receiver bundle.
async function privateContainers() {
  const entries = [
    {
      name: 'hello-file',
      payloadType: 3,
      archiveFormat: 0,
      displayName: 'note.txt',
      payload: '68656c6c6f',
    },
    {
      name: 'empty-stream',
      payloadType: 2,
      archiveFormat: 0,
      displayName: 'stdin.bin',
      payload: '',
    },
    {
      name: 'binary-utf8-name',
      payloadType: 1,
      archiveFormat: 0,
      displayName: 'wiadomość.txt',
      payload: '00ff0a7f',
    },
    {
      name: 'empty-collection',
      payloadType: 4,
      archiveFormat: 1,
      displayName: 'dud-collection.tar',
      payload: '00'.repeat(1024),
    },
  ];
  return Promise.all(
    entries.map(async (entry) => {
      const name = new TextEncoder().encode(entry.displayName);
      const payload = BufferFromHex(entry.payload);
      const encoded = new Uint8Array(64 + name.length + payload.length);
      encoded.set(new TextEncoder().encode('DUDCAP1\0'));
      encoded[8] = 1;
      encoded[9] = entry.payloadType;
      encoded[10] = entry.archiveFormat;
      const view = new DataView(encoded.buffer);
      view.setUint16(12, 64);
      view.setUint16(14, name.length);
      view.setBigUint64(16, BigInt(payload.length));
      view.setBigUint64(24, BigInt(payload.length));
      encoded.set(
        new Uint8Array(
          await crypto.subtle.digest(
            'SHA-256',
            payload as Uint8Array<ArrayBuffer>,
          ),
        ),
        32,
      );
      encoded.set(name, 64);
      encoded.set(payload, 64 + name.length);
      return { ...entry, bytes: hex(encoded) };
    }),
  );
}

const output = {
  format: FORMAT_VERSION,
  generatedBy: 'typescript',
  sessionId: hex(sessionId),
  selection: [
    {
      stripe: 0,
      sequence: 0,
      sourceCount: 4,
      selected: selectBlocks(sessionId, 0, 0, 4),
    },
    {
      stripe: 0,
      sequence: 4,
      sourceCount: 4,
      selected: selectBlocks(sessionId, 0, 4, 4),
    },
    {
      stripe: 0,
      sequence: 1121,
      sourceCount: 1024,
      selected: selectBlocks(sessionId, 0, 1121, 1024),
    },
    {
      stripe: 7,
      sequence: 1007,
      sourceCount: 1000,
      selected: selectBlocks(sessionId, 7, 1007, 1000),
    },
    {
      stripe: 85,
      sequence: 0xffff_fffe,
      sourceCount: 1024,
      selected: selectBlocks(sessionId, 85, 0xffff_fffe, 1024),
    },
  ],
  cases: [complete, boundary, highDensity],
  invalid,
  hostile,
  privateContainers: await privateContainers(),
};

const target = process.argv[2];
if (!target) {
  throw new Error('usage: vector-gen OUTPUT.json');
}
writeFileSync(target, `${JSON.stringify(output, null, 2)}\n`);

function mutate(value: Uint8Array, offset: number, xor: number): Uint8Array {
  const copy = new Uint8Array(value);
  copy[offset] ^= xor;
  return copy;
}

function mutateWithCrc(
  value: Uint8Array,
  offset: number,
  xor: number,
): Uint8Array {
  const copy = mutate(value, offset, xor);
  recomputeCrc(copy);
  return copy;
}

function BufferFromHex(value: string): Uint8Array {
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index++) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}
