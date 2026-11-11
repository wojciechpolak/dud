// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  decodeQRMatrix,
  readQRMetadata,
  QRDecodeError,
} from '../.work/receiver/qr-matrix.js';
import { correctQRBlock } from '../.work/receiver/qr-reed-solomon.js';

function fixture(version, name = 'random') {
  const record = JSON.parse(
    readFileSync(
      new URL(
        `../../../client/optical-sender/testdata/qr/oracle-v${version}-${name}.json`,
        import.meta.url,
      ),
      'utf8',
    ),
  );
  return {
    size: record.rows.length,
    modules: Uint8Array.from(record.rows.join(''), Number),
    payload: Buffer.from(record.payload, 'base64'),
  };
}

function corruptCopies(modules, positions, count) {
  for (const copy of positions) {
    for (const index of copy.slice(0, count)) {
      modules[index] ^= 1;
    }
  }
}

function rejects(fn, code) {
  assert.throws(
    fn,
    (error) => error instanceof QRDecodeError && error.code === code,
  );
}

function metadataPositions(size) {
  const positions = new Set();
  for (let bit = 0; bit < 18; bit++) {
    const x = size - 11 + (bit % 3),
      y = Math.floor(bit / 3);
    positions.add(`${x},${y}`);
    positions.add(`${y},${x}`);
  }
  for (let bit = 0; bit < 15; bit++) {
    const x = bit < 8 ? 8 : bit === 8 ? 7 : 14 - bit;
    const y = bit < 6 ? bit : bit < 8 ? bit + 1 : 8;
    positions.add(`${x},${y}`);
    positions.add(bit < 8 ? `${size - 1 - bit},8` : `8,${size - 15 + bit}`);
  }
  return positions;
}

test('BCH metadata reads only both format and version copies independently of payload modules', () => {
  for (const version of [30, 40]) {
    const { modules, size } = fixture(version);
    const positions = metadataPositions(size);
    let reads = 0;
    const header = readQRMetadata(size, (x, y) => {
      assert.ok(positions.has(`${x},${y}`));
      reads++;
      return modules[y * size + x];
    });
    assert.equal(reads, 66);
    assert.equal(header.version, version);
    assert.equal(header.mask, decodeQRMatrix(modules, size).mask);
    rejects(() => readQRMetadata(size, () => 2), 'qr-matrix');
    rejects(() => readQRMetadata(size, () => undefined), 'qr-matrix');
  }
  rejects(() => readQRMetadata(21, () => 0), 'qr-version');
});

// Test field multiplication reduces the complete polynomial product in one pass.
function gf(a, b) {
  let polynomial = 0;
  for (let bit = 0; bit < 8; bit++) {
    if (b & (1 << bit)) {
      polynomial ^= a << bit;
    }
  }
  for (let bit = 14; bit >= 8; bit--) {
    if (polynomial & (1 << bit)) {
      polynomial ^= 0x11d << (bit - 8);
    }
  }
  return polynomial;
}

function encodedBlock(data) {
  let generator = [1];
  let root = 1;
  for (let i = 0; i < 30; i++) {
    const next = new Array(generator.length + 1).fill(0);
    for (let j = 0; j < generator.length; j++) {
      next[j] ^= generator[j];
      next[j + 1] ^= gf(generator[j], root);
    }
    generator = next;
    root = gf(root, 2);
  }
  const remainder = new Uint8Array(data.length + 30);
  remainder.set(data);
  for (let i = 0; i < data.length; i++) {
    const factor = remainder[i];
    for (let j = 0; j < generator.length; j++) {
      remainder[i + j] ^= gf(factor, generator[j]);
    }
  }
  const block = new Uint8Array(remainder.length);
  block.set(data);
  block.set(remainder.subarray(data.length), data.length);
  return block;
}

function profile(version) {
  return version === 30
    ? {
        data: 1735,
        short: 5,
        count: 15,
        length: 115,
        alignment: [6, 26, 52, 78, 104, 130],
      }
    : {
        data: 2956,
        short: 19,
        count: 25,
        length: 118,
        alignment: [6, 30, 58, 86, 114, 142, 170],
      };
}

function reserved(x, y, size, alignment) {
  if (x === 6 || y === 6) {
    return true;
  }
  if (
    (x < 9 && y < 9) ||
    (x >= size - 8 && y < 9) ||
    (x < 9 && y >= size - 8)
  ) {
    return true;
  }
  if (
    (x >= size - 11 && x < size - 8 && y < 6) ||
    (y >= size - 11 && y < size - 8 && x < 6)
  ) {
    return true;
  }
  return alignment.some((cx, ix) =>
    alignment.some((cy, iy) => {
      const last = alignment.length - 1;
      const finder =
        (ix === 0 && iy === 0) ||
        (ix === last && iy === 0) ||
        (ix === 0 && iy === last);
      return !finder && Math.abs(x - cx) <= 2 && Math.abs(y - cy) <= 2;
    }),
  );
}

function coordinates(version) {
  const size = 17 + version * 4;
  const { alignment } = profile(version);
  const coordinates = [];
  let stripe = 0;
  for (let column = size - 1; column > 0; column -= 2, stripe++) {
    if (column === 6) {
      column--;
    }
    for (let i = 0; i < size; i++) {
      const y = stripe % 2 === 0 ? size - 1 - i : i;
      for (const x of [column, column - 1]) {
        if (!reserved(x, y, size, alignment)) {
          coordinates.push(y * size + x);
        }
      }
    }
  }
  return coordinates;
}

function maskBit(mask, x, y) {
  const product = x * y;
  return (
    [
      (x + y) % 2,
      y % 2,
      x % 3,
      (x + y) % 3,
      (Math.floor(y / 2) + Math.floor(x / 3)) % 2,
      (product % 2) + (product % 3),
      ((product % 2) + (product % 3)) % 2,
      (((x + y) % 2) + (product % 3)) % 2,
    ][mask] === 0
  );
}

function bch(data, degree, generator) {
  let value = data << degree;
  for (let bit = 17; bit >= degree; bit--) {
    if (value & (1 << bit)) {
      value ^= generator << (bit - degree);
    }
  }
  return (data << degree) | value;
}

function formatCoordinates(size) {
  const first = [];
  const second = [];
  for (let i = 0; i < 15; i++) {
    first.push(
      i < 6
        ? i * size + 8
        : i < 8
          ? (i + 1) * size + 8
          : i === 8
            ? 8 * size + 7
            : 8 * size + 14 - i,
    );
    second.push(i < 8 ? 8 * size + size - 1 - i : (size - 15 + i) * size + 8);
  }
  return [first, second];
}

function versionCoordinates(size) {
  const first = [];
  const second = [];
  for (let i = 0; i < 18; i++) {
    const x = size - 11 + (i % 3);
    const y = Math.floor(i / 3);
    first.push(y * size + x);
    second.push(x * size + y);
  }
  return [first, second];
}

function writeBits(modules, positions, bits) {
  for (const copy of positions) {
    copy.forEach((position, i) => {
      modules[position] = (bits >>> i) & 1;
    });
  }
}

function wordMaps(version) {
  const p = profile(version);
  const maps = Array.from(
    { length: p.count },
    (_, i) => new Array(p.length + Number(i >= p.short) + 30),
  );
  let index = 0;
  for (let column = 0; column <= p.length; column++) {
    for (const map of maps) {
      if (column < map.length - 30) {
        map[column] = index++;
      }
    }
  }
  for (let column = 0; column < 30; column++) {
    for (const map of maps) {
      map[map.length - 30 + column] = index++;
    }
  }
  return maps;
}

function changeWord(modules, positions, index, xor) {
  for (let bit = 0; bit < 8; bit++) {
    if (xor & (128 >>> bit)) {
      modules[positions[index * 8 + bit]] ^= 1;
    }
  }
}

function replaceData(f, version, data) {
  const p = profile(version);
  const maps = wordMaps(version);
  const positions = coordinates(version);
  const { mask } = decodeQRMatrix(f.modules, f.size);
  const modules = f.modules.slice();
  let offset = 0;
  for (const map of maps) {
    const count = map.length - 30;
    const block = encodedBlock(data.subarray(offset, offset + count));
    offset += count;
    for (let word = 0; word < map.length; word++) {
      for (let bit = 0; bit < 8; bit++) {
        const index = positions[map[word] * 8 + bit];
        modules[index] =
          ((block[word] >>> (7 - bit)) & 1) ^
          Number(maskBit(mask, index % f.size, Math.floor(index / f.size)));
      }
    }
  }
  assert.equal(offset, p.data);
  return modules;
}

function segment(version, payload) {
  const data = new Uint8Array(profile(version).data);
  let bit = 0;
  const write = (value, count) => {
    for (let i = count - 1; i >= 0; i--, bit++) {
      data[bit >>> 3] |= ((value >>> i) & 1) << (7 - (bit & 7));
    }
  };
  write(4, 4);
  write(payload.length, 16);
  for (const byte of payload) {
    write(byte, 8);
  }
  write(0, 4);
  for (let pad = 0xec; bit < data.length * 8; pad ^= 0xfd) {
    write(pad, 8);
  }
  return data;
}

for (const version of [30, 40]) {
  for (const name of ['zero', 'cycle', 'random', 'capacity']) {
    test(`Version ${version} ${name} matrix recovers exact bytes with every mask`, () => {
      const f = fixture(version, name);
      const original = f.modules.slice();
      const decoded = decodeQRMatrix(f.modules, f.size);
      assert.deepEqual(Buffer.from(decoded.payload), f.payload);
      assert.equal(decoded.correctedCodewords, 0);
      const positions = coordinates(version);
      assert.equal(
        positions.length,
        (profile(version).data + 30 * profile(version).count) * 8 +
          (version === 30 ? 3 : 0),
      );
      for (let mask = 0; mask < 8; mask++) {
        const modules = f.modules.slice();
        for (const index of positions) {
          const x = index % f.size;
          const y = Math.floor(index / f.size);
          modules[index] ^=
            Number(maskBit(decoded.mask, x, y)) ^ Number(maskBit(mask, x, y));
        }
        writeBits(
          modules,
          formatCoordinates(f.size),
          bch(8 | mask, 10, 0x537) ^ 0x5412,
        );
        const result = decodeQRMatrix(modules, f.size);
        assert.deepEqual(Buffer.from(result.payload), f.payload);
        assert.equal(result.mask, mask);
        assert.equal(result.version, version);
      }
      assert.deepEqual(f.modules, original);
    });
  }

  test(`Version ${version} corrects 15 data and parity errors in every block`, () => {
    const f = fixture(version);
    const positions = coordinates(version);
    const modules = f.modules.slice();
    for (const map of wordMaps(version)) {
      for (let i = 0; i < 15; i++) {
        const local = i < 7 ? i : map.length - 1 - (i - 7);
        changeWord(modules, positions, map[local], i + 1);
      }
    }
    const result = decodeQRMatrix(modules, f.size);
    assert.deepEqual(Buffer.from(result.payload), f.payload);
    assert.equal(result.correctedCodewords, 15 * profile(version).count);
    const broken = f.modules.slice();
    const map = wordMaps(version)[0];
    for (let i = 0; i < 16; i++) {
      changeWord(broken, positions, map[i], i + 1);
    }
    rejects(() => decodeQRMatrix(broken, f.size), 'qr-reed-solomon');
  });

  test(`Version ${version} validates both BCH copies with three-bit correction`, () => {
    const f = fixture(version);
    for (const [positions, code] of [
      [formatCoordinates(f.size), 'qr-format'],
      [versionCoordinates(f.size), 'qr-version'],
    ]) {
      const corrected = f.modules.slice();
      corruptCopies(corrected, positions, 3);
      assert.deepEqual(
        Buffer.from(decodeQRMatrix(corrected, f.size).payload),
        f.payload,
      );
      const broken = f.modules.slice();
      corruptCopies(broken, positions, 4);
      rejects(() => decodeQRMatrix(broken, f.size), code);
      // One unreadable copy leaves the redundant copy usable.
      for (const index of positions[1].slice(0, 4)) {
        broken[index] ^= 1;
      }
      assert.deepEqual(
        Buffer.from(decodeQRMatrix(broken, f.size).payload),
        f.payload,
      );
    }
    const mismatched = f.modules.slice();
    const { mask } = decodeQRMatrix(f.modules, f.size);
    writeBits(
      mismatched,
      [formatCoordinates(f.size)[0]],
      bch(8 | ((mask + 1) % 8), 10, 0x537) ^ 0x5412,
    );
    rejects(() => decodeQRMatrix(mismatched, f.size), 'qr-format');
    for (const level of [0, 2, 3]) {
      const modules = f.modules.slice();
      writeBits(
        modules,
        formatCoordinates(f.size),
        bch((level << 3) | mask, 10, 0x537) ^ 0x5412,
      );
      rejects(() => decodeQRMatrix(modules, f.size), 'qr-error-correction');
    }
    for (const otherVersion of [7, version === 30 ? 40 : 30]) {
      const modules = f.modules.slice();
      writeBits(
        modules,
        versionCoordinates(f.size),
        bch(otherVersion, 12, 0x1f25),
      );
      rejects(() => decodeQRMatrix(modules, f.size), 'qr-version');
    }
    const conflictingVersion = f.modules.slice();
    writeBits(
      conflictingVersion,
      [versionCoordinates(f.size)[0]],
      bch(version === 30 ? 40 : 30, 12, 0x1f25),
    );
    rejects(() => decodeQRMatrix(conflictingVersion, f.size), 'qr-version');
  });

  test(`Version ${version} enforces binary segment counts, mode, terminator and padding`, () => {
    const f = fixture(version);
    for (const payload of [
      new Uint8Array(),
      Uint8Array.of(0, 255, 192, 128, 254),
    ]) {
      const data = segment(version, payload);
      const modules = replaceData(f, version, data);
      assert.deepEqual(decodeQRMatrix(modules, f.size).payload, payload);
      const invalid = data.slice();
      invalid[0] = (invalid[0] & 15) | 0x10;
      rejects(
        () => decodeQRMatrix(replaceData(f, version, invalid), f.size),
        'qr-mode',
      );
      invalid.set(data);
      invalid[0] |= 15;
      invalid[1] = 255;
      invalid[2] |= 0xf0;
      rejects(
        () => decodeQRMatrix(replaceData(f, version, invalid), f.size),
        'qr-capacity',
      );
      invalid.set(data);
      invalid[2 + payload.length] |= 1;
      rejects(
        () => decodeQRMatrix(replaceData(f, version, invalid), f.size),
        'qr-mode',
      );
      invalid.set(data);
      invalid[invalid.length - 1] ^= 1;
      rejects(
        () => decodeQRMatrix(replaceData(f, version, invalid), f.size),
        'qr-padding',
      );
    }
  });
}

for (const length of [115, 116, 118, 119]) {
  test(`Reed-Solomon ${length}-byte data block corrects every codeword position`, () => {
    const block = encodedBlock(
      Uint8Array.from({ length }, (_, i) => (i * 71 + 13) & 255),
    );
    assert.deepEqual(correctQRBlock(block).words, block);
    for (let position = 0; position < block.length; position++) {
      const damaged = block.slice();
      damaged[position] ^= 0xff;
      const original = damaged.slice();
      const result = correctQRBlock(damaged);
      assert.deepEqual(result.words, block);
      assert.equal(result.correctedCodewords, 1);
      assert.deepEqual(damaged, original);
    }
    for (let count = 1; count <= 15; count++) {
      const damaged = block.slice();
      for (let i = 0; i < count; i++) {
        damaged[(i * 17 + 3) % block.length] ^= i * 7 + 1;
      }
      const result = correctQRBlock(damaged);
      assert.deepEqual(result.words, block);
      assert.equal(result.correctedCodewords, count);
    }
  });
}

test('matrix input dimensions and module values are bounded before decoding', () => {
  for (const size of [0, -1, 21, 141, 4096, NaN, Infinity, 137.5]) {
    rejects(() => decodeQRMatrix(new Uint8Array(), size), 'qr-version');
  }
  for (const modules of [
    [],
    null,
    new Uint8Array(137 * 137 - 1),
    new Uint8Array(137 * 137 + 1),
    new Uint8Array(137 * 137).fill(2),
  ]) {
    rejects(() => decodeQRMatrix(modules, 137), 'qr-matrix');
  }
  for (const length of [0, 30, 256]) {
    assert.throws(() => correctQRBlock(new Uint8Array(length)));
  }
  assert.throws(() => correctQRBlock([]));
});

test('Reed-Solomon recovers deterministic random errors through its correction bound', () => {
  let state = 0x193afc74;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  for (let sample = 0; sample < 300; sample++) {
    const length = [115, 116, 118, 119][sample % 4];
    const block = encodedBlock(Uint8Array.from({ length }, () => next() & 255));
    const damaged = block.slice();
    const count = 1 + (next() % 15);
    const positions = new Set();
    while (positions.size < count) {
      positions.add(next() % block.length);
    }
    for (const position of positions) {
      damaged[position] ^= 1 + (next() % 255);
    }
    const result = correctQRBlock(damaged);
    assert.deepEqual(result.words, block);
    assert.equal(result.correctedCodewords, count);
  }
});

test('Version 30 remainder modules carry no codeword data', () => {
  const f = fixture(30);
  const positions = coordinates(30);
  for (const position of positions.slice(-3)) {
    const modules = f.modules.slice();
    modules[position] ^= 1;
    assert.deepEqual(
      Buffer.from(decodeQRMatrix(modules, f.size).payload),
      f.payload,
    );
  }
});

test('deterministic damaged symbols return exact bytes or a typed rejection', () => {
  let state = 0x7c01a39b;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  for (let iteration = 0; iteration < 160; iteration++) {
    const f = fixture(iteration % 2 === 0 ? 30 : 40);
    const flips = next() % 600;
    for (let i = 0; i < flips; i++) {
      f.modules[next() % f.modules.length] ^= 1;
    }
    try {
      const result = decodeQRMatrix(f.modules, f.size);
      assert.deepEqual(Buffer.from(result.payload), f.payload);
    } catch (error) {
      assert.ok(error instanceof QRDecodeError, String(error));
    }
  }
});
