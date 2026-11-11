#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const defaultOutput = path.resolve(here, '..', '.work', 'corpus');
const output = path.resolve(process.argv[2] ?? defaultOutput);
const manifestPath = path.join(here, 'manifest.json');
const blockSize = 64 * 1024;

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function writeGenerated(name, size, fill) {
  const target = path.join(output, name);
  const hash = createHash('sha256');
  const chunks = [];
  for (let offset = 0; offset < size; offset += blockSize) {
    const length = Math.min(blockSize, size - offset);
    const chunk = fill(offset, length);
    if (chunk.length !== length) {
      throw new Error(
        `${name}: generator returned ${chunk.length}, wanted ${length}`,
      );
    }
    chunks.push(chunk);
    hash.update(chunk);
  }
  writeFileSync(target, Buffer.concat(chunks));
  return { name, size, sha256: hash.digest('hex') };
}

function randomFill(offset, length) {
  const result = Buffer.allocUnsafe(length);
  let written = 0;
  while (written < length) {
    const absolute = offset + written;
    const block = Math.floor(absolute / 32);
    const within = absolute % 32;
    const digest = createHash('sha256')
      .update('dud optical corpus random 0\0')
      .update(String(block))
      .digest();
    const count = Math.min(digest.length - within, length - written);
    digest.copy(result, written, within, within + count);
    written += count;
  }
  return result;
}

const compressiblePattern = Buffer.from('DUD optical corpus 0\n', 'ascii');
function compressibleFill(offset, length) {
  const result = Buffer.allocUnsafe(length);
  for (let index = 0; index < length; index++) {
    result[index] =
      compressiblePattern[(offset + index) % compressiblePattern.length];
  }
  return result;
}

function octal(value, width) {
  return `${value.toString(8).padStart(width - 1, '0')}\0`;
}

function tarEntry(name, body, options = {}) {
  const data = Buffer.from(body);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  header.write(octal(options.mode ?? 0o644, 8), 100, 8, 'ascii');
  header.write(octal(0, 8), 108, 8, 'ascii');
  header.write(octal(0, 8), 116, 8, 'ascii');
  header.write(octal(data.length, 12), 124, 12, 'ascii');
  header.write(octal(0, 12), 136, 12, 'ascii');
  header.fill(0x20, 148, 156);
  header[156] = (options.type ?? '0').charCodeAt(0);
  if (options.linkname) {
    header.write(options.linkname, 157, 100, 'utf8');
  }
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  const padding = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([header, data, padding]);
}

function tar(entries) {
  return Buffer.concat([...entries, Buffer.alloc(1024)]);
}

mkdirSync(output, { recursive: true });
const generated = [];
for (const size of [1024, 1024 ** 2, 16 * 1024 ** 2, 64 * 1024 ** 2]) {
  const label = size === 1024 ? '1kib' : `${size / 1024 ** 2}mib`;
  generated.push(writeGenerated(`random-${label}.bin`, size, randomFill));
  generated.push(
    writeGenerated(`compressible-${label}.bin`, size, compressibleFill),
  );
}

const fixed = new Map([
  [
    'message-utf8.txt',
    Buffer.from(
      'Optical dead drop\nZażółć gęślą jaźń.\n光学転送\nCamera: 📷\n',
      'utf8',
    ),
  ],
  ['single-file.bin', randomFill(17, 4099)],
  [
    'collection-safe.tar',
    tar([
      tarEntry('notes.txt', 'safe collection\n'),
      tarEntry('nested/data.bin', randomFill(211, 257)),
    ]),
  ],
  [
    'collection-hostile.tar',
    tar([
      tarEntry('../escape.txt', 'parent traversal\n'),
      tarEntry('/absolute.txt', 'absolute path\n'),
      tarEntry('nested\\windows.txt', 'backslash path\n'),
      tarEntry('duplicate.txt', 'first\n'),
      tarEntry('duplicate.txt', 'second\n'),
      tarEntry('link', '', { type: '2', linkname: '../outside' }),
    ]),
  ],
]);
for (const [name, data] of fixed) {
  writeFileSync(path.join(output, name), data);
  generated.push({ name, size: data.length, sha256: sha256(data) });
}

generated.sort((left, right) => left.name.localeCompare(right.name));
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
if (manifest.files.length === 0) {
  process.stdout.write(`${JSON.stringify(generated, null, 2)}\n`);
  process.exit(2);
}
if (JSON.stringify(generated) !== JSON.stringify(manifest.files)) {
  throw new Error(`generated corpus does not match ${manifestPath}`);
}
console.log(`verified ${generated.length} optical corpus files in ${output}`);
