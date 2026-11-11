// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
import { gzipSync } from 'node:zlib';

// Flat regular files make installation independent of tar path interpretation.
export function archive(files) {
  const blocks = [];
  for (const [name, { bytes, mode = 0o644 }] of Object.entries(files).sort()) {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/.test(name)) {
      throw new Error('archive names must be flat and at most 100 bytes');
    }
    const data = Buffer.from(bytes);
    const header = Buffer.alloc(512);
    header.write(name, 0);
    const octal = (value, offset, width) =>
      header.write(value.toString(8).padStart(width - 1, '0') + '\0', offset);
    octal(mode, 100, 8);
    octal(0, 108, 8);
    octal(0, 116, 8);
    octal(data.length, 124, 12);
    octal(0, 136, 12);
    header.fill(32, 148, 156);
    header.write('0', 156);
    header.write('ustar\0', 257);
    header.write('00', 263);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
    blocks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks), { level: 9 });
}
