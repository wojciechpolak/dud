// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
import { createServer } from 'node:http';

const target = (process.env.DUD_E2E_TARGET_IP ?? '')
  .split('.')
  .map((part) => Number(part));
if (
  target.length !== 4 ||
  target.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
) {
  throw new Error('DUD_E2E_TARGET_IP must be an IPv4 address');
}

function questionEnd(query) {
  let offset = 12;
  while (offset < query.length) {
    const length = query[offset];
    offset += 1;
    if (length === 0) {
      return offset + 4;
    }
    if (length > 63 || offset + length > query.length) {
      throw new Error('invalid DNS question');
    }
    offset += length;
  }
  throw new Error('truncated DNS question');
}

createServer((request, response) => {
  if (request.method !== 'POST' || request.url !== '/dns-query') {
    response.writeHead(404).end();
    return;
  }
  const chunks = [];
  let size = 0;
  request.on('data', (chunk) => {
    size += chunk.length;
    if (size > 4096) {
      request.destroy();
      return;
    }
    chunks.push(chunk);
  });
  request.on('end', () => {
    try {
      const query = Buffer.concat(chunks);
      const end = questionEnd(query);
      const type = query.readUInt16BE(end - 4);
      const answerCount = type === 1 ? 1 : 0;
      const header = Buffer.alloc(12);
      query.copy(header, 0, 0, 2);
      header.writeUInt16BE(0x8180, 2);
      header.writeUInt16BE(1, 4);
      header.writeUInt16BE(answerCount, 6);
      const question = query.subarray(12, end);
      const answer =
        answerCount === 0
          ? Buffer.alloc(0)
          : Buffer.from([
              0xc0,
              0x0c,
              0x00,
              0x01,
              0x00,
              0x01,
              0x00,
              0x00,
              0x00,
              0x3c,
              0x00,
              0x04,
              ...target,
            ]);
      const body = Buffer.concat([header, question, answer]);
      response.writeHead(200, {
        'cache-control': 'no-store',
        'content-length': String(body.length),
        'content-type': 'application/dns-message',
      });
      response.end(body);
    } catch {
      response.writeHead(400).end();
    }
  });
}).listen(8053, '0.0.0.0');
