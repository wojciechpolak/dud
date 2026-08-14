// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { CipherSuite, HkdfSha256 } from '@hpke/core';
import { XWing } from '@hpke/hybridkem-x-wing';

const textEncoder = new TextEncoder();
const AGE_HYBRID_LABEL = textEncoder.encode(
  'age-encryption.org/mlkem768x25519',
);
const AGE_CHUNK_SIZE = 64 * 1024;

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function concat(...parts: Uint8Array[]): Uint8Array {
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

function base64Raw(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/=+$/, '');
}

async function hkdf(
  input: Uint8Array,
  salt: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(input),
    'HKDF',
    false,
    ['deriveBits'],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: arrayBuffer(salt),
        info: arrayBuffer(textEncoder.encode(info)),
      },
      key,
      256,
    ),
  );
}

async function hmac(keyBytes: Uint8Array, body: Uint8Array) {
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(keyBytes),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(
    await crypto.subtle.sign('HMAC', key, arrayBuffer(body)),
  );
}

function chunkNonce(index: number, last: boolean): Uint8Array {
  const nonce = new Uint8Array(12);
  const view = new DataView(nonce.buffer);
  view.setUint32(3, Math.floor(index / 0x100000000), false);
  view.setUint32(7, index >>> 0, false);
  if (last) {
    nonce[11] = 1;
  }
  return nonce;
}

function encryptAgePayload(
  plaintext: Uint8Array,
  streamKey: Uint8Array,
): Uint8Array {
  const chunks: Uint8Array[] = [];
  if (plaintext.byteLength === 0) {
    chunks.push(
      chacha20poly1305(streamKey, chunkNonce(0, true)).encrypt(
        new Uint8Array(),
      ),
    );
    return concat(...chunks);
  }
  for (let offset = 0, index = 0; offset < plaintext.byteLength; index++) {
    const end = Math.min(offset + AGE_CHUNK_SIZE, plaintext.byteLength);
    const last = end === plaintext.byteLength;
    chunks.push(
      chacha20poly1305(streamKey, chunkNonce(index, last)).encrypt(
        plaintext.subarray(offset, end),
      ),
    );
    offset = end;
  }
  return concat(...chunks);
}

/**
 * Encrypts a bounded capability grant as a native age v1
 * MLKEM768-X25519 file. The implementation intentionally covers only the
 * single-recipient hybrid form used by the frozen v2 protocol.
 */
export async function encryptV2AgeGrant(
  plaintext: Uint8Array,
  recipient: Uint8Array,
  randomBytes: (length: number) => Uint8Array,
): Promise<Uint8Array> {
  if (recipient.byteLength !== 1216) {
    throw new Error('Hybrid age recipient must be exactly 1216 bytes.');
  }
  if (plaintext.byteLength > AGE_CHUNK_SIZE) {
    throw new Error('Capability grant exceeds the single-chunk age limit.');
  }
  const fileKey = randomBytes(16);
  const nonce = randomBytes(16);
  if (fileKey.byteLength !== 16 || nonce.byteLength !== 16) {
    throw new Error('V2 random source returned an invalid byte count.');
  }

  const suite = new CipherSuite({
    kem: new XWing(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  const publicKey = await suite.kem.importKey(
    'raw',
    arrayBuffer(recipient),
    true,
  );
  const sender = await suite.createSenderContext({
    recipientPublicKey: publicKey,
    info: AGE_HYBRID_LABEL,
  });
  const wrapped = new Uint8Array(await sender.seal(fileKey));
  const encapsulation = new Uint8Array(sender.enc);
  if (encapsulation.byteLength !== 1120 || wrapped.byteLength !== 32) {
    throw new Error('Hybrid HPKE produced an unexpected age stanza size.');
  }

  const headerWithoutMac = textEncoder.encode(
    `age-encryption.org/v1\n-> mlkem768x25519 ${base64Raw(encapsulation)}\n${base64Raw(wrapped)}\n---`,
  );
  const headerKey = await hkdf(fileKey, new Uint8Array(), 'header');
  const mac = await hmac(headerKey, headerWithoutMac);
  const header = concat(
    headerWithoutMac,
    textEncoder.encode(` ${base64Raw(mac)}\n`),
  );
  const streamKey = await hkdf(fileKey, nonce, 'payload');
  return concat(header, nonce, encryptAgePayload(plaintext, streamKey));
}
