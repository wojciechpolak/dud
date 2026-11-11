// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { concatBytes, toArrayBuffer } from './bytes.js';

/** Byte length of the nonce that prefixes every sealed record. */
const NONCE_BYTES = 12;

async function importKey(
  keyBytes: Uint8Array,
  usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    'AES-GCM',
    false,
    [usage],
  );
}

/**
 * Encrypts `plaintext` under AES-GCM bound to `additionalData` and returns
 * `nonce || ciphertext || tag`. Callers choose and validate the nonce, so each
 * record type keeps its own error for a faulty random source.
 */
export async function sealV2AesGcm(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  additionalData: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const key = await importKey(keyBytes, 'encrypt');
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(nonce),
        additionalData: toArrayBuffer(additionalData),
      },
      key,
      toArrayBuffer(plaintext),
    ),
  );
  return concatBytes(nonce, ciphertext);
}

/**
 * Opens a record produced by {@link sealV2AesGcm}. It throws whenever the key,
 * nonce, tag, or additional data does not match; callers translate that into
 * their own authentication error without revealing which part failed.
 */
export async function openV2AesGcm(
  keyBytes: Uint8Array,
  sealed: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  const key = await importKey(keyBytes, 'decrypt');
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(sealed.subarray(0, NONCE_BYTES)),
        additionalData: toArrayBuffer(additionalData),
      },
      key,
      toArrayBuffer(sealed.subarray(NONCE_BYTES)),
    ),
  );
}
