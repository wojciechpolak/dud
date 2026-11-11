// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { MAX_CAPSULE_SIZE } from './codec.js';

export const ENCRYPTED_CAPSULE_FILENAME = 'dud-encrypted-capsule.age';

// CapsuleReceipt owns verified ciphertext after reconstruction. It neither
// parses the age header nor inspects the encrypted container.
export class CapsuleReceipt {
  private capsule: Uint8Array | undefined;

  get available(): boolean {
    return this.capsule !== undefined;
  }

  accept(capsule: Uint8Array): void {
    if (capsule.byteLength < 1 || capsule.byteLength > MAX_CAPSULE_SIZE) {
      throw new RangeError('encrypted capsule is outside the optical bound');
    }
    this.clear();
    this.capsule = capsule;
  }

  blob(): Blob {
    if (!this.capsule) {
      throw new Error('no encrypted capsule is ready to save');
    }
    const exactBytes = new Uint8Array(this.capsule).buffer;
    return new Blob([exactBytes], { type: 'application/octet-stream' });
  }

  clear(): void {
    this.capsule?.fill(0);
    this.capsule = undefined;
  }
}
