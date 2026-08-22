// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { bytesEqual } from './cbor.js';
import { sha256 } from './sha256.js';
import type { V2BodyStore } from './v2-repository.js';

/** In-memory opaque body store for shared repository and handler tests. */
export class MemoryV2BodyStore implements V2BodyStore {
  private readonly bodies = new Map<string, Uint8Array>();

  async stage(
    body: ReadableStream<Uint8Array>,
    length: number,
    digest: Uint8Array,
  ): Promise<string> {
    const key = `staging/${crypto.randomUUID().replaceAll('-', '')}.bin`;
    await this.put(key, body, length, digest);
    return key;
  }

  async promote(stagedKey: string, key: string): Promise<void> {
    const staged = this.bodies.get(stagedKey);
    if (!staged) {
      throw new Error('Staged delivery body is unavailable.');
    }
    const existing = this.bodies.get(key);
    if (existing && !bytesEqual(existing, staged)) {
      throw new Error('Delivery body conflicts with an existing payload.');
    }
    if (!existing) {
      this.bodies.set(key, staged);
    }
    this.bodies.delete(stagedKey);
  }

  async put(
    key: string,
    body: ReadableStream<Uint8Array>,
    length: number,
    digest: Uint8Array,
  ): Promise<void> {
    const bytes = new Uint8Array(await new Response(body).arrayBuffer());
    if (bytes.byteLength !== length || !bytesEqual(sha256(bytes), digest)) {
      throw new Error('Delivery body does not match its declared digest.');
    }
    this.bodies.set(key, bytes);
  }

  async get(key: string) {
    const bytes = this.bodies.get(key);
    if (!bytes) {
      return null;
    }
    return {
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(Uint8Array.from(bytes));
          controller.close();
        },
      }),
      size: bytes.byteLength,
    };
  }

  async head(key: string): Promise<boolean> {
    return this.bodies.has(key);
  }

  async delete(key: string): Promise<void> {
    this.bodies.delete(key);
  }
}
