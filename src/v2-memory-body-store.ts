// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { bytesEqual } from './cbor.js';
import { sha256 } from './sha256.js';
import {
  v2CommittedBodyParts,
  v2DeliveryChunkKey,
  v2StagedChunkKey,
  validateV2BodyPartDeclarations,
} from './v2-body-keys.js';
import type {
  V2BodyPartDeclaration,
  V2BodyStore,
  V2CommittedBodyPart,
} from './v2-repository.js';

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

  async stagePart(
    uploadId: string,
    part: V2BodyPartDeclaration,
    body: ReadableStream<Uint8Array>,
  ): Promise<string> {
    const key = v2StagedChunkKey(uploadId, part.id);
    const bytes = new Uint8Array(await new Response(body).arrayBuffer());
    if (
      bytes.byteLength !== part.length ||
      !bytesEqual(sha256(bytes), part.digest)
    ) {
      throw new Error('Delivery chunk does not match its declaration.');
    }
    const existing = this.bodies.get(key);
    if (existing && !bytesEqual(existing, bytes)) {
      throw new Error('Staged delivery chunk conflicts with existing bytes.');
    }
    if (!existing) {
      this.bodies.set(key, bytes);
    }
    return key;
  }

  async commitParts(input: {
    uploadId: string;
    deliveryId: string;
    parts: readonly V2BodyPartDeclaration[];
    expectedTotalLength: number;
  }): Promise<V2CommittedBodyPart[]> {
    validateV2BodyPartDeclarations(input.parts, input.expectedTotalLength);
    const committed = input.parts.map((part) =>
      this.verifiedStagedPart(input.uploadId, input.deliveryId, part),
    );
    for (const part of committed) {
      this.bodies.set(part.key, part.bytes);
      this.bodies.delete(part.stagedKey);
    }
    return v2CommittedBodyParts(committed);
  }

  /**
   * Resolves a part from its staged bytes, or from bytes a retried commit
   * already moved, requiring the declared length and digest. Staged and moved
   * copies that both exist must be identical.
   */
  private verifiedStagedPart(
    uploadId: string,
    deliveryId: string,
    part: V2BodyPartDeclaration,
  ) {
    const stagedKey = v2StagedChunkKey(uploadId, part.id);
    const key = v2DeliveryChunkKey(deliveryId, part.id);
    const staged = this.bodies.get(stagedKey);
    const existing = this.bodies.get(key);
    const bytes = staged ?? existing;
    if (
      !bytes ||
      bytes.byteLength !== part.length ||
      !bytesEqual(sha256(bytes), part.digest) ||
      (existing !== undefined &&
        staged !== undefined &&
        !bytesEqual(existing, staged))
    ) {
      throw new Error('Staged delivery chunk is unavailable or invalid.');
    }
    return { ...part, key, stagedKey, bytes };
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
