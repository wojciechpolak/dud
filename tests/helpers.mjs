// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
// fallow-ignore-file unused-class-member

export function textStream(text) {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

export function makeContext() {
  const promises = [];
  return {
    waitUntil(promise) {
      promises.push(Promise.resolve(promise));
    },
    async flush() {
      await Promise.allSettled(promises);
    },
  };
}

export class MemoryBlobStore {
  constructor() {
    this.objects = new Map();
    this.deletedKeys = [];
    this.failPut = false;
  }

  async put(key, body, metadata) {
    if (this.failPut) {
      throw new Error('put failed');
    }

    const bytes = new Uint8Array(await new Response(body).arrayBuffer());
    this.objects.set(key, {
      bytes,
      contentType: metadata.contentType,
      customMetadata: { ...(metadata.customMetadata ?? {}) },
    });
  }

  async get(key) {
    const entry = this.objects.get(key);
    if (!entry) {
      return null;
    }

    return {
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(entry.bytes);
          controller.close();
        },
      }),
      size: entry.bytes.byteLength,
      customMetadata: { ...entry.customMetadata },
    };
  }

  async head(key) {
    const entry = this.objects.get(key);
    if (!entry) {
      return null;
    }

    return {
      size: entry.bytes.byteLength,
      customMetadata: { ...entry.customMetadata },
    };
  }

  async list(prefix, limit) {
    return Array.from(this.objects.keys())
      .filter((key) => key.startsWith(prefix))
      .sort()
      .slice(0, limit)
      .map((key) => ({ key }));
  }

  async delete(key) {
    this.deletedKeys.push(key);
    this.objects.delete(key);
  }
}
