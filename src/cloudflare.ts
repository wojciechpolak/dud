// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type {
  BlobHead,
  BlobObject,
  BlobStore,
  BlobWriteMetadata,
  ListedBlob,
  R2BucketLike,
  R2ListResultLike,
  R2ObjectBodyLike,
  R2ObjectLike,
} from './types.js';

// Cloudflare Workers global — not in standard TypeScript libs
declare class FixedLengthStream extends TransformStream<
  Uint8Array,
  Uint8Array
> {
  constructor(expectedLength: number);
}

function toBlobHead(object: R2ObjectLike | null): BlobHead | null {
  if (!object) {
    return null;
  }

  return {
    size: object.size,
    customMetadata: object.customMetadata,
  };
}

export class R2BlobStore implements BlobStore {
  constructor(private readonly bucket: R2BucketLike) {}

  async put(
    key: string,
    body: ReadableStream<Uint8Array>,
    metadata: BlobWriteMetadata,
  ): Promise<void> {
    const options = {
      httpMetadata: { contentType: metadata.contentType },
      customMetadata: metadata.customMetadata,
    };

    if (metadata.length !== undefined) {
      const fls = new FixedLengthStream(metadata.length);
      const pipe = body.pipeTo(fls.writable);
      await Promise.all([this.bucket.put(key, fls.readable, options), pipe]);
    } else {
      await this.bucket.put(key, body, options);
    }
  }

  async get(key: string): Promise<BlobObject | null> {
    const object = (await this.bucket.get(key)) as R2ObjectBodyLike | null;

    if (!object || !object.body) {
      return null;
    }

    return {
      body: object.body,
      size: object.size,
      customMetadata: object.customMetadata,
    };
  }

  async head(key: string): Promise<BlobHead | null> {
    return toBlobHead((await this.bucket.head(key)) as R2ObjectLike | null);
  }

  async list(prefix: string, limit: number): Promise<ListedBlob[]> {
    const result = (await this.bucket.list({
      prefix,
      limit,
    })) as R2ListResultLike;

    return result.objects.map((object) => ({ key: object.key }));
  }

  async delete(key: string): Promise<void> {
    await this.bucket.delete(key);
  }
}
