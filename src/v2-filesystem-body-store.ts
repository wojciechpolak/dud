// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { createReadStream } from 'node:fs';
import { link, mkdir, open, opendir, rename, rm, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Readable } from 'node:stream';

import { bytesEqual } from './cbor.js';
import { StreamingSha256 } from './sha256.js';
import {
  v2BodyKeyKind,
  v2DeliveryChunkKey,
  v2StagedChunkKey,
  validateV2BodyPartDeclarations,
} from './v2-body-keys.js';
import type { BlobObject } from './types.js';
import type {
  V2BodyInventory,
  V2BodyInventoryEntry,
  V2BodyPartDeclaration,
  V2BodyStore,
  V2CommittedBodyPart,
} from './v2-repository.js';

async function fileDigest(path: string): Promise<{
  size: number;
  digest: Uint8Array;
}> {
  const info = await stat(path);
  const hasher = new StreamingSha256();
  for await (const chunk of createReadStream(path)) {
    hasher.update(Uint8Array.from(chunk));
  }
  return { size: info.size, digest: hasher.digest() };
}

async function sameFileDigest(left: string, right: string): Promise<boolean> {
  const [leftInfo, rightInfo] = await Promise.all([
    fileDigest(left),
    fileDigest(right),
  ]);
  return (
    leftInfo.size === rightInfo.size &&
    bytesEqual(leftInfo.digest, rightInfo.digest)
  );
}

async function fileMatches(
  path: string,
  length: number,
  digest: Uint8Array,
): Promise<boolean> {
  try {
    const actual = await fileDigest(path);
    return actual.size === length && bytesEqual(actual.digest, digest);
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

const BODY_NAMESPACES = [
  ['deliveries', 'delivery-bodies'],
  ['staging', 'delivery-staging'],
] as const;

/**
 * Inserts one candidate into an ordered page that never grows past `limit`, so
 * a reconciliation walk holds at most one page in memory no matter how many
 * bodies the namespace contains.
 */
function insertBounded(
  page: V2BodyInventoryEntry[],
  entry: V2BodyInventoryEntry,
  limit: number,
): void {
  if (page.length === limit && entry.key >= page[limit - 1]!.key) {
    return;
  }
  let index = page.length;
  while (index > 0 && page[index - 1]!.key > entry.key) {
    index--;
  }
  page.splice(index, 0, entry);
  if (page.length > limit) {
    page.pop();
  }
}

/** Isolated, verified body storage for the V2 delivery namespace. */
export class FilesystemV2BodyStore implements V2BodyStore, V2BodyInventory {
  constructor(private readonly rootDir: string) {}

  async stage(
    body: ReadableStream<Uint8Array>,
    expectedLength: number,
    expectedDigest: Uint8Array,
  ): Promise<string> {
    const key = `staging/${crypto.randomUUID().replaceAll('-', '')}.bin`;
    await this.put(key, body, expectedLength, expectedDigest);
    return key;
  }

  async promote(stagedKey: string, key: string): Promise<void> {
    const stagedPath = this.pathForKey(stagedKey);
    const destinationPath = this.pathForKey(key);
    if (!stagedKey.startsWith('staging/') || !key.startsWith('deliveries/')) {
      throw new Error('Delivery body promotion keys are invalid.');
    }
    await mkdir(dirname(destinationPath), { recursive: true, mode: 0o700 });
    try {
      await stat(destinationPath);
      if (await sameFileDigest(stagedPath, destinationPath)) {
        await rm(stagedPath, { force: true });
        return;
      }
      throw new Error('Delivery body conflicts with an existing payload.');
    } catch (error) {
      if ((error as { code?: string }).code !== 'ENOENT') {
        throw error;
      }
    }
    await rename(stagedPath, destinationPath);
  }

  async stagePart(
    uploadId: string,
    part: V2BodyPartDeclaration,
    body: ReadableStream<Uint8Array>,
  ): Promise<string> {
    const key = v2StagedChunkKey(uploadId, part.id);
    await this.put(key, body, part.length, part.digest);
    return key;
  }

  async commitParts(input: {
    uploadId: string;
    deliveryId: string;
    parts: readonly V2BodyPartDeclaration[];
    expectedTotalLength: number;
  }): Promise<V2CommittedBodyPart[]> {
    validateV2BodyPartDeclarations(input.parts, input.expectedTotalLength);
    const parts = await Promise.all(
      input.parts.map(async (part) => {
        const stagedKey = v2StagedChunkKey(input.uploadId, part.id);
        const key = v2DeliveryChunkKey(input.deliveryId, part.id);
        const stagedPath = this.pathForKey(stagedKey);
        const destinationPath = this.pathForKey(key);
        const [stagedMatches, destinationMatches] = await Promise.all([
          fileMatches(stagedPath, part.length, part.digest),
          fileMatches(destinationPath, part.length, part.digest),
        ]);
        if (!stagedMatches && !destinationMatches) {
          throw new Error('Staged delivery chunk is unavailable or invalid.');
        }
        return {
          ...part,
          key,
          stagedPath,
          destinationPath,
          destinationMatches,
        };
      }),
    );
    for (const part of parts) {
      if (!part.destinationMatches) {
        await mkdir(dirname(part.destinationPath), {
          recursive: true,
          mode: 0o700,
        });
        try {
          await link(part.stagedPath, part.destinationPath);
        } catch (error) {
          if (
            (error as { code?: string }).code !== 'EEXIST' ||
            !(await fileMatches(part.destinationPath, part.length, part.digest))
          ) {
            throw error;
          }
        }
      }
      await rm(part.stagedPath, { force: true });
    }
    return parts.map(({ id, length, digest, key }) => ({
      id,
      length,
      digest: Uint8Array.from(digest),
      key,
    }));
  }

  async put(
    key: string,
    body: ReadableStream<Uint8Array>,
    expectedLength: number,
    expectedDigest: Uint8Array,
  ): Promise<void> {
    if (!Number.isSafeInteger(expectedLength) || expectedLength < 0) {
      throw new Error('Expected body length is invalid.');
    }
    const path = this.pathForKey(key);
    const temporaryPath = `${path}.tmp-${crypto.randomUUID()}`;
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const file = await open(temporaryPath, 'wx', 0o600);
    const reader = body.getReader();
    const hasher = new StreamingSha256();
    let length = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (!(value instanceof Uint8Array)) {
          throw new Error('Delivery body chunk is invalid.');
        }
        length += value.byteLength;
        if (length > expectedLength) {
          throw new Error('Delivery body exceeds its declared length.');
        }
        hasher.update(value);
        await file.write(value);
      }
      if (
        length !== expectedLength ||
        !bytesEqual(hasher.digest(), expectedDigest)
      ) {
        throw new Error('Delivery body does not match its declared digest.');
      }
      await file.sync();
      await file.close();
      try {
        await link(temporaryPath, path);
      } catch (error) {
        if (
          (error as { code?: string }).code !== 'EEXIST' ||
          !(await sameFileDigest(temporaryPath, path))
        ) {
          throw error;
        }
      }
      await rm(temporaryPath, { force: true });
    } catch (error) {
      await file.close().catch(() => undefined);
      await rm(temporaryPath, { force: true }).catch(() => undefined);
      throw error;
    } finally {
      reader.releaseLock();
    }
  }

  async get(key: string): Promise<BlobObject | null> {
    const path = this.pathForKey(key);
    try {
      const info = await stat(path);
      return {
        body: Readable.toWeb(
          createReadStream(path),
        ) as ReadableStream<Uint8Array>,
        size: info.size,
      };
    } catch (error) {
      if ((error as { code?: string }).code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }

  async head(key: string): Promise<boolean> {
    try {
      await stat(this.pathForKey(key));
      return true;
    } catch (error) {
      if ((error as { code?: string }).code === 'ENOENT') {
        return false;
      }
      throw error;
    }
  }

  async delete(key: string): Promise<void> {
    await rm(this.pathForKey(key), { force: true });
  }

  /**
   * One ordered page of stored body keys, for the administrator reconciliation
   * command only. Directory entries stream through a page-sized window, so the
   * walk is bounded in memory and resumable through the returned cursor. No
   * request path calls this.
   */
  async listBodies(input: { cursor?: string; limit: number }): Promise<{
    entries: V2BodyInventoryEntry[];
    cursor?: string;
  }> {
    if (
      !Number.isSafeInteger(input.limit) ||
      input.limit < 1 ||
      input.limit > 1_000
    ) {
      throw new Error('Body inventory page limit is invalid.');
    }
    const page: V2BodyInventoryEntry[] = [];
    const consider = async (key: string, path: string): Promise<void> => {
      if (input.cursor !== undefined && key <= input.cursor) {
        return;
      }
      if (page.length === input.limit && key >= page[input.limit - 1]!.key) {
        return;
      }
      const info = await stat(path);
      insertBounded(
        page,
        {
          key,
          size: info.size,
          modifiedAt: Math.floor(info.mtimeMs / 1000),
        },
        input.limit,
      );
    };
    for (const [prefix, namespace] of BODY_NAMESPACES) {
      const directory = join(this.rootDir, 'v2', namespace);
      let entries;
      try {
        entries = await opendir(directory);
      } catch (error) {
        if ((error as { code?: string }).code === 'ENOENT') {
          continue;
        }
        throw error;
      }
      for await (const item of entries) {
        if (!item.isFile() || !/^[a-f0-9]{32}\.bin$/.test(item.name)) {
          continue;
        }
        const key = `${prefix}/${item.name}`;
        await consider(key, join(directory, item.name));
      }
    }
    const deliveryDirectory = join(this.rootDir, 'v2', 'delivery-bodies');
    let deliveries;
    try {
      deliveries = await opendir(deliveryDirectory);
    } catch (error) {
      if ((error as { code?: string }).code !== 'ENOENT') {
        throw error;
      }
    }
    if (deliveries) {
      for await (const delivery of deliveries) {
        if (!delivery.isDirectory() || !/^[a-f0-9]{32}$/.test(delivery.name)) {
          continue;
        }
        const chunksDirectory = join(
          deliveryDirectory,
          delivery.name,
          'chunks',
        );
        let chunks;
        try {
          chunks = await opendir(chunksDirectory);
        } catch (error) {
          if ((error as { code?: string }).code === 'ENOENT') {
            continue;
          }
          throw error;
        }
        for await (const chunk of chunks) {
          if (!chunk.isFile() || !/^[a-f0-9]{32}\.age$/.test(chunk.name)) {
            continue;
          }
          const key = `deliveries/${delivery.name}/chunks/${chunk.name}`;
          await consider(key, join(chunksDirectory, chunk.name));
        }
      }
    }
    const uploadsDirectory = join(
      this.rootDir,
      'v2',
      'delivery-staging',
      'uploads',
    );
    let uploads;
    try {
      uploads = await opendir(uploadsDirectory);
    } catch (error) {
      if ((error as { code?: string }).code !== 'ENOENT') {
        throw error;
      }
    }
    if (uploads) {
      for await (const upload of uploads) {
        if (!upload.isDirectory() || !/^[a-f0-9]{32}$/.test(upload.name)) {
          continue;
        }
        const uploadDirectory = join(uploadsDirectory, upload.name);
        const chunks = await opendir(uploadDirectory);
        for await (const chunk of chunks) {
          if (!chunk.isFile() || !/^[a-f0-9]{32}\.age$/.test(chunk.name)) {
            continue;
          }
          const key = `staging/uploads/${upload.name}/${chunk.name}`;
          await consider(key, join(uploadDirectory, chunk.name));
        }
      }
    }
    return {
      entries: page,
      ...(page.length === input.limit
        ? { cursor: page[page.length - 1]!.key }
        : {}),
    };
  }

  private pathForKey(key: string): string {
    const components = key.split('/');
    switch (v2BodyKeyKind(key)) {
      case 'delivery':
        return join(this.rootDir, 'v2', 'delivery-bodies', components[1]!);
      case 'staging':
        return join(this.rootDir, 'v2', 'delivery-staging', components[1]!);
      case 'delivery-chunk':
        return join(
          this.rootDir,
          'v2',
          'delivery-bodies',
          components[1]!,
          'chunks',
          components[3]!,
        );
      case 'staged-chunk':
        return join(
          this.rootDir,
          'v2',
          'delivery-staging',
          'uploads',
          components[2]!,
          components[3]!,
        );
    }
  }
}
