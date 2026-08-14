// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { createReadStream } from 'node:fs';
import { mkdir, open, opendir, rename, rm, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Readable } from 'node:stream';

import { bytesEqual } from './cbor.js';
import { StreamingSha256 } from './sha256.js';
import type { BlobObject } from './types.js';
import type {
  V2BodyInventory,
  V2BodyInventoryEntry,
  V2BodyStore,
} from './v2-repository.js';

function deliveryIdFromKey(key: string): string {
  const match = /^(?:deliveries|staging)\/([a-f0-9]{32})\.bin$/.exec(key);
  if (!match) {
    throw new Error('Delivery body key is invalid.');
  }
  return match[1];
}

async function sameFileDigest(left: string, right: string): Promise<boolean> {
  const [leftInfo, rightInfo] = await Promise.all([stat(left), stat(right)]);
  if (leftInfo.size !== rightInfo.size) {
    return false;
  }
  const digest = async (path: string): Promise<Uint8Array> => {
    const hasher = new StreamingSha256();
    for await (const chunk of createReadStream(path)) {
      hasher.update(Uint8Array.from(chunk));
    }
    return hasher.digest();
  };
  return bytesEqual(await digest(left), await digest(right));
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
      await rename(temporaryPath, path);
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
        if (input.cursor !== undefined && key <= input.cursor) {
          continue;
        }
        if (page.length === input.limit && key >= page[input.limit - 1]!.key) {
          continue;
        }
        const info = await stat(join(directory, item.name));
        insertBounded(
          page,
          {
            key,
            size: info.size,
            modifiedAt: Math.floor(info.mtimeMs / 1000),
          },
          input.limit,
        );
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
    const id = deliveryIdFromKey(key);
    const namespace = key.startsWith('staging/')
      ? 'delivery-staging'
      : 'delivery-bodies';
    return join(this.rootDir, 'v2', namespace, `${id}.bin`);
  }
}
