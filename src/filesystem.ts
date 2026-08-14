// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { createReadStream, createWriteStream } from 'node:fs';
import {
  mkdir,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Readable } from 'node:stream';

import type {
  BlobHead,
  BlobObject,
  BlobStore,
  BlobWriteMetadata,
  ListedBlob,
} from './types.js';

interface StoredSidecar {
  contentType: string;
  customMetadata?: Record<string, string>;
  size?: number;
}

function normalizeKey(key: string): string[] {
  const segments = key.split('/').filter(Boolean);
  if (segments.length === 0) {
    throw new Error(`Invalid blob key: ${key}`);
  }

  for (const segment of segments) {
    if (segment === '.' || segment === '..') {
      throw new Error(`Invalid blob key: ${key}`);
    }
  }

  return segments;
}

function bodyPath(rootDir: string, key: string): string {
  return join(rootDir, 'blobs', ...normalizeKey(key));
}

function sidecarPath(rootDir: string, key: string): string {
  return `${join(rootDir, 'meta', ...normalizeKey(key))}.json`;
}

async function ensureParentDir(filePath: string): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true, mode: 0o700 });
}

async function readSidecar(
  rootDir: string,
  key: string,
): Promise<StoredSidecar | null> {
  try {
    const raw = await readFile(sidecarPath(rootDir, key), 'utf8');
    return JSON.parse(raw) as StoredSidecar;
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') {
      return null;
    }

    return null;
  }
}

async function removeIfExists(filePath: string): Promise<void> {
  await rm(filePath, { force: true }).catch(() => undefined);
}

async function listKeysInDir(
  dirPath: string,
  baseKeyPrefix = '',
): Promise<string[]> {
  let entries: any[];
  try {
    entries = (await readdir(dirPath, { withFileTypes: true })) as any[];
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') {
      return [];
    }
    throw error;
  }

  const keys: string[] = [];
  for (const entry of entries) {
    const nextPrefix = baseKeyPrefix
      ? `${baseKeyPrefix}/${entry.name}`
      : entry.name;
    if (entry.isDirectory()) {
      keys.push(
        ...(await listKeysInDir(join(dirPath, entry.name), nextPrefix)),
      );
    } else if (entry.isFile()) {
      keys.push(nextPrefix);
    }
  }

  return keys;
}

export class FilesystemBlobStore implements BlobStore {
  constructor(private readonly rootDir: string) {}

  async put(
    key: string,
    body: ReadableStream<Uint8Array>,
    metadata: BlobWriteMetadata,
  ): Promise<void> {
    const filePath = bodyPath(this.rootDir, key);
    const metadataPath = sidecarPath(this.rootDir, key);
    const suffix = `.tmp-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const tempFilePath = `${filePath}${suffix}`;
    const tempMetadataPath = `${metadataPath}${suffix}`;

    await ensureParentDir(filePath);
    await ensureParentDir(metadataPath);

    let byteLength = 0;
    const nodeReadable = Readable.fromWeb(body);
    nodeReadable.on('data', (chunk: Uint8Array) => {
      byteLength += chunk.byteLength;
    });

    const writable = createWriteStream(tempFilePath, { mode: 0o600 });

    try {
      await new Promise<void>((resolve, reject) => {
        nodeReadable.on('error', reject);
        writable.on('error', reject);
        writable.on('finish', () => resolve());
        nodeReadable.pipe(writable);
      });

      const sidecar: StoredSidecar = {
        contentType: metadata.contentType,
        customMetadata: metadata.customMetadata,
        size: metadata.length ?? byteLength,
      };
      await writeFile(tempMetadataPath, JSON.stringify(sidecar), {
        encoding: 'utf8',
        mode: 0o600,
      });

      await rename(tempFilePath, filePath);
      await rename(tempMetadataPath, metadataPath);
    } catch (error) {
      await Promise.all([
        removeIfExists(tempFilePath),
        removeIfExists(tempMetadataPath),
      ]);
      throw error;
    }
  }

  async get(key: string): Promise<BlobObject | null> {
    const filePath = bodyPath(this.rootDir, key);
    try {
      const fileStat = await stat(filePath);
      const sidecar = await readSidecar(this.rootDir, key);

      return {
        body: Readable.toWeb(
          createReadStream(filePath),
        ) as ReadableStream<Uint8Array>,
        size: sidecar?.size ?? fileStat.size,
        customMetadata: sidecar?.customMetadata,
      };
    } catch (error) {
      if ((error as { code?: string }).code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }

  async head(key: string): Promise<BlobHead | null> {
    const filePath = bodyPath(this.rootDir, key);
    try {
      const fileStat = await stat(filePath);
      const sidecar = await readSidecar(this.rootDir, key);

      return {
        size: sidecar?.size ?? fileStat.size,
        customMetadata: sidecar?.customMetadata,
      };
    } catch (error) {
      if ((error as { code?: string }).code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }

  async list(prefix: string, limit: number): Promise<ListedBlob[]> {
    const keys = await listKeysInDir(join(this.rootDir, 'blobs'));
    return keys
      .filter((key) => key.startsWith(prefix))
      .sort()
      .slice(0, limit)
      .map((key) => ({ key }));
  }

  async delete(key: string): Promise<void> {
    await Promise.all([
      removeIfExists(bodyPath(this.rootDir, key)),
      removeIfExists(sidecarPath(this.rootDir, key)),
    ]);
  }
}
