// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export interface BlobObject {
  body: ReadableStream<Uint8Array>;
  size?: number;
  customMetadata?: Record<string, string>;
}

export interface BlobHead {
  size?: number;
  customMetadata?: Record<string, string>;
}

export interface ListedBlob {
  key: string;
}

export interface BlobStore {
  put(
    key: string,
    body: ReadableStream<Uint8Array>,
    metadata: BlobWriteMetadata,
  ): Promise<void>;
  get(key: string): Promise<BlobObject | null>;
  head(key: string): Promise<BlobHead | null>;
  list(prefix: string, limit: number): Promise<ListedBlob[]>;
  delete(key: string): Promise<void>;
}

export interface BlobWriteMetadata {
  contentType: string;
  customMetadata?: Record<string, string>;
  length?: number;
}

export interface DudConfig {
  serviceName: string;
  version: string;
  defaultTtlMs: number;
  maxTtlMs: number;
  maxUploadBytes: number;
  cleanupBatchSize: number;
  flushMaxIterations: number;
  secretToken?: string;
  storageConfigured: boolean;
}

export interface ExecutionContextLike {
  waitUntil(promise: Promise<unknown>): void;
}

export interface R2ObjectLike {
  size?: number;
  customMetadata?: Record<string, string>;
}

export interface R2ObjectBodyLike extends R2ObjectLike {
  body: ReadableStream<Uint8Array> | null;
}

export interface R2PutOptionsLike {
  httpMetadata?: {
    contentType?: string;
  };
  customMetadata?: Record<string, string>;
}

export interface R2ListOptionsLike {
  prefix?: string;
  limit?: number;
}

export interface R2ListedObjectLike {
  key: string;
}

export interface R2ListResultLike {
  objects: R2ListedObjectLike[];
}

export interface R2BucketLike {
  put(
    key: string,
    body: ReadableStream<Uint8Array>,
    options?: R2PutOptionsLike,
  ): Promise<unknown>;
  get(key: string): Promise<R2ObjectBodyLike | null>;
  head(key: string): Promise<R2ObjectLike | null>;
  list(options?: R2ListOptionsLike): Promise<R2ListResultLike>;
  delete(key: string): Promise<void>;
}

export interface Env {
  APP_VERSION?: string;
  DUD_SECRET_TOKEN?: string;
  FILES?: R2BucketLike;
}
