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
  storageNotConfiguredMessage: string;
  secretToken?: string;
  storageConfigured: boolean;
  v1Enabled: boolean;
  v2AdminSecret?: string;
  v2DeploymentKey?: string;
  v2Enabled: boolean;
  v2Limits: import('./v2-types.js').V2Limits;
  /** Gates rendezvous creation. Absent only under `v2OpenEnrollment`. */
  v2Secret?: string;
  v2OpenEnrollment?: boolean;
  /** Accepts a `v2Secret` that states a work factor below the default. */
  v2AcceptWeakEnrollmentKdf?: boolean;
}

export interface ExecutionContextLike {
  waitUntil(promise: Promise<unknown>): void;
}

export interface R2ObjectLike {
  key?: string;
  size?: number;
  etag?: string;
  customMetadata?: Record<string, string>;
}

export interface R2ObjectBodyLike extends R2ObjectLike {
  body: ReadableStream<Uint8Array> | null;
}

export interface R2PutOptionsLike {
  onlyIf?: {
    etagMatches?: string;
    etagDoesNotMatch?: string;
  };
  httpMetadata?: {
    contentType?: string;
  };
  customMetadata?: Record<string, string>;
}

export interface R2ListOptionsLike {
  cursor?: string;
  prefix?: string;
  limit?: number;
  include?: string[];
}

export interface R2ListedObjectLike {
  key: string;
  size?: number;
  uploaded?: Date | string;
  customMetadata?: Record<string, string>;
}

export interface R2ListResultLike {
  objects: R2ListedObjectLike[];
  cursor?: string;
  truncated?: boolean;
}

export interface R2BucketLike {
  put(
    key: string,
    body: ReadableStream<Uint8Array> | string | Uint8Array,
    options?: R2PutOptionsLike,
  ): Promise<R2ObjectLike | null | void>;
  get(key: string): Promise<R2ObjectBodyLike | null>;
  head(key: string): Promise<R2ObjectLike | null>;
  list(options?: R2ListOptionsLike): Promise<R2ListResultLike>;
  delete(key: string): Promise<void>;
}

/** Minimal Cloudflare D1 binding surface used by the granular V2 backend. */
export interface D1StatementLike {
  bind(...values: unknown[]): D1StatementLike;
  run<T = unknown>(): Promise<T>;
  first<T = unknown>(): Promise<T | null>;
  all<T = unknown>(): Promise<T>;
}

export interface D1RunResultLike {
  meta?: { changes?: number };
}

export interface D1DatabaseLike {
  prepare(query: string): D1StatementLike;
  batch<T = unknown>(statements: D1StatementLike[]): Promise<T[]>;
}

export interface Env {
  APP_VERSION?: string;
  DUD_DROP_ENABLED?: string;
  DUD_DROP_SECRET?: string;
  DUD_PEER_ADMIN_SECRET?: string;
  DUD_PEER_DEPLOYMENT_KEY?: string;
  DUD_PEER_ACCEPT_WEAK_ENROLLMENT_KDF?: string;
  DUD_PEER_ENABLED?: string;
  DUD_PEER_OPEN_ENROLLMENT?: string;
  DUD_PEER_SECRET?: string;
  FILES?: R2BucketLike;
  DB?: D1DatabaseLike;
}
