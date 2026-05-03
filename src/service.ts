// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { DEFAULT_CONFIG } from './config.js';
import { errorResponse, jsonResponse } from './http.js';
import { formatOpaqueId, generateOpaqueId, parseOpaqueId } from './ids.js';
import { parseTtl } from './ttl.js';
import type { BlobStore, DudConfig, ExecutionContextLike } from './types.js';

interface StoredFileMetadata {
  id: string;
  createdAt: number;
  expiresAt: number;
  deleteAfterRead: boolean;
}

interface TombstoneMetadata {
  reason: 'expired' | 'consumed';
  expiresAt: number;
}

function parseDeleteAfterRead(headerValue: string | null): boolean {
  if (!headerValue) {
    return false;
  }

  const normalized = headerValue.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

function fileKey(id: string): string {
  return `files/${id}.age`;
}

function tombstoneKey(id: string): string {
  return `tombstones/${id}.json`;
}

function encodeJsonStream(value: unknown): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  return new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

function parseBoolean(value: string | undefined): boolean {
  return value === 'true';
}

function parseNumber(value: string | undefined): number | null {
  if (!value) {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseStoredFileMetadata(
  metadata: Record<string, string> | undefined,
): StoredFileMetadata | null {
  if (!metadata) {
    return null;
  }

  const id = metadata.dudId;
  const createdAt = parseNumber(metadata.createdAt);
  const expiresAt = parseNumber(metadata.expiresAt);

  if (!id || createdAt === null || expiresAt === null) {
    return null;
  }

  return {
    id,
    createdAt,
    expiresAt,
    deleteAfterRead: parseBoolean(metadata.deleteAfterRead),
  };
}

function parseTombstoneMetadata(
  metadata: Record<string, string> | undefined,
): TombstoneMetadata | null {
  if (!metadata) {
    return null;
  }

  const expiresAt = parseNumber(metadata.expiresAt);
  const reason =
    metadata.reason === 'expired' || metadata.reason === 'consumed'
      ? metadata.reason
      : null;

  if (!reason || expiresAt === null) {
    return null;
  }

  return { reason, expiresAt };
}

function uploadResponseBody(metadata: StoredFileMetadata): Response {
  return jsonResponse(
    {
      id: formatOpaqueId(metadata.id),
      expiresAt: new Date(metadata.expiresAt).toISOString(),
      deleteAfterRead: metadata.deleteAfterRead,
    },
    { status: 201 },
  );
}

function streamWithCompletion(
  stream: ReadableStream<Uint8Array>,
  onComplete: () => Promise<void>,
  ctx: ExecutionContextLike,
): ReadableStream<Uint8Array> {
  const reader = stream.getReader();

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await reader.read();

      if (done) {
        controller.close();
        ctx.waitUntil(onComplete());
        return;
      }

      controller.enqueue(value);
    },
    async cancel(reason) {
      await reader.cancel(reason);
      ctx.waitUntil(onComplete());
    },
  });
}

class UploadTooLargeError extends Error {}

function sizeLimitedBody(
  body: ReadableStream<Uint8Array>,
  maxBytes: number,
): ReadableStream<Uint8Array> {
  let total = 0;
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        total += chunk.byteLength;
        if (total > maxBytes) {
          controller.error(new UploadTooLargeError());
        } else {
          controller.enqueue(chunk);
        }
      },
    }),
  );
}

export interface DudDependencies {
  blobStore: BlobStore;
  config?: Partial<DudConfig>;
  now?: () => number;
  createId?: () => string;
}

export function createDudService(dependencies: DudDependencies) {
  const blobStore = dependencies.blobStore;
  const config: DudConfig = {
    ...DEFAULT_CONFIG,
    ...dependencies.config,
  };
  const now = dependencies.now ?? (() => Date.now());
  const createId = dependencies.createId ?? generateOpaqueId;

  function ensureStorageConfigured(): Response | null {
    if (config.storageConfigured) {
      return null;
    }

    return errorResponse(503, 'Storage is not configured. Bind R2 as FILES.');
  }

  function scheduleCleanup(ctx: ExecutionContextLike, limit?: number): void {
    ctx.waitUntil(cleanup(limit));
  }

  function isSecretAuthorized(request: Request): boolean {
    const provided = request.headers.get('x-dud-secret-token');
    if (!config.secretToken || !provided) {
      return false;
    }

    const enc = new TextEncoder();
    const a = enc.encode(provided);
    const b = enc.encode(config.secretToken);
    const maxLen = Math.max(a.byteLength, b.byteLength);
    const ap = new Uint8Array(maxLen);
    const bp = new Uint8Array(maxLen);
    ap.set(a);
    bp.set(b);
    // Include length mismatch in diff so unequal-length tokens always fail
    // without short-circuiting on the first byte difference.
    let diff = a.byteLength ^ b.byteLength;
    for (let i = 0; i < maxLen; i++) {
      diff |= ap[i] ^ bp[i];
    }
    return diff === 0;
  }

  async function writeTombstone(
    id: string,
    reason: TombstoneMetadata['reason'],
    expiresAt: number,
  ): Promise<void> {
    await blobStore.put(
      tombstoneKey(id),
      encodeJsonStream({
        id,
        reason,
        expiresAt,
      }),
      {
        contentType: 'application/json',
        customMetadata: {
          expiresAt: String(expiresAt),
          reason,
        },
      },
    );
  }

  async function cleanupPrefix(
    prefix: string,
    limit: number,
    onEntry: (key: string) => Promise<boolean>,
  ): Promise<number> {
    const entries = await blobStore.list(prefix, limit);
    let deletedCount = 0;

    for (const entry of entries) {
      if (await onEntry(entry.key)) {
        deletedCount += 1;
      }
    }

    return deletedCount;
  }

  async function cleanup(limit = config.cleanupBatchSize): Promise<number> {
    const currentTime = now();
    let remaining = limit;
    let deletedCount = 0;

    deletedCount += await cleanupPrefix(
      'files/',
      remaining,
      async (key): Promise<boolean> => {
        const head = await blobStore.head(key);
        const metadata = parseStoredFileMetadata(head?.customMetadata);

        if (!metadata || metadata.expiresAt > currentTime) {
          return false;
        }

        await blobStore.delete(key).catch(() => undefined);
        return true;
      },
    );

    remaining = limit - deletedCount;
    if (remaining <= 0) {
      return deletedCount;
    }

    deletedCount += await cleanupPrefix(
      'tombstones/',
      remaining,
      async (key): Promise<boolean> => {
        const head = await blobStore.head(key);
        const metadata = parseTombstoneMetadata(head?.customMetadata);

        if (!metadata || metadata.expiresAt > currentTime) {
          return false;
        }

        await blobStore.delete(key).catch(() => undefined);
        return true;
      },
    );

    return deletedCount;
  }

  async function handleUpload(
    request: Request,
    ctx: ExecutionContextLike,
  ): Promise<Response> {
    const storageError = ensureStorageConfigured();
    if (storageError) {
      return storageError;
    }

    if (!config.secretToken) {
      return errorResponse(503, 'Upload endpoint is not configured.');
    }

    if (!isSecretAuthorized(request)) {
      return errorResponse(403, 'Invalid secret token.');
    }

    if (!request.body) {
      return errorResponse(400, 'Request body is required.');
    }

    const contentLength = Number(request.headers.get('content-length') ?? NaN);
    if (!Number.isNaN(contentLength) && contentLength > config.maxUploadBytes) {
      return errorResponse(413, 'Payload exceeds the maximum upload size.');
    }

    const requestedTtl = request.headers.get('x-dud-ttl');
    const deleteAfterRead = parseDeleteAfterRead(
      request.headers.get('x-dud-delete-after-read'),
    );

    let ttlMs: number;
    try {
      ttlMs = parseTtl(requestedTtl, config.defaultTtlMs, config.maxTtlMs);
    } catch (error) {
      return errorResponse(
        400,
        error instanceof Error ? error.message : 'Invalid TTL.',
      );
    }

    const createdAt = now();
    const id = createId();
    const metadata: StoredFileMetadata = {
      id,
      createdAt,
      expiresAt: createdAt + ttlMs,
      deleteAfterRead,
    };

    try {
      await blobStore.put(
        fileKey(id),
        sizeLimitedBody(request.body, config.maxUploadBytes),
        {
          contentType:
            request.headers.get('content-type') ?? 'application/octet-stream',
          customMetadata: {
            dudId: metadata.id,
            createdAt: String(metadata.createdAt),
            expiresAt: String(metadata.expiresAt),
            deleteAfterRead: String(metadata.deleteAfterRead),
          },
          ...(Number.isFinite(contentLength) ? { length: contentLength } : {}),
        },
      );
      await blobStore.delete(tombstoneKey(id)).catch(() => undefined);
    } catch (error) {
      await blobStore.delete(fileKey(id)).catch(() => undefined);
      if (error instanceof UploadTooLargeError) {
        return errorResponse(413, 'Payload exceeds the maximum upload size.');
      }
      console.error('Upload R2 write failed:', error);
      return errorResponse(
        500,
        'Upload failed before the file could be committed.',
      );
    }

    scheduleCleanup(ctx);
    return uploadResponseBody(metadata);
  }

  async function handleDownload(
    id: string,
    ctx: ExecutionContextLike,
  ): Promise<Response> {
    const storageError = ensureStorageConfigured();
    if (storageError) {
      return storageError;
    }

    const tombstone = await blobStore.head(tombstoneKey(id));
    const tombstoneMetadata = parseTombstoneMetadata(tombstone?.customMetadata);
    if (tombstoneMetadata) {
      scheduleCleanup(ctx);
      return errorResponse(410, 'File is no longer available.');
    }

    const blob = await blobStore.get(fileKey(id));
    if (!blob) {
      return errorResponse(404, 'Unknown file ID.');
    }

    const metadata = parseStoredFileMetadata(blob.customMetadata);
    if (!metadata) {
      ctx.waitUntil(blobStore.delete(fileKey(id)).catch(() => undefined));
      return errorResponse(410, 'File is no longer available.');
    }

    const currentTime = now();
    if (metadata.expiresAt <= currentTime) {
      ctx.waitUntil(
        Promise.all([
          blobStore.delete(fileKey(id)).catch(() => undefined),
          writeTombstone(id, 'expired', metadata.expiresAt).catch(
            () => undefined,
          ),
          cleanup(),
        ]),
      );
      return errorResponse(410, 'File has expired.');
    }

    const responseBody = streamWithCompletion(
      blob.body,
      async () => {
        if (metadata.deleteAfterRead) {
          await blobStore.delete(fileKey(id)).catch(() => undefined);
          await writeTombstone(id, 'consumed', metadata.expiresAt).catch(
            () => undefined,
          );
        }
        await cleanup();
      },
      ctx,
    );

    return new Response(responseBody, {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'cache-control': 'no-store',
      },
    });
  }

  async function handleFlush(
    request: Request,
    _ctx: ExecutionContextLike,
  ): Promise<Response> {
    const storageError = ensureStorageConfigured();
    if (storageError) {
      return storageError;
    }

    if (!config.secretToken) {
      return errorResponse(503, 'Flush endpoint is not configured.');
    }

    if (!isSecretAuthorized(request)) {
      return errorResponse(403, 'Invalid secret token.');
    }

    let deletedCount = 0;
    let partial = false;

    for (let i = 0; i < config.flushMaxIterations; i++) {
      const deletedInBatch = await cleanup();
      deletedCount += deletedInBatch;

      if (deletedInBatch < config.cleanupBatchSize) {
        break;
      }

      if (i === config.flushMaxIterations - 1) {
        partial = true;
      }
    }

    return jsonResponse({ ok: true, deletedCount, partial });
  }

  async function handleFetch(
    request: Request,
    ctx: ExecutionContextLike,
  ): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'GET' && path === '/v1/test') {
      return jsonResponse({
        ok: true,
        service: config.serviceName,
        host: url.host,
        version: config.version,
      });
    }

    if (request.method === 'POST' && path === '/v1/files') {
      return handleUpload(request, ctx);
    }

    if (request.method === 'GET' && path.startsWith('/v1/files/')) {
      const requestedId = path.slice('/v1/files/'.length).trim();
      if (!requestedId) {
        return errorResponse(400, 'File ID is required.');
      }
      const id = parseOpaqueId(requestedId);
      if (!id) {
        return errorResponse(400, 'Invalid file ID.');
      }
      return handleDownload(id, ctx);
    }

    if (request.method === 'POST' && path === '/v1/admin/flush') {
      return handleFlush(request, ctx);
    }

    if (request.method === 'GET' && path === '/robots.txt') {
      return new Response('User-agent: *\nDisallow: /\n', {
        headers: {
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'public, max-age=86400',
        },
      });
    }

    return new Response(
      '<!DOCTYPE html><html><head><meta name="robots" content="noindex,nofollow"></head><body></body></html>',
      {
        status: 200,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'x-robots-tag': 'noindex, nofollow',
        },
      },
    );
  }

  return {
    fetch: handleFetch,
  };
}
