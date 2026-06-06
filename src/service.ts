// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { DEFAULT_CONFIG } from './config.js';
import { errorResponse, jsonResponse } from './http.js';
import { formatOpaqueId, generateOpaqueId, parseOpaqueId } from './ids.js';
import { parseTtl } from './ttl.js';
import type {
  BlobObject,
  BlobStore,
  DudConfig,
  ExecutionContextLike,
} from './types.js';

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

interface DudServiceContext {
  blobStore: BlobStore;
  config: DudConfig;
  now: () => number;
  createId: () => string;
}

interface UploadRequestData {
  body: ReadableStream<Uint8Array>;
  contentLength: number | null;
  contentType: string;
  deleteAfterRead: boolean;
  ttlMs: number;
}

interface DownloadReadyResult {
  blob: BlobObject;
  metadata: StoredFileMetadata;
}

function ensureStorageConfigured(config: DudConfig): Response | null {
  if (config.storageConfigured) {
    return null;
  }

  return errorResponse(503, config.storageNotConfiguredMessage);
}

function scheduleCleanup(
  service: DudServiceContext,
  ctx: ExecutionContextLike,
  limit?: number,
): void {
  ctx.waitUntil(cleanup(service, limit));
}

function isSecretAuthorized(request: Request, secretToken: string): boolean {
  const provided = request.headers.get('x-dud-secret-token');
  if (!provided) {
    return false;
  }

  const enc = new TextEncoder();
  const a = enc.encode(provided);
  const b = enc.encode(secretToken);
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

function requireAuthorizedRequest(
  service: DudServiceContext,
  request: Request,
  unavailableMessage: string,
): Response | null {
  const storageError = ensureStorageConfigured(service.config);
  if (storageError) {
    return storageError;
  }

  if (!service.config.secretToken) {
    return errorResponse(503, unavailableMessage);
  }

  if (!isSecretAuthorized(request, service.config.secretToken)) {
    return errorResponse(403, 'Invalid secret token.');
  }

  return null;
}

async function writeTombstone(
  service: DudServiceContext,
  id: string,
  reason: TombstoneMetadata['reason'],
  expiresAt: number,
): Promise<void> {
  await service.blobStore.put(
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
  blobStore: BlobStore,
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

async function cleanup(
  service: DudServiceContext,
  limit = service.config.cleanupBatchSize,
): Promise<number> {
  const currentTime = service.now();
  let remaining = limit;
  let deletedCount = 0;

  deletedCount += await cleanupPrefix(
    service.blobStore,
    'files/',
    remaining,
    async (key): Promise<boolean> => {
      const head = await service.blobStore.head(key);
      const metadata = parseStoredFileMetadata(head?.customMetadata);

      if (!metadata || metadata.expiresAt > currentTime) {
        return false;
      }

      await service.blobStore.delete(key).catch(() => undefined);
      return true;
    },
  );

  remaining = limit - deletedCount;
  if (remaining <= 0) {
    return deletedCount;
  }

  deletedCount += await cleanupPrefix(
    service.blobStore,
    'tombstones/',
    remaining,
    async (key): Promise<boolean> => {
      const head = await service.blobStore.head(key);
      const metadata = parseTombstoneMetadata(head?.customMetadata);

      if (!metadata || metadata.expiresAt > currentTime) {
        return false;
      }

      await service.blobStore.delete(key).catch(() => undefined);
      return true;
    },
  );

  return deletedCount;
}

function parseUploadContentLength(
  service: DudServiceContext,
  request: Request,
): number | null | Response {
  const rawContentLength = Number(request.headers.get('content-length') ?? NaN);
  if (
    !Number.isNaN(rawContentLength) &&
    rawContentLength > service.config.maxUploadBytes
  ) {
    return errorResponse(413, 'Payload exceeds the maximum upload size.');
  }

  return Number.isFinite(rawContentLength) ? rawContentLength : null;
}

function parseUploadTtlOrError(
  service: DudServiceContext,
  request: Request,
): number | Response {
  try {
    return parseTtl(
      request.headers.get('x-dud-ttl'),
      service.config.defaultTtlMs,
      service.config.maxTtlMs,
    );
  } catch (error) {
    return errorResponse(
      400,
      error instanceof Error ? error.message : 'Invalid TTL.',
    );
  }
}

function validateUploadRequest(
  service: DudServiceContext,
  request: Request,
): { ok: true; data: UploadRequestData } | { ok: false; response: Response } {
  if (!request.body) {
    return {
      ok: false,
      response: errorResponse(400, 'Request body is required.'),
    };
  }

  const contentLength = parseUploadContentLength(service, request);
  if (contentLength instanceof Response) {
    return { ok: false, response: contentLength };
  }

  const ttlMs = parseUploadTtlOrError(service, request);
  if (ttlMs instanceof Response) {
    return { ok: false, response: ttlMs };
  }

  return {
    ok: true,
    data: {
      body: request.body,
      contentLength,
      contentType:
        request.headers.get('content-type') ?? 'application/octet-stream',
      deleteAfterRead: parseDeleteAfterRead(
        request.headers.get('x-dud-delete-after-read'),
      ),
      ttlMs,
    },
  };
}

async function storeUpload(
  service: DudServiceContext,
  requestData: UploadRequestData,
  metadata: StoredFileMetadata,
): Promise<Response | null> {
  try {
    await service.blobStore.put(
      fileKey(metadata.id),
      sizeLimitedBody(requestData.body, service.config.maxUploadBytes),
      {
        contentType: requestData.contentType,
        customMetadata: {
          dudId: metadata.id,
          createdAt: String(metadata.createdAt),
          expiresAt: String(metadata.expiresAt),
          deleteAfterRead: String(metadata.deleteAfterRead),
        },
        ...(requestData.contentLength !== null
          ? { length: requestData.contentLength }
          : {}),
      },
    );
    await service.blobStore
      .delete(tombstoneKey(metadata.id))
      .catch(() => undefined);
    return null;
  } catch (error) {
    await service.blobStore.delete(fileKey(metadata.id)).catch(() => undefined);
    if (error instanceof UploadTooLargeError) {
      return errorResponse(413, 'Payload exceeds the maximum upload size.');
    }
    console.error('Upload R2 write failed:', error);
    return errorResponse(
      500,
      'Upload failed before the file could be committed.',
    );
  }
}

async function handleUpload(
  service: DudServiceContext,
  request: Request,
  ctx: ExecutionContextLike,
): Promise<Response> {
  const authError = requireAuthorizedRequest(
    service,
    request,
    'Upload endpoint is not configured.',
  );
  if (authError) {
    return authError;
  }

  const uploadRequest = validateUploadRequest(service, request);
  if (!uploadRequest.ok) {
    return uploadRequest.response;
  }

  const createdAt = service.now();
  const metadata: StoredFileMetadata = {
    id: service.createId(),
    createdAt,
    expiresAt: createdAt + uploadRequest.data.ttlMs,
    deleteAfterRead: uploadRequest.data.deleteAfterRead,
  };

  const uploadError = await storeUpload(service, uploadRequest.data, metadata);
  if (uploadError) {
    return uploadError;
  }

  scheduleCleanup(service, ctx);
  return uploadResponseBody(metadata);
}

async function loadDownloadBlob(
  service: DudServiceContext,
  id: string,
  ctx: ExecutionContextLike,
): Promise<Response | BlobObject> {
  const storageError = ensureStorageConfigured(service.config);
  if (storageError) {
    return storageError;
  }

  const tombstone = await service.blobStore.head(tombstoneKey(id));
  const tombstoneMetadata = parseTombstoneMetadata(tombstone?.customMetadata);
  if (tombstoneMetadata) {
    scheduleCleanup(service, ctx);
    return errorResponse(410, 'File is no longer available.');
  }

  const blob = await service.blobStore.get(fileKey(id));
  if (!blob) {
    return errorResponse(404, 'Unknown file ID.');
  }

  return blob;
}

function queueExpiredDownloadCleanup(
  service: DudServiceContext,
  id: string,
  ctx: ExecutionContextLike,
  expiresAt: number,
): void {
  ctx.waitUntil(
    Promise.all([
      service.blobStore.delete(fileKey(id)).catch(() => undefined),
      writeTombstone(service, id, 'expired', expiresAt).catch(() => undefined),
      cleanup(service),
    ]),
  );
}

function loadDownloadMetadata(
  service: DudServiceContext,
  id: string,
  blob: BlobObject,
  ctx: ExecutionContextLike,
): Response | StoredFileMetadata {
  const metadata = parseStoredFileMetadata(blob.customMetadata);
  if (!metadata) {
    ctx.waitUntil(service.blobStore.delete(fileKey(id)).catch(() => undefined));
    return errorResponse(410, 'File is no longer available.');
  }

  if (metadata.expiresAt <= service.now()) {
    queueExpiredDownloadCleanup(service, id, ctx, metadata.expiresAt);
    return errorResponse(410, 'File has expired.');
  }

  return metadata;
}

async function loadDownloadReadyResult(
  service: DudServiceContext,
  id: string,
  ctx: ExecutionContextLike,
): Promise<Response | DownloadReadyResult> {
  const blob = await loadDownloadBlob(service, id, ctx);
  if (blob instanceof Response) {
    return blob;
  }

  const metadata = loadDownloadMetadata(service, id, blob, ctx);
  if (metadata instanceof Response) {
    return metadata;
  }

  return { blob, metadata };
}

async function handleDownload(
  service: DudServiceContext,
  id: string,
  ctx: ExecutionContextLike,
): Promise<Response> {
  const downloadReady = await loadDownloadReadyResult(service, id, ctx);
  if (downloadReady instanceof Response) {
    return downloadReady;
  }

  const responseBody = streamWithCompletion(
    downloadReady.blob.body,
    async () => {
      if (downloadReady.metadata.deleteAfterRead) {
        await service.blobStore.delete(fileKey(id)).catch(() => undefined);
        await writeTombstone(
          service,
          id,
          'consumed',
          downloadReady.metadata.expiresAt,
        ).catch(() => undefined);
      }
      await cleanup(service);
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
  service: DudServiceContext,
  request: Request,
): Promise<Response> {
  const authError = requireAuthorizedRequest(
    service,
    request,
    'Flush endpoint is not configured.',
  );
  if (authError) {
    return authError;
  }

  const { deletedCount, partial } = await flushExpiredEntries(service);
  return jsonResponse({ ok: true, deletedCount, partial });
}

async function flushExpiredEntries(
  service: DudServiceContext,
): Promise<{ deletedCount: number; partial: boolean }> {
  let deletedCount = 0;
  let partial = false;

  for (let i = 0; i < service.config.flushMaxIterations; i++) {
    const deletedInBatch = await cleanup(service);
    deletedCount += deletedInBatch;

    if (deletedInBatch < service.config.cleanupBatchSize) {
      break;
    }

    if (i === service.config.flushMaxIterations - 1) {
      partial = true;
    }
  }

  return { deletedCount, partial };
}

function testResponse(service: DudServiceContext, url: URL): Response {
  return jsonResponse({
    ok: true,
    service: service.config.serviceName,
    host: url.host,
    version: service.config.version,
  });
}

function robotsResponse(): Response {
  return new Response('User-agent: *\nDisallow: /\n', {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'public, max-age=86400',
    },
  });
}

function shellResponse(): Response {
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

function parseRequestedFileId(path: string): string | Response {
  const requestedId = path.slice('/v1/files/'.length).trim();
  if (!requestedId) {
    return errorResponse(400, 'File ID is required.');
  }

  const id = parseOpaqueId(requestedId);
  return id ?? errorResponse(400, 'Invalid file ID.');
}

function staticGetResponse(
  service: DudServiceContext,
  url: URL,
): Response | null {
  const path = url.pathname;
  if (path === '/v1/test') {
    return testResponse(service, url);
  }

  if (path === '/robots.txt') {
    return robotsResponse();
  }

  return null;
}

async function handleGetRequest(
  service: DudServiceContext,
  path: string,
  url: URL,
  ctx: ExecutionContextLike,
): Promise<Response> {
  const response = staticGetResponse(service, url);
  if (response) {
    return response;
  }

  if (!path.startsWith('/v1/files/')) {
    return shellResponse();
  }

  const id = parseRequestedFileId(path);
  return id instanceof Response ? id : handleDownload(service, id, ctx);
}

async function handlePostRequest(
  service: DudServiceContext,
  request: Request,
  path: string,
  ctx: ExecutionContextLike,
): Promise<Response> {
  if (path === '/v1/files') {
    return handleUpload(service, request, ctx);
  }

  if (path === '/v1/admin/flush') {
    return handleFlush(service, request);
  }

  return shellResponse();
}

async function handleFetch(
  service: DudServiceContext,
  request: Request,
  ctx: ExecutionContextLike,
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'GET') {
    return handleGetRequest(service, path, url, ctx);
  }

  if (request.method === 'POST') {
    return handlePostRequest(service, request, path, ctx);
  }

  return shellResponse();
}

export function createDudService(dependencies: DudDependencies) {
  const service: DudServiceContext = {
    blobStore: dependencies.blobStore,
    config: {
      ...DEFAULT_CONFIG,
      ...dependencies.config,
    },
    now: dependencies.now ?? (() => Date.now()),
    createId: dependencies.createId ?? generateOpaqueId,
  };

  return {
    fetch(request: Request, ctx: ExecutionContextLike) {
      return handleFetch(service, request, ctx);
    },
  };
}
