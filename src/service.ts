// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { DEFAULT_CONFIG } from './config.js';
import { bytesEqual } from './cbor.js';
import { errorResponse, jsonResponse } from './http.js';
import { formatOpaqueId, generateOpaqueId, parseOpaqueId } from './ids.js';
import { parseTtl } from './ttl.js';
import {
  parseV2Credential,
  parseV2DeploymentKey,
  parseV2EnrollmentCredential,
  parseV2EnrollmentSecret,
} from './v2-auth.js';
import { v2ErrorResponse } from './v2-http.js';
import { createV2Service } from './v2-service.js';
import type { V2TimingObserver } from './v2-timing.js';
import type { V2RejectionObserver } from './v2-delivery-service.js';
import type { V2PairingRepository } from './v2-d1-pairing-repository.js';
import type { V2BodyStore, V2Repository } from './v2-repository.js';
import type {
  BlobObject,
  BlobStore,
  DudConfig,
  ExecutionContextLike,
} from './types.js';
import type { V2StoredState, V2Store } from './v2-types.js';

const LEGACY_RESERVATION_SECONDS = 5 * 60;

function validateV2Limits(limits: DudConfig['v2Limits']): void {
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error(`V2 limit ${name} must be a positive safe integer.`);
    }
  }
  if (
    limits.maxStagedBytes < limits.maxObjectBytes ||
    limits.maxTotalBytes < limits.maxObjectBytes
  ) {
    throw new Error(
      'V2 staged and total byte limits must permit one maximum-sized object.',
    );
  }
}

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
  beforeClose: (() => Promise<void>) | undefined,
  onComplete: () => Promise<void>,
  ctx: ExecutionContextLike,
): ReadableStream<Uint8Array> {
  const reader = stream.getReader();
  let completed = false;

  const complete = async (): Promise<void> => {
    if (completed) {
      return;
    }
    completed = true;
    if (beforeClose) {
      await beforeClose();
    }
    ctx.waitUntil(onComplete());
  };

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await reader.read();

      if (done) {
        await complete();
        controller.close();
        return;
      }

      controller.enqueue(value);
    },
    async cancel(reason) {
      await reader.cancel(reason);
      await complete();
    },
  });
}

class UploadTooLargeError extends Error {}

function sizeLimitedBody(
  body: ReadableStream<Uint8Array>,
  maxBytes: number,
  onBytes?: (count: number) => void,
): ReadableStream<Uint8Array> {
  let total = 0;
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        total += chunk.byteLength;
        if (total > maxBytes) {
          controller.error(new UploadTooLargeError());
        } else {
          onBytes?.(chunk.byteLength);
          controller.enqueue(chunk);
        }
      },
    }),
  );
}

function pruneLegacyAccounting(state: V2StoredState, now: number): void {
  for (const [id, reservation] of Object.entries(state.reservations)) {
    if (reservation.expiresAt <= now) {
      delete state.reservations[id];
    }
  }
  for (const [id, object] of Object.entries(state.legacyObjects)) {
    if (object.expiresAt > now) {
      continue;
    }
    delete state.legacyObjects[id];
    state.legacyCommittedBytes = Math.max(
      0,
      state.legacyCommittedBytes - object.ciphertextSize,
    );
  }
}

function legacyReservedBytes(state: V2StoredState): number {
  return Object.values(state.reservations).reduce(
    (total, reservation) => total + reservation.reservedBytes,
    0,
  );
}

function applyLegacyRateLimit(
  state: V2StoredState,
  key: string,
  now: number,
  maximum: number,
): boolean {
  const minute = Math.floor(now / 60);
  const window = state.rateWindows[key];
  if (!window || window.minute !== minute) {
    state.rateWindows[key] = { minute, count: 1 };
    return true;
  }
  if (window.count >= maximum) {
    return false;
  }
  window.count += 1;
  return true;
}

export interface DudDependencies {
  blobStore: BlobStore;
  config?: Partial<DudConfig>;
  now?: () => number;
  createId?: () => string;
  randomBytes?: (length: number) => Uint8Array;
  v2Store?: V2Store;
  v2Repository?: V2Repository;
  v2PairingRepository?: V2PairingRepository;
  v2BodyStore?: V2BodyStore;
  /** Receives one redacted phase-timing record per v2 request. */
  observeV2Timing?: V2TimingObserver;
  /**
   * Reports the reason a v2 request was refused. The wire response stays
   * uniform; only the operator sees this.
   */
  observeV2Rejection?: V2RejectionObserver;
  monotonicMs?: () => number;
}

interface DudServiceContext {
  blobStore: BlobStore;
  config: DudConfig;
  now: () => number;
  createId: () => string;
  v2?: ReturnType<typeof createV2Service>;
  /**
   * The whole-state ledger dead drop rate metering and the storage quota drops
   * share with peer transfers are charged to. It is set only where the store
   * keeps whole state; a deployment holding every peer record in a granular
   * repository has no such ledger, so its dead drop routes meter and account
   * exactly as they do with peer mode disabled.
   */
  legacyAccounting?: V2Store;
  v2Initialized?: Promise<void>;
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

async function meterLegacyRequest(
  service: DudServiceContext,
  operation: string,
  sourceKey: string,
): Promise<Response | null> {
  if (!service.legacyAccounting || !service.v2Initialized) {
    return null;
  }
  await service.v2Initialized;
  const now = Math.floor(service.now() / 1000);
  const allowed = await service.legacyAccounting.transaction((state) => {
    pruneLegacyAccounting(state, now);
    return applyLegacyRateLimit(
      state,
      `legacy:${operation}:${sourceKey}`,
      now,
      service.config.v2Limits.maxRequestsPerMinute,
    );
  });
  return allowed
    ? null
    : jsonResponse(
        { error: 'Legacy request rate exceeded.' },
        { status: 429, headers: { 'retry-after': '60' } },
      );
}

async function reserveLegacyUpload(
  service: DudServiceContext,
  objectId: string,
  contentLength: number | null,
): Promise<string | Response | null> {
  if (!service.legacyAccounting || !service.v2Initialized) {
    return null;
  }
  await service.v2Initialized;
  const now = Math.floor(service.now() / 1000);
  const reservationId = `v1-${objectId}`;
  const reservedBytes = contentLength ?? service.config.v2Limits.maxObjectBytes;
  try {
    await service.legacyAccounting.transaction((state) => {
      pruneLegacyAccounting(state, now);
      const legacyReservations = Object.values(state.reservations);
      const reservedForLegacy = legacyReservedBytes(state);
      if (
        legacyReservations.length >=
          service.config.v2Limits.maxConcurrentUploads ||
        reservedForLegacy + reservedBytes >
          service.config.v2Limits.maxStagedBytes ||
        Object.keys(state.legacyObjects).length + legacyReservations.length >=
          service.config.v2Limits.maxObjectsPerCapability ||
        state.legacyCommittedBytes + reservedForLegacy + reservedBytes >
          service.config.v2Limits.maxTotalBytes
      ) {
        throw new Error('legacy-quota');
      }
      state.reservations[reservationId] = {
        id: reservationId,
        objectId,
        reservedBytes,
        expiresAt: now + LEGACY_RESERVATION_SECONDS,
      };
    });
  } catch (error) {
    if (error instanceof Error && error.message === 'legacy-quota') {
      return errorResponse(429, 'Legacy upload quota exceeded.');
    }
    throw error;
  }
  return reservationId;
}

async function abortLegacyReservation(
  service: DudServiceContext,
  reservationId: string | null,
): Promise<void> {
  if (!reservationId || !service.legacyAccounting) {
    return;
  }
  await service.legacyAccounting.transaction((state) => {
    delete state.reservations[reservationId];
  });
}

async function commitLegacyUpload(
  service: DudServiceContext,
  reservationId: string | null,
  metadata: StoredFileMetadata,
  ciphertextSize: number,
): Promise<void> {
  if (!reservationId || !service.legacyAccounting) {
    return;
  }
  await service.legacyAccounting.transaction((state) => {
    const reservation = state.reservations[reservationId];
    if (!reservation || reservation.objectId !== metadata.id) {
      throw new Error('Legacy upload reservation is missing.');
    }
    if (
      state.legacyCommittedBytes + ciphertextSize >
      service.config.v2Limits.maxTotalBytes
    ) {
      throw new Error('Legacy upload exceeds the total storage quota.');
    }
    state.legacyObjects[metadata.id] = {
      objectId: metadata.id,
      ciphertextSize,
      expiresAt: Math.floor(metadata.expiresAt / 1000),
    };
    state.legacyCommittedBytes += ciphertextSize;
    delete state.reservations[reservationId];
  });
}

async function removeLegacyObjectAccounting(
  service: DudServiceContext,
  objectId: string,
): Promise<void> {
  if (!service.legacyAccounting) {
    return;
  }
  await service.legacyAccounting.transaction((state) => {
    const object = state.legacyObjects[objectId];
    if (!object) {
      return;
    }
    delete state.legacyObjects[objectId];
    state.legacyCommittedBytes = Math.max(
      0,
      state.legacyCommittedBytes - object.ciphertextSize,
    );
  });
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

  // The V2 whole-state store holds shared quota accounting, so its bounded
  // prune rides along with V1 cleanup rather than with any V2 request. It
  // starts here and is awaited only on the way out, so it neither delays nor
  // reorders the V1 blob passes.
  const legacyPrune = service.v2?.cleanup().catch(() => undefined);

  try {
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
        await removeLegacyObjectAccounting(service, metadata.id).catch(
          () => undefined,
        );
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
  } finally {
    await legacyPrune;
  }
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
): Promise<{ error: Response | null; storedBytes: number }> {
  let storedBytes = 0;
  try {
    await service.blobStore.put(
      fileKey(metadata.id),
      sizeLimitedBody(
        requestData.body,
        service.config.maxUploadBytes,
        (count) => {
          storedBytes += count;
        },
      ),
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
    return { error: null, storedBytes };
  } catch (error) {
    await service.blobStore.delete(fileKey(metadata.id)).catch(() => undefined);
    if (error instanceof UploadTooLargeError) {
      return {
        error: errorResponse(413, 'Payload exceeds the maximum upload size.'),
        storedBytes,
      };
    }
    console.error('Upload R2 write failed:', error);
    return {
      error: errorResponse(
        500,
        'Upload failed before the file could be committed.',
      ),
      storedBytes,
    };
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

  const reservation = await reserveLegacyUpload(
    service,
    metadata.id,
    uploadRequest.data.contentLength,
  );
  if (reservation instanceof Response) {
    return reservation;
  }
  const stored = await storeUpload(service, uploadRequest.data, metadata);
  if (stored.error) {
    await abortLegacyReservation(service, reservation);
    return stored.error;
  }
  try {
    await commitLegacyUpload(
      service,
      reservation,
      metadata,
      stored.storedBytes,
    );
  } catch (error) {
    await service.blobStore.delete(fileKey(metadata.id)).catch(() => undefined);
    await abortLegacyReservation(service, reservation).catch(() => undefined);
    console.error('Legacy upload accounting failed:', error);
    return errorResponse(
      503,
      'Upload could not be committed to quota accounting.',
    );
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
    (async () => {
      try {
        await Promise.all([
          service.blobStore.delete(fileKey(id)).catch(() => undefined),
          removeLegacyObjectAccounting(service, id).catch(() => undefined),
          cleanup(service),
        ]);
      } finally {
        // Tombstones record a file's original expiry, which is already in the
        // past here. Writing one after cleanup keeps this cleanup pass from
        // deleting the marker before a subsequent download can observe it.
        await writeTombstone(service, id, 'expired', expiresAt).catch(
          () => undefined,
        );
      }
    })(),
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
    ctx.waitUntil(
      Promise.all([
        service.blobStore.delete(fileKey(id)).catch(() => undefined),
        removeLegacyObjectAccounting(service, id).catch(() => undefined),
      ]),
    );
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
    downloadReady.metadata.deleteAfterRead
      ? async () => {
          // Make consumption visible before the response stream closes. Blob
          // deletion and quota cleanup can remain asynchronous because every
          // subsequent read checks the tombstone first.
          await writeTombstone(
            service,
            id,
            'consumed',
            downloadReady.metadata.expiresAt,
          ).catch(() => undefined);
        }
      : undefined,
    async () => {
      if (downloadReady.metadata.deleteAfterRead) {
        await service.blobStore.delete(fileKey(id)).catch(() => undefined);
        await removeLegacyObjectAccounting(service, id).catch(() => undefined);
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
  sourceKey: string,
  observeV2Timing?: V2TimingObserver,
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path.startsWith('/v2/')) {
    if (!service.config.v2Enabled || !service.v2) {
      return v2ErrorResponse(4, 'V2 endpoint is not available.');
    }
    return service.v2.fetch(
      request,
      service.config.v1Enabled,
      sourceKey,
      observeV2Timing,
    );
  }

  if (!service.config.v1Enabled && path.startsWith('/v1/')) {
    return errorResponse(404, 'Endpoint is not available.');
  }

  if (path.startsWith('/v1/')) {
    const operation = path.startsWith('/v1/files/')
      ? `${request.method}:files-object`
      : `${request.method}:${path}`;
    const rateError = await meterLegacyRequest(service, operation, sourceKey);
    if (rateError) {
      return rateError;
    }
  }

  if (request.method === 'GET') {
    return handleGetRequest(service, path, url, ctx);
  }

  if (request.method === 'POST') {
    return handlePostRequest(service, request, path, ctx);
  }

  return shellResponse();
}

export function createDudService(dependencies: DudDependencies) {
  const config = {
    ...DEFAULT_CONFIG,
    ...dependencies.config,
    v2Limits: {
      ...DEFAULT_CONFIG.v2Limits,
      ...dependencies.config?.v2Limits,
    },
  };
  validateV2Limits(config.v2Limits);
  const service: DudServiceContext = {
    blobStore: dependencies.blobStore,
    config,
    now: dependencies.now ?? (() => Date.now()),
    createId: dependencies.createId ?? generateOpaqueId,
  };
  if (config.v2Enabled) {
    if (!dependencies.v2Store) {
      throw new Error('A v2 store is required when v2 endpoints are enabled.');
    }
    const deploymentKey = parseV2DeploymentKey(config.v2DeploymentKey);
    const adminSecret = config.v2AdminSecret
      ? parseV2Credential('DUD_PEER_ADMIN_SECRET', config.v2AdminSecret)
      : undefined;
    const enrollmentSecret = parseV2EnrollmentSecret(
      config.v2Secret,
      config.v2AcceptWeakEnrollmentKdf,
    );
    // The 32-byte credentials are compared decoded, which catches two spellings
    // of one key — including an enrollment secret that carries a derived key,
    // whose prefix would otherwise make a reused deployment key look distinct.
    // The v1 secret and an enrollment passphrase are opaque strings, so they can
    // only be compared textually.
    const textCredentials = [
      config.secretToken,
      config.v2DeploymentKey,
      config.v2AdminSecret,
      config.v2Secret,
    ].filter((value): value is string => value !== undefined);
    const carriedEnrollmentKey =
      enrollmentSecret === undefined
        ? undefined
        : parseV2EnrollmentCredential(enrollmentSecret);
    const reusedBinaryKey =
      carriedEnrollmentKey?.kind === 'key' &&
      [deploymentKey, adminSecret].some(
        (credential) =>
          credential && bytesEqual(credential, carriedEnrollmentKey.key),
      );
    const collides =
      (adminSecret && bytesEqual(adminSecret, deploymentKey)) ||
      reusedBinaryKey ||
      new Set(textCredentials).size !== textCredentials.length;
    if (collides) {
      throw new Error(
        'V1, v2 administration, v2 enrollment, and v2 deployment credentials must be distinct.',
      );
    }
    if (!enrollmentSecret && !config.v2OpenEnrollment) {
      throw new Error(
        'DUD_PEER_SECRET is required when v2 is enabled. Set DUD_PEER_OPEN_ENROLLMENT=true to accept pairing from anyone who learns the hostname.',
      );
    }
    if (dependencies.v2Store.wholeState) {
      service.legacyAccounting = dependencies.v2Store;
    }
    service.v2 = createV2Service({
      store: dependencies.v2Store,
      repository: dependencies.v2Repository,
      pairingRepository: dependencies.v2PairingRepository,
      bodyStore: dependencies.v2BodyStore,
      deploymentKey,
      adminSecret,
      enrollmentSecret,
      limits: config.v2Limits,
      now: service.now,
      randomBytes: dependencies.randomBytes,
      observeTiming: dependencies.observeV2Timing,
      observeRejection: dependencies.observeV2Rejection,
      monotonicMs: dependencies.monotonicMs,
    });
    // The same readiness the v2 routes await. Initializing the store a second
    // time here would run a concurrent duplicate of that work and leave it in
    // flight, because only a v1 request that meters against v2 accounting ever
    // awaits this one — on a v2-only deployment, nothing would.
    service.v2Initialized = service.v2.initialized;
  }

  return {
    /**
     * `observeV2Timing` reports the phase timings of this one request, which is
     * how a caller correlates them with its own access log entry. It takes
     * precedence over the observer the service was constructed with.
     */
    fetch(
      request: Request,
      ctx: ExecutionContextLike,
      sourceKey = 'unknown',
      observeV2Timing?: V2TimingObserver,
    ) {
      return handleFetch(service, request, ctx, sourceKey, observeV2Timing);
    },
  };
}
