// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { bytesEqual, decodeCbor, encodeCbor, type CborValue } from './cbor.js';
import {
  encodeV2DeliveryFrameAuthorizationPrefix,
  validateV2DeliveryRequestHeader,
  V2_DELIVERY_FRAME_MAGIC,
  V2_DELIVERY_FRAME_PREFIX_BYTES,
  V2_DELIVERY_HEADER_OVERHEAD_BYTES,
  V2_DELIVERY_REQUEST_KEYS,
  V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES,
  V2_MAX_ENCRYPTED_PAYLOAD_BYTES,
} from './v2-delivery-frame.js';
import { V2_ERROR_HTTP_STATUS, type V2ErrorCode } from './v2-contract.js';
import { StreamingSha256 } from './sha256.js';

export const V2_CBOR_CONTENT_TYPE = 'application/dud+cbor; version=2';
export const V2_CONTENT_SHA256_HEADER = 'dud-content-sha256';

export type { V2ErrorCode } from './v2-contract.js';

export interface V2FramedDeliveryRequest {
  header: Map<number, CborValue>;
  payload: ReadableStream<Uint8Array>;
  verified: Promise<void>;
  authorizationDigest: Promise<Uint8Array>;
}

function requireExactContentLength(request: Request, maximum: number): number {
  const raw = request.headers.get('content-length');
  if (
    raw === null ||
    !/^(?:0|[1-9][0-9]*)$/.test(raw) ||
    Number(raw) > maximum
  ) {
    throw new Error('Framed request Content-Length is invalid or too large.');
  }
  return Number(raw);
}

function requireContentDigest(request: Request): Uint8Array {
  const value = request.headers.get(V2_CONTENT_SHA256_HEADER);
  if (!value || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(
      'DUD-Content-SHA256 must contain a lowercase SHA-256 digest.',
    );
  }
  return Uint8Array.from(value.match(/.{2}/g)!, (byte) =>
    Number.parseInt(byte, 16),
  );
}

async function readAtLeast(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  bytes: Uint8Array[],
  minimum: number,
  size: number,
): Promise<number> {
  let total = size;
  while (total < minimum) {
    const result = await reader.read();
    if (result.done) {
      throw new Error('Framed request body is truncated.');
    }
    bytes.push(result.value);
    total += result.value.byteLength;
  }
  return total;
}

function joinPrefix(chunks: readonly Uint8Array[], length: number): Uint8Array {
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    const amount = Math.min(chunk.byteLength, length - offset);
    result.set(chunk.subarray(0, amount), offset);
    offset += amount;
    if (offset === length) {
      break;
    }
  }
  return result;
}

function remainderAfter(
  chunks: readonly Uint8Array[],
  consumed: number,
): Uint8Array[] {
  const remainder: Uint8Array[] = [];
  let offset = consumed;
  for (const chunk of chunks) {
    if (offset >= chunk.byteLength) {
      offset -= chunk.byteLength;
      continue;
    }
    remainder.push(chunk.subarray(offset));
    offset = 0;
  }
  return remainder;
}

function secureHeaders(headers?: HeadersInit): Headers {
  const result = new Headers(headers);
  result.set('cache-control', 'no-store');
  result.set('x-content-type-options', 'nosniff');
  result.set('x-frame-options', 'DENY');
  return result;
}

export function v2CborResponse(
  body: CborValue,
  status = 200,
  headers?: HeadersInit,
): Response {
  const responseHeaders = secureHeaders(headers);
  responseHeaders.set('content-type', V2_CBOR_CONTENT_TYPE);
  return new Response(Uint8Array.from(encodeCbor(body)).buffer, {
    status,
    headers: responseHeaders,
  });
}

export function v2EmptyResponse(status = 204): Response {
  return new Response(null, { status, headers: secureHeaders() });
}

export function v2ErrorResponse(
  code: V2ErrorCode,
  message: string,
  retryAfter?: number,
): Response {
  const safeMessage =
    new TextEncoder().encode(message).byteLength <= 256
      ? message
      : 'Request failed.';
  const body = new Map<number, CborValue>([
    [1, code],
    [2, safeMessage],
  ]);
  if (retryAfter !== undefined) {
    body.set(3, retryAfter);
  }
  return v2CborResponse(body, V2_ERROR_HTTP_STATUS[code]);
}

export function v2NotFoundResponse(): Response {
  return v2ErrorResponse(4, 'Object is not available.');
}

/** Reads a bounded V2 CBOR request without losing its canonical source bytes. */
export async function readV2RequestBytes(
  request: Request,
  maxBytes: number,
): Promise<Uint8Array> {
  if (request.headers.get('content-type') !== V2_CBOR_CONTENT_TYPE) {
    throw new Error(`Content-Type must be ${V2_CBOR_CONTENT_TYPE}.`);
  }
  const rawContentLength = request.headers.get('content-length');
  if (
    rawContentLength !== null &&
    (!/^(?:0|[1-9][0-9]*)$/.test(rawContentLength) ||
      Number(rawContentLength) > maxBytes)
  ) {
    throw new Error('CBOR request Content-Length is invalid or too large.');
  }
  if (!request.body) {
    throw new Error('CBOR request body is missing.');
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = request.body.getReader();
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) {
        break;
      }
      size += result.value.byteLength;
      if (size > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error('CBOR request body exceeds the configured limit.');
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/**
 * Reads only the bounded frame prefix and header, then exposes the opaque
 * ciphertext as a verifying stream. A caller must await `verified` after
 * storing the stream before making the associated metadata visible.
 */
export async function readV2FramedDeliveryRequest(
  request: Request,
  maximumDescriptorBytes = V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES,
  maximumPayloadBytes = V2_MAX_ENCRYPTED_PAYLOAD_BYTES,
): Promise<V2FramedDeliveryRequest> {
  if (request.headers.get('content-type') !== V2_CBOR_CONTENT_TYPE) {
    throw new Error(`Content-Type must be ${V2_CBOR_CONTENT_TYPE}.`);
  }
  if (!request.body) {
    throw new Error('Framed request body is missing.');
  }
  // The header ceiling follows the configured descriptor limit, so lowering
  // that limit also lowers what a hostile caller can make the server read
  // before the descriptor itself is rejected. The protocol constant stays the
  // absolute bound, so a configured value can only tighten this.
  const maximumHeaderBytes = Math.min(
    V2_MAX_ENCRYPTED_DESCRIPTOR_BYTES,
    maximumDescriptorBytes + V2_DELIVERY_HEADER_OVERHEAD_BYTES,
  );
  const maximum =
    V2_DELIVERY_FRAME_PREFIX_BYTES + maximumHeaderBytes + maximumPayloadBytes;
  const contentLength = requireExactContentLength(request, maximum);
  const contentDigest = requireContentDigest(request);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    received = await readAtLeast(
      reader,
      chunks,
      V2_DELIVERY_FRAME_PREFIX_BYTES,
      received,
    );
    const prefix = joinPrefix(chunks, V2_DELIVERY_FRAME_PREFIX_BYTES);
    if (!bytesEqual(prefix.subarray(0, 4), V2_DELIVERY_FRAME_MAGIC)) {
      throw new Error('Delivery frame magic is invalid.');
    }
    const headerLength = new DataView(
      prefix.buffer,
      prefix.byteOffset,
      prefix.byteLength,
    ).getUint32(4, false);
    if (headerLength === 0 || headerLength > maximumHeaderBytes) {
      throw new Error('Delivery frame header length is invalid.');
    }
    const headerEnd = V2_DELIVERY_FRAME_PREFIX_BYTES + headerLength;
    if (contentLength < headerEnd) {
      throw new Error('Framed request body is truncated.');
    }
    received = await readAtLeast(reader, chunks, headerEnd, received);
    const frameHeader = joinPrefix(chunks, headerEnd);
    const decoded = decodeCbor(
      frameHeader.subarray(V2_DELIVERY_FRAME_PREFIX_BYTES),
      {
        maxBytes: maximumHeaderBytes,
        maxMapPairs: 16,
        maxDepth: 4,
        requireDeterministic: true,
      },
    );
    if (!(decoded instanceof Map)) {
      throw new Error('Delivery frame header must be a CBOR map.');
    }
    const header = validateV2DeliveryRequestHeader(
      decoded,
      maximumDescriptorBytes,
    );
    const payloadLength = header.get(V2_DELIVERY_REQUEST_KEYS.payloadLength);
    const payloadDigest = header.get(V2_DELIVERY_REQUEST_KEYS.payloadDigest);
    if (
      typeof payloadLength !== 'number' ||
      !Number.isSafeInteger(payloadLength) ||
      payloadLength < 0 ||
      payloadLength > maximumPayloadBytes ||
      !(payloadDigest instanceof Uint8Array) ||
      payloadDigest.byteLength !== 32 ||
      contentLength !== headerEnd + payloadLength
    ) {
      throw new Error(
        'Framed request Content-Length does not match its frame.',
      );
    }

    const frameHash = new StreamingSha256().update(frameHeader);
    const authorizationHash = new StreamingSha256().update(
      encodeV2DeliveryFrameAuthorizationPrefix(header),
    );
    const payloadHash = new StreamingSha256();
    const queued = remainderAfter(chunks, headerEnd);
    let payloadBytes = 0;
    let settled = false;
    let resolveVerified!: () => void;
    let rejectVerified!: (reason: unknown) => void;
    let resolveAuthorizationDigest!: (digest: Uint8Array) => void;
    let rejectAuthorizationDigest!: (reason: unknown) => void;
    const verified = new Promise<void>((resolve, reject) => {
      resolveVerified = resolve;
      rejectVerified = reject;
    });
    const authorizationDigest = new Promise<Uint8Array>((resolve, reject) => {
      resolveAuthorizationDigest = resolve;
      rejectAuthorizationDigest = reject;
    });
    const fail = (reason: unknown): void => {
      if (!settled) {
        settled = true;
        rejectVerified(reason);
        rejectAuthorizationDigest(reason);
      }
    };
    const verifyEnd = async (): Promise<void> => {
      if (queued.length !== 0) {
        throw new Error('Framed request body has an invalid size.');
      }
      const trailing = await reader.read();
      if (!trailing.done || payloadBytes !== payloadLength) {
        throw new Error('Framed request body has an invalid size.');
      }
      if (!bytesEqual(payloadHash.digest(), payloadDigest)) {
        throw new Error(
          'Framed request payload digest does not match its body.',
        );
      }
      if (!bytesEqual(frameHash.digest(), contentDigest)) {
        throw new Error(
          'DUD-Content-SHA256 does not match the framed request.',
        );
      }
    };
    const payload = new ReadableStream<Uint8Array>({
      async pull(controller): Promise<void> {
        try {
          if (payloadBytes === payloadLength) {
            await verifyEnd();
            settled = true;
            resolveVerified();
            resolveAuthorizationDigest(authorizationHash.digest());
            controller.close();
            return;
          }
          const chunk = queued.shift() ?? (await reader.read()).value;
          if (!chunk) {
            throw new Error('Framed request body is truncated.');
          }
          payloadBytes += chunk.byteLength;
          if (payloadBytes > payloadLength) {
            throw new Error('Framed request body has an invalid size.');
          }
          payloadHash.update(chunk);
          frameHash.update(chunk);
          authorizationHash.update(chunk);
          controller.enqueue(chunk);
          if (payloadBytes === payloadLength) {
            await verifyEnd();
            settled = true;
            resolveVerified();
            resolveAuthorizationDigest(authorizationHash.digest());
            controller.close();
          }
        } catch (error) {
          fail(error);
          controller.error(error);
          await reader.cancel(error).catch(() => undefined);
        }
      },
      async cancel(reason): Promise<void> {
        fail(
          reason instanceof Error
            ? reason
            : new Error('Payload was cancelled.'),
        );
        await reader.cancel(reason).catch(() => undefined);
      },
    });
    return { header, payload, verified, authorizationDigest };
  } catch (error) {
    await reader.cancel(error).catch(() => undefined);
    throw error;
  }
}

export async function readV2CborRequest(
  request: Request,
  maxBytes: number,
): Promise<CborValue> {
  return decodeCbor(await readV2RequestBytes(request, maxBytes), { maxBytes });
}

export function v2RawResponse(
  body: ReadableStream<Uint8Array> | null,
  status: number,
  headers?: HeadersInit,
): Response {
  const responseHeaders = secureHeaders(headers);
  responseHeaders.set('content-type', 'application/octet-stream');
  return new Response(body, { status, headers: responseHeaders });
}

/** Emits a bounded DUD2 response frame without buffering its opaque payload. */
export function v2FramedResponse(
  body: ReadableStream<Uint8Array>,
  contentLength: number,
): Response {
  if (!Number.isSafeInteger(contentLength) || contentLength < 0) {
    throw new Error('Framed response Content-Length is invalid.');
  }
  const headers = secureHeaders();
  headers.set('content-type', V2_CBOR_CONTENT_TYPE);
  headers.set('content-length', String(contentLength));
  return new Response(body, { status: 200, headers });
}
