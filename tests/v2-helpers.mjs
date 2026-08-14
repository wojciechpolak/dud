// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  deriveV2EnrollmentKey,
  deriveV2EnrollmentProof,
  encodeBase64Url,
} from '../dist/src/v2-auth.js';
import { encodeCbor } from '../dist/src/cbor.js';
import { createDudService } from '../dist/src/service.js';
import { MemoryBlobStore } from './helpers.mjs';

export const V2_NOW_MS = 1_800_000_000_000;
export const V2_ORIGIN = 'https://dud.example.com';
export const V2_RELATIONSHIP_ID = Uint8Array.from(
  { length: 16 },
  (_, index) => index + 1,
);
export const V2_TOKEN_SECRET = Uint8Array.from(
  { length: 32 },
  (_, index) => 0x40 + index,
);
export const V2_DEPLOYMENT_KEY = Uint8Array.from(
  { length: 32 },
  (_, index) => 0x80 + index,
);
export const V2_ADMIN_SECRET = Uint8Array.from(
  { length: 32 },
  (_, index) => 0xc0 + index,
);
/** A passphrase, the way an operator configures it. */
export const V2_ENROLLMENT_SECRET = 'squid-lantern-rotate-9-mango';

export function deterministicRandom() {
  let call = 0;
  return (length) => {
    call += 1;
    return Uint8Array.from(
      { length },
      (_, index) => (call * 17 + index) & 0xff,
    );
  };
}

export async function createV2TestService(v2Store, options = {}) {
  const randomBytes = options.randomBytes ?? deterministicRandom();
  await v2Store.initialize();
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    v2Store,
    ...(options.repository ? { v2Repository: options.repository } : {}),
    ...(options.pairingRepository
      ? { v2PairingRepository: options.pairingRepository }
      : {}),
    ...(options.bodyStore ? { v2BodyStore: options.bodyStore } : {}),
    now: options.now ?? (() => V2_NOW_MS),
    randomBytes,
    ...(options.observeTiming
      ? { observeV2Timing: options.observeTiming }
      : {}),
    ...(options.monotonicMs ? { monotonicMs: options.monotonicMs } : {}),
    config: {
      secretToken: 'legacy-secret',
      v2Enabled: true,
      v2DeploymentKey: encodeBase64Url(V2_DEPLOYMENT_KEY),
      v2AdminSecret: encodeBase64Url(V2_ADMIN_SECRET),
      // Gated by default, the way a deployment starts, so every test that
      // creates a rendezvous exercises the enrollment check.
      ...(options.openEnrollment
        ? { v2OpenEnrollment: true }
        : { v2Secret: options.enrollmentSecret ?? V2_ENROLLMENT_SECRET }),
      ...(options.acceptWeakEnrollmentKdf
        ? { v2AcceptWeakEnrollmentKdf: true }
        : {}),
      ...(options.limits ? { v2Limits: options.limits } : {}),
    },
  });
  return { randomBytes, service };
}

/**
 * The `DUD2-Enroll` header that authorizes creating one rendezvous. It binds
 * the locator and the expiry, so a header built for one rendezvous authorizes
 * no other.
 */
export async function enrollmentHeader(
  locator,
  expiresAt,
  secret = V2_ENROLLMENT_SECRET,
) {
  return `DUD2-Enroll ${encodeBase64Url(
    await deriveV2EnrollmentProof(
      await deriveV2EnrollmentKey(secret),
      locator,
      expiresAt,
    ),
  )}`;
}

export function adminRequest(path, body) {
  const encoded = encodeCbor(body);
  return new Request(`${V2_ORIGIN}${path}`, {
    method: 'POST',
    headers: {
      authorization: `DUD2-Bearer ${encodeBase64Url(V2_ADMIN_SECRET)}`,
      'content-length': String(encoded.byteLength),
      'content-type': 'application/dud+cbor; version=2',
    },
    body: encoded,
  });
}

export class MockR2Bucket {
  constructor() {
    this.objects = new Map();
    this.version = 0;
  }

  async put(key, body, options = {}) {
    if (options.onlyIf?.etagDoesNotMatch === '*' && this.objects.has(key)) {
      return null;
    }
    if (
      options.onlyIf?.etagMatches !== undefined &&
      this.objects.get(key)?.etag !== options.onlyIf.etagMatches
    ) {
      return null;
    }
    let bytes;
    if (typeof body === 'string') {
      bytes = new TextEncoder().encode(body);
    } else if (body instanceof Uint8Array) {
      bytes = Uint8Array.from(body);
    } else {
      bytes = new Uint8Array(await new Response(body).arrayBuffer());
    }
    const etag = String(++this.version);
    this.objects.set(key, {
      bytes,
      customMetadata: { ...(options.customMetadata ?? {}) },
      etag,
      uploaded: this.uploaded ?? new Date(0),
    });
    return { key, size: bytes.byteLength, etag };
  }

  async get(key) {
    const object = this.objects.get(key);
    if (!object) {
      return null;
    }
    return {
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(object.bytes);
          controller.close();
        },
      }),
      size: object.bytes.byteLength,
      etag: object.etag,
      customMetadata: { ...object.customMetadata },
    };
  }

  async head(key) {
    const object = this.objects.get(key);
    return object
      ? {
          key,
          size: object.bytes.byteLength,
          etag: object.etag,
          customMetadata: { ...object.customMetadata },
        }
      : null;
  }

  async list(options = {}) {
    const limit = options.limit ?? 1000;
    const matching = Array.from(this.objects.entries())
      .filter(([key]) => key.startsWith(options.prefix ?? ''))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .filter(([key]) => options.cursor === undefined || key > options.cursor);
    const entries = matching.slice(0, limit).map(([key, object]) => ({
      key,
      size: object.bytes.byteLength,
      uploaded: object.uploaded,
      customMetadata: { ...object.customMetadata },
    }));
    const truncated = matching.length > entries.length;
    return {
      objects: entries,
      truncated,
      ...(truncated ? { cursor: entries[entries.length - 1].key } : {}),
    };
  }

  async delete(key) {
    this.objects.delete(key);
  }
}
