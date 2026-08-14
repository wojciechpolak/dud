// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { R2BlobStore } from './cloudflare.js';
import { bytesEqual } from './cbor.js';
import { StreamingSha256 } from './sha256.js';
import type { BlobObject, R2BucketLike } from './types.js';
import type {
  V2BodyInventory,
  V2BodyInventoryEntry,
  V2BodyStore,
} from './v2-repository.js';
import { emptyV2State, type V2StoredState, type V2Store } from './v2-types.js';

const STATE_KEY = 'v2/state.json';
const NONCE_PREFIX = 'v2/nonces/';
const BODY_KEY = /^deliveries\/([a-f0-9]{32})\.bin$/;
const STAGING_KEY = /^staging\/([a-f0-9]{32})\.bin$/;

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

function requireBodyKey(key: string, staging: boolean): void {
  if ((staging ? STAGING_KEY : BODY_KEY).test(key)) {
    return;
  }
  throw new Error('R2 delivery body key is invalid.');
}

function verifiedBody(
  body: ReadableStream<Uint8Array>,
  expectedLength: number,
  expectedDigest: Uint8Array,
): ReadableStream<Uint8Array> {
  if (
    !Number.isSafeInteger(expectedLength) ||
    expectedLength < 0 ||
    expectedDigest.byteLength !== 32
  ) {
    throw new Error('R2 delivery body declaration is invalid.');
  }
  const hasher = new StreamingSha256();
  let length = 0;
  return body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        if (!(chunk instanceof Uint8Array)) {
          throw new Error('R2 delivery body chunk is invalid.');
        }
        length += chunk.byteLength;
        if (length > expectedLength) {
          throw new Error('R2 delivery body exceeds its declared length.');
        }
        hasher.update(chunk);
        controller.enqueue(chunk);
      },
      flush() {
        if (
          length !== expectedLength ||
          !bytesEqual(hasher.digest(), expectedDigest)
        ) {
          throw new Error(
            'R2 delivery body does not match its declared digest.',
          );
        }
      },
    }),
  );
}

const BODY_PREFIXES = ['deliveries/', 'staging/'] as const;

/**
 * Opaque resume token for the reconciliation walk. It names only the prefix
 * being drained and R2's own cursor, so it discloses no peer or relationship
 * data even if an operator pastes it into a ticket.
 */
function parseInventoryCursor(cursor: string | undefined): {
  prefixIndex: number;
  r2Cursor?: string;
} {
  if (cursor === undefined) {
    return { prefixIndex: 0 };
  }
  const prefixIndex = Number(cursor[0]);
  if (
    cursor.length > 2_048 ||
    cursor[1] !== '|' ||
    prefixIndex >= BODY_PREFIXES.length ||
    !/^[0-9]$/.test(cursor[0]!)
  ) {
    throw new Error('R2 body inventory cursor is invalid.');
  }
  const r2Cursor = cursor.slice(2);
  return { prefixIndex, ...(r2Cursor ? { r2Cursor } : {}) };
}

function inventoryUploadedAt(
  value: Date | string | undefined,
): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const milliseconds =
    value instanceof Date ? value.getTime() : Date.parse(value);
  return Number.isFinite(milliseconds)
    ? Math.floor(milliseconds / 1000)
    : undefined;
}

/**
 * Opaque R2 body store for the granular delivery backend. The permanent key is
 * derived only from an opaque server delivery ID; relationship and peer data
 * never enter the R2 namespace.
 */
export class R2V2BodyStore implements V2BodyStore, V2BodyInventory {
  private readonly blobStore: R2BlobStore;

  constructor(private readonly bucket: R2BucketLike) {
    this.blobStore = new R2BlobStore(bucket);
  }

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
    requireBodyKey(stagedKey, true);
    requireBodyKey(key, false);
    const staged = await this.blobStore.get(stagedKey);
    if (!staged) {
      throw new Error('Staged R2 delivery body is unavailable.');
    }
    const digest = staged.customMetadata?.dudSha256;
    if (!digest || !/^[a-f0-9]{64}$/.test(digest)) {
      throw new Error('Staged R2 delivery body metadata is invalid.');
    }
    const result = await this.bucket.put(key, staged.body, {
      onlyIf: { etagDoesNotMatch: '*' },
      httpMetadata: { contentType: 'application/octet-stream' },
      customMetadata: { dudSha256: digest },
    });
    if (result === null) {
      const existing = await this.blobStore.head(key);
      if (
        !existing ||
        existing.size !== staged.size ||
        existing.customMetadata?.dudSha256 !== digest
      ) {
        throw new Error('R2 delivery body conflicts with an existing payload.');
      }
    }
    await this.blobStore.delete(stagedKey);
  }

  async put(
    key: string,
    body: ReadableStream<Uint8Array>,
    expectedLength: number,
    expectedDigest: Uint8Array,
  ): Promise<void> {
    requireBodyKey(key, key.startsWith('staging/'));
    const digest = bytesToHex(expectedDigest);
    if (expectedDigest.byteLength !== 32) {
      throw new Error('R2 delivery body digest is invalid.');
    }
    await this.blobStore.put(
      key,
      verifiedBody(body, expectedLength, expectedDigest),
      {
        contentType: 'application/octet-stream',
        customMetadata: { dudSha256: digest },
        length: expectedLength,
      },
    );
  }

  async get(key: string): Promise<BlobObject | null> {
    requireBodyKey(key, false);
    return this.blobStore.get(key);
  }

  async head(key: string): Promise<boolean> {
    requireBodyKey(key, key.startsWith('staging/'));
    return (await this.blobStore.head(key)) !== null;
  }

  async delete(key: string): Promise<void> {
    requireBodyKey(key, key.startsWith('staging/'));
    await this.blobStore.delete(key);
  }

  /**
   * One bounded page of the opaque body namespace, for the administrator
   * reconciliation command only. Request handling never lists the bucket; this
   * method exists solely behind the explicit offline command.
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
    const { prefixIndex, r2Cursor } = parseInventoryCursor(input.cursor);
    const prefix = BODY_PREFIXES[prefixIndex];
    if (prefix === undefined) {
      throw new Error('R2 body inventory cursor is invalid.');
    }
    const result = await this.bucket.list({
      prefix,
      limit: input.limit,
      ...(r2Cursor === undefined ? {} : { cursor: r2Cursor }),
    });
    const entries = result.objects
      .filter(
        (object) => BODY_KEY.test(object.key) || STAGING_KEY.test(object.key),
      )
      .map((object) => ({
        key: object.key,
        size: object.size ?? 0,
        ...(inventoryUploadedAt(object.uploaded) === undefined
          ? {}
          : { modifiedAt: inventoryUploadedAt(object.uploaded)! }),
      }));
    if (result.truncated && result.cursor) {
      return { entries, cursor: `${prefixIndex}|${result.cursor}` };
    }
    return prefixIndex + 1 < BODY_PREFIXES.length
      ? { entries, cursor: `${prefixIndex + 1}|` }
      : { entries };
  }
}

function validateState(value: unknown): V2StoredState {
  const state = value as Partial<V2StoredState>;
  if (
    state?.version !== 2 ||
    !state.capabilities ||
    !state.reservations ||
    !state.revocations ||
    !state.rateWindows
  ) {
    throw new Error('R2 v2 state is invalid.');
  }
  state.invitations ??= {};
  state.relationships ??= {};
  state.legacyObjects ??= {};
  state.legacyCommittedBytes ??= 0;
  if (
    !Number.isSafeInteger(state.legacyCommittedBytes) ||
    state.legacyCommittedBytes < 0
  ) {
    throw new Error('R2 v2 legacy accounting state is invalid.');
  }
  return state as V2StoredState;
}

export class R2V2Store implements V2Store {
  readonly quotaEnforcement = 'atomic' as const;
  readonly wholeState = true;
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly bucket: R2BucketLike) {}

  async initialize(): Promise<void> {
    const existing = await this.bucket.head(STATE_KEY);
    if (existing) {
      return;
    }
    await this.bucket.put(STATE_KEY, JSON.stringify(emptyV2State()), {
      onlyIf: { etagDoesNotMatch: '*' },
      httpMetadata: { contentType: 'application/json' },
    });
  }

  async readState(): Promise<V2StoredState> {
    const object = await this.bucket.get(STATE_KEY);
    if (!object?.body) {
      throw new Error('R2 v2 state is missing.');
    }
    return structuredClone(
      validateState(JSON.parse(await new Response(object.body).text())),
    );
  }

  async transaction<T>(
    operation: (state: V2StoredState) => T | Promise<T>,
  ): Promise<T> {
    let resolveResult!: (result: T) => void;
    let rejectResult!: (reason: unknown) => void;
    const result = new Promise<T>((resolve, reject) => {
      resolveResult = resolve;
      rejectResult = reject;
    });
    this.queue = this.queue.then(async () => {
      try {
        for (let attempt = 0; attempt < 8; attempt++) {
          const object = await this.bucket.get(STATE_KEY);
          if (!object?.body || !object.etag) {
            throw new Error('R2 v2 state or ETag is missing.');
          }
          const state = structuredClone(
            validateState(JSON.parse(await new Response(object.body).text())),
          );
          const value = await operation(state);
          const updated = await this.bucket.put(
            STATE_KEY,
            JSON.stringify(state),
            {
              onlyIf: { etagMatches: object.etag },
              httpMetadata: { contentType: 'application/json' },
            },
          );
          if (updated !== null) {
            resolveResult(value);
            return;
          }
        }
        throw new Error(
          'R2 v2 state transaction contention exceeded retry limit.',
        );
      } catch (error) {
        rejectResult(error);
      }
    });
    await this.queue;
    return result;
  }

  async claimNonce(
    key: string,
    expiresAt: number,
    _now: number,
  ): Promise<boolean> {
    if (!/^[a-f0-9]{64}$/.test(key)) {
      throw new Error('Invalid v2 nonce storage key.');
    }
    const storageKey = `${NONCE_PREFIX}${key}.json`;
    const created = await this.bucket.put(
      storageKey,
      JSON.stringify({ expiresAt }),
      {
        onlyIf: { etagDoesNotMatch: '*' },
        httpMetadata: { contentType: 'application/json' },
        customMetadata: { expiresAt: String(expiresAt) },
      },
    );
    return created !== null;
  }

  async deleteExpiredNonces(now: number, limit: number): Promise<number> {
    const result = await this.bucket.list({
      prefix: NONCE_PREFIX,
      limit,
      include: ['customMetadata'],
    });
    let deleted = 0;
    for (const entry of result.objects) {
      const expiresAt = Number(entry.customMetadata?.expiresAt);
      if (Number.isFinite(expiresAt) && expiresAt < now) {
        await this.bucket.delete(entry.key);
        deleted += 1;
      }
    }
    return deleted;
  }
}
