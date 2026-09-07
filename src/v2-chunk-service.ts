// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  bytesEqual,
  decodeCbor,
  encodeCbor,
  requireCborMap,
  type CborValue,
} from './cbor.js';
import {
  bytesToHex,
  decodeBase64Url,
  decryptV2TokenSecret,
  parseV2DeliveryProof,
  verifyV2DeliveryProof,
} from './v2-auth.js';
import {
  v2StagedChunkKey,
  validateV2BodyPartDeclarations,
} from './v2-body-keys.js';
import { V2_CHUNK_LIMITS } from './v2-contract.js';
import { V2_TRANSPORT_POLICY_KEYS } from './v2-delivery-frame.js';
import {
  readV2RequestBytes,
  v2CborResponse,
  v2EmptyResponse,
  v2ErrorResponse,
} from './v2-http.js';
import { isV2OperationConflict } from './v2-repository.js';
import type {
  V2BodyPartDeclaration,
  V2BodyStore,
  V2ChunkUpload,
  V2Repository,
  V2RepositoryAuthorization,
  V2RepositoryCapability,
} from './v2-repository.js';
import { sha256 } from './sha256.js';
import type { V2TimingRecorder } from './v2-timing.js';

const UPLOADS_PATH = '/v2/deliveries/uploads';
const UPLOAD_PATH = /^\/v2\/deliveries\/uploads\/([a-f0-9]{32})$/;
const PART_PATH =
  /^\/v2\/deliveries\/uploads\/([a-f0-9]{32})\/chunks\/([a-f0-9]{32})$/;
const RENEW_PATH = /^\/v2\/deliveries\/uploads\/([a-f0-9]{32})\/renew$/;
const COMMIT_PATH = /^\/v2\/deliveries\/uploads\/([a-f0-9]{32})\/commit$/;
const DOWNLOAD_PATH =
  /^\/v2\/deliveries\/([a-f0-9]{32})\/chunks\/([a-f0-9]{32})$/;
const MAX_REQUEST_BYTES = 262_144;
const MAX_PROOF_LIFETIME_SECONDS = 5 * 60;
const PART_WRITE_LEASE_SECONDS = 5 * 60;
const AUTHORIZATION_PREFIX = 'DUD2 ';
const EMPTY_REQUEST_DIGEST = new Uint8Array(32);

const CREATE_KEYS = [1, 2, 3, 4, 5, 6] as const;
const PART_KEYS = [1, 2, 3] as const;
const RENEW_KEYS = [1] as const;
const COMMIT_KEYS = [1, 2, 3] as const;

interface ChunkAuthorization {
  capability: V2RepositoryCapability;
  authorization: V2RepositoryAuthorization;
}

interface CreateRequest {
  operationId: Uint8Array;
  chain: number;
  slot: Uint8Array;
  epoch: number;
  parts: V2BodyPartDeclaration[];
  totalLength: number;
}

export interface V2ChunkHandlerDependencies {
  repository: V2Repository;
  bodyStore: V2BodyStore;
  deploymentKey: Uint8Array;
  now: () => number;
  maximumRequestsPerMinute: number;
  maximumConcurrentUploads: number;
  maximumStagedBytes: number;
  maximumDescriptorBytes: number;
  maximumTtlSeconds: number;
  maximumTotalBytes?: number;
  maximumPendingDeliveries?: number;
  maximumObjectsPerCapability?: number;
  observeRejection?: (rejection: { route: string; reason: string }) => void;
}

function requireBytes(
  map: Map<number, CborValue>,
  key: number,
  length: number,
): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new Error('Chunk request byte field is invalid.');
  }
  return value;
}

function requireNumber(map: Map<number, CborValue>, key: number): number {
  const value = map.get(key);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error('Chunk request numeric field is invalid.');
  }
  return value;
}

function parseCreateRequest(bytes: Uint8Array): CreateRequest {
  const map = requireCborMap(
    decodeCbor(bytes, {
      maxBytes: MAX_REQUEST_BYTES,
      maxArrayElements: V2_CHUNK_LIMITS.maxChunksPerDelivery,
      maxMapPairs: 6,
      maxDepth: 4,
      requireDeterministic: true,
    }),
    CREATE_KEYS,
    CREATE_KEYS,
  );
  const rawParts = map.get(5);
  if (!Array.isArray(rawParts)) {
    throw new Error('Chunk manifest is invalid.');
  }
  const parts = rawParts.map((raw) => {
    const part = requireCborMap(raw, PART_KEYS, PART_KEYS);
    return {
      id: bytesToHex(requireBytes(part, 1, 16)),
      length: requireNumber(part, 2),
      digest: requireBytes(part, 3, 32),
    };
  });
  const totalLength = requireNumber(map, 6);
  validateV2BodyPartDeclarations(parts, totalLength);
  return {
    operationId: requireBytes(map, 1, 16),
    chain: requireNumber(map, 2),
    slot: requireBytes(map, 3, 16),
    epoch: requireNumber(map, 4),
    parts,
    totalLength,
  };
}

function parseRenewRequest(bytes: Uint8Array): Uint8Array {
  const map = requireCborMap(
    decodeCbor(bytes, {
      maxBytes: MAX_REQUEST_BYTES,
      maxMapPairs: 1,
      maxDepth: 2,
      requireDeterministic: true,
    }),
    RENEW_KEYS,
    RENEW_KEYS,
  );
  return requireBytes(map, 1, 16);
}

function parseCommitRequest(
  bytes: Uint8Array,
  maximumDescriptorBytes: number,
): {
  operationId: Uint8Array;
  encryptedDescriptor: Uint8Array;
  requestedPolicy: Map<number, CborValue>;
} {
  const map = requireCborMap(
    decodeCbor(bytes, {
      maxBytes: MAX_REQUEST_BYTES,
      maxMapPairs: 8,
      maxDepth: 4,
      requireDeterministic: true,
    }),
    COMMIT_KEYS,
    COMMIT_KEYS,
  );
  const encryptedDescriptor = map.get(2);
  const requestedPolicy = map.get(3);
  const requestedExpiry =
    requestedPolicy instanceof Map
      ? requestedPolicy.get(V2_TRANSPORT_POLICY_KEYS.expiresAt)
      : undefined;
  if (
    !(encryptedDescriptor instanceof Uint8Array) ||
    encryptedDescriptor.byteLength < 1 ||
    encryptedDescriptor.byteLength > maximumDescriptorBytes ||
    !(requestedPolicy instanceof Map) ||
    typeof requestedExpiry !== 'number' ||
    !Number.isSafeInteger(requestedExpiry) ||
    requestedExpiry < 0
  ) {
    throw new Error('Chunk commit descriptor or policy is invalid.');
  }
  return {
    operationId: requireBytes(map, 1, 16),
    encryptedDescriptor,
    requestedPolicy,
  };
}

function parseAuthorizationHeader(request: Request): Uint8Array {
  const value = request.headers.get('dud-authorization');
  if (!value || value.length > 256 || !value.startsWith(AUTHORIZATION_PREFIX)) {
    throw new Error('Chunk authorization header is invalid.');
  }
  return decodeBase64Url(value.slice(AUTHORIZATION_PREFIX.length));
}

function currentEpoch(current: number): number {
  return Math.floor(current / 86_400);
}

function leaseExpiry(
  current: number,
  epoch: number,
  capabilityExpiry: number,
): number {
  return Math.min(
    current + V2_CHUNK_LIMITS.maxUploadLeaseSeconds,
    (epoch + 1) * 86_400,
    capabilityExpiry,
  );
}

async function authorize(
  dependencies: V2ChunkHandlerDependencies,
  input: {
    request: Request;
    origin: string;
    path: string;
    requestDigest: Uint8Array;
    chain: number;
    slot: Uint8Array;
    epoch: number;
    current: number;
    expectedCapabilityId?: string;
    timing: V2TimingRecorder;
  },
): Promise<ChunkAuthorization | null> {
  const proof = parseAuthorizationHeader(input.request);
  const parsed = parseV2DeliveryProof(proof);
  if (
    parsed.expiresAt < input.current ||
    parsed.expiresAt > input.current + MAX_PROOF_LIFETIME_SECONDS ||
    parsed.operationIndex !== 0
  ) {
    return null;
  }
  const capability = await input.timing.measure('authorization', () =>
    dependencies.repository.findCapabilityLookup(
      parsed.capabilityLookupId,
      input.epoch,
    ),
  );
  if (
    !capability ||
    capability.scope !== 'write' ||
    capability.id !== (input.expectedCapabilityId ?? capability.id) ||
    capability.expiresAt <= input.current ||
    capability.revokedAt !== undefined
  ) {
    return null;
  }
  const verified = await input.timing.measure('authorization', async () =>
    verifyV2DeliveryProof({
      tokenSecret: await decryptV2TokenSecret(
        dependencies.deploymentKey,
        capability,
      ),
      capabilityLookupId: parsed.capabilityLookupId,
      direction: capability.direction,
      scope: 'write',
      chain: input.chain,
      slot: input.slot,
      slotEpoch: input.epoch,
      method: input.request.method,
      canonicalOrigin: input.origin,
      normalizedPath: input.path,
      requestDigest: input.requestDigest,
      proof,
    }),
  );
  if (!verified || verified.operationIndex !== 0) {
    return null;
  }
  return {
    capability,
    authorization: {
      claims: [
        {
          capabilityId: capability.id,
          nonce: verified.nonce,
          expiresAt: verified.expiresAt,
        },
      ],
      maximumRequestsPerMinute: dependencies.maximumRequestsPerMinute,
    },
  };
}

function missingParts(upload: V2ChunkUpload): Uint8Array[] {
  return upload.parts
    .filter((part) => part.bodyKey === undefined)
    .map((part) =>
      Uint8Array.from(part.id.match(/.{2}/g)!, (pair) =>
        Number.parseInt(pair, 16),
      ),
    );
}

function createResponse(upload: V2ChunkUpload, idempotent: boolean): Response {
  return v2CborResponse(
    new Map<number, CborValue>([
      [
        1,
        Uint8Array.from(upload.id.match(/.{2}/g)!, (pair) =>
          Number.parseInt(pair, 16),
        ),
      ],
      [2, upload.expiresAt],
      [3, missingParts(upload)],
      [4, idempotent],
    ]),
    idempotent ? 200 : 201,
  );
}

function rejected(
  dependencies: V2ChunkHandlerDependencies,
  route: string,
  error: unknown,
): Response {
  if (isV2OperationConflict(error)) {
    return v2ErrorResponse(5, 'Operation ID conflicts with a prior request.');
  }
  dependencies.observeRejection?.({
    route,
    reason: error instanceof Error ? error.message : String(error),
  });
  return v2ErrorResponse(1, 'Chunk transfer request is invalid.');
}

export function createV2ChunkHandler(dependencies: V2ChunkHandlerDependencies) {
  async function create(
    request: Request,
    origin: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const body = await readV2RequestBytes(request, MAX_REQUEST_BYTES);
      const parsed = parseCreateRequest(body);
      const current = Math.floor(dependencies.now() / 1000);
      if (parsed.epoch !== currentEpoch(current)) {
        return v2ErrorResponse(2, 'Chunk authorization proof is invalid.');
      }
      const authorized = await authorize(dependencies, {
        request,
        origin,
        path: UPLOADS_PATH,
        requestDigest: sha256(body),
        chain: parsed.chain,
        slot: parsed.slot,
        epoch: parsed.epoch,
        current,
        timing,
      });
      if (!authorized) {
        return v2ErrorResponse(2, 'Chunk authorization proof is invalid.');
      }
      const expiresAt = leaseExpiry(
        current,
        parsed.epoch,
        authorized.capability.expiresAt,
      );
      if (expiresAt <= current) {
        return v2ErrorResponse(3, 'Chunk capability is not active.');
      }
      const created = await timing.measure('metadata', () =>
        dependencies.repository.createChunkUpload({
          capabilityId: authorized.capability.id,
          chain: parsed.chain,
          slot: parsed.slot,
          epoch: parsed.epoch,
          operationId: parsed.operationId,
          operationDigest: sha256(body),
          parts: parsed.parts,
          totalLength: parsed.totalLength,
          authorization: authorized.authorization,
          now: current,
          expiresAt,
          maximumConcurrentUploads: dependencies.maximumConcurrentUploads,
          maximumStagedBytes: dependencies.maximumStagedBytes,
        }),
      );
      return createResponse(created.upload, created.idempotent);
    } catch (error) {
      return rejected(dependencies, UPLOADS_PATH, error);
    }
  }

  async function resolveUpload(
    request: Request,
    origin: string,
    path: string,
    uploadId: string,
    requestDigest: Uint8Array,
    current: number,
    timing: V2TimingRecorder,
    forCommit = false,
  ): Promise<
    { upload: V2ChunkUpload; authorized: ChunkAuthorization } | Response
  > {
    const proof = parseAuthorizationHeader(request);
    const parsedProof = parseV2DeliveryProof(proof);
    const capability = await timing.measure('authorization', () =>
      dependencies.repository.findCapabilityLookup(
        parsedProof.capabilityLookupId,
        currentEpoch(current),
      ),
    );
    if (!capability || capability.scope !== 'write') {
      return v2ErrorResponse(2, 'Chunk authorization proof is invalid.');
    }
    const upload = await timing.measure('metadata', () =>
      forCommit
        ? dependencies.repository.findChunkUploadForCommit({
            id: uploadId,
            capabilityId: capability.id,
            now: current,
          })
        : dependencies.repository.findChunkUpload({
            id: uploadId,
            capabilityId: capability.id,
            now: current,
          }),
    );
    if (!upload) {
      return v2ErrorResponse(2, 'Chunk authorization proof is invalid.');
    }
    const authorized = await authorize(dependencies, {
      request,
      origin,
      path,
      requestDigest,
      chain: upload.chain,
      slot: upload.slot,
      epoch: upload.epoch,
      current,
      expectedCapabilityId: upload.capabilityId,
      timing,
    });
    return authorized
      ? { upload, authorized }
      : v2ErrorResponse(2, 'Chunk authorization proof is invalid.');
  }

  async function putPart(
    request: Request,
    origin: string,
    path: string,
    uploadId: string,
    partId: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      if (request.headers.get('content-type') !== 'application/octet-stream') {
        throw new Error('Chunk Content-Type is invalid.');
      }
      const digestText = request.headers.get('dud-content-sha256');
      const lengthText = request.headers.get('content-length');
      if (
        !digestText ||
        !/^[a-f0-9]{64}$/.test(digestText) ||
        !lengthText ||
        !/^(?:0|[1-9][0-9]*)$/.test(lengthText) ||
        !request.body
      ) {
        throw new Error('Chunk body declaration is invalid.');
      }
      const current = Math.floor(dependencies.now() / 1000);
      const digest = Uint8Array.from(digestText.match(/.{2}/g)!, (pair) =>
        Number.parseInt(pair, 16),
      );
      const resolved = await resolveUpload(
        request,
        origin,
        path,
        uploadId,
        digest,
        current,
        timing,
      );
      if (resolved instanceof Response) {
        return resolved;
      }
      const part = resolved.upload.parts.find(
        (candidate) => candidate.id === partId,
      );
      if (
        !part ||
        Number(lengthText) !== part.length ||
        !bytesEqual(digest, part.digest)
      ) {
        return v2ErrorResponse(1, 'Chunk does not match its manifest.');
      }
      const operationId = Uint8Array.from(partId.match(/.{2}/g)!, (pair) =>
        Number.parseInt(pair, 16),
      );
      const operationDigest = sha256(
        encodeCbor(
          new Map<number, CborValue>([
            [1, operationId],
            [2, part.length],
            [3, part.digest],
          ]),
        ),
      );
      const writeToken = crypto.randomUUID().replaceAll('-', '');
      const prepared = await timing.measure('metadata', () =>
        dependencies.repository.prepareChunkUploadPart({
          id: uploadId,
          capabilityId: resolved.authorized.capability.id,
          partId,
          writeToken,
          writeExpiresAt: Math.min(
            resolved.upload.expiresAt,
            current + PART_WRITE_LEASE_SECONDS,
          ),
          operationId,
          operationDigest,
          authorization: resolved.authorized.authorization,
          now: current,
        }),
      );
      const stagedKey = v2StagedChunkKey(uploadId, partId);
      try {
        const bodyKey = await timing.measure('body', () =>
          dependencies.bodyStore.stagePart(uploadId, part, request.body!),
        );
        if (!prepared.idempotent) {
          await timing.measure('metadata', () =>
            dependencies.repository.completeChunkUploadPart({
              id: uploadId,
              capabilityId: resolved.authorized.capability.id,
              partId,
              writeToken,
              bodyKey,
              now: current,
            }),
          );
        }
      } catch (error) {
        if (!prepared.idempotent) {
          try {
            const deleteBody =
              await dependencies.repository.abortChunkUploadPart({
                id: uploadId,
                partId,
                writeToken,
              });
            if (deleteBody) {
              await dependencies.bodyStore.delete(stagedKey);
            }
          } catch (compensationError) {
            throw new AggregateError(
              [error, compensationError],
              'Chunk upload part compensation failed.',
            );
          }
        }
        throw error;
      }
      return v2EmptyResponse();
    } catch (error) {
      return rejected(
        dependencies,
        '/v2/deliveries/uploads/:id/chunks/:id',
        error,
      );
    }
  }

  async function headPart(
    request: Request,
    origin: string,
    path: string,
    uploadId: string,
    partId: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const current = Math.floor(dependencies.now() / 1000);
      const resolved = await resolveUpload(
        request,
        origin,
        path,
        uploadId,
        EMPTY_REQUEST_DIGEST,
        current,
        timing,
      );
      if (resolved instanceof Response) {
        return resolved;
      }
      const authorizedUpload = await timing.measure('metadata', () =>
        dependencies.repository.authorizeChunkUpload({
          id: uploadId,
          capabilityId: resolved.authorized.capability.id,
          authorization: resolved.authorized.authorization,
          now: current,
        }),
      );
      const part = authorizedUpload.parts.find(
        (candidate) => candidate.id === partId,
      );
      if (!part || part.bodyKey === undefined) {
        return v2ErrorResponse(4, 'Chunk upload part is unavailable.');
      }
      return v2EmptyResponse(200, {
        'content-type': 'application/octet-stream',
        'content-length': String(part.length),
        'dud-content-sha256': bytesToHex(part.digest),
      });
    } catch (error) {
      return rejected(
        dependencies,
        '/v2/deliveries/uploads/:id/chunks/:id',
        error,
      );
    }
  }

  async function renew(
    request: Request,
    origin: string,
    path: string,
    uploadId: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const body = await readV2RequestBytes(request, MAX_REQUEST_BYTES);
      const operationId = parseRenewRequest(body);
      const current = Math.floor(dependencies.now() / 1000);
      const operationDigest = sha256(body);
      const resolved = await resolveUpload(
        request,
        origin,
        path,
        uploadId,
        operationDigest,
        current,
        timing,
      );
      if (resolved instanceof Response) {
        return resolved;
      }
      const renewed = await timing.measure('metadata', () =>
        dependencies.repository.renewChunkUpload({
          id: uploadId,
          capabilityId: resolved.authorized.capability.id,
          operationId,
          operationDigest,
          authorization: resolved.authorized.authorization,
          now: current,
          expiresAt: leaseExpiry(
            current,
            resolved.upload.epoch,
            resolved.authorized.capability.expiresAt,
          ),
        }),
      );
      return v2CborResponse(
        new Map<number, CborValue>([
          [1, renewed.upload.expiresAt],
          [2, renewed.idempotent],
        ]),
      );
    } catch (error) {
      return rejected(dependencies, '/v2/deliveries/uploads/:id/renew', error);
    }
  }

  async function abandon(
    request: Request,
    origin: string,
    path: string,
    uploadId: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const current = Math.floor(dependencies.now() / 1000);
      const resolved = await resolveUpload(
        request,
        origin,
        path,
        uploadId,
        EMPTY_REQUEST_DIGEST,
        current,
        timing,
      );
      if (resolved instanceof Response) {
        return resolved;
      }
      await timing.measure('metadata', () =>
        dependencies.repository.abandonChunkUpload({
          id: uploadId,
          capabilityId: resolved.authorized.capability.id,
          authorization: resolved.authorized.authorization,
          now: current,
        }),
      );
      return v2EmptyResponse();
    } catch (error) {
      return rejected(dependencies, '/v2/deliveries/uploads/:id', error);
    }
  }

  async function commit(
    request: Request,
    origin: string,
    path: string,
    uploadId: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const body = await readV2RequestBytes(request, MAX_REQUEST_BYTES);
      const parsed = parseCommitRequest(
        body,
        dependencies.maximumDescriptorBytes,
      );
      const current = Math.floor(dependencies.now() / 1000);
      const requestDigest = sha256(body);
      const resolved = await resolveUpload(
        request,
        origin,
        path,
        uploadId,
        requestDigest,
        current,
        timing,
        true,
      );
      if (resolved instanceof Response) {
        return resolved;
      }
      if (
        resolved.upload.committedAt === undefined &&
        resolved.upload.parts.some((part) => part.bodyKey === undefined)
      ) {
        return v2ErrorResponse(8, 'Chunk upload is incomplete.');
      }
      const policyBytes = encodeCbor(parsed.requestedPolicy);
      const policyDigest = sha256(policyBytes);
      const requestedExpiry = parsed.requestedPolicy.get(
        V2_TRANSPORT_POLICY_KEYS.expiresAt,
      ) as number;
      const expiresAt = Math.min(
        resolved.authorized.capability.expiresAt,
        current + dependencies.maximumTtlSeconds,
        requestedExpiry,
      );
      if (expiresAt <= current) {
        return v2ErrorResponse(7, 'Chunk delivery policy has expired.');
      }
      const operationDigest = sha256(
        encodeCbor(
          new Map<number, CborValue>([
            [1, requestDigest],
            [
              2,
              Uint8Array.from(uploadId.match(/.{2}/g)!, (pair) =>
                Number.parseInt(pair, 16),
              ),
            ],
            [
              3,
              resolved.upload.parts.map(
                (part) =>
                  new Map<number, CborValue>([
                    [
                      1,
                      Uint8Array.from(part.id.match(/.{2}/g)!, (pair) =>
                        Number.parseInt(pair, 16),
                      ),
                    ],
                    [2, part.length],
                    [3, part.digest],
                  ]),
              ),
            ],
          ]),
        ),
      );
      const reservation = await timing.measure('metadata', () =>
        dependencies.repository.reserveDelivery({
          capabilityId: resolved.authorized.capability.id,
          operationId: parsed.operationId,
          operationDigest,
          payloadLength: resolved.upload.totalLength,
          chunkUploadId: uploadId,
          maximumTotalBytes: dependencies.maximumTotalBytes,
          maximumPendingDeliveries: dependencies.maximumPendingDeliveries,
          maximumObjectsPerCapability: dependencies.maximumObjectsPerCapability,
          authorization: resolved.authorized.authorization,
          now: current,
          expiresAt: Math.min(expiresAt, current + MAX_PROOF_LIFETIME_SECONDS),
        }),
      );
      if ('existing' in reservation) {
        return v2CborResponse(
          new Map<number, CborValue>([
            [
              1,
              Uint8Array.from(reservation.existing.id.match(/.{2}/g)!, (pair) =>
                Number.parseInt(pair, 16),
              ),
            ],
            [2, true],
          ]),
        );
      }
      const parts = await timing.measure('body', () =>
        dependencies.bodyStore.commitParts({
          uploadId,
          deliveryId: reservation.deliveryId,
          parts: resolved.upload.parts,
          expectedTotalLength: resolved.upload.totalLength,
        }),
      );
      const published = await timing.measure('metadata', () =>
        dependencies.repository.publishDelivery({
          id: reservation.deliveryId,
          relationshipId: resolved.authorized.capability.relationshipId,
          direction: resolved.authorized.capability.direction,
          slot: resolved.upload.slot,
          epoch: resolved.upload.epoch,
          chain: resolved.upload.chain,
          encryptedDescriptor: parsed.encryptedDescriptor,
          requestedPolicy: policyBytes,
          effectivePolicy: policyBytes,
          policyDigest,
          payloadKey: reservation.payloadKey,
          payloadLength: resolved.upload.totalLength,
          payloadDigest: operationDigest,
          parts,
          chunkUploadId: uploadId,
          operationId: parsed.operationId,
          operationDigest,
          createdAt: current,
          expiresAt,
        }),
      );
      return v2CborResponse(
        new Map<number, CborValue>([
          [
            1,
            Uint8Array.from(published.delivery.id.match(/.{2}/g)!, (pair) =>
              Number.parseInt(pair, 16),
            ),
          ],
          [2, published.idempotent],
        ]),
      );
    } catch (error) {
      return rejected(dependencies, '/v2/deliveries/uploads/:id/commit', error);
    }
  }

  async function download(
    request: Request,
    origin: string,
    path: string,
    deliveryId: string,
    partId: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const current = Math.floor(dependencies.now() / 1000);
      let proof: Uint8Array;
      let parsed: ReturnType<typeof parseV2DeliveryProof>;
      try {
        proof = parseAuthorizationHeader(request);
        parsed = parseV2DeliveryProof(proof);
      } catch {
        return v2ErrorResponse(2, 'Chunk read proof is invalid.');
      }
      if (
        parsed.expiresAt < current ||
        parsed.expiresAt > current + MAX_PROOF_LIFETIME_SECONDS ||
        parsed.operationIndex !== 0
      ) {
        return v2ErrorResponse(2, 'Chunk read proof is invalid.');
      }
      const delivery = await timing.measure('metadata', () =>
        dependencies.repository.findDelivery(deliveryId),
      );
      const part = delivery?.parts?.find(
        (candidate) => candidate.id === partId,
      );
      const capability = await timing.measure('authorization', () =>
        dependencies.repository.findCapabilityLookup(
          parsed.capabilityLookupId,
          delivery?.epoch ?? currentEpoch(current),
        ),
      );
      if (
        !delivery ||
        delivery.expiresAt <= current ||
        delivery.chain === undefined ||
        !capability ||
        capability.scope !== 'read' ||
        capability.relationshipId !== delivery.relationshipId ||
        capability.direction !== delivery.direction ||
        capability.expiresAt <= current ||
        capability.revokedAt !== undefined
      ) {
        return v2ErrorResponse(2, 'Chunk read proof is invalid.');
      }
      const verified = await timing.measure('authorization', async () =>
        verifyV2DeliveryProof({
          tokenSecret: await decryptV2TokenSecret(
            dependencies.deploymentKey,
            capability,
          ),
          capabilityLookupId: parsed.capabilityLookupId,
          direction: capability.direction,
          scope: 'read',
          chain: delivery.chain!,
          slot: delivery.slot,
          slotEpoch: delivery.epoch,
          method: 'GET',
          canonicalOrigin: origin,
          normalizedPath: path,
          requestDigest: EMPTY_REQUEST_DIGEST,
          proof,
        }),
      );
      if (!verified || verified.operationIndex !== 0) {
        return v2ErrorResponse(2, 'Chunk read proof is invalid.');
      }
      const authorized = await timing.measure('metadata', () =>
        dependencies.repository.queryInbox({
          relationshipId: delivery.relationshipId,
          direction: delivery.direction,
          dataSlots: [{ slot: delivery.slot, epoch: delivery.epoch }],
          controlSlots: [],
          authorization: {
            claims: [
              {
                capabilityId: capability.id,
                nonce: verified.nonce,
                expiresAt: verified.expiresAt,
              },
            ],
            maximumRequestsPerMinute: dependencies.maximumRequestsPerMinute,
          },
          now: current,
        }),
      );
      if (!authorized.authorizationAccepted) {
        return v2ErrorResponse(6, 'Chunk read proof was already used.');
      }
      if (authorized.delivery?.id !== deliveryId) {
        return v2ErrorResponse(4, 'Delivery chunk is unavailable.');
      }
      if (!part) {
        return v2ErrorResponse(4, 'Delivery chunk is unavailable.');
      }
      const body = await timing.measure('body', () =>
        dependencies.bodyStore.get(part.key),
      );
      if (!body || body.size !== part.length) {
        return v2ErrorResponse(13, 'Delivery chunk is unavailable.');
      }
      return new Response(body.body, {
        status: 200,
        headers: {
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'content-type': 'application/octet-stream',
          'content-length': String(part.length),
          'dud-content-sha256': bytesToHex(part.digest),
        },
      });
    } catch (error) {
      return rejected(dependencies, '/v2/deliveries/:id/chunks/:id', error);
    }
  }

  return {
    async route(
      request: Request,
      origin: string,
      pathname: string,
      timing: V2TimingRecorder,
    ): Promise<Response | null> {
      if (request.method === 'POST' && pathname === UPLOADS_PATH) {
        return create(request, origin, timing);
      }
      const part = PART_PATH.exec(pathname);
      if (part && request.method === 'PUT') {
        return putPart(request, origin, pathname, part[1]!, part[2]!, timing);
      }
      if (part && request.method === 'HEAD') {
        return headPart(request, origin, pathname, part[1]!, part[2]!, timing);
      }
      const renewal = RENEW_PATH.exec(pathname);
      if (renewal && request.method === 'POST') {
        return renew(request, origin, pathname, renewal[1]!, timing);
      }
      const commitment = COMMIT_PATH.exec(pathname);
      if (commitment && request.method === 'POST') {
        return commit(request, origin, pathname, commitment[1]!, timing);
      }
      const downloadPart = DOWNLOAD_PATH.exec(pathname);
      if (downloadPart && request.method === 'GET') {
        return download(
          request,
          origin,
          pathname,
          downloadPart[1]!,
          downloadPart[2]!,
          timing,
        );
      }
      const upload = UPLOAD_PATH.exec(pathname);
      if (upload && request.method === 'DELETE') {
        return abandon(request, origin, pathname, upload[1]!, timing);
      }
      return null;
    },
  };
}
