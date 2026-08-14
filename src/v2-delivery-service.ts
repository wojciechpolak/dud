// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { decodeCbor, encodeCbor, type CborValue } from './cbor.js';
import {
  bytesToHex,
  decryptV2TokenSecret,
  parseV2DeliveryProof,
  verifyV2DeliveryProof,
} from './v2-auth.js';
import {
  decodeV2SlotProof,
  decodeV2ControlEventRequest,
  decodeV2CompletionRequest,
  decodeV2InboxRequest,
  v2InboxRequestAuthorizationDigest,
  v2CompletionRequestAuthorizationDigest,
  v2ControlEventRequestAuthorizationDigest,
  V2_COMPLETION_REQUEST_KEYS,
  V2_CONTROL_EVENT_REQUEST_KEYS,
  V2_DELIVERY_FRAME_MAGIC,
  V2_DELIVERY_FRAME_PREFIX_BYTES,
  V2_DELIVERY_REQUEST_KEYS,
  V2_INBOX_REQUEST_KEYS,
  V2_INBOX_RESPONSE_KEYS,
  V2_SLOT_PROOF_KEYS,
  V2_TRANSPORT_POLICY_KEYS,
} from './v2-delivery-frame.js';
import {
  readV2RequestBytes,
  readV2FramedDeliveryRequest,
  v2CborResponse,
  v2ErrorResponse,
  v2FramedResponse,
} from './v2-http.js';
import { isV2OperationConflict } from './v2-repository.js';
import type {
  V2BodyStore,
  V2Repository,
  V2RepositoryCapability,
} from './v2-repository.js';
import { sha256 } from './sha256.js';
import {
  classifyV2Operation,
  startV2Timing,
  type V2TimingObserver,
  type V2TimingRecorder,
} from './v2-timing.js';

const DELIVERY_PATH = '/v2/deliveries';
const INBOX_PATH = '/v2/inbox';
const CONTROL_EVENTS_PATH = '/v2/control-events';
const COMPLETION_PATH = /^\/v2\/deliveries\/([a-f0-9]{32})\/complete$/;
const MAX_PROOF_LIFETIME_SECONDS = 5 * 60;
const MAX_DELIVERY_TTL_SECONDS = 30 * 24 * 60 * 60;
const MAX_PENDING_CONTROL_EVENTS = 64;
const MAX_CONTROL_EVENT_BYTES = 4 * 1024 * 1024;
const MAX_INBOX_CONTROL_EVENTS = 16;
const MAX_INBOX_CONTROL_BYTES = 1024 * 1024;

/**
 * Reports why a request was refused, to the operator only. The wire response
 * stays uniform on purpose (see `rejection` below), which leaves an operator
 * with no way to tell a quota problem from a stale replay. This hook closes
 * that gap without widening what the caller learns.
 */
export type V2RejectionObserver = (rejection: {
  route: string;
  reason: string;
}) => void;

export interface V2DeliveryHandlerDependencies {
  repository: V2Repository;
  bodyStore: V2BodyStore;
  deploymentKey: Uint8Array;
  observeRejection?: V2RejectionObserver;
  now?: () => number;
  maximumTotalBytes?: number;
  maximumDescriptorBytes?: number;
  maximumObjectBytes?: number;
  maximumTtlSeconds?: number;
  maximumRequestsPerMinute?: number;
  maximumPendingDeliveries?: number;
  maximumObjectsPerCapability?: number;
  maximumConcurrentUploads?: number;
  maximumStagedBytes?: number;
  maximumPendingControlEvents?: number;
  maximumControlEventBytes?: number;
  maximumInboxControlEvents?: number;
  maximumInboxControlBytes?: number;
  observeTiming?: V2TimingObserver;
  monotonicMs?: () => number;
}

/**
 * Maps a failed repository operation to a response. A caller that reuses one of
 * its own operation IDs with different bytes learns that it conflicts, because
 * that is its own prior write and a client must surface a fork rather than
 * retry it. Every other rejection keeps one uniform response so quota, rate,
 * replay, and capability state never leak back to a proven capability holder.
 */
function rejection(
  error: unknown,
  message: string,
  observe?: V2RejectionObserver,
  route?: string,
): Response {
  if (isV2OperationConflict(error)) {
    return v2ErrorResponse(5, 'Operation ID conflicts with a prior request.');
  }
  observe?.({
    route: route ?? 'unknown',
    reason: error instanceof Error ? error.message : String(error),
  });
  return v2ErrorResponse(1, message);
}

function idBytes(id: string): Uint8Array {
  if (!/^[a-f0-9]{32}$/.test(id)) {
    throw new Error('Repository returned an invalid delivery ID.');
  }
  return Uint8Array.from(id.match(/.{2}/g)!, (value) =>
    Number.parseInt(value, 16),
  );
}

function requireNumber(header: Map<number, CborValue>, key: number): number {
  const value = header.get(key);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error('Delivery frame numeric field is invalid.');
  }
  return value;
}

function requireBytes(header: Map<number, CborValue>, key: number): Uint8Array {
  const value = header.get(key);
  if (!(value instanceof Uint8Array)) {
    throw new Error('Delivery frame byte field is invalid.');
  }
  return value;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength && left.every((v, i) => v === right[i])
  );
}

function boundedControlEvents<T extends { encryptedEnvelope: Uint8Array }>(
  events: readonly T[],
  maximumEvents: number,
  maximumBytes: number,
): T[] {
  const result: T[] = [];
  let bytes = 0;
  for (const event of events) {
    if (
      result.length >= maximumEvents ||
      bytes + event.encryptedEnvelope.byteLength > maximumBytes
    ) {
      break;
    }
    result.push(event);
    bytes += event.encryptedEnvelope.byteLength;
  }
  return result;
}

function oppositeDirection(direction: V2RepositoryCapability['direction']) {
  return direction === 'inviter->invitee'
    ? 'invitee->inviter'
    : 'inviter->invitee';
}

function publicationDigest(
  header: Map<number, CborValue>,
  slot: { slot: Uint8Array; epoch: number; chain: number },
): Uint8Array {
  return sha256(
    encodeCbor(
      new Map<number, CborValue>([
        [1, requireBytes(header, V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor)],
        [2, header.get(V2_DELIVERY_REQUEST_KEYS.requestedPolicy)!],
        [3, requireNumber(header, V2_DELIVERY_REQUEST_KEYS.payloadLength)],
        [4, requireBytes(header, V2_DELIVERY_REQUEST_KEYS.payloadDigest)],
        [5, slot.slot],
        [6, slot.epoch],
        [7, slot.chain],
      ]),
    ),
  );
}

function deliveryResponse(
  id: string,
  effectivePolicy: CborValue,
  idempotent: boolean,
  controlResults: CborValue[] = [],
  controlEvents: CborValue[] = [],
): Response {
  return v2CborResponse(
    new Map<number, CborValue>([
      [1, idBytes(id)],
      [2, effectivePolicy],
      [3, idempotent],
      [4, controlResults],
      [5, controlEvents],
    ]),
  );
}

function frameStream(
  header: Map<number, CborValue>,
  payload: ReadableStream<Uint8Array>,
): { body: ReadableStream<Uint8Array>; contentLength: number } {
  const encodedHeader = encodeCbor(header);
  const prefix = new Uint8Array(
    V2_DELIVERY_FRAME_PREFIX_BYTES + encodedHeader.byteLength,
  );
  prefix.set(V2_DELIVERY_FRAME_MAGIC);
  new DataView(prefix.buffer).setUint32(4, encodedHeader.byteLength, false);
  prefix.set(encodedHeader, V2_DELIVERY_FRAME_PREFIX_BYTES);
  const reader = payload.getReader();
  let sentPrefix = false;
  return {
    contentLength:
      prefix.byteLength +
      requireNumber(header, V2_INBOX_RESPONSE_KEYS.payloadLength),
    body: new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (!sentPrefix) {
          sentPrefix = true;
          controller.enqueue(prefix);
          return;
        }
        const next = await reader.read();
        if (next.done) {
          reader.releaseLock();
          controller.close();
          return;
        }
        controller.enqueue(next.value);
      },
      async cancel(reason) {
        await reader.cancel(reason).catch(() => undefined);
      },
    }),
  };
}

function emptyPayload(): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.close();
    },
  });
}

function inboxSlotResult(
  slot: { slot: Uint8Array; epoch: number },
  more: boolean,
) {
  return new Map<number, CborValue>([
    [V2_SLOT_PROOF_KEYS.slot, slot.slot],
    [V2_SLOT_PROOF_KEYS.epoch, slot.epoch],
    [3, more],
  ]);
}

async function authorizeReadProofs(
  dependencies: V2DeliveryHandlerDependencies,
  proofs: readonly CborValue[],
  requestDigest: Uint8Array,
  origin: string,
  normalizedPath: string,
  operationOffset: number,
  current: number,
) {
  const authorized: Array<{
    slot: { slot: Uint8Array; epoch: number; chain: number };
    capability: V2RepositoryCapability;
    nonce: Uint8Array;
    expiresAt: number;
  }> = [];
  for (const [index, rawProof] of proofs.entries()) {
    const slot = decodeV2SlotProof(rawProof);
    const parsed = parseV2DeliveryProof(slot.proof);
    if (
      parsed.expiresAt < current ||
      parsed.expiresAt > current + MAX_PROOF_LIFETIME_SECONDS ||
      parsed.operationIndex !== operationOffset + index
    ) {
      throw new Error('Inbox authorization proof is expired or misplaced.');
    }
    const capability = await dependencies.repository.findCapabilityLookup(
      parsed.capabilityLookupId,
      slot.epoch,
    );
    if (
      !capability ||
      capability.scope !== 'read' ||
      capability.expiresAt <= current ||
      capability.revokedAt !== undefined
    ) {
      throw new Error('Inbox capability is not active.');
    }
    const verified = await verifyV2DeliveryProof({
      tokenSecret: await decryptV2TokenSecret(
        dependencies.deploymentKey,
        capability,
      ),
      capabilityLookupId: parsed.capabilityLookupId,
      direction: capability.direction,
      scope: 'read',
      chain: slot.chain,
      slot: slot.slot,
      slotEpoch: slot.epoch,
      method: 'POST',
      canonicalOrigin: origin,
      normalizedPath,
      requestDigest,
      proof: slot.proof,
    });
    if (!verified) {
      throw new Error('Read authorization proof is invalid.');
    }
    authorized.push({
      slot,
      capability,
      nonce: verified.nonce,
      expiresAt: verified.expiresAt,
    });
  }
  return authorized;
}

function eventResponse(event: {
  id: string;
  slot: Uint8Array;
  epoch: number;
  encryptedEnvelope: Uint8Array;
  sequence: number;
}): Map<number, CborValue> {
  return new Map<number, CborValue>([
    [1, idBytes(event.id)],
    [2, event.slot],
    [3, event.epoch],
    [4, event.encryptedEnvelope],
    [5, event.sequence],
  ]);
}

function controlEventIds(value: CborValue | undefined): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((id) => {
    if (!(id instanceof Uint8Array)) {
      throw new Error('Processed control-event ID is invalid.');
    }
    return Array.from(id, (byte) => byte.toString(16).padStart(2, '0')).join(
      '',
    );
  });
}

function requireDistinctNonceClaims(
  claims: readonly { capability: V2RepositoryCapability; nonce: Uint8Array }[],
): void {
  const seen = new Set<string>();
  for (const claim of claims) {
    const key = `${claim.capability.id}|${bytesToHex(claim.nonce)}`;
    if (seen.has(key)) {
      throw new Error('Authorization nonce is duplicated within the request.');
    }
    seen.add(key);
  }
}

/** Atomic delivery publication through the granular metadata repository. */
export function createV2DeliveryHandler(
  dependencies: V2DeliveryHandlerDependencies,
) {
  const now = dependencies.now ?? (() => Date.now());

  async function publish(
    request: Request,
    origin: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    let stagedKey: string | undefined;
    let stagingId: string | undefined;
    try {
      const framed = await readV2FramedDeliveryRequest(
        request,
        dependencies.maximumDescriptorBytes,
        dependencies.maximumObjectBytes,
      );
      // Both settle from the body reader, so any path that returns before
      // awaiting them would leave a hostile request's rejection unhandled.
      // Marking them handled here does not stop the awaits below from throwing.
      framed.verified.catch(() => undefined);
      framed.authorizationDigest.catch(() => undefined);
      const header = framed.header;
      const slot = decodeV2SlotProof(
        header.get(V2_DELIVERY_REQUEST_KEYS.dataSlotProof)!,
      );
      const parsedProof = parseV2DeliveryProof(slot.proof);
      const current = Math.floor(now() / 1000);
      if (
        parsedProof.expiresAt < current ||
        parsedProof.expiresAt > current + MAX_PROOF_LIFETIME_SECONDS
      ) {
        return v2ErrorResponse(2, 'Delivery authorization proof has expired.');
      }
      const capability = await timing.measure('authorization', () =>
        dependencies.repository.findCapabilityLookup(
          parsedProof.capabilityLookupId,
          slot.epoch,
        ),
      );
      // An unregistered lookup is answered exactly like an unverifiable proof,
      // so a caller cannot probe which capability lookups exist.
      if (!capability || capability.scope !== 'write') {
        return v2ErrorResponse(2, 'Delivery authorization proof is invalid.');
      }
      const payloadLength = requireNumber(
        header,
        V2_DELIVERY_REQUEST_KEYS.payloadLength,
      );
      const payloadDigest = requireBytes(
        header,
        V2_DELIVERY_REQUEST_KEYS.payloadDigest,
      );
      stagingId = crypto.randomUUID().replaceAll('-', '');
      stagedKey = await timing.measure('metadata', () =>
        dependencies.repository.reserveStagedBody({
          id: stagingId!,
          expiresAt: current + MAX_PROOF_LIFETIME_SECONDS,
          now: current,
          reservedBytes: payloadLength,
          maximumConcurrentUploads: dependencies.maximumConcurrentUploads ?? 4,
          maximumStagedBytes:
            dependencies.maximumStagedBytes ?? 200 * 1024 * 1024,
        }),
      );
      await timing.measure('body', async () => {
        await dependencies.bodyStore.put(
          stagedKey!,
          framed.payload,
          payloadLength,
          payloadDigest,
        );
        await framed.verified;
      });
      const requestDigest = await framed.authorizationDigest;
      const tokenSecret = await timing.measure('authorization', () =>
        decryptV2TokenSecret(dependencies.deploymentKey, capability),
      );
      const verified = await timing.measure('authorization', () =>
        verifyV2DeliveryProof({
          tokenSecret,
          capabilityLookupId: parsedProof.capabilityLookupId,
          direction: capability.direction,
          scope: 'write',
          chain: slot.chain,
          slot: slot.slot,
          slotEpoch: slot.epoch,
          method: request.method,
          canonicalOrigin: origin,
          normalizedPath: DELIVERY_PATH,
          requestDigest,
          proof: slot.proof,
        }),
      );
      if (!verified || verified.operationIndex !== 0) {
        return v2ErrorResponse(2, 'Delivery authorization proof is invalid.');
      }
      // Only a proven capability holder learns that its tuple is inactive.
      if (
        capability.expiresAt <= current ||
        capability.revokedAt !== undefined
      ) {
        return v2ErrorResponse(3, 'Delivery capability is not active.');
      }
      const controlQueries = (header.get(
        V2_DELIVERY_REQUEST_KEYS.controlQueries,
      ) ?? []) as CborValue[];
      const controls = await timing.measure('authorization', () =>
        authorizeReadProofs(
          dependencies,
          controlQueries,
          requestDigest,
          origin,
          DELIVERY_PATH,
          1,
          current,
        ),
      );
      if (
        controls.some(
          ({ capability: controlCapability }) =>
            controlCapability.relationshipId !== capability.relationshipId,
        )
      ) {
        return v2ErrorResponse(
          3,
          'Delivery control proofs target another relationship.',
        );
      }
      const controlDirection = controls[0]?.capability.direction;
      if (
        controlDirection !== undefined &&
        controls.some(
          ({ capability: controlCapability }) =>
            controlCapability.direction !== controlDirection,
        )
      ) {
        return v2ErrorResponse(
          3,
          'Delivery control proofs use different directions.',
        );
      }
      requireDistinctNonceClaims([
        { capability, nonce: verified.nonce },
        ...controls,
      ]);
      const processed = controlEventIds(
        header.get(V2_DELIVERY_REQUEST_KEYS.processedControlEventIds),
      );
      if (processed.length > 0) {
        if (controlDirection === undefined) {
          return v2ErrorResponse(
            1,
            'Processed control events require control-slot proofs.',
          );
        }
      }
      const operationId = requireBytes(
        header,
        V2_DELIVERY_REQUEST_KEYS.operationId,
      );
      const digest = publicationDigest(header, slot);
      // Protocol §7.4: server-visible expiry may be earlier than the signed
      // policy but never later, so the sender's own expiry is a ceiling here
      // alongside the capability lifetime and the deployment TTL cap.
      const signedExpiresAt = (
        header.get(V2_DELIVERY_REQUEST_KEYS.requestedPolicy) as Map<
          number,
          CborValue
        >
      ).get(V2_TRANSPORT_POLICY_KEYS.expiresAt) as number;
      const expiresAt = Math.min(
        capability.expiresAt,
        current +
          Math.min(
            dependencies.maximumTtlSeconds ?? MAX_DELIVERY_TTL_SECONDS,
            MAX_DELIVERY_TTL_SECONDS,
          ),
        signedExpiresAt,
      );
      const reservation = await timing.measure('metadata', () =>
        dependencies.repository.reserveDelivery({
          capabilityId: capability.id,
          operationId,
          operationDigest: digest,
          payloadLength,
          maximumTotalBytes: dependencies.maximumTotalBytes,
          maximumPendingDeliveries: dependencies.maximumPendingDeliveries,
          maximumObjectsPerCapability: dependencies.maximumObjectsPerCapability,
          authorization: {
            claims: [
              {
                capabilityId: capability.id,
                nonce: verified.nonce,
                expiresAt: verified.expiresAt,
              },
              ...controls.map(
                ({ capability: controlCapability, nonce, expiresAt }) => ({
                  capabilityId: controlCapability.id,
                  nonce,
                  expiresAt,
                }),
              ),
            ],
            maximumRequestsPerMinute:
              dependencies.maximumRequestsPerMinute ?? 60,
          },
          consumeControlEvents:
            processed.length > 0 && controlDirection !== undefined
              ? {
                  ids: processed,
                  relationshipId: capability.relationshipId,
                  direction: controlDirection,
                  now: current,
                }
              : undefined,
          now: current,
          expiresAt,
        }),
      );
      let deliveryId: string;
      let idempotent: boolean;
      if ('existing' in reservation) {
        await timing.measure('body', () =>
          dependencies.bodyStore.delete(stagedKey!),
        );
        await timing.measure('metadata', () =>
          dependencies.repository.releaseStagedBody(stagingId!),
        );
        stagedKey = undefined;
        stagingId = undefined;
        deliveryId = reservation.existing.id;
        idempotent = true;
      } else {
        await timing.measure('body', () =>
          dependencies.bodyStore.promote(stagedKey!, reservation.payloadKey),
        );
        await timing.measure('metadata', () =>
          dependencies.repository.releaseStagedBody(stagingId!),
        );
        stagedKey = undefined;
        stagingId = undefined;
        const requestedPolicy = encodeCbor(
          header.get(V2_DELIVERY_REQUEST_KEYS.requestedPolicy)!,
        );
        const published = await timing.measure('metadata', () =>
          dependencies.repository.publishDelivery({
            id: reservation.deliveryId,
            relationshipId: capability.relationshipId,
            direction: capability.direction,
            slot: slot.slot,
            epoch: slot.epoch,
            encryptedDescriptor: requireBytes(
              header,
              V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor,
            ),
            requestedPolicy,
            effectivePolicy: requestedPolicy,
            policyDigest: sha256(requestedPolicy),
            payloadKey: reservation.payloadKey,
            payloadLength,
            payloadDigest,
            operationId,
            operationDigest: digest,
            createdAt: current,
            expiresAt,
          }),
        );
        deliveryId = published.delivery.id;
        idempotent = published.idempotent;
      }
      const controlsResult = controlDirection
        ? await timing.measure('metadata', () =>
            dependencies.repository.queryInbox({
              relationshipId: capability.relationshipId,
              direction: controlDirection,
              dataSlots: [],
              controlSlots: controls.map(({ slot: controlSlot }) => ({
                slot: controlSlot.slot,
                epoch: controlSlot.epoch,
              })),
              maximumControlEvents:
                dependencies.maximumInboxControlEvents ??
                MAX_INBOX_CONTROL_EVENTS,
              maximumControlBytes:
                dependencies.maximumInboxControlBytes ??
                MAX_INBOX_CONTROL_BYTES,
              now: current,
            }),
          )
        : undefined;
      return deliveryResponse(
        deliveryId,
        header.get(V2_DELIVERY_REQUEST_KEYS.requestedPolicy)!,
        idempotent,
        controls.map(({ slot: controlSlot }) =>
          inboxSlotResult(
            controlSlot,
            controlsResult?.pendingEpochs.has(controlSlot.epoch) ?? false,
          ),
        ),
        controlsResult?.controlEvents.map(eventResponse) ?? [],
      );
    } catch (error) {
      return rejection(
        error,
        'Delivery request is invalid.',
        dependencies.observeRejection,
        DELIVERY_PATH,
      );
    } finally {
      if (stagedKey) {
        await dependencies.bodyStore.delete(stagedKey).catch(() => undefined);
      }
      if (stagingId) {
        await dependencies.repository
          .releaseStagedBody(stagingId)
          .catch(() => undefined);
      }
    }
  }

  async function inbox(
    request: Request,
    origin: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const bytes = await readV2RequestBytes(request, 262_144);
      const query = decodeV2InboxRequest(bytes).header;
      const dataProofs = (query.get(V2_INBOX_REQUEST_KEYS.dataSlotProofs) ??
        []) as CborValue[];
      const controlProofs = (query.get(
        V2_INBOX_REQUEST_KEYS.controlSlotProofs,
      ) ?? []) as CborValue[];
      if (dataProofs.length + controlProofs.length === 0) {
        return v2ErrorResponse(1, 'Inbox requires at least one slot proof.');
      }
      const current = Math.floor(now() / 1000);
      const requestDigest = v2InboxRequestAuthorizationDigest(bytes);
      const data = await timing.measure('authorization', () =>
        authorizeReadProofs(
          dependencies,
          dataProofs,
          requestDigest,
          origin,
          INBOX_PATH,
          0,
          current,
        ),
      );
      const control = await timing.measure('authorization', () =>
        authorizeReadProofs(
          dependencies,
          controlProofs,
          requestDigest,
          origin,
          INBOX_PATH,
          data.length,
          current,
        ),
      );
      const all = [...data, ...control];
      const relationshipId = all[0]!.capability.relationshipId;
      const direction = all[0]!.capability.direction;
      if (
        all.some(
          ({ capability }) =>
            capability.relationshipId !== relationshipId ||
            capability.direction !== direction,
        )
      ) {
        return v2ErrorResponse(
          3,
          'Inbox proofs target different relationships.',
        );
      }
      requireDistinctNonceClaims(all);
      const processed = controlEventIds(
        query.get(V2_INBOX_REQUEST_KEYS.processedControlEventIds),
      );
      const result = await timing.measure('metadata', () =>
        dependencies.repository.queryInbox({
          relationshipId,
          direction,
          dataSlots: data.map(({ slot }) => ({
            slot: slot.slot,
            epoch: slot.epoch,
          })),
          controlSlots: control.map(({ slot }) => ({
            slot: slot.slot,
            epoch: slot.epoch,
          })),
          maximumControlEvents:
            dependencies.maximumInboxControlEvents ?? MAX_INBOX_CONTROL_EVENTS,
          maximumControlBytes:
            dependencies.maximumInboxControlBytes ?? MAX_INBOX_CONTROL_BYTES,
          authorization: {
            claims: all.map(({ capability, nonce, expiresAt }) => ({
              capabilityId: capability.id,
              nonce,
              expiresAt,
            })),
            maximumRequestsPerMinute:
              dependencies.maximumRequestsPerMinute ?? 60,
            consumeControlEventIds: processed,
          },
          now: current,
        }),
      );
      if (!result.authorizationAccepted) {
        return v2ErrorResponse(
          6,
          'Inbox authorization nonce was already used.',
        );
      }
      const header = new Map<number, CborValue>([
        [
          V2_INBOX_RESPONSE_KEYS.slotResults,
          data.map(({ slot }) =>
            inboxSlotResult(slot, result.pendingEpochs.has(slot.epoch)),
          ),
        ],
        [
          V2_INBOX_RESPONSE_KEYS.controlEvents,
          boundedControlEvents(
            result.controlEvents,
            dependencies.maximumInboxControlEvents ?? MAX_INBOX_CONTROL_EVENTS,
            dependencies.maximumInboxControlBytes ?? MAX_INBOX_CONTROL_BYTES,
          ).map(eventResponse),
        ],
      ]);
      let payload = emptyPayload();
      if (result.delivery) {
        const body = await timing.measure('body', () =>
          dependencies.bodyStore.get(result.delivery!.payloadKey),
        );
        if (!body || body.size !== result.delivery.payloadLength) {
          return v2ErrorResponse(13, 'Inbox payload is unavailable.');
        }
        header.set(
          V2_INBOX_RESPONSE_KEYS.deliveryId,
          idBytes(result.delivery.id),
        );
        header.set(V2_INBOX_RESPONSE_KEYS.slot, result.delivery.slot);
        header.set(
          V2_INBOX_RESPONSE_KEYS.encryptedDescriptor,
          result.delivery.encryptedDescriptor,
        );
        const effectivePolicy = decodeCbor(result.delivery.effectivePolicy, {
          maxBytes: 262_144,
          maxMapPairs: 16,
          maxDepth: 4,
          requireDeterministic: true,
        });
        if (!(effectivePolicy instanceof Map)) {
          throw new Error('Stored delivery policy is invalid.');
        }
        header.set(V2_INBOX_RESPONSE_KEYS.effectivePolicy, effectivePolicy);
        header.set(V2_INBOX_RESPONSE_KEYS.payloadLength, body.size);
        header.set(
          V2_INBOX_RESPONSE_KEYS.payloadDigest,
          result.delivery.payloadDigest,
        );
        header.set(
          V2_INBOX_RESPONSE_KEYS.moreDeliveries,
          Array.from(result.pendingEpochs, (epoch) => epoch),
        );
        payload = body.body;
      } else {
        header.set(V2_INBOX_RESPONSE_KEYS.payloadLength, 0);
        header.set(
          V2_INBOX_RESPONSE_KEYS.payloadDigest,
          sha256(new Uint8Array()),
        );
        header.set(V2_INBOX_RESPONSE_KEYS.moreDeliveries, []);
      }
      const framed = frameStream(header, payload);
      return v2FramedResponse(framed.body, framed.contentLength);
    } catch (error) {
      return rejection(
        error,
        'Inbox request is invalid.',
        dependencies.observeRejection,
        INBOX_PATH,
      );
    }
  }

  async function complete(
    request: Request,
    origin: string,
    deliveryId: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const body = await readV2RequestBytes(request, 262_144);
      const header = decodeV2CompletionRequest(body).header;
      if (
        !bytesEqual(
          requireBytes(header, V2_COMPLETION_REQUEST_KEYS.deliveryId),
          idBytes(deliveryId),
        )
      ) {
        return v2ErrorResponse(
          1,
          'Completion delivery ID does not match its path.',
        );
      }
      const delivery = await timing.measure('metadata', () =>
        dependencies.repository.findDelivery(deliveryId),
      );
      const current = Math.floor(now() / 1000);
      if (!delivery || delivery.expiresAt <= current) {
        return v2ErrorResponse(4, 'Delivery is unavailable.');
      }
      const source = requireBytes(
        header,
        V2_COMPLETION_REQUEST_KEYS.sourceSlot,
      );
      const target = requireBytes(
        header,
        V2_COMPLETION_REQUEST_KEYS.targetSlot,
      );
      // Only the source slot and the policy digest are server-verifiable. The
      // descriptor digest is SHA-256 of the deterministic descriptor map
      // (protocol §7.2), which lives inside the opaque encrypted descriptor, so
      // the server cannot recompute it; it binds the completion end to end
      // through the receiver-signed acknowledgement and, below, through the
      // operation digest that makes a retry idempotent and a changed
      // acknowledgement a conflict.
      if (
        !bytesEqual(source, delivery.slot) ||
        !bytesEqual(
          requireBytes(header, V2_COMPLETION_REQUEST_KEYS.policyDigest),
          delivery.policyDigest,
        )
      ) {
        return v2ErrorResponse(3, 'Completion does not bind the delivery.');
      }
      const requestDigest = v2CompletionRequestAuthorizationDigest(body);
      const slots = [
        {
          raw: header.get(V2_COMPLETION_REQUEST_KEYS.dataAckProof)!,
          scope: 'ack' as const,
          direction: delivery.direction,
          expectedSlot: source,
          index: 0,
        },
        {
          raw: header.get(V2_COMPLETION_REQUEST_KEYS.controlWriteProof)!,
          scope: 'write' as const,
          direction: oppositeDirection(delivery.direction),
          expectedSlot: target,
          index: 1,
        },
      ];
      const verifiedProofs: Array<{
        capability: V2RepositoryCapability;
        nonce: Uint8Array;
        expiresAt: number;
      }> = [];
      for (const entry of slots) {
        const slot = decodeV2SlotProof(entry.raw);
        const parsed = parseV2DeliveryProof(slot.proof);
        if (
          !bytesEqual(slot.slot, entry.expectedSlot) ||
          parsed.expiresAt < current ||
          parsed.expiresAt > current + MAX_PROOF_LIFETIME_SECONDS ||
          parsed.operationIndex !== entry.index
        ) {
          return v2ErrorResponse(
            2,
            'Completion authorization proof is invalid.',
          );
        }
        const capability = await timing.measure('authorization', () =>
          dependencies.repository.findCapabilityLookup(
            parsed.capabilityLookupId,
            slot.epoch,
          ),
        );
        if (
          !capability ||
          capability.relationshipId !== delivery.relationshipId ||
          capability.direction !== entry.direction ||
          capability.scope !== entry.scope
        ) {
          return v2ErrorResponse(
            2,
            'Completion authorization proof is invalid.',
          );
        }
        const verified = await timing.measure('authorization', async () =>
          verifyV2DeliveryProof({
            tokenSecret: await decryptV2TokenSecret(
              dependencies.deploymentKey,
              capability,
            ),
            capabilityLookupId: parsed.capabilityLookupId,
            direction: capability.direction,
            scope: capability.scope,
            chain: slot.chain,
            slot: slot.slot,
            slotEpoch: slot.epoch,
            method: 'POST',
            canonicalOrigin: origin,
            normalizedPath: `/v2/deliveries/${deliveryId}/complete`,
            requestDigest,
            proof: slot.proof,
          }),
        );
        if (!verified) {
          return v2ErrorResponse(
            2,
            'Completion authorization proof is invalid.',
          );
        }
        if (
          capability.expiresAt <= current ||
          capability.revokedAt !== undefined
        ) {
          return v2ErrorResponse(3, 'Completion capability is not active.');
        }
        verifiedProofs.push({
          capability,
          nonce: verified.nonce,
          expiresAt: verified.expiresAt,
        });
      }
      requireDistinctNonceClaims(verifiedProofs);
      const operationId = requireBytes(
        header,
        V2_COMPLETION_REQUEST_KEYS.operationId,
      );
      const acknowledgement = requireBytes(
        header,
        V2_COMPLETION_REQUEST_KEYS.encryptedAcknowledgement,
      );
      const operationDigest = sha256(
        encodeCbor(
          new Map<number, CborValue>([
            [1, idBytes(deliveryId)],
            [2, source],
            [3, target],
            [4, requireBytes(header, V2_COMPLETION_REQUEST_KEYS.policyDigest)],
            [
              5,
              requireBytes(header, V2_COMPLETION_REQUEST_KEYS.descriptorDigest),
            ],
            [6, header.get(V2_COMPLETION_REQUEST_KEYS.result)!],
            [7, operationId],
            [8, acknowledgement],
          ]),
        ),
      );
      const result = header.get(V2_COMPLETION_REQUEST_KEYS.result) as 0 | 1;
      const completed = await timing.measure('metadata', () =>
        dependencies.repository.completeDeliveryWithControl({
          completion: {
            id: deliveryId,
            operationId,
            operationDigest,
            completionDigest: sha256(acknowledgement),
            result,
            now: current,
          },
          event: {
            id: bytesToHex(operationId),
            relationshipId: delivery.relationshipId,
            direction: oppositeDirection(delivery.direction),
            slot: target,
            epoch: decodeV2SlotProof(
              header.get(V2_COMPLETION_REQUEST_KEYS.controlWriteProof)!,
            ).epoch,
            encryptedEnvelope: acknowledgement,
            operationId,
            operationDigest,
            sequence: 0,
            createdAt: current,
            expiresAt: Math.min(
              delivery.expiresAt,
              verifiedProofs[1]!.capability.expiresAt,
            ),
          },
          authorization: {
            claims: verifiedProofs.map(({ capability, nonce, expiresAt }) => ({
              capabilityId: capability.id,
              nonce,
              expiresAt,
            })),
            maximumRequestsPerMinute:
              dependencies.maximumRequestsPerMinute ?? 60,
            controlQuota: {
              maximumEvents:
                dependencies.maximumPendingControlEvents ??
                MAX_PENDING_CONTROL_EVENTS,
              maximumBytes:
                dependencies.maximumControlEventBytes ??
                MAX_CONTROL_EVENT_BYTES,
            },
          },
        }),
      );
      if (!completed.authorizationAccepted) {
        return v2ErrorResponse(
          6,
          'Completion authorization nonce was already used.',
        );
      }
      return v2CborResponse(
        new Map<number, CborValue>([
          [1, idBytes(completed.delivery.id)],
          [2, idBytes(completed.event.id)],
          [3, completed.idempotent],
        ]),
      );
    } catch (error) {
      return rejection(
        error,
        'Completion request is invalid.',
        dependencies.observeRejection,
        '/v2/deliveries/:id/complete',
      );
    }
  }

  async function publishControlEvent(
    request: Request,
    origin: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    try {
      const body = await readV2RequestBytes(request, 262_144);
      const header = decodeV2ControlEventRequest(body).header;
      const slot = decodeV2SlotProof(
        header.get(V2_CONTROL_EVENT_REQUEST_KEYS.controlSlotProof)!,
      );
      const parsed = parseV2DeliveryProof(slot.proof);
      const current = Math.floor(now() / 1000);
      if (
        parsed.expiresAt < current ||
        parsed.expiresAt > current + MAX_PROOF_LIFETIME_SECONDS
      ) {
        return v2ErrorResponse(2, 'Control authorization proof has expired.');
      }
      const capability = await timing.measure('authorization', () =>
        dependencies.repository.findCapabilityLookup(
          parsed.capabilityLookupId,
          slot.epoch,
        ),
      );
      if (!capability || capability.scope !== 'write') {
        return v2ErrorResponse(2, 'Control authorization proof is invalid.');
      }
      const requestDigest = v2ControlEventRequestAuthorizationDigest(body);
      const verified = await timing.measure('authorization', async () =>
        verifyV2DeliveryProof({
          tokenSecret: await decryptV2TokenSecret(
            dependencies.deploymentKey,
            capability,
          ),
          capabilityLookupId: parsed.capabilityLookupId,
          direction: capability.direction,
          scope: 'write',
          chain: slot.chain,
          slot: slot.slot,
          slotEpoch: slot.epoch,
          method: 'POST',
          canonicalOrigin: origin,
          normalizedPath: CONTROL_EVENTS_PATH,
          requestDigest,
          proof: slot.proof,
        }),
      );
      if (!verified || verified.operationIndex !== 0) {
        return v2ErrorResponse(2, 'Control authorization proof is invalid.');
      }
      if (
        capability.expiresAt <= current ||
        capability.revokedAt !== undefined
      ) {
        return v2ErrorResponse(3, 'Control capability is not active.');
      }
      const operationId = requireBytes(
        header,
        V2_CONTROL_EVENT_REQUEST_KEYS.operationId,
      );
      const envelope = requireBytes(
        header,
        V2_CONTROL_EVENT_REQUEST_KEYS.encryptedEnvelope,
      );
      const published = await timing.measure('metadata', () =>
        dependencies.repository.publishControlEvent(
          {
            id: bytesToHex(operationId),
            relationshipId: capability.relationshipId,
            direction: capability.direction,
            slot: slot.slot,
            epoch: slot.epoch,
            encryptedEnvelope: envelope,
            operationId,
            operationDigest: sha256(
              encodeCbor(
                new Map<number, CborValue>([
                  [1, operationId],
                  [2, slot.slot],
                  [3, slot.epoch],
                  [4, envelope],
                ]),
              ),
            ),
            sequence: 0,
            createdAt: current,
            expiresAt: capability.expiresAt,
          },
          {
            claims: [
              {
                capabilityId: capability.id,
                nonce: verified.nonce,
                expiresAt: verified.expiresAt,
              },
            ],
            maximumRequestsPerMinute:
              dependencies.maximumRequestsPerMinute ?? 60,
            controlQuota: {
              maximumEvents:
                dependencies.maximumPendingControlEvents ??
                MAX_PENDING_CONTROL_EVENTS,
              maximumBytes:
                dependencies.maximumControlEventBytes ??
                MAX_CONTROL_EVENT_BYTES,
            },
          },
        ),
      );
      if (!published.authorizationAccepted) {
        return v2ErrorResponse(
          6,
          'Control authorization nonce was already used.',
        );
      }
      return v2CborResponse(
        new Map<number, CborValue>([
          [1, idBytes(published.event.id)],
          [2, published.idempotent],
        ]),
      );
    } catch (error) {
      return rejection(
        error,
        'Control event request is invalid.',
        dependencies.observeRejection,
        CONTROL_EVENTS_PATH,
      );
    }
  }

  /** Resolves a routable path to the handler that owns it. */
  function resolve(
    pathname: string,
  ):
    | ((
        request: Request,
        origin: string,
        timing: V2TimingRecorder,
      ) => Promise<Response>)
    | null {
    if (pathname === DELIVERY_PATH) {
      return publish;
    }
    if (pathname === INBOX_PATH) {
      return inbox;
    }
    if (pathname === CONTROL_EVENTS_PATH) {
      return publishControlEvent;
    }
    const completion = COMPLETION_PATH.exec(pathname);
    if (completion) {
      const deliveryId = completion[1]!;
      return (request, origin, timing) =>
        complete(request, origin, deliveryId, timing);
    }
    return null;
  }

  return {
    /**
     * `timing` lets an enclosing router report one record per request. Without
     * it the handler records and reports on its own, which is how it behaves
     * when it is mounted directly.
     */
    async route(
      request: Request,
      origin: string,
      pathname: string,
      timing?: V2TimingRecorder,
    ): Promise<Response | null> {
      if (request.method !== 'POST') {
        return null;
      }
      const run = resolve(pathname);
      if (!run) {
        return null;
      }
      const owned = timing === undefined;
      const recorder =
        timing ??
        startV2Timing(
          classifyV2Operation(request.method, pathname),
          dependencies.observeTiming,
          dependencies.monotonicMs,
        );
      const response = await run(request, origin, recorder);
      if (owned) {
        recorder.finish(response.status);
      }
      return response;
    },
  };
}
