// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type {
  V2ChunkUpload,
  V2DeliveryReservation,
  V2MaintenanceResult,
  V2RepositoryControlEvent,
  V2RepositoryDelivery,
} from './v2-repository.js';
import { v2StagedChunkKey } from './v2-body-keys.js';

interface QuotaAccount {
  committedBytes: number;
  reservedBytes: number;
  objectCount: number;
}

interface OperationRecord {
  digest: Uint8Array;
  deliveryId: string;
}

export interface MemoryV2MaintenanceState {
  deliveries: Map<string, V2RepositoryDelivery>;
  reservations: Map<string, V2DeliveryReservation>;
  stagedBodies: Map<
    string,
    { capabilityId: string; expiresAt: number; reservedBytes: number }
  >;
  chunkUploads: Map<string, V2ChunkUpload>;
  chunkUploadOperations: Map<string, { digest: Uint8Array; uploadId: string }>;
  chunkRenewals: Map<
    string,
    { operationId: Uint8Array; operationDigest: Uint8Array }
  >;
  reservationBytes: Map<string, number>;
  reservationObjects: Set<string>;
  deliveryObjects: Set<string>;
  reservationRelationships: Map<string, string>;
  reservationDirections: Map<string, V2RepositoryDelivery['direction']>;
  quotaAccounts: Map<string, QuotaAccount>;
  operations: Map<string, OperationRecord>;
  nonces: Map<string, number>;
  controlEvents: Map<string, V2RepositoryControlEvent>;
  controlOperations: Map<string, string>;
  rateWindows: Map<string, { minute: number; count: number }>;
}

function operationKey(operationId: Uint8Array): string {
  if (operationId.byteLength !== 16) {
    throw new Error('Operation ID is invalid.');
  }
  return Array.from(operationId, (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

function deleteOperationForDelivery(
  operations: Map<string, OperationRecord>,
  deliveryId: string,
): void {
  for (const [operation, value] of operations) {
    if (value.deliveryId === deliveryId) {
      operations.delete(operation);
    }
  }
}

function expireDeliveries(
  state: MemoryV2MaintenanceState,
  now: number,
  limit: number,
  expiredDeliveryIds: string[],
  expiredBodyKeys: string[],
): void {
  for (const [id, delivery] of state.deliveries) {
    if (expiredDeliveryIds.length >= limit || expiredBodyKeys.length >= limit) {
      break;
    }
    if (delivery.expiresAt > now) {
      continue;
    }
    const chunked = delivery.parts !== undefined;
    while (delivery.parts?.length && expiredBodyKeys.length < limit) {
      expiredBodyKeys.push(delivery.parts.shift()!.key);
    }
    if (delivery.parts?.length) {
      break;
    }
    state.deliveries.delete(id);
    const account = state.quotaAccounts.get(delivery.relationshipId);
    if (account) {
      account.committedBytes -= delivery.payloadLength;
      if (state.deliveryObjects.delete(id)) {
        account.objectCount--;
      }
    }
    deleteOperationForDelivery(state.operations, id);
    expiredDeliveryIds.push(id);
    if (!chunked) {
      expiredBodyKeys.push(delivery.payloadKey);
    }
  }
}

function releaseReservationQuota(
  state: MemoryV2MaintenanceState,
  id: string,
): void {
  const relationshipId = state.reservationRelationships.get(id);
  const account = relationshipId
    ? state.quotaAccounts.get(relationshipId)
    : undefined;
  const reservedBytes = state.reservationBytes.get(id);
  if (reservedBytes !== undefined) {
    if (account) {
      account.reservedBytes -= reservedBytes;
    }
    state.reservationBytes.delete(id);
  }
  if (state.reservationObjects.delete(id) && account) {
    account.objectCount--;
  }
}

function expireReservations(
  state: MemoryV2MaintenanceState,
  now: number,
  limit: number,
  expiredBodyKeys: string[],
): void {
  for (const [id, reservation] of state.reservations) {
    if (expiredBodyKeys.length >= limit) {
      break;
    }
    if (reservation.expiresAt > now) {
      continue;
    }
    state.reservations.delete(id);
    releaseReservationQuota(state, id);
    state.reservationRelationships.delete(id);
    state.reservationDirections.delete(id);
    deleteOperationForDelivery(state.operations, id);
    expiredBodyKeys.push(reservation.payloadKey);
  }
}

function expireStagedBodies(
  state: MemoryV2MaintenanceState,
  now: number,
  limit: number,
  expiredBodyKeys: string[],
): void {
  for (const [id, staged] of state.stagedBodies) {
    if (expiredBodyKeys.length >= limit) {
      break;
    }
    if (staged.expiresAt <= now) {
      state.stagedBodies.delete(id);
      expiredBodyKeys.push(`staging/${id}.bin`);
    }
  }
}

function expireChunkUploads(
  state: MemoryV2MaintenanceState,
  now: number,
  limit: number,
  expiredBodyKeys: string[],
): number {
  let expired = 0;
  for (const [id, upload] of state.chunkUploads) {
    if (expired >= limit) {
      break;
    }
    if (upload.expiresAt > now) {
      continue;
    }
    while (upload.parts.length > 0) {
      const part = upload.parts[0]!;
      const bodyKey =
        part.bodyKey ??
        (upload.committedAt === undefined
          ? v2StagedChunkKey(upload.id, part.id)
          : undefined);
      if (bodyKey !== undefined && expiredBodyKeys.length >= limit) {
        return expired;
      }
      upload.parts.shift();
      if (bodyKey !== undefined) {
        expiredBodyKeys.push(bodyKey);
      }
    }
    state.chunkUploads.delete(id);
    state.chunkRenewals.delete(id);
    for (const [operation, value] of state.chunkUploadOperations) {
      if (value.uploadId === id) {
        state.chunkUploadOperations.delete(operation);
      }
    }
    expired++;
  }
  return expired;
}

function deleteExpiredEntries<K, V>(
  entries: Map<K, V>,
  limit: number,
  expired: (value: V) => boolean,
): number {
  let deleted = 0;
  for (const [key, value] of entries) {
    if (deleted >= limit) {
      break;
    }
    if (expired(value)) {
      entries.delete(key);
      deleted++;
    }
  }
  return deleted;
}

function expireControlEvents(
  state: MemoryV2MaintenanceState,
  now: number,
  limit: number,
): number {
  let deleted = 0;
  for (const [id, event] of state.controlEvents) {
    if (deleted >= limit) {
      break;
    }
    if (event.expiresAt <= now) {
      state.controlEvents.delete(id);
      state.controlOperations.delete(operationKey(event.operationId));
      deleted++;
    }
  }
  return deleted;
}

export function runMemoryV2Maintenance(
  state: MemoryV2MaintenanceState,
  now: number,
  limit: number,
): V2MaintenanceResult {
  const expiredDeliveryIds: string[] = [];
  const expiredBodyKeys: string[] = [];
  expireDeliveries(state, now, limit, expiredDeliveryIds, expiredBodyKeys);
  expireReservations(state, now, limit, expiredBodyKeys);
  expireStagedBodies(state, now, limit, expiredBodyKeys);
  const expiredChunkUploads = expireChunkUploads(
    state,
    now,
    limit,
    expiredBodyKeys,
  );

  const deletedNonces = deleteExpiredEntries(
    state.nonces,
    limit,
    (expiresAt) => expiresAt < now,
  );
  const deletedControlEvents = expireControlEvents(state, now, limit);
  const minute = Math.floor(now / 60);
  const deletedRateWindows = deleteExpiredEntries(
    state.rateWindows,
    limit,
    (window) => window.minute < minute,
  );
  return {
    expiredDeliveryIds,
    expiredBodyKeys,
    deletedNonces,
    deletedControlEvents,
    deletedRateWindows,
    deletedInvitations: 0,
    complete:
      expiredDeliveryIds.length < limit &&
      expiredChunkUploads < limit &&
      expiredBodyKeys.length < limit &&
      deletedNonces < limit &&
      deletedControlEvents < limit &&
      deletedRateWindows < limit,
  };
}
