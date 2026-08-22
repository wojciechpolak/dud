// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type {
  V2DeliveryReservation,
  V2MaintenanceResult,
  V2RepositoryControlEvent,
  V2RepositoryDelivery,
} from './v2-repository.js';

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
  stagedBodies: Map<string, { expiresAt: number; reservedBytes: number }>;
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
    if (expiredDeliveryIds.length >= limit) {
      break;
    }
    if (delivery.expiresAt > now) {
      continue;
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
    expiredBodyKeys.push(delivery.payloadKey);
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
  expiredBodyKeys: string[],
): void {
  for (const [id, staged] of state.stagedBodies) {
    if (staged.expiresAt <= now) {
      state.stagedBodies.delete(id);
      expiredBodyKeys.push(`staging/${id}.bin`);
    }
  }
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
  expireStagedBodies(state, now, expiredBodyKeys);

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
      expiredBodyKeys.length < limit &&
      deletedNonces < limit &&
      deletedControlEvents < limit &&
      deletedRateWindows < limit,
  };
}
