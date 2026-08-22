// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type {
  V2BodyInventory,
  V2BodyStore,
  V2MaintenanceResult,
  V2ReconciliationRepository,
  V2Repository,
} from './v2-repository.js';
import {
  reconcileStorage,
  type ReconciliationOptions,
  type ReconciliationReport,
} from './v2-reconciliation.js';

export type V2ReconciliationOptions = ReconciliationOptions;
export type V2ReconciliationReport = ReconciliationReport;

/** Upper bound on batches one scheduled pass runs before yielding its lease. */
export const MAINTENANCE_MAX_BATCHES = 16;

export interface V2MaintenancePassResult {
  batches: number;
  deletedBodies: number;
  expiredDeliveries: number;
  deletedNonces: number;
  deletedControlEvents: number;
  deletedRateWindows: number;
  deletedInvitations: number;
  /** False when the batch budget ran out before the backend was drained. */
  complete: boolean;
}

/**
 * Runs bounded, restartable maintenance batches until the repository reports
 * no expired records remain or the batch budget is spent. Each batch expires
 * delivery, reservation, control, staging, nonce, rate-window, and invitation
 * metadata, releases the aggregate byte accounting those records held, and
 * names the bodies to delete. Body deletion is restricted to keys the metadata
 * transaction returned, so a pass never touches an unnamed object, and an
 * interrupted pass simply resumes from the next scheduled batch.
 */
export async function runV2MaintenancePass(
  repository: V2Repository,
  bodyStore: V2BodyStore,
  now: number,
  limit: number,
  maxBatches = MAINTENANCE_MAX_BATCHES,
): Promise<V2MaintenancePassResult> {
  const totals: V2MaintenancePassResult = {
    batches: 0,
    deletedBodies: 0,
    expiredDeliveries: 0,
    deletedNonces: 0,
    deletedControlEvents: 0,
    deletedRateWindows: 0,
    deletedInvitations: 0,
    complete: false,
  };
  while (totals.batches < maxBatches) {
    const result: V2MaintenanceResult = await repository.runMaintenance(
      now,
      limit,
    );
    totals.batches++;
    totals.expiredDeliveries += result.expiredDeliveryIds.length;
    totals.deletedNonces += result.deletedNonces;
    totals.deletedControlEvents += result.deletedControlEvents;
    totals.deletedRateWindows += result.deletedRateWindows;
    totals.deletedInvitations += result.deletedInvitations;
    const deletions = await Promise.allSettled(
      result.expiredBodyKeys.map((key) => bodyStore.delete(key)),
    );
    totals.deletedBodies += deletions.filter(
      (deletion) => deletion.status === 'fulfilled',
    ).length;
    if (result.complete) {
      totals.complete = true;
      break;
    }
  }
  return totals;
}

export async function reconcileV2Storage(
  repository: V2ReconciliationRepository,
  bodyStore: V2BodyStore & V2BodyInventory,
  options: V2ReconciliationOptions,
): Promise<V2ReconciliationReport> {
  return reconcileStorage(repository, bodyStore, options);
}
