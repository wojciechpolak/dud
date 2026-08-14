// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { decodeBase64Url, encodeBase64Url } from './v2-auth.js';
import type {
  V2BodyInventory,
  V2BodyStore,
  V2MaintenanceResult,
  V2ReconciliationRepository,
  V2Repository,
} from './v2-repository.js';

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

export interface V2ReconciliationOptions {
  now: number;
  limit: number;
  cursor?: string;
  /**
   * Bodies younger than this many seconds are reported but never deleted, so a
   * reconciliation that races an in-flight upload cannot remove live bytes.
   */
  minimumAgeSeconds: number;
  /** Without this, the walk only reports; it mutates nothing. */
  apply: boolean;
}

export interface V2ReconciliationReport {
  scannedBodies: number;
  scannedMetadataKeys: number;
  /** Stored bodies that no live metadata names. */
  orphanBodies: string[];
  /** Orphans held back because they are younger than the minimum age. */
  retainedRecentBodies: number;
  /** Orphans actually removed; empty unless `apply` was requested. */
  deletedBodies: string[];
  /** Body keys that metadata names but storage does not hold. */
  missingBodies: string[];
  /** Resume token for the next page, absent once both walks are drained. */
  cursor?: string;
  complete: boolean;
}

interface ReconciliationCursor {
  bodies?: string;
  metadata?: string;
  bodiesDone: boolean;
  metadataDone: boolean;
}

function encodeCursor(cursor: ReconciliationCursor): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(cursor)));
}

function decodeCursor(value: string | undefined): ReconciliationCursor {
  if (value === undefined) {
    return { bodiesDone: false, metadataDone: false };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
  } catch {
    throw new Error('Reconciliation cursor is invalid.');
  }
  const cursor = parsed as Partial<ReconciliationCursor>;
  if (
    typeof cursor !== 'object' ||
    cursor === null ||
    typeof cursor.bodiesDone !== 'boolean' ||
    typeof cursor.metadataDone !== 'boolean' ||
    (cursor.bodies !== undefined && typeof cursor.bodies !== 'string') ||
    (cursor.metadata !== undefined && typeof cursor.metadata !== 'string')
  ) {
    throw new Error('Reconciliation cursor is invalid.');
  }
  return {
    ...(cursor.bodies === undefined ? {} : { bodies: cursor.bodies }),
    ...(cursor.metadata === undefined ? {} : { metadata: cursor.metadata }),
    bodiesDone: cursor.bodiesDone,
    metadataDone: cursor.metadataDone,
  };
}

/**
 * One bounded page of full storage reconciliation: it walks the opaque body
 * namespace against the metadata that names it in both directions. This is
 * never reachable from a request; only the explicit administrator command runs
 * it, and it reports by default so removal is always a deliberate choice.
 */
export async function reconcileV2Storage(
  repository: V2ReconciliationRepository,
  bodyStore: V2BodyStore & V2BodyInventory,
  options: V2ReconciliationOptions,
): Promise<V2ReconciliationReport> {
  if (
    !Number.isSafeInteger(options.limit) ||
    options.limit < 1 ||
    options.limit > 1_000
  ) {
    throw new Error('Reconciliation page limit is invalid.');
  }
  if (
    !Number.isSafeInteger(options.minimumAgeSeconds) ||
    options.minimumAgeSeconds < 0
  ) {
    throw new Error('Reconciliation minimum age is invalid.');
  }
  const cursor = decodeCursor(options.cursor);
  const report: V2ReconciliationReport = {
    scannedBodies: 0,
    scannedMetadataKeys: 0,
    orphanBodies: [],
    retainedRecentBodies: 0,
    deletedBodies: [],
    missingBodies: [],
    complete: false,
  };

  if (!cursor.bodiesDone) {
    const page = await bodyStore.listBodies({
      ...(cursor.bodies === undefined ? {} : { cursor: cursor.bodies }),
      limit: options.limit,
    });
    report.scannedBodies = page.entries.length;
    const known = new Set(
      await repository.filterKnownBodyKeys(
        page.entries.map((entry) => entry.key),
      ),
    );
    for (const entry of page.entries) {
      if (known.has(entry.key)) {
        continue;
      }
      report.orphanBodies.push(entry.key);
      const age =
        entry.modifiedAt === undefined
          ? undefined
          : options.now - entry.modifiedAt;
      if (age === undefined || age < options.minimumAgeSeconds) {
        report.retainedRecentBodies++;
        continue;
      }
      if (options.apply) {
        await bodyStore.delete(entry.key);
        report.deletedBodies.push(entry.key);
      }
    }
    if (page.cursor === undefined) {
      cursor.bodiesDone = true;
      delete cursor.bodies;
    } else {
      cursor.bodies = page.cursor;
    }
  }

  if (!cursor.metadataDone) {
    const page = await repository.listBodyKeys({
      ...(cursor.metadata === undefined ? {} : { cursor: cursor.metadata }),
      limit: options.limit,
    });
    report.scannedMetadataKeys = page.keys.length;
    for (const key of page.keys) {
      if (!(await bodyStore.head(key))) {
        report.missingBodies.push(key);
      }
    }
    if (page.cursor === undefined) {
      cursor.metadataDone = true;
      delete cursor.metadata;
    } else {
      cursor.metadata = page.cursor;
    }
  }

  report.complete = cursor.bodiesDone && cursor.metadataDone;
  if (!report.complete) {
    report.cursor = encodeCursor(cursor);
  }
  return report;
}
