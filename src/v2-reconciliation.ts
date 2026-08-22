// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { decodeBase64Url, encodeBase64Url } from './v2-auth.js';
import type {
  V2BodyInventory,
  V2BodyStore,
  V2ReconciliationRepository,
} from './v2-repository.js';

export interface ReconciliationOptions {
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

export interface ReconciliationReport {
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

type ReconciliationBodyStore = V2BodyStore & V2BodyInventory;

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

function validateOptions(options: ReconciliationOptions): void {
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
}

function createReport(): ReconciliationReport {
  return {
    scannedBodies: 0,
    scannedMetadataKeys: 0,
    orphanBodies: [],
    retainedRecentBodies: 0,
    deletedBodies: [],
    missingBodies: [],
    complete: false,
  };
}

async function reconcileBodyPage(
  repository: V2ReconciliationRepository,
  bodyStore: ReconciliationBodyStore,
  options: ReconciliationOptions,
  cursor: ReconciliationCursor,
  report: ReconciliationReport,
): Promise<void> {
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

  cursor.bodies = page.cursor;
  cursor.bodiesDone = page.cursor === undefined;
}

async function reconcileMetadataPage(
  repository: V2ReconciliationRepository,
  bodyStore: ReconciliationBodyStore,
  options: ReconciliationOptions,
  cursor: ReconciliationCursor,
  report: ReconciliationReport,
): Promise<void> {
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

  cursor.metadata = page.cursor;
  cursor.metadataDone = page.cursor === undefined;
}

/**
 * One bounded page of full storage reconciliation: it walks the opaque body
 * namespace against the metadata that names it in both directions. This is
 * never reachable from a request; only the explicit administrator command runs
 * it, and it reports by default so removal is always a deliberate choice.
 */
export async function reconcileStorage(
  repository: V2ReconciliationRepository,
  bodyStore: ReconciliationBodyStore,
  options: ReconciliationOptions,
): Promise<ReconciliationReport> {
  validateOptions(options);
  const cursor = decodeCursor(options.cursor);
  const report = createReport();

  if (!cursor.bodiesDone) {
    await reconcileBodyPage(repository, bodyStore, options, cursor, report);
  }
  if (!cursor.metadataDone) {
    await reconcileMetadataPage(repository, bodyStore, options, cursor, report);
  }

  report.complete = cursor.bodiesDone && cursor.metadataDone;
  if (!report.complete) {
    report.cursor = encodeCursor(cursor);
  }
  return report;
}
