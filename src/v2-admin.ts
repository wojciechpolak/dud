// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  bytesToHex,
  deriveV2EnrollmentKey,
  formatV2EnrollmentKey,
  hexToBytes,
  isV2Direction,
  isV2Scope,
  parseV2DeploymentKey,
  parseV2EnrollmentSecret,
  rewrapV2VerifierKeys,
} from './v2-auth.js';
import { FilesystemV2Store } from './v2-filesystem.js';
import { FilesystemV2BodyStore } from './v2-filesystem-body-store.js';
import {
  reconcileV2Storage,
  type V2ReconciliationReport,
} from './v2-maintenance.js';
import { SQLiteV2Repository } from './v2-sqlite-repository.js';
import type {
  V2Direction,
  V2RevocationRecord,
  V2Scope,
  V2Store,
} from './v2-types.js';

interface ParsedArguments {
  command: string;
  values: Map<string, string>;
}

/** Options that stand alone; every other option still takes one value. */
const FLAG_OPTIONS: ReadonlySet<string> = new Set(['apply', 'json']);

function parseArguments(args: string[]): ParsedArguments {
  const command = args.shift() ?? '';
  const values = new Map<string, string>();
  while (args.length !== 0) {
    const option = args.shift()!;
    if (!option.startsWith('--')) {
      throw new Error(`Invalid option ${option}.`);
    }
    const name = option.slice(2);
    if (values.has(name)) {
      throw new Error(`Duplicate option --${name}.`);
    }
    if (FLAG_OPTIONS.has(name)) {
      values.set(name, 'true');
      continue;
    }
    if (args.length === 0) {
      throw new Error(`Invalid option ${option}.`);
    }
    values.set(name, args.shift()!);
  }
  return { command, values };
}

function positiveInteger(
  values: Map<string, string>,
  name: string,
  fallback: number,
  maximum: number,
): number {
  const raw = values.get(name);
  if (raw === undefined) {
    return fallback;
  }
  if (!/^[0-9]{1,9}$/.test(raw)) {
    throw new Error(`--${name} must be a non-negative integer.`);
  }
  const value = Number(raw);
  if (value > maximum) {
    throw new Error(`--${name} must not exceed ${maximum}.`);
  }
  return value;
}

function required(values: Map<string, string>, name: string): string {
  const value = values.get(name);
  if (!value) {
    throw new Error(`--${name} is required.`);
  }
  return value;
}

function requireOnly(
  values: Map<string, string>,
  allowed: readonly string[],
): void {
  const names = new Set(allowed);
  for (const name of values.keys()) {
    if (!names.has(name)) {
      throw new Error(`Unknown option --${name}.`);
    }
  }
}

function revocationKey(
  relationshipId: string,
  direction?: V2Direction,
  scope?: V2Scope,
): string {
  return `${relationshipId}|${direction ?? '*'}|${scope ?? '*'}`;
}

export async function offlineRevokeV2Relationship(
  store: V2Store,
  relationshipId: Uint8Array,
  now: number,
  direction?: V2Direction,
  scope?: V2Scope,
): Promise<number> {
  if (relationshipId.byteLength !== 16) {
    throw new Error('Relationship ID must be 16 bytes.');
  }
  const relationship = bytesToHex(relationshipId);
  return store.transaction((state) => {
    const record: V2RevocationRecord = {
      relationshipId: relationship,
      ...(direction ? { direction } : {}),
      ...(scope ? { scope } : {}),
      revoked: true,
      rotatedAt: now,
    };
    state.revocations[revocationKey(relationship, direction, scope)] = record;
    let count = 0;
    for (const capability of Object.values(state.capabilities)) {
      if (
        capability.relationshipId === relationship &&
        (!direction || capability.direction === direction) &&
        (!scope || capability.scope === scope)
      ) {
        capability.revoked = true;
        capability.rotatedAt = now;
        count += 1;
      }
    }
    return count;
  });
}

const RECONCILE_DEFAULT_LIMIT = 200;
const RECONCILE_DEFAULT_MINIMUM_AGE = 86_400;

function formatReconciliationReport(
  report: V2ReconciliationReport,
  applied: boolean,
): string {
  const lines = [
    `Scanned ${report.scannedBodies} stored body/bodies and ${report.scannedMetadataKeys} metadata key(s).`,
    `Orphan bodies (no live metadata): ${report.orphanBodies.length}`,
    `Retained as too recent to remove: ${report.retainedRecentBodies}`,
    applied
      ? `Deleted orphan bodies: ${report.deletedBodies.length}`
      : 'Dry run: no body was deleted. Re-run with --apply to remove them.',
    `Metadata keys with no stored body: ${report.missingBodies.length}`,
  ];
  for (const key of report.orphanBodies) {
    lines.push(`  orphan ${key}`);
  }
  for (const key of report.missingBodies) {
    lines.push(`  missing ${key}`);
  }
  lines.push(
    report.complete
      ? 'Reconciliation walk is complete.'
      : `Reconciliation walk is incomplete. Resume with --cursor ${report.cursor}`,
  );
  return `${lines.join('\n')}\n`;
}

/**
 * Runs one bounded reconciliation page against the Node backend. The command
 * is always explicit: no request path reaches this code, and it reports by
 * default so removing bytes stays a deliberate operator decision.
 */
async function reconcileCommand(values: Map<string, string>): Promise<string> {
  const dataDir = required(values, 'data-dir');
  const limit = positiveInteger(
    values,
    'limit',
    RECONCILE_DEFAULT_LIMIT,
    1_000,
  );
  if (limit < 1) {
    throw new Error('--limit must be at least 1.');
  }
  const minimumAgeSeconds = positiveInteger(
    values,
    'min-age',
    RECONCILE_DEFAULT_MINIMUM_AGE,
    31_536_000,
  );
  const apply = values.get('apply') === 'true';
  const json = values.get('json') === 'true';
  const repository = new SQLiteV2Repository(dataDir);
  await repository.initialize();
  try {
    const report = await reconcileV2Storage(
      repository,
      new FilesystemV2BodyStore(dataDir),
      {
        now: Math.floor(Date.now() / 1000),
        limit,
        ...(values.has('cursor') ? { cursor: values.get('cursor')! } : {}),
        minimumAgeSeconds,
        apply,
      },
    );
    return json
      ? `${JSON.stringify(report, null, 2)}\n`
      : formatReconciliationReport(report, apply);
  } finally {
    repository.close();
  }
}

/**
 * Stretches the configured passphrase once, here, and prints the value that
 * carries the result. A server given that value verifies enrollment proofs
 * without deriving anything, which is what makes a gated deployment affordable
 * on a Worker; the work factor still prices every guess an attacker makes,
 * because the clients that hold the passphrase still pay it.
 */
async function enrollmentKeyCommand(): Promise<string> {
  const secret = process.env.DUD_PEER_SECRET;
  if (!secret) {
    throw new Error(
      'enrollment-key reads the passphrase from DUD_PEER_SECRET, which is unset. ' +
        'It is not accepted on the command line, where it would reach the shell history.',
    );
  }
  // Validated first, so a passphrase this deployment would refuse at startup is
  // refused here too rather than converted into a key that hides the problem.
  parseV2EnrollmentSecret(secret, true);
  return `${formatV2EnrollmentKey(await deriveV2EnrollmentKey(secret))}\n`;
}

function usage(): string {
  return `Usage:
  node dist/src/v2-admin.js revoke --data-dir DIR --relationship HEX [--direction NAME] [--scope NAME]
  node dist/src/v2-admin.js rewrap-key --data-dir DIR
  node dist/src/v2-admin.js reconcile --data-dir DIR [--limit N] [--cursor TOKEN]
      [--min-age SECONDS] [--apply] [--json]
  node dist/src/v2-admin.js enrollment-key

rewrap-key reads the old key from DUD_PEER_DEPLOYMENT_KEY and the new key from
DUD_PEER_NEW_DEPLOYMENT_KEY. Neither key is accepted on the command line.

enrollment-key reads the passphrase from DUD_PEER_SECRET and prints the derived
enrollment key, in the form DUD_PEER_SECRET itself accepts. Configure a server
with that value and it verifies enrollment without running the key derivation,
which a free-tier Worker invocation has too little CPU to finish. Clients keep
the passphrase.

reconcile walks one bounded page of the delivery body namespace against the
metadata that names it, in both directions, and prints a resume cursor when
more pages remain. It reports only; --apply additionally deletes orphan bodies
that are at least --min-age seconds old (default ${RECONCILE_DEFAULT_MINIMUM_AGE}).
`;
}

async function main(args: string[]): Promise<void> {
  process.umask(0o077);
  const parsed = parseArguments(args);
  if (!parsed.command || parsed.command === 'help') {
    process.stdout.write(usage());
    return;
  }
  const allowedOptions: Record<string, readonly string[]> = {
    revoke: ['data-dir', 'relationship', 'direction', 'scope'],
    'rewrap-key': ['data-dir'],
    reconcile: ['data-dir', 'limit', 'cursor', 'min-age', 'apply', 'json'],
    'enrollment-key': [],
  };
  const allowed = allowedOptions[parsed.command];
  if (!allowed) {
    throw new Error(`Unknown v2 admin command ${parsed.command}.\n${usage()}`);
  }
  requireOnly(parsed.values, allowed);
  if (parsed.command === 'enrollment-key') {
    process.stdout.write(await enrollmentKeyCommand());
    return;
  }
  if (parsed.command === 'reconcile') {
    process.stdout.write(await reconcileCommand(parsed.values));
    return;
  }
  const store = new FilesystemV2Store(required(parsed.values, 'data-dir'));
  await store.initialize();
  if (parsed.command === 'rewrap-key') {
    const count = await rewrapV2VerifierKeys(
      store,
      parseV2DeploymentKey(process.env.DUD_PEER_DEPLOYMENT_KEY),
      parseV2DeploymentKey(process.env.DUD_PEER_NEW_DEPLOYMENT_KEY),
    );
    process.stdout.write(`Rewrapped ${count} capability verifier(s).\n`);
    return;
  }
  const relationshipId = hexToBytes(
    required(parsed.values, 'relationship'),
    16,
  );
  const directionValue = parsed.values.get('direction');
  if (directionValue !== undefined && !isV2Direction(directionValue)) {
    throw new Error('--direction is invalid.');
  }
  const direction = directionValue as V2Direction | undefined;

  const scopeValue = parsed.values.get('scope');
  if (scopeValue !== undefined && !isV2Scope(scopeValue)) {
    throw new Error('--scope is invalid.');
  }
  const count = await offlineRevokeV2Relationship(
    store,
    relationshipId,
    Math.floor(Date.now() / 1000),
    direction,
    scopeValue as V2Scope | undefined,
  );
  process.stdout.write(`Revoked ${count} active capability record(s).\n`);
}

if (
  process.argv[1] &&
  import.meta.url === new URL(`file://${process.argv[1]}`).toString()
) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
