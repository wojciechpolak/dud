// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { V2Direction, V2Scope } from './v2-types.js';

export interface V2RelationshipStatus {
  fullyRevoked: boolean;
  tuples: Array<{
    direction: V2Direction;
    scope: V2Scope;
    revoked: boolean;
    rotatedAt: number;
  }>;
}

type TupleStatus = V2RelationshipStatus['tuples'][number];
type Row = Record<string, unknown>;

function storedDirection(value: unknown): V2Direction {
  return Number(value) === 0 ? 'inviter->invitee' : 'invitee->inviter';
}

/**
 * When the newest revocation covering a tuple was recorded, or undefined when
 * none covers it. A revocation with no direction or no scope covers every
 * value of the missing field.
 */
function latestCoveringRevocation(
  revocations: readonly Row[],
  direction: V2Direction,
  scope: V2Scope,
): number | undefined {
  const covering = revocations.filter(
    (row) =>
      (row.direction === null ||
        storedDirection(row.direction) === direction) &&
      (row.scope === null || row.scope === scope),
  );
  return covering.length === 0
    ? undefined
    : Math.max(...covering.map((row) => Number(row.created_at)));
}

/** Orders tuples by direction, then scope, so status output is stable. */
export function sortV2RelationshipTuples(
  tuples: Iterable<TupleStatus>,
): TupleStatus[] {
  return Array.from(tuples).sort((a, b) =>
    `${a.direction}|${a.scope}`.localeCompare(`${b.direction}|${b.scope}`),
  );
}

/**
 * Status of a relationship from its stored capability and revocation rows, as
 * the SQL repositories hold them: direction as 0 or 1, and a null direction or
 * scope on a revocation meaning it covers every value. A tuple is revoked when
 * the whole relationship is, when any of its capabilities is, or when a
 * revocation covers it; it rotated at the latest of those events and its
 * capabilities' creation.
 */
export function v2RelationshipStatusFromRows(input: {
  relationshipRevoked: boolean;
  capabilities: readonly Row[];
  revocations: readonly Row[];
}): V2RelationshipStatus {
  const fullyRevoked =
    input.relationshipRevoked ||
    input.revocations.some(
      (row) => row.direction === null && row.scope === null,
    );
  const tuples = new Map<string, TupleStatus>();
  for (const row of input.capabilities) {
    const direction = storedDirection(row.direction);
    const scope = row.scope as V2Scope;
    const key = `${direction}|${scope}`;
    const revokedAt =
      row.revoked_at === null || row.revoked_at === undefined
        ? undefined
        : Number(row.revoked_at);
    const recorded = latestCoveringRevocation(
      input.revocations,
      direction,
      scope,
    );
    const existing = tuples.get(key);
    tuples.set(key, {
      direction,
      scope,
      revoked:
        fullyRevoked ||
        revokedAt !== undefined ||
        recorded !== undefined ||
        existing?.revoked === true,
      rotatedAt: Math.max(
        Number(row.created_at),
        revokedAt ?? 0,
        recorded ?? 0,
        existing?.rotatedAt ?? 0,
      ),
    });
  }
  for (const row of input.revocations) {
    if (row.direction === null || row.scope === null) {
      continue;
    }
    const direction = storedDirection(row.direction);
    const scope = row.scope as V2Scope;
    const key = `${direction}|${scope}`;
    tuples.set(key, {
      direction,
      scope,
      revoked: true,
      rotatedAt: Math.max(
        tuples.get(key)?.rotatedAt ?? 0,
        Number(row.created_at),
      ),
    });
  }
  return { fullyRevoked, tuples: sortV2RelationshipTuples(tuples.values()) };
}
