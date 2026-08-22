// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  createV2CapabilityRecord,
  deriveV2DailyCapabilityLookupId,
} from './v2-auth.js';
import { directionForReissue, ReissueError } from './v2-reissue-protocol.js';
import type {
  V2CapabilityRegistration,
  V2Repository,
} from './v2-repository.js';
import type {
  V2CapabilityRecord,
  V2Direction,
  V2Limits,
  V2Scope,
  V2StoredState,
  V2Store,
} from './v2-types.js';

export interface PreparedReissueCapability {
  record: V2CapabilityRecord;
  direction: V2Direction;
  scope: V2Scope;
  tokenSecret: Uint8Array;
}

export interface PreparedReissueCapabilities {
  items: PreparedReissueCapability[];
  expectedActive: Map<string, string[]>;
}

export function isReissueTupleRevoked(
  state: V2StoredState,
  relationshipId: string,
  direction: V2Direction,
  scope: V2Scope,
): boolean {
  const key = (candidateDirection?: V2Direction, candidateScope?: V2Scope) =>
    `${relationshipId}|${candidateDirection ?? '*'}|${candidateScope ?? '*'}`;
  return (
    state.revocations[key()]?.revoked === true ||
    state.revocations[key(direction)]?.revoked === true ||
    state.revocations[key(undefined, scope)]?.revoked === true ||
    state.revocations[key(direction, scope)]?.revoked === true
  );
}

function activeCapabilityIds(
  state: V2StoredState,
  relationshipId: string,
  direction: V2Direction,
  scope: V2Scope,
): string[] {
  return Object.values(state.capabilities)
    .filter(
      (capability) =>
        capability.relationshipId === relationshipId &&
        capability.direction === direction &&
        capability.scope === scope &&
        !capability.revoked,
    )
    .map((capability) => capability.id)
    .sort();
}

export async function prepareReissueCapabilities(input: {
  deploymentKey: Uint8Array;
  relationship: Uint8Array;
  relationshipId: string;
  role: 0 | 1;
  scopes: readonly V2Scope[];
  now: number;
  limits: V2Limits;
  randomBytes: (length: number) => Uint8Array;
  state?: V2StoredState;
}): Promise<PreparedReissueCapabilities> {
  const items: PreparedReissueCapability[] = [];
  const expectedActive = new Map<string, string[]>();
  for (const scope of input.scopes) {
    const direction = directionForReissue(input.role, scope);
    if (input.state) {
      expectedActive.set(
        `${direction}|${scope}`,
        activeCapabilityIds(
          input.state,
          input.relationshipId,
          direction,
          scope,
        ),
      );
    }
    const tokenSecret = input.randomBytes(32);
    if (tokenSecret.byteLength !== 32) {
      throw new Error('V2 random source returned an invalid byte count.');
    }
    items.push({
      direction,
      scope,
      tokenSecret,
      record: await createV2CapabilityRecord(input.deploymentKey, {
        relationshipId: input.relationship,
        direction,
        scope,
        tokenSecret,
        createdAt: input.now,
        expiresAt: input.now + input.limits.maxTtlSeconds,
        randomBytes: input.randomBytes,
      }),
    });
  }
  return { items, expectedActive };
}

/** Derives the tuple retirements and daily lookups a reissue must commit. */
export async function buildCapabilityReplacement(
  prepared: readonly PreparedReissueCapability[],
): Promise<{
  revocations: Array<{
    relationshipId: string;
    direction: V2Direction;
    scope: V2Scope;
  }>;
  registrations: V2CapabilityRegistration[];
}> {
  const registrations: V2CapabilityRegistration[] = [];
  const revocations: Array<{
    relationshipId: string;
    direction: V2Direction;
    scope: V2Scope;
  }> = [];
  for (const item of prepared) {
    revocations.push({
      relationshipId: item.record.relationshipId,
      direction: item.direction,
      scope: item.scope,
    });
    const firstEpoch = Math.floor(item.record.createdAt / 86_400);
    const lastEpoch = Math.floor((item.record.expiresAt - 1) / 86_400);
    for (let epoch = firstEpoch; epoch <= lastEpoch; epoch++) {
      registrations.push({
        capability: {
          id: item.record.id,
          relationshipId: item.record.relationshipId,
          direction: item.direction,
          scope: item.scope,
          encryptedTokenSecret: item.record.encryptedTokenSecret,
          createdAt: item.record.createdAt,
          expiresAt: item.record.expiresAt,
        },
        lookupId: await deriveV2DailyCapabilityLookupId(
          item.tokenSecret,
          epoch,
        ),
        epoch,
      });
    }
  }
  return { revocations, registrations };
}

async function replaceRepositoryCapabilities(
  repository: V2Repository | undefined,
  prepared: readonly PreparedReissueCapability[],
  now: number,
): Promise<void> {
  if (!repository) {
    return;
  }
  const { revocations, registrations } =
    await buildCapabilityReplacement(prepared);
  if (registrations.length > 0) {
    await repository.replaceCapabilities({ revocations, registrations, now });
  }
}

function assertPreparedCapabilityCurrent(
  state: V2StoredState,
  relationshipId: string,
  prepared: PreparedReissueCapabilities,
  item: PreparedReissueCapability,
): void {
  if (
    isReissueTupleRevoked(state, relationshipId, item.direction, item.scope)
  ) {
    throw new ReissueError(
      3,
      'A requested relationship capability is revoked.',
    );
  }
  const active = activeCapabilityIds(
    state,
    relationshipId,
    item.direction,
    item.scope,
  );
  const expected =
    prepared.expectedActive.get(`${item.direction}|${item.scope}`) ?? [];
  if (
    active.length !== expected.length ||
    active.some((id, index) => id !== expected[index])
  ) {
    throw new ReissueError(5, 'Capability tuple changed during re-issuance.');
  }
}

function revokeCapabilityTuple(
  state: V2StoredState,
  relationshipId: string,
  item: PreparedReissueCapability,
  now: number,
): void {
  for (const capability of Object.values(state.capabilities)) {
    if (
      capability.relationshipId === relationshipId &&
      capability.direction === item.direction &&
      capability.scope === item.scope
    ) {
      capability.revoked = true;
      capability.rotatedAt = now;
    }
  }
}

function commitStoredCapabilitiesToState(
  state: V2StoredState,
  relationshipId: string,
  prepared: PreparedReissueCapabilities,
  now: number,
): void {
  if (!state.relationships[relationshipId]) {
    throw new ReissueError(4, 'Relationship is not available.');
  }
  for (const item of prepared.items) {
    assertPreparedCapabilityCurrent(state, relationshipId, prepared, item);
    revokeCapabilityTuple(state, relationshipId, item, now);
    if (state.capabilities[item.record.id]) {
      throw new Error('V2 random capability identifier collision.');
    }
    state.capabilities[item.record.id] = item.record;
  }
}

export async function commitStoredCapabilities(input: {
  store: V2Store;
  repository?: V2Repository;
  relationshipId: string;
  prepared: PreparedReissueCapabilities;
  now: number;
}): Promise<void> {
  await input.store.transaction((state) =>
    commitStoredCapabilitiesToState(
      state,
      input.relationshipId,
      input.prepared,
      input.now,
    ),
  );
  await replaceRepositoryCapabilities(
    input.repository,
    input.prepared.items,
    input.now,
  );
}
