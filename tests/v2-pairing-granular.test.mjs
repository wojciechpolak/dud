// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createV2CapabilityRecord,
  deriveV2DailyCapabilityLookupId,
} from '../dist/src/v2-auth.js';
import { MemoryV2Repository } from '../dist/src/v2-memory-repository.js';
import { registerActivationCapabilities } from '../dist/src/v2-pairing.js';

test('pairing activation registers daily granular capability lookups', async () => {
  const deploymentKey = new Uint8Array(32).fill(1);
  const tokenSecret = new Uint8Array(32).fill(2);
  const repository = new MemoryV2Repository();
  const capability = await createV2CapabilityRecord(deploymentKey, {
    relationshipId: new Uint8Array(16).fill(3),
    direction: 'inviter->invitee',
    scope: 'write',
    tokenSecret,
    createdAt: 86_400,
    expiresAt: 2 * 86_400 + 1,
    randomBytes: (length) => new Uint8Array(length).fill(4),
  });
  await registerActivationCapabilities({ repository, deploymentKey }, [
    capability,
  ]);
  for (const epoch of [1, 2]) {
    const lookup = await deriveV2DailyCapabilityLookupId(tokenSecret, epoch);
    assert.equal(
      (await repository.findCapabilityLookup(lookup, epoch)).id,
      capability.id,
    );
  }
});
