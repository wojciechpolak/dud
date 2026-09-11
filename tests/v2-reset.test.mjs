// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import {
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
} from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { decodeCbor, encodeCbor, requireCborMap } from '../dist/src/cbor.js';
import { bytesToHex, encodeBase64Url } from '../dist/src/v2-auth.js';
import { sha256 } from '../dist/src/sha256.js';
import { MemoryV2Store } from '../dist/src/v2-memory.js';
import { encryptV2RelationshipState } from '../dist/src/v2-relationship-state.js';
import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import { WorkerV2Store } from '../dist/src/v2-worker-store.js';
import {
  V2_DEPLOYMENT_KEY,
  V2_NOW_MS,
  V2_ORIGIN,
  createV2TestService,
} from './v2-helpers.mjs';

const encoder = new TextEncoder();
const now = Math.floor(V2_NOW_MS / 1000);

function fixed(start, length) {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function concat(...parts) {
  const result = new Uint8Array(
    parts.reduce((length, part) => length + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

function ed25519Key(seed) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(seed),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(privateKey).export({
    format: 'der',
    type: 'spki',
  });
  return {
    privateKey,
    publicKey: new Uint8Array(spki.subarray(spki.byteLength - 32)),
  };
}

function signReset(label, value, key) {
  return new Uint8Array(
    signEd25519(
      null,
      concat(
        encoder.encode(`dud/v2/relationship-reset/${label}\0`),
        sha256(encodeCbor(value)),
      ),
      key,
    ),
  );
}

function snapshot(start = 0) {
  return ['out:data', 'out:control', 'in:data', 'in:control'].map(
    (name, index) =>
      new Map([
        [1, name],
        [2, start + index],
        [3, fixed(0x70 + index, 32)],
      ]),
  );
}

function disposition(start = 0) {
  return new Map(
    Array.from({ length: 8 }, (_, index) => [index + 1, start + index]),
  );
}

function resetRequest(action, ...values) {
  const body = encodeCbor(
    new Map([[1, action], ...values.map((value, index) => [index + 2, value])]),
  );
  return new Request(`${V2_ORIGIN}/v2/relationships/reset`, {
    method: 'POST',
    headers: {
      accept: 'application/dud+cbor; version=2',
      'content-type': 'application/dud+cbor; version=2',
      'content-length': String(body.byteLength),
    },
    body,
  });
}

function decodeMap(responseBody) {
  return requireCborMap(
    decodeCbor(new Uint8Array(responseBody)),
    Array.from({ length: 16 }, (_, index) => index + 1),
    [],
  );
}

async function fixture() {
  const store = new MemoryV2Store();
  const { service } = await createV2TestService(store);
  const oldRelationshipId = fixed(0x10, 16);
  const inviter = ed25519Key(fixed(0x20, 32));
  const invitee = ed25519Key(fixed(0x40, 32));
  await store.transaction((state) => {
    state.relationships[bytesToHex(oldRelationshipId)] = {
      relationshipId: bytesToHex(oldRelationshipId),
      canonicalOrigin: V2_ORIGIN,
      inviterSigningPublicKey: encodeBase64Url(inviter.publicKey),
      inviterAgeRecipient: encodeBase64Url(fixed(0x50, 1216)),
      inviteeSigningPublicKey: encodeBase64Url(invitee.publicKey),
      inviteeAgeRecipient: encodeBase64Url(fixed(0x60, 1216)),
      createdAt: now - 60,
      generation: 0,
    };
    state.capabilities.old = {
      id: 'old',
      relationshipId: bytesToHex(oldRelationshipId),
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: encodeBase64Url(fixed(0x90, 32)),
      createdAt: now - 60,
      expiresAt: now + 3600,
      revoked: false,
      rotatedAt: 0,
    };
  });
  return { invitee, inviter, oldRelationshipId, service, store };
}

function proposal(fixture, options = {}) {
  const resetId = options.resetId ?? fixed(0xa0, 16);
  const newRelationshipId = options.newRelationshipId ?? fixed(0xb0, 16);
  const value = new Map([
    [1, 1],
    [2, fixture.oldRelationshipId],
    [3, resetId],
    [4, newRelationshipId],
    [5, 0],
    [6, options.generation ?? 1],
    [7, V2_ORIGIN],
    [8, snapshot(4)],
    [9, fixed(0x01, 16)],
    [10, fixed(0x02, 16)],
    [11, fixed(0x03, 16)],
    [12, ed25519Key(fixed(0xc0, 32)).publicKey],
    [13, fixed(0xd0, 1216)],
    [14, disposition(1)],
    [15, now + 3600],
    [16, 0],
  ]);
  return {
    newRelationshipId,
    resetId,
    signature: signReset('proposal', value, fixture.inviter.privateKey),
    value,
  };
}

function acceptance(fixture, reset) {
  const value = new Map([
    [1, 1],
    [2, sha256(encodeCbor(reset.value))],
    [3, 1],
    [4, fixed(0x04, 16)],
    [5, ed25519Key(fixed(0xe0, 32)).publicKey],
    [6, fixed(0xf0, 1216)],
    [7, snapshot(8)],
    [8, disposition(9)],
    [9, now + 3600],
  ]);
  return {
    signature: signReset('acceptance', value, fixture.invitee.privateKey),
    value,
  };
}

async function proposeReset(fixture, reset) {
  return fixture.service.fetch(resetRequest(1, reset.value, reset.signature));
}

test('peer relationship reset activates one fresh generation and revokes the old one', async () => {
  const value = await fixture();
  const reset = proposal(value);
  const proposed = await proposeReset(value, reset);
  assert.equal(proposed.status, 200);
  assert.equal(decodeMap(await proposed.arrayBuffer()).get(1), 1);

  const consent = acceptance(value, reset);
  const activate = () =>
    value.service.fetch(
      resetRequest(
        3,
        reset.value,
        reset.signature,
        consent.value,
        consent.signature,
      ),
    );
  const activated = await activate();
  assert.equal(activated.status, 200);
  const response = decodeMap(await activated.arrayBuffer());
  assert.equal(response.get(1), 2);
  const receipt = decodeMap(response.get(6));
  assert.equal(bytesToHex(receipt.get(2)), bytesToHex(reset.resetId));
  assert.equal(bytesToHex(receipt.get(4)), bytesToHex(reset.newRelationshipId));
  assert.equal(receipt.get(5), 1);

  const state = await value.store.readState();
  const oldId = bytesToHex(value.oldRelationshipId);
  const newId = bytesToHex(reset.newRelationshipId);
  assert.equal(state.relationships[newId].generation, 1);
  assert.equal(state.capabilities.old.revoked, true);
  assert.equal(state.revocations[`${oldId}|*|*`].revoked, true);
  assert.equal(state.relationshipResets[oldId].state, 'active');

  const replay = await activate();
  assert.equal(replay.status, 200);
  assert.equal(decodeMap(await replay.arrayBuffer()).get(1), 2);

  const changedConsent = acceptance(value, reset);
  changedConsent.value.set(9, now + 3599);
  changedConsent.signature = signReset(
    'acceptance',
    changedConsent.value,
    value.invitee.privateKey,
  );
  const conflictingRetry = await value.service.fetch(
    resetRequest(
      3,
      reset.value,
      reset.signature,
      changedConsent.value,
      changedConsent.signature,
    ),
  );
  assert.equal(conflictingRetry.status, 409);

  const statusValue = new Map([
    [1, 1],
    [2, value.oldRelationshipId],
    [3, 0],
    [4, fixed(0x31, 16)],
    [5, now + 60],
    [6, V2_ORIGIN],
  ]);
  const status = await value.service.fetch(
    resetRequest(
      2,
      statusValue,
      signReset('status', statusValue, value.inviter.privateKey),
    ),
  );
  assert.equal(status.status, 200);
  assert.equal(decodeMap(await status.arrayBuffer()).get(1), 2);
});

test('peer relationship reset cancellation is signed, idempotent, and forbidden after activation', async () => {
  const value = await fixture();
  const first = proposal(value);
  assert.equal((await proposeReset(value, first)).status, 200);
  const cancellation = new Map([
    [1, 1],
    [2, value.oldRelationshipId],
    [3, first.resetId],
    [4, 0],
    [5, fixed(0x33, 16)],
    [6, now + 60],
    [7, V2_ORIGIN],
  ]);
  const cancel = () =>
    value.service.fetch(
      resetRequest(
        4,
        cancellation,
        signReset('cancellation', cancellation, value.inviter.privateKey),
      ),
    );
  assert.equal(decodeMap(await (await cancel()).arrayBuffer()).get(1), 3);
  assert.equal(decodeMap(await (await cancel()).arrayBuffer()).get(1), 3);
  const changedCancellation = new Map(cancellation);
  changedCancellation.set(5, fixed(0x34, 16));
  const conflictingCancellation = await value.service.fetch(
    resetRequest(
      4,
      changedCancellation,
      signReset('cancellation', changedCancellation, value.inviter.privateKey),
    ),
  );
  assert.equal(conflictingCancellation.status, 409);

  const cancelledConsent = acceptance(value, first);
  const cancelledActivation = await value.service.fetch(
    resetRequest(
      3,
      first.value,
      first.signature,
      cancelledConsent.value,
      cancelledConsent.signature,
    ),
  );
  assert.equal(cancelledActivation.status, 409);
  const oldId = bytesToHex(value.oldRelationshipId);
  const cancelledState = await value.store.readState();
  assert.equal(cancelledState.relationshipResets[oldId].state, 'cancelled');
  assert.equal(
    cancelledState.relationships[bytesToHex(first.newRelationshipId)],
    undefined,
  );

  const second = proposal(value, {
    resetId: fixed(0x90, 16),
    newRelationshipId: fixed(0x91, 16),
  });
  const selected = decodeMap(
    await (await proposeReset(value, second)).arrayBuffer(),
  );
  assert.equal(bytesToHex(selected.get(2).get(3)), bytesToHex(second.resetId));
  const consent = acceptance(value, second);
  assert.equal(
    (
      await value.service.fetch(
        resetRequest(
          3,
          second.value,
          second.signature,
          consent.value,
          consent.signature,
        ),
      )
    ).status,
    200,
  );
  const lateCancellation = new Map(cancellation);
  lateCancellation.set(3, second.resetId);
  const late = await value.service.fetch(
    resetRequest(
      4,
      lateCancellation,
      signReset('cancellation', lateCancellation, value.inviter.privateKey),
    ),
  );
  assert.equal(late.status, 422);
});

test('peer relationship reset selects the smaller proposal ID and rejects stale or one-sided activation', async () => {
  const value = await fixture();
  const high = proposal(value, {
    resetId: fixed(0xc0, 16),
    newRelationshipId: fixed(0xc1, 16),
  });
  const low = proposal(value, {
    resetId: fixed(0x20, 16),
    newRelationshipId: fixed(0x21, 16),
  });
  assert.equal((await proposeReset(value, high)).status, 200);
  const selected = decodeMap(
    await (await proposeReset(value, low)).arrayBuffer(),
  );
  assert.equal(bytesToHex(selected.get(2).get(3)), bytesToHex(low.resetId));

  const staleConsent = acceptance(value, high);
  const stale = await value.service.fetch(
    resetRequest(
      3,
      high.value,
      high.signature,
      staleConsent.value,
      staleConsent.signature,
    ),
  );
  assert.equal(stale.status, 409);

  const oneSided = acceptance(value, low);
  oneSided.signature = signReset(
    'acceptance',
    oneSided.value,
    value.inviter.privateKey,
  );
  const rejected = await value.service.fetch(
    resetRequest(
      3,
      low.value,
      low.signature,
      oneSided.value,
      oneSided.signature,
    ),
  );
  assert.equal(rejected.status, 403);

  const skipped = proposal(value, {
    generation: 2,
    resetId: fixed(0x10, 16),
    newRelationshipId: fixed(0x11, 16),
  });
  assert.equal((await proposeReset(value, skipped)).status, 400);
});

test('SQLite activates a fresh relationship and revokes the old one atomically', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-reset-'));
  const repository = new SQLiteV2Repository(directory);
  await repository.initialize();
  t.after(async () => {
    repository.close();
    await rm(directory, { recursive: true, force: true });
  });
  const oldRelationshipId = fixed(0x10, 16);
  const inviter = ed25519Key(fixed(0x20, 32));
  const invitee = ed25519Key(fixed(0x40, 32));
  const relationship = {
    relationshipId: bytesToHex(oldRelationshipId),
    canonicalOrigin: V2_ORIGIN,
    inviterSigningPublicKey: encodeBase64Url(inviter.publicKey),
    inviterAgeRecipient: encodeBase64Url(fixed(0x50, 1216)),
    inviteeSigningPublicKey: encodeBase64Url(invitee.publicKey),
    inviteeAgeRecipient: encodeBase64Url(fixed(0x60, 1216)),
    createdAt: now - 60,
    generation: 0,
  };
  await repository.createRelationship({
    id: relationship.relationshipId,
    canonicalOrigin: V2_ORIGIN,
    encryptedState: await encryptV2RelationshipState(
      V2_DEPLOYMENT_KEY,
      relationship,
      (length) => fixed(0x11, length),
    ),
    createdAt: relationship.createdAt,
  });
  const { service } = await createV2TestService(new WorkerV2Store(), {
    repository,
  });
  const value = { oldRelationshipId, inviter, invitee, service };
  const reset = proposal(value);
  assert.equal((await proposeReset(value, reset)).status, 200);
  const consent = acceptance(value, reset);
  const activated = await service.fetch(
    resetRequest(
      3,
      reset.value,
      reset.signature,
      consent.value,
      consent.signature,
    ),
  );
  assert.equal(activated.status, 200);
  assert.equal(
    await repository.findRelationship(relationship.relationshipId),
    null,
  );
  assert.ok(
    await repository.findRelationship(bytesToHex(reset.newRelationshipId)),
  );
  assert.equal(
    (await repository.findRelationshipReset(relationship.relationshipId)).state,
    'active',
  );
});
