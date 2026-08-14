// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import { D1V2Repository } from '../dist/src/v2-d1-repository.js';
import { D1V2PairingRepository } from '../dist/src/v2-d1-pairing-repository.js';

const bytes = (length, seed) =>
  Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);

class MockD1 {
  statements = [];
  firstRows = [];
  batchResults = [];

  prepare(query) {
    const statement = {
      query,
      values: [],
      bind: (...values) => {
        statement.values = values;
        return statement;
      },
      run: async () => ({ meta: { changes: 1 } }),
      first: async () => this.firstRows.shift() ?? null,
      all: async () => ({ results: [] }),
    };
    this.statements.push(statement);
    return statement;
  }

  async batch(statements) {
    this.batchResults.push(statements);
    return statements.map((_, index) => ({
      meta: { changes: index === 0 ? 1 : 0 },
    }));
  }
}

function delivery(id = 'a'.repeat(32)) {
  return {
    id,
    relationship_id: 'relationship',
    direction: 0,
    slot: bytes(16, 1),
    epoch: 20_000,
    encrypted_descriptor: bytes(2, 2),
    requested_policy: bytes(2, 3),
    effective_policy: bytes(2, 4),
    policy_digest: bytes(32, 5),
    payload_key: `deliveries/${id}.bin`,
    payload_length: 3,
    payload_digest: bytes(32, 6),
    operation_id: bytes(16, 7),
    operation_digest: bytes(32, 8),
    state: 'published',
    created_at: 10,
    expires_at: 100,
    completed_at: null,
    completion_operation_id: null,
    completion_operation_digest: null,
    completion_digest: null,
    completion_result: null,
  };
}

test('D1 granular repository reserves delivery metadata with opaque body keys', async () => {
  const database = new MockD1();
  const repository = new D1V2Repository(database);
  const operationId = bytes(16, 10);
  const operationDigest = bytes(32, 11);
  database.firstRows.push({
    delivery_id: 'b'.repeat(32),
    payload_key: `deliveries/${'b'.repeat(32)}.bin`,
    expires_at: 99,
    operation_digest: operationDigest,
  });

  assert.deepEqual(
    await repository.reserveDelivery({
      capabilityId: 'capability',
      operationId,
      operationDigest,
      payloadLength: 123,
      now: 10,
      expiresAt: 99,
    }),
    {
      deliveryId: 'b'.repeat(32),
      payloadKey: `deliveries/${'b'.repeat(32)}.bin`,
      expiresAt: 99,
    },
  );
  const insert = database.statements.find((statement) =>
    statement.query.startsWith('INSERT OR IGNORE INTO reservations'),
  );
  assert.ok(insert);
  assert.match(insert.values[2], /^deliveries\/[a-f0-9]{32}\.bin$/);
  assert.doesNotMatch(insert.values[2], /relationship|capability/);
});

test('D1 granular repository claims every request nonce or none', async () => {
  const database = new MockD1();
  database.batch = async (statements) => {
    database.batchResults.push(statements);
    return [{ meta: { changes: 1 } }, { meta: { changes: 2 } }];
  };
  const repository = new D1V2Repository(database);
  assert.equal(
    await repository.claimNonces(
      [
        { capabilityId: 'first', nonce: bytes(16, 20), expiresAt: 100 },
        { capabilityId: 'second', nonce: bytes(16, 21), expiresAt: 100 },
      ],
      10,
    ),
    true,
  );
  assert.equal(database.batchResults[0].length, 2);
  assert.match(database.batchResults[0][1].query, /^WITH claims/);
  assert.match(database.batchResults[0][1].query, /NOT EXISTS/);
  assert.equal(
    await repository.claimNonces(
      [
        { capabilityId: 'first', nonce: bytes(16, 22), expiresAt: 100 },
        { capabilityId: 'first', nonce: bytes(16, 22), expiresAt: 100 },
      ],
      10,
    ),
    false,
  );
  assert.equal(database.batchResults.length, 1);
});

test('D1 pairing repository uses one opaque row and revision compare-and-swap', async () => {
  const database = new MockD1();
  const repository = new D1V2PairingRepository(database);
  const value = bytes(3, 60);
  assert.equal(
    await repository.create({
      locator: 'a'.repeat(64),
      phase: 0,
      createdAt: 1,
      expiresAt: 100,
      value,
    }),
    true,
  );
  assert.match(
    database.statements[0].query,
    /^INSERT OR IGNORE INTO invitations/,
  );
  database.firstRows.push({
    id: 'a'.repeat(64),
    phase: '0',
    encrypted_grant: value,
    created_at: 1,
    expires_at: 100,
    revision: 4,
  });
  const record = await repository.find('a'.repeat(64));
  assert.equal(record.revision, 4);
  assert.equal(
    await repository.compareAndSwap(record, { phase: 1, value: bytes(3, 61) }),
    true,
  );
  const update = database.statements.at(-1);
  assert.match(update.query, /revision = revision \+ 1/);
  assert.deepEqual(update.values.slice(-2), ['a'.repeat(64), 4]);
  database.firstRows.push({ count: 3 });
  assert.equal(await repository.countActive(10), 3);
  assert.equal(
    await repository.claimRateWindow('pairing-create:global', 1, 60),
    true,
  );
  assert.match(database.statements.at(-1).query, /pairing_rate_windows/);
  database.batch = async (statements) => {
    database.batchResults.push(statements);
    return statements.map((_, index) => ({
      meta: { changes: index === statements.length - 1 ? 1 : 0 },
    }));
  };
  assert.equal(
    await repository.admit({
      record: {
        locator: 'b'.repeat(64),
        phase: 0,
        createdAt: 1,
        expiresAt: 100,
        value: bytes(48, 62),
      },
      sourceKey: 'pairing-create:source',
      minute: 1,
      globalMaximum: 60,
      sourceMaximum: 2,
      pendingMaximum: 8,
      now: 10,
    }),
    true,
  );
  const admission = database.batchResults.at(-1);
  assert.equal(admission.length, 3);
  assert.match(admission[1].query, /changes\(\) = 1/);
  assert.match(admission[2].query, /INSERT INTO invitations/);
});

test('D1 pairing activation conditionally publishes grants, relation, and lookups', async () => {
  const database = new MockD1();
  database.batch = async (statements) => {
    database.batchResults.push(statements);
    return statements.map((_, index) => ({
      meta: { changes: index === statements.length - 1 ? 1 : 0 },
    }));
  };
  const repository = new D1V2PairingRepository(database);
  assert.equal(
    await repository.activate({
      record: {
        locator: 'a'.repeat(64),
        phase: 2,
        createdAt: 1,
        expiresAt: 100,
        value: bytes(48, 1),
        revision: 3,
      },
      invitationValue: bytes(48, 2),
      relationship: {
        id: 'relationship',
        canonicalOrigin: 'https://dud.example',
        encryptedState: bytes(48, 3),
        createdAt: 10,
      },
      registrations: [
        {
          capability: {
            id: 'capability',
            relationshipId: 'relationship',
            direction: 'inviter->invitee',
            scope: 'write',
            encryptedTokenSecret: 'opaque',
            createdAt: 10,
            expiresAt: 100,
          },
          lookupId: bytes(16, 4),
          epoch: 20_000,
        },
      ],
    }),
    true,
  );
  const statements = database.batchResults[0];
  assert.match(statements[0].query, /INSERT OR IGNORE INTO relationships/);
  assert.match(statements[1].query, /INSERT OR IGNORE INTO capabilities/);
  assert.match(statements[2].query, /INSERT OR IGNORE INTO capability_lookups/);
  assert.match(statements.at(-1).query, /UPDATE invitations SET phase/);
  for (const statement of statements) {
    assert.match(statement.query, /revision = \?|WHERE EXISTS/);
  }
});

test('D1 relationship recovery keeps opaque state and bounded nonce/rate rows', async () => {
  const database = new MockD1();
  const repository = new D1V2Repository(database);
  const encryptedState = bytes(48, 70);
  await repository.createRelationship({
    id: 'relationship',
    canonicalOrigin: 'https://dud.example',
    encryptedState,
    createdAt: 10,
  });
  assert.match(
    database.statements[0].query,
    /^INSERT OR IGNORE INTO relationships/,
  );
  assert.equal(database.statements[0].values[2], encryptedState);
  await repository.commitCapabilityReissue({
    relationshipId: 'relationship',
    nonce: bytes(32, 71),
    nonceExpiresAt: 100,
    now: 10,
    minute: 1,
    maximumRequestsPerMinute: 60,
    revocations: [],
    registrations: [],
  });
  const [prune, rate, claim] = database.batchResults[0];
  assert.match(prune.query, /DELETE FROM relationship_nonces WHERE expires_at/);
  assert.match(rate.query, /relationship_rate_windows/);
  assert.match(claim.query, /INSERT INTO relationship_nonces/);
});

test('D1 relationship reissue claims nonce and rate in one conditional batch', async () => {
  const database = new MockD1();
  database.batch = async (statements) => {
    database.batchResults.push(statements);
    return statements.map((_, index) => ({
      meta: { changes: index === 0 ? 0 : 1 },
    }));
  };
  const repository = new D1V2Repository(database);
  assert.equal(
    await repository.commitCapabilityReissue({
      relationshipId: 'relationship',
      nonce: bytes(32, 90),
      nonceExpiresAt: 100,
      now: 10,
      minute: 0,
      maximumRequestsPerMinute: 60,
      revocations: [
        {
          relationshipId: 'relationship',
          direction: 'inviter->invitee',
          scope: 'write',
        },
      ],
      registrations: [
        {
          capability: {
            id: 'rotated',
            relationshipId: 'relationship',
            direction: 'inviter->invitee',
            scope: 'write',
            encryptedTokenSecret: 'opaque',
            createdAt: 10,
            expiresAt: 100,
          },
          lookupId: bytes(16, 91),
          epoch: 20_000,
        },
      ],
    }),
    'accepted',
  );
  const statements = database.batchResults[0];
  assert.equal(statements.length, 6);
  // The window is charged only for an unclaimed nonce against a live,
  // unrevoked tuple, and every publication hangs off the nonce claim.
  assert.match(statements[1].query, /relationship_rate_windows/);
  assert.match(
    statements[1].query,
    /NOT EXISTS \(SELECT 1 FROM relationship_nonces/,
  );
  assert.match(statements[1].query, /state = 'active'/);
  assert.match(statements[1].query, /NOT EXISTS \(SELECT 1 FROM revocations/);
  assert.match(statements[2].query, /INSERT INTO relationship_nonces/);
  assert.match(statements[2].query, /changes\(\) = 1/);
  assert.match(statements[3].query, /INSERT INTO capabilities/);
  assert.match(statements[3].query, /changes\(\) = 1/);
  assert.match(statements[4].query, /INSERT INTO capability_lookups/);
  assert.match(statements[4].query, /changes\(\) = 1/);
  // Retirement runs last, guarded by the lookup only this request published.
  assert.match(statements[5].query, /UPDATE capabilities SET revoked_at/);
  assert.match(
    statements[5].query,
    /EXISTS \(SELECT 1 FROM capability_lookups/,
  );
});

test('D1 granular maintenance prunes nonce and rate windows in bounded statements', async () => {
  const database = new MockD1();
  const repository = new D1V2Repository(database);
  const result = await repository.runMaintenance(600, 8);
  assert.equal(result.deletedNonces, 1);
  assert.equal(result.deletedRateWindows, 0);
  assert.equal(result.deletedControlEvents, 0);
  const statements = database.batchResults[0];
  assert.match(statements.at(-5).query, /DELETE FROM nonces/);
  assert.match(statements.at(-4).query, /DELETE FROM rate_windows/);
  assert.deepEqual(statements.at(-4).values, [10, 8]);
  assert.match(statements.at(-1).query, /DELETE FROM pairing_rate_windows/);
});

test('D1 granular administration revokes and rotates capability tuples in D1', async () => {
  const database = new MockD1();
  const repository = new D1V2Repository(database);
  await repository.revokeRelationship({
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    scope: 'write',
    now: 10,
  });
  assert.equal(database.batchResults[0].length, 2);
  assert.match(
    database.batchResults[0][0].query,
    /^UPDATE capabilities SET revoked_at/,
  );
  assert.match(database.batchResults[0][1].query, /^INSERT INTO revocations/);
  assert.equal(
    await repository.rotateCapability({
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      now: 11,
    }),
    true,
  );
  const status = await repository.relationshipStatus('relationship');
  assert.deepEqual(status, { fullyRevoked: false, tuples: [] });
  assert.match(database.statements.at(-2).query, /FROM capabilities/);
  assert.match(database.statements.at(-1).query, /FROM revocations/);
});

test('D1 granular repository finalizes reservations and completion/control together in batches', async () => {
  const database = new MockD1();
  const repository = new D1V2Repository(database);
  const existing = delivery();
  database.firstRows.push(existing);
  const published = await repository.publishDelivery({
    id: existing.id,
    relationshipId: 'relationship',
    direction: 'inviter->invitee',
    slot: existing.slot,
    epoch: existing.epoch,
    encryptedDescriptor: existing.encrypted_descriptor,
    requestedPolicy: existing.requested_policy,
    effectivePolicy: existing.effective_policy,
    policyDigest: existing.policy_digest,
    payloadKey: existing.payload_key,
    payloadLength: existing.payload_length,
    payloadDigest: existing.payload_digest,
    operationId: existing.operation_id,
    operationDigest: existing.operation_digest,
    createdAt: existing.created_at,
    expiresAt: existing.expires_at,
  });
  assert.equal(published.idempotent, false);
  assert.equal(database.batchResults[0].length, 3);
  assert.match(
    database.batchResults[0][0].query,
    /INSERT INTO deliveries[\s\S]*SELECT[\s\S]*FROM reservations/,
  );
  assert.match(database.batchResults[0][1].query, /^UPDATE quota_accounts/);
  assert.match(database.batchResults[0][2].query, /^DELETE FROM reservations/);

  const completionOperationId = bytes(16, 30);
  const completionOperationDigest = bytes(32, 31);
  const completionDigest = bytes(32, 32);
  const completed = {
    ...existing,
    state: 'completed',
    completion_operation_id: completionOperationId,
    completion_operation_digest: completionOperationDigest,
    completion_digest: completionDigest,
    completion_result: 0,
  };
  const event = {
    id: 'c'.repeat(32),
    relationshipId: 'relationship',
    direction: 'invitee->inviter',
    slot: bytes(16, 40),
    epoch: 20_000,
    encryptedEnvelope: bytes(2, 41),
    operationId: bytes(16, 42),
    operationDigest: bytes(32, 43),
    sequence: 0,
    createdAt: 20,
    expiresAt: 100,
  };
  database.firstRows.push(completed, {
    id: event.id,
    relationship_id: event.relationshipId,
    direction: 1,
    slot: event.slot,
    epoch: event.epoch,
    encrypted_envelope: event.encryptedEnvelope,
    operation_id: event.operationId,
    operation_digest: event.operationDigest,
    sequence: 1,
    created_at: event.createdAt,
    expires_at: event.expiresAt,
    consumed_at: null,
  });
  const result = await repository.completeDeliveryWithControl({
    completion: {
      id: existing.id,
      operationId: completionOperationId,
      operationDigest: completionOperationDigest,
      completionDigest,
      result: 0,
      now: 20,
    },
    event,
  });
  assert.equal(result.event.sequence, 1);
  assert.equal(database.batchResults[1].length, 2);
  assert.match(database.batchResults[1][0].query, /NOT EXISTS/);
  assert.match(database.batchResults[1][1].query, /operation_digest <>/);
});
