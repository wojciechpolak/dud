// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import { D1V2AuthorizationRepository } from '../dist/src/v2-d1-auth-repository.js';

class MockD1 {
  batches = [];
  firstRow = null;
  nextChanges = 1;

  prepare(query) {
    const statement = {
      query,
      values: [],
      bind: (...values) => {
        statement.values = values;
        return statement;
      },
      run: async () => ({ meta: { changes: this.nextChanges } }),
      first: async () => this.firstRow,
      all: async () => ({ results: [] }),
    };
    return statement;
  }

  async batch(statements) {
    this.batches.push(statements);
    return Promise.all(statements.map((statement) => statement.run()));
  }
}

const capability = {
  id: 'capability',
  relationshipId: 'relationship',
  direction: 'inviter->invitee',
  scope: 'write',
  encryptedTokenSecret: 'opaque',
  createdAt: 1,
  expiresAt: 100,
};

test('D1 authorization repository uses batched prepared statements for lookup registration and nonce claims', async () => {
  const database = new MockD1();
  const repository = new D1V2AuthorizationRepository(database);
  const lookup = Uint8Array.from({ length: 16 }, (_, index) => index);
  await repository.registerCapability(capability, lookup, 20_000);
  assert.equal(database.batches[0].length, 2);
  assert.match(
    database.batches[0][0].query,
    /^INSERT OR IGNORE INTO capabilities/,
  );
  assert.deepEqual(database.batches[0][1].values, [
    lookup,
    20_000,
    'capability',
  ]);

  database.firstRow = {
    id: 'capability',
    relationship_id: 'relationship',
    direction: 0,
    scope: 'write',
    encrypted_token_secret: 'opaque',
    created_at: 1,
    expires_at: 100,
    revoked_at: null,
  };
  assert.deepEqual(
    await repository.findCapabilityLookup(lookup, 20_000),
    capability,
  );

  assert.equal(await repository.claimNonce('capability', lookup, 90, 10), true);
  assert.equal(database.batches[1].length, 2);
  assert.match(database.batches[1][1].query, /^INSERT OR IGNORE INTO nonces/);
  database.nextChanges = 0;
  assert.equal(
    await repository.claimNonce('capability', lookup, 90, 10),
    false,
  );
});

test('D1 authorization repository atomically rotates lookup registrations', async () => {
  const database = new MockD1();
  const repository = new D1V2AuthorizationRepository(database);
  await repository.replaceCapabilities({
    revocations: [capability],
    registrations: [
      {
        capability: { ...capability, id: 'replacement' },
        lookupId: Uint8Array.from({ length: 16 }, () => 7),
        epoch: 20_001,
      },
    ],
    now: 10,
  });
  assert.equal(database.batches[0].length, 3);
  assert.match(
    database.batches[0][0].query,
    /^UPDATE capabilities SET revoked_at/,
  );
  assert.match(database.batches[0][1].query, /^INSERT INTO capabilities/);
});
