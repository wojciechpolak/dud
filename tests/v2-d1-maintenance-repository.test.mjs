// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import { D1V2MaintenanceRepository } from '../dist/src/v2-d1-maintenance-repository.js';

test('D1 maintenance lease uses one conditional prepared statement', async () => {
  let statement;
  const database = {
    prepare(query) {
      statement = {
        query,
        values: [],
        bind(...values) {
          this.values = values;
          return this;
        },
        async run() {
          return { meta: { changes: 1 } };
        },
      };
      return statement;
    },
    async batch() {
      throw new Error('not used');
    },
  };
  const repository = new D1V2MaintenanceRepository(database);
  assert.equal(await repository.acquireLease('v2-maintenance', 600, 300), true);
  assert.match(statement.query, /ON CONFLICT\(name\) DO UPDATE/);
  assert.match(statement.query, /expires_at <= \?/);
  assert.deepEqual(statement.values, ['v2-maintenance', 600, 300]);
  await assert.rejects(repository.acquireLease('../bad', 600, 300), /name/);
});
