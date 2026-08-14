// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import {
  applyV2SQLiteMigrations,
  V2_SQLITE_MIGRATIONS,
} from '../dist/src/v2-sqlite-schema.js';

test('v2 SQLite migrations create the normalized schema', () => {
  const database = new DatabaseSync(':memory:');
  applyV2SQLiteMigrations(database, 1_800_000_000);
  applyV2SQLiteMigrations(database, 1_800_000_001);
  const tables = database
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    )
    .all()
    .map((row) => row.name);
  assert.deepEqual(tables, [
    'capabilities',
    'capability_lookups',
    'control_events',
    'deliveries',
    'invitations',
    'maintenance_leases',
    'nonces',
    'pairing_rate_windows',
    'quota_accounts',
    'rate_windows',
    'relationship_nonces',
    'relationship_rate_windows',
    'relationships',
    'reservations',
    'revocations',
    'schema_migrations',
    'staged_bodies',
  ]);
  database.close();
});

test('v2 SQLite migrations record every version exactly once in order', () => {
  const database = new DatabaseSync(':memory:');
  applyV2SQLiteMigrations(database, 1_800_000_000);
  const expected = Array.from(
    { length: V2_SQLITE_MIGRATIONS.length - 1 },
    (_, index) => index + 1,
  );
  const applied = () =>
    database
      .prepare('SELECT version FROM schema_migrations ORDER BY rowid')
      .all()
      .map((row) => Number(row.version));
  assert.deepEqual(applied(), expected);

  applyV2SQLiteMigrations(database, 1_800_000_500);
  assert.deepEqual(applied(), expected);
  assert.deepEqual(
    database
      .prepare('SELECT applied_at FROM schema_migrations ORDER BY version')
      .all()
      .map((row) => Number(row.applied_at)),
    expected.map(() => 1_800_000_000),
  );
  database.close();
});

// With a single bootstrap migration this asserts that an already-recorded
// version is neither re-executed nor re-stamped. `applied` tracks the migration
// count, so appending one exercises a real resume.
test('a partially migrated v2 SQLite database resumes at its next version', () => {
  const database = new DatabaseSync(':memory:');
  database.exec(V2_SQLITE_MIGRATIONS[0]);
  const applied = Math.min(4, V2_SQLITE_MIGRATIONS.length);
  for (let index = 1; index < applied; index++) {
    database.exec(V2_SQLITE_MIGRATIONS[index]);
    database
      .prepare(
        'INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)',
      )
      .run(index, 1_700_000_000);
  }
  applyV2SQLiteMigrations(database, 1_800_000_000);
  assert.deepEqual(
    database
      .prepare(
        'SELECT version, applied_at FROM schema_migrations ORDER BY version',
      )
      .all()
      .map((row) => [Number(row.version), Number(row.applied_at)]),
    Array.from({ length: V2_SQLITE_MIGRATIONS.length - 1 }, (_, index) => [
      index + 1,
      index + 1 < applied ? 1_700_000_000 : 1_800_000_000,
    ]),
  );
  assert.ok(
    database
      .prepare("SELECT name FROM sqlite_master WHERE name = 'staged_bodies'")
      .get(),
  );
  database.close();
});
