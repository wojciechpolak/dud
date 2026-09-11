// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

test('D1 chunk upload migration creates the complete schema', async () => {
  const database = new DatabaseSync(':memory:');
  database.exec(
    await readFile(
      new URL('../migrations/d1/0001_v2_schema.sql', import.meta.url),
      'utf8',
    ),
  );
  database
    .prepare(
      "INSERT INTO capabilities(id, relationship_id, direction, scope, encrypted_token_secret, created_at, expires_at) VALUES ('writer', 'relationship', 0, 'write', X'01', 1, 100)",
    )
    .run();
  database.exec(
    await readFile(
      new URL('../migrations/d1/0002_chunk_uploads.sql', import.meta.url),
      'utf8',
    ),
  );
  database.exec(
    await readFile(
      new URL('../migrations/d1/0003_relationship_resets.sql', import.meta.url),
      'utf8',
    ),
  );
  database
    .prepare(
      "INSERT INTO chunk_uploads(id, delivery_id, capability_id, total_length, created_at, expires_at, operation_id, operation_digest) VALUES ('upload', 'delivery', 'writer', 7, 2, 90, X'00000000000000000000000000000000', X'0000000000000000000000000000000000000000000000000000000000000000')",
    )
    .run();
  database
    .prepare(
      "INSERT INTO chunk_upload_parts(upload_id, part_id, ordinal, length, digest) VALUES ('upload', 'part', 0, 7, X'0000000000000000000000000000000000000000000000000000000000000000')",
    )
    .run();
  database
    .prepare(
      "INSERT INTO staged_bodies(id, body_key, expires_at, reserved_bytes) VALUES ('staged', 'staging/staged.bin', 90, 7)",
    )
    .run();
  assert.deepEqual(
    database
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'chunk_upload%' ORDER BY name",
      )
      .all()
      .map((row) => row.name),
    ['chunk_upload_parts', 'chunk_uploads'],
  );
  assert.equal(
    database
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'delivery_chunks'",
      )
      .get().name,
    'delivery_chunks',
  );
  assert.equal(
    database
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'relationship_resets'",
      )
      .get().name,
    'relationship_resets',
  );
  assert.equal(
    database.prepare("SELECT scope FROM capabilities WHERE id = 'writer'").get()
      .scope,
    'write',
  );
  const upload = database
    .prepare(
      'SELECT chain, length(slot) AS slot_length, epoch, committed_at FROM chunk_uploads WHERE id = ?',
    )
    .get('upload');
  assert.deepEqual(
    { ...upload },
    { chain: 0, slot_length: 16, epoch: 0, committed_at: null },
  );
  assert.equal(
    database
      .prepare(
        "SELECT name FROM pragma_table_info('deliveries') WHERE name = 'authorization_chain'",
      )
      .get().name,
    'authorization_chain',
  );
  assert.deepEqual(
    database
      .prepare('PRAGMA table_info(chunk_upload_parts)')
      .all()
      .filter((column) =>
        ['write_token', 'write_expires_at'].includes(column.name),
      )
      .map((column) => column.name),
    ['write_token', 'write_expires_at'],
  );
  assert.deepEqual(
    {
      ...database
        .prepare(
          "SELECT body_key, write_token, write_expires_at FROM chunk_upload_parts WHERE upload_id = 'upload' AND part_id = 'part'",
        )
        .get(),
    },
    { body_key: null, write_token: null, write_expires_at: null },
  );
  assert.equal(
    database
      .prepare(
        "SELECT name FROM pragma_table_info('staged_bodies') WHERE name = 'capability_id'",
      )
      .get().name,
    'capability_id',
  );
  assert.equal(
    database
      .prepare("SELECT capability_id FROM staged_bodies WHERE id = 'staged'")
      .get().capability_id,
    null,
  );
  database.close();
});
