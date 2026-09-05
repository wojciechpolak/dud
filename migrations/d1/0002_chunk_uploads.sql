-- SPDX-License-Identifier: MIT
-- Copyright (C) 2026 Wojciech Polak

-- Upload sessions own the complete immutable manifest, write-proof context,
-- and lease. Parts become visible to an inbox only after the session is
-- converted into a delivery.
CREATE TABLE IF NOT EXISTS chunk_uploads (
  id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL UNIQUE,
  capability_id TEXT NOT NULL REFERENCES capabilities(id),
  chain INTEGER NOT NULL DEFAULT 0 CHECK(chain >= 0),
  slot BLOB NOT NULL DEFAULT X'00000000000000000000000000000000',
  epoch INTEGER NOT NULL DEFAULT 0 CHECK(epoch >= 0),
  total_length INTEGER NOT NULL CHECK(total_length > 0),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  operation_id BLOB NOT NULL UNIQUE,
  operation_digest BLOB NOT NULL,
  renewal_operation_id BLOB UNIQUE,
  renewal_operation_digest BLOB,
  committed_at INTEGER
);
CREATE INDEX IF NOT EXISTS active_chunk_upload
  ON chunk_uploads(capability_id, expires_at);
CREATE INDEX IF NOT EXISTS expired_chunk_upload
  ON chunk_uploads(expires_at, id);

-- A part write claims authorization before ciphertext reaches body storage.
-- The bounded token keeps cross-store compensation from deleting a body owned
-- by a concurrent request.
CREATE TABLE IF NOT EXISTS chunk_upload_parts (
  upload_id TEXT NOT NULL REFERENCES chunk_uploads(id) ON DELETE CASCADE,
  part_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  length INTEGER NOT NULL CHECK(length > 0),
  digest BLOB NOT NULL,
  body_key TEXT UNIQUE,
  received_at INTEGER,
  operation_id BLOB UNIQUE,
  operation_digest BLOB,
  write_token TEXT,
  write_expires_at INTEGER,
  PRIMARY KEY(upload_id, part_id),
  UNIQUE(upload_id, ordinal)
);
CREATE UNIQUE INDEX IF NOT EXISTS chunk_upload_part_write_token
  ON chunk_upload_parts(write_token);

-- A committed upload keeps its proof context for idempotent commit retries.
-- Its staged keys move to delivery_chunks, so it holds no staging reservation.
ALTER TABLE deliveries ADD COLUMN authorization_chain INTEGER CHECK(authorization_chain >= 0);
CREATE TABLE IF NOT EXISTS delivery_chunks (
  delivery_id TEXT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  part_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
  length INTEGER NOT NULL CHECK(length > 0),
  digest BLOB NOT NULL,
  body_key TEXT NOT NULL UNIQUE,
  PRIMARY KEY(delivery_id, part_id),
  UNIQUE(delivery_id, ordinal)
);

-- Limit 8 accounts staged ciphertext independently for each capability.
ALTER TABLE staged_bodies ADD COLUMN capability_id TEXT;
CREATE INDEX IF NOT EXISTS staged_body_capability_usage
  ON staged_bodies(capability_id, expires_at);
