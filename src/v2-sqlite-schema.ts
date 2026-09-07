// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

/**
 * Ordered, idempotent migrations for the self-hosted Node metadata database.
 *
 * Version 0 is the bookkeeping table and version 1 is the complete bootstrap.
 * Every schema extension occupies a higher index. Applied entries are immutable
 * because the applier runs only versions above the highest recorded index.
 */
export const V2_SQLITE_MIGRATIONS = [
  `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);`,
  `CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY, canonical_origin TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','active','revoked')),
    encrypted_state BLOB NOT NULL, created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL, revoked_at INTEGER
  );
  -- Pairing rendezvous state is a single, bounded record per opaque locator,
  -- and \`revision\` makes the pairing transition a compare-and-swap.
  CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY, relationship_id TEXT REFERENCES relationships(id),
    phase TEXT NOT NULL, encrypted_grant BLOB NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS active_invitation_expiry ON invitations(expires_at);
  CREATE INDEX IF NOT EXISTS pending_invitation_expiry ON invitations(expires_at, id);
  CREATE TABLE IF NOT EXISTS revocations (
    id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL,
    direction INTEGER CHECK(direction IN (0,1)),
    scope TEXT CHECK(scope IN ('write','read','ack')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    encrypted_envelope BLOB NOT NULL
  );
  CREATE INDEX IF NOT EXISTS active_relationship_revocation ON revocations(relationship_id, direction, scope, expires_at);
  CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL, direction INTEGER NOT NULL CHECK(direction IN (0,1)),
    scope TEXT NOT NULL CHECK(scope IN ('write','read','ack')), encrypted_token_secret TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER,
    committed_bytes INTEGER NOT NULL DEFAULT 0 CHECK(committed_bytes >= 0),
    object_count INTEGER NOT NULL DEFAULT 0 CHECK(object_count >= 0)
  );
  CREATE TABLE IF NOT EXISTS capability_lookups (
    lookup_id BLOB NOT NULL, epoch INTEGER NOT NULL, capability_id TEXT NOT NULL REFERENCES capabilities(id),
    PRIMARY KEY (lookup_id, epoch)
  );
  CREATE INDEX IF NOT EXISTS active_capability_lookup ON capability_lookups(lookup_id, epoch);
  -- \`sequence\` is a server-assigned insertion counter per relationship and
  -- direction, the same one \`control_events\` carries. The inbox hands back the
  -- oldest pending delivery, and \`created_at\` is whole seconds while \`id\` is
  -- random, so two sends inside one second could otherwise be returned in
  -- either order. A receiver reads that as a chain gap and quarantines it.
  CREATE TABLE IF NOT EXISTS deliveries (
    id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL, direction INTEGER NOT NULL CHECK(direction IN (0,1)),
    slot BLOB NOT NULL, epoch INTEGER NOT NULL, encrypted_descriptor BLOB NOT NULL, requested_policy BLOB NOT NULL,
    effective_policy BLOB NOT NULL, policy_digest BLOB NOT NULL, payload_key TEXT NOT NULL UNIQUE,
    payload_length INTEGER NOT NULL CHECK(payload_length >= 0), payload_digest BLOB NOT NULL,
    operation_id BLOB NOT NULL UNIQUE, operation_digest BLOB NOT NULL, state TEXT NOT NULL CHECK(state IN ('reserved','published','completed')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, completed_at INTEGER, completion_digest BLOB,
    completion_result INTEGER CHECK(completion_result IN (0,1)),
    completion_operation_id BLOB, completion_operation_digest BLOB,
    sequence INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS pending_delivery_inbox ON deliveries(relationship_id, direction, slot, epoch, state, expires_at, sequence, id);
  CREATE UNIQUE INDEX IF NOT EXISTS delivery_completion_operation_id ON deliveries(completion_operation_id);
  CREATE TABLE IF NOT EXISTS control_events (
    id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL, direction INTEGER NOT NULL CHECK(direction IN (0,1)),
    slot BLOB NOT NULL, epoch INTEGER NOT NULL, encrypted_envelope BLOB NOT NULL, operation_id BLOB NOT NULL UNIQUE,
    operation_digest BLOB NOT NULL, sequence INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS pending_control_inbox ON control_events(relationship_id, direction, consumed_at, expires_at, sequence);
  CREATE TABLE IF NOT EXISTS nonces (capability_id TEXT NOT NULL, nonce BLOB NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(capability_id, nonce));
  CREATE INDEX IF NOT EXISTS expired_nonces ON nonces(expires_at);
  CREATE TABLE IF NOT EXISTS rate_windows (capability_id TEXT NOT NULL REFERENCES capabilities(id), minute INTEGER NOT NULL, count INTEGER NOT NULL CHECK(count >= 0), PRIMARY KEY(capability_id, minute));
  CREATE TABLE IF NOT EXISTS reservations (
    delivery_id TEXT PRIMARY KEY, capability_id TEXT NOT NULL REFERENCES capabilities(id), payload_key TEXT NOT NULL UNIQUE,
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes >= 0), expires_at INTEGER NOT NULL,
    operation_id BLOB, operation_digest BLOB
  );
  CREATE INDEX IF NOT EXISTS expired_reservations ON reservations(expires_at);
  CREATE UNIQUE INDEX IF NOT EXISTS reservation_operation_id ON reservations(operation_id);
  -- This backend enforces the object cap by counting the durable rows at
  -- reservation time rather than by reading \`object_count\`, which is kept so
  -- \`quota_accounts\` stays comparable with the D1 backend's maintained counter.
  CREATE TABLE IF NOT EXISTS quota_accounts (
    relationship_id TEXT PRIMARY KEY, committed_bytes INTEGER NOT NULL DEFAULT 0 CHECK(committed_bytes >= 0),
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0),
    object_count INTEGER NOT NULL DEFAULT 0 CHECK(object_count >= 0),
    updated_at INTEGER NOT NULL
  );
  -- Per-relationship recovery accounting is intentionally separate from
  -- capability nonces and rate rows: reissue occurs before a capability exists.
  CREATE TABLE IF NOT EXISTS relationship_nonces (
    relationship_id TEXT NOT NULL REFERENCES relationships(id), nonce BLOB NOT NULL,
    expires_at INTEGER NOT NULL, PRIMARY KEY (relationship_id, nonce)
  );
  CREATE INDEX IF NOT EXISTS expired_relationship_nonce ON relationship_nonces(expires_at);
  CREATE TABLE IF NOT EXISTS relationship_rate_windows (
    relationship_id TEXT NOT NULL REFERENCES relationships(id), minute INTEGER NOT NULL,
    count INTEGER NOT NULL CHECK(count >= 0), PRIMARY KEY (relationship_id, minute)
  );
  CREATE TABLE IF NOT EXISTS pairing_rate_windows (
    key TEXT NOT NULL, minute INTEGER NOT NULL, count INTEGER NOT NULL CHECK(count >= 0),
    PRIMARY KEY (key, minute)
  );
  -- \`reserved_bytes\` reserves staging capacity before ciphertext is written, so
  -- invalid framed deliveries cannot accumulate unbounded staging bodies.
  CREATE TABLE IF NOT EXISTS staged_bodies (
    id TEXT PRIMARY KEY, body_key TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0)
  );
  CREATE INDEX IF NOT EXISTS expired_staged_body ON staged_bodies(expires_at);
  CREATE TABLE IF NOT EXISTS maintenance_leases (name TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);`,
  `CREATE TABLE chunk_uploads (
    id TEXT PRIMARY KEY, delivery_id TEXT NOT NULL UNIQUE,
    capability_id TEXT NOT NULL REFERENCES capabilities(id),
    total_length INTEGER NOT NULL CHECK(total_length > 0),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    operation_id BLOB NOT NULL UNIQUE, operation_digest BLOB NOT NULL,
    renewal_operation_id BLOB UNIQUE, renewal_operation_digest BLOB
  );
  CREATE INDEX active_chunk_upload ON chunk_uploads(capability_id, expires_at);
  CREATE INDEX expired_chunk_upload ON chunk_uploads(expires_at, id);
  CREATE TABLE chunk_upload_parts (
    upload_id TEXT NOT NULL REFERENCES chunk_uploads(id) ON DELETE CASCADE,
    part_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    length INTEGER NOT NULL CHECK(length > 0), digest BLOB NOT NULL,
    body_key TEXT UNIQUE, received_at INTEGER,
    operation_id BLOB UNIQUE, operation_digest BLOB,
    PRIMARY KEY(upload_id, part_id), UNIQUE(upload_id, ordinal)
  );`,
  `ALTER TABLE chunk_uploads ADD COLUMN chain INTEGER NOT NULL DEFAULT 0 CHECK(chain >= 0);
  ALTER TABLE chunk_uploads ADD COLUMN slot BLOB NOT NULL DEFAULT X'00000000000000000000000000000000';
  ALTER TABLE chunk_uploads ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0 CHECK(epoch >= 0);`,
  `ALTER TABLE chunk_uploads ADD COLUMN committed_at INTEGER;
  ALTER TABLE deliveries ADD COLUMN authorization_chain INTEGER CHECK(authorization_chain >= 0);
  CREATE UNIQUE INDEX chunk_upload_delivery_id ON chunk_uploads(delivery_id);
  CREATE TABLE delivery_chunks (
    delivery_id TEXT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
    part_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    length INTEGER NOT NULL CHECK(length > 0), digest BLOB NOT NULL,
    body_key TEXT NOT NULL UNIQUE,
    PRIMARY KEY(delivery_id, part_id), UNIQUE(delivery_id, ordinal)
  );`,
  `ALTER TABLE chunk_upload_parts ADD COLUMN write_token TEXT;
  ALTER TABLE chunk_upload_parts ADD COLUMN write_expires_at INTEGER;
  CREATE UNIQUE INDEX chunk_upload_part_write_token ON chunk_upload_parts(write_token);`,
  `ALTER TABLE staged_bodies ADD COLUMN capability_id TEXT;
  CREATE INDEX staged_body_capability_usage ON staged_bodies(capability_id, expires_at);`,
] as const;

export interface V2SQLiteDatabase {
  exec(sql: string): void;
  prepare(sql: string): {
    get(...parameters: unknown[]): unknown;
    run(...parameters: unknown[]): unknown;
  };
}

/** Applies each migration exactly once inside the caller's transaction. */
export function applyV2SQLiteMigrations(
  database: V2SQLiteDatabase,
  now: number,
): void {
  database.exec(V2_SQLITE_MIGRATIONS[0]);
  const seen = database.prepare(
    'SELECT version FROM schema_migrations WHERE version = ?',
  );
  const recorded = database.prepare(
    'INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)',
  );
  for (let index = 1; index < V2_SQLITE_MIGRATIONS.length; index++) {
    if (seen.get(index)) {
      continue;
    }
    database.exec(V2_SQLITE_MIGRATIONS[index]);
    recorded.run(index, now);
  }
}
