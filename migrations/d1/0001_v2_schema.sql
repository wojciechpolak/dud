-- D1 V2 granular metadata schema, as one idempotent bootstrap. Payload bytes
-- live exclusively in the FILES R2 binding; every column here is either opaque
-- ciphertext or bounded accounting.
--
-- Wrangler records this file in `d1_migrations` and never reruns it, and every
-- statement below is `IF NOT EXISTS`, so editing it changes nothing on a
-- database that already has it. A schema change means recreating each database
-- — see "Recreating the database" in docs/server-v2.md.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS relationships (
  id TEXT PRIMARY KEY, canonical_origin TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','active','revoked')),
  encrypted_state BLOB NOT NULL, created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL, revoked_at INTEGER
);

-- Pairing rendezvous state is a single, bounded record per opaque locator.
-- `encrypted_grant` doubles as that opaque record blob: the Worker never lists
-- it, and the compare-and-swap `revision` prevents a lost pairing transition.
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
CREATE INDEX IF NOT EXISTS active_relationship_revocation
  ON revocations(relationship_id, direction, scope, expires_at);

CREATE TABLE IF NOT EXISTS capabilities (
  id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL,
  direction INTEGER NOT NULL CHECK(direction IN (0,1)),
  scope TEXT NOT NULL CHECK(scope IN ('write','read','ack')),
  encrypted_token_secret BLOB NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, revoked_at INTEGER,
  committed_bytes INTEGER NOT NULL DEFAULT 0 CHECK(committed_bytes >= 0),
  object_count INTEGER NOT NULL DEFAULT 0 CHECK(object_count >= 0)
);
CREATE TABLE IF NOT EXISTS capability_lookups (
  lookup_id BLOB NOT NULL, epoch INTEGER NOT NULL,
  capability_id TEXT NOT NULL REFERENCES capabilities(id),
  PRIMARY KEY (lookup_id, epoch)
);
CREATE INDEX IF NOT EXISTS active_capability_lookup ON capability_lookups(lookup_id, epoch);

CREATE TABLE IF NOT EXISTS deliveries (
  id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL,
  direction INTEGER NOT NULL CHECK(direction IN (0,1)), slot BLOB NOT NULL,
  epoch INTEGER NOT NULL, encrypted_descriptor BLOB NOT NULL,
  requested_policy BLOB NOT NULL, effective_policy BLOB NOT NULL,
  policy_digest BLOB NOT NULL, payload_key TEXT NOT NULL UNIQUE,
  payload_length INTEGER NOT NULL CHECK(payload_length >= 0), payload_digest BLOB NOT NULL,
  operation_id BLOB NOT NULL UNIQUE, operation_digest BLOB NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('reserved','published','completed')),
  sequence INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, completed_at INTEGER,
  completion_digest BLOB, completion_result INTEGER CHECK(completion_result IN (0,1)),
  completion_operation_id BLOB UNIQUE, completion_operation_digest BLOB
);
-- `sequence` is a server-assigned insertion counter per relationship and
-- direction, exactly like the one on `control_events`. The inbox must hand
-- deliveries back in publication order: `created_at` is whole seconds and `id`
-- is random, so two sends inside one second would otherwise be returned in
-- either order, which a receiver reads as a chain gap.
CREATE INDEX IF NOT EXISTS pending_delivery_inbox ON deliveries(relationship_id, direction, slot, epoch, state, expires_at, sequence, id);

CREATE TABLE IF NOT EXISTS control_events (
  id TEXT PRIMARY KEY, relationship_id TEXT NOT NULL,
  direction INTEGER NOT NULL CHECK(direction IN (0,1)), slot BLOB NOT NULL,
  epoch INTEGER NOT NULL, encrypted_envelope BLOB NOT NULL,
  operation_id BLOB NOT NULL UNIQUE, operation_digest BLOB NOT NULL,
  sequence INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS pending_control_inbox ON control_events(relationship_id, direction, consumed_at, expires_at, sequence);

CREATE TABLE IF NOT EXISTS nonces (
  capability_id TEXT NOT NULL REFERENCES capabilities(id), nonce BLOB NOT NULL,
  expires_at INTEGER NOT NULL, PRIMARY KEY(capability_id, nonce)
);
CREATE INDEX IF NOT EXISTS expired_nonce ON nonces(expires_at);

CREATE TABLE IF NOT EXISTS rate_windows (
  capability_id TEXT NOT NULL REFERENCES capabilities(id), minute INTEGER NOT NULL,
  count INTEGER NOT NULL CHECK(count >= 0), PRIMARY KEY(capability_id, minute)
);

CREATE TABLE IF NOT EXISTS reservations (
  delivery_id TEXT PRIMARY KEY, capability_id TEXT NOT NULL REFERENCES capabilities(id),
  payload_key TEXT NOT NULL UNIQUE, reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes >= 0),
  operation_id BLOB UNIQUE, operation_digest BLOB, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS expired_reservation ON reservations(expires_at);

CREATE TABLE IF NOT EXISTS quota_accounts (
  relationship_id TEXT PRIMARY KEY,
  committed_bytes INTEGER NOT NULL DEFAULT 0 CHECK(committed_bytes >= 0),
  reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0),
  object_count INTEGER NOT NULL DEFAULT 0 CHECK(object_count >= 0),
  updated_at INTEGER NOT NULL
);

-- Per-relationship recovery accounting is intentionally separate from
-- capability nonces/rate rows: reissue occurs before a capability exists.
CREATE TABLE IF NOT EXISTS relationship_nonces (
  relationship_id TEXT NOT NULL REFERENCES relationships(id),
  nonce BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (relationship_id, nonce)
);
CREATE INDEX IF NOT EXISTS expired_relationship_nonce
  ON relationship_nonces(expires_at);

CREATE TABLE IF NOT EXISTS relationship_rate_windows (
  relationship_id TEXT NOT NULL REFERENCES relationships(id),
  minute INTEGER NOT NULL,
  count INTEGER NOT NULL CHECK(count >= 0),
  PRIMARY KEY (relationship_id, minute)
);

CREATE TABLE IF NOT EXISTS pairing_rate_windows (
  key TEXT NOT NULL,
  minute INTEGER NOT NULL,
  count INTEGER NOT NULL CHECK(count >= 0),
  PRIMARY KEY (key, minute)
);

-- `reserved_bytes` reserves staging capacity before ciphertext is written, so
-- invalid framed deliveries cannot accumulate unbounded R2 or filesystem
-- staging bodies.
CREATE TABLE IF NOT EXISTS staged_bodies (
  id TEXT PRIMARY KEY,
  body_key TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0)
);
CREATE INDEX IF NOT EXISTS expired_staged_body ON staged_bodies(expires_at);

CREATE TABLE IF NOT EXISTS maintenance_leases (name TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
