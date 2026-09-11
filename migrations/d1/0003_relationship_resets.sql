CREATE TABLE relationship_resets (
  old_relationship_id TEXT PRIMARY KEY,
  reset_id TEXT NOT NULL UNIQUE,
  new_relationship_id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK(state IN ('proposed','active','cancelled')),
  encrypted_state BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  activated_at INTEGER
);
