-- Drops the V2 metadata schema so `wrangler d1 migrations apply` runs
-- migrations/d1 from scratch, which is how an edit to that bootstrap reaches a
-- deployment. It destroys every relationship, so each paired device pairs
-- again; delivery bodies in R2 are left alone.
--
-- Deliberately outside migrations/d1: Wrangler applies every .sql file in that
-- directory, and so does the test harness. Dropping `d1_migrations` is what
-- makes the bootstrap eligible to run again, and order matters because foreign
-- keys are enforced.

DROP TABLE IF EXISTS capability_lookups;
DROP TABLE IF EXISTS nonces;
DROP TABLE IF EXISTS rate_windows;
DROP TABLE IF EXISTS reservations;
DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS relationship_nonces;
DROP TABLE IF EXISTS relationship_rate_windows;
DROP TABLE IF EXISTS capabilities;
DROP TABLE IF EXISTS relationships;
DROP TABLE IF EXISTS deliveries;
DROP TABLE IF EXISTS control_events;
DROP TABLE IF EXISTS revocations;
DROP TABLE IF EXISTS quota_accounts;
DROP TABLE IF EXISTS pairing_rate_windows;
DROP TABLE IF EXISTS staged_bodies;
DROP TABLE IF EXISTS maintenance_leases;
DROP TABLE IF EXISTS d1_migrations;
