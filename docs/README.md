# DUD Documentation

DUD has two transfer modes, and neither replaces the other. A **dead drop** is
addressed by an opaque ID shared out of band. A **peer** transfer is addressed
by the local alias of a device you have paired with. The [README](../README.md)
introduces both and covers deployment; everything below goes deeper.

## Using DUD

- [`peer-setup.md`](peer-setup.md) — pairing two devices, sending, receiving,
  and reading the status block
- [`dead-drops-v1.md`](dead-drops-v1.md) — upload, download, keys, Git sync by
  ID, and the `/v1` HTTP API
- [`client.md`](client.md) — client environment, configuration layers, profiles,
  wrappers, JSON output, and the interactive menu
- [`git-sync-v2.md`](git-sync-v2.md) — Git checkpoints between paired devices

## Running a server

- [`server-v2.md`](server-v2.md) — what the server stores, credentials, feature
  flags, limits, administration, logging, and health checks
- [`migration-v1-v2.md`](migration-v1-v2.md) — moving a deployment from v1-only
  to dual-stack to v2-only, and back
- [`recovery-v2.md`](recovery-v2.md) — rollback, revocation, key rotation,
  corrupted state, and local erasure
- [`supported-versions.md`](supported-versions.md) — build toolchain, pinned
  sources, and the update policy

## Design

- [`protocol-v2.md`](protocol-v2.md) — the v2 wire format, identity derivation,
  pairing, descriptors, authorization, transport, endpoints, and test vectors
- [`threat-model-v2.md`](threat-model-v2.md) — adversaries, guarantees, known
  metadata leakage, and what is out of scope
- [`../SECURITY.md`](../SECURITY.md) — reporting, supported versions, and the
  patch policy

## Contributing

- [`development.md`](development.md) — repository layout, commands, coverage,
  local HTTPS, integration testing, and the documentation rules
