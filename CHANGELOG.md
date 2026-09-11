# Changelog

All notable changes to DUD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for public releases.

## [Unreleased]

### Added

- Add `dud peer reset PEER` for an authenticated peer relationship reset. Both
  devices sign the same transcript before the server atomically activates a
  fresh relationship ID and cryptographic generation. Reset preserves the peer
  alias, device trust, canonical origin, repository identity, and managed Git
  refs. The next Git push sends a complete checkpoint.
- Advertise peer relationship reset support during pairing and reject reset
  proposals before changing local state when either endpoint lacks it. Peer
  status, doctor, and JSON output report the proposal ID, both consents, server
  activation, exact abandoned-delivery counts, and the recovery command for an
  interrupted reset.
- Add durable peer relationship reset records to the memory, SQLite, and D1
  backends. D1 deployments must apply migration `0003_relationship_resets.sql`
  before serving reset requests.

### Fixed

- Fix rollback detection across the independent peer data and control chains.
  Signed outgoing high-water marks advertise queued work and do not halt a peer
  that has not read it. Contradictions against retained signed acknowledgements
  still halt the relationship and record both values, the field name, control
  descriptor, and relationship ID.
- Allow `dud peer revoke PEER --yes` to revoke a halted relationship without
  advancing either delivery chain. The client preserves the halt evidence and
  records the local profile as revoked after the server confirms revocation.

## [2.2.0] - 2026-09-08

### Added

- Add `DUD_DROP_BASE_URL` and `DUD_PEER_BASE_URL` so each transfer mode can
  select its bootstrap origin independently. `DUD_BASE_URL` remains the shared
  fallback, and a paired peer still uses the origin pinned in its profile.
- Add resumable chunked peer transfers, negotiated through server capabilities
  and signed peer acknowledgements. Regular files larger than 16 MiB stream into
  a private encrypted spool, and `dud sync PEER` resumes queued uploads after a
  connection failure or process restart.
- Resume downloads from verified encrypted chunks when repeating
  `dud receive PEER`. The receiver verifies the complete plaintext and installs
  the output atomically before advancing its receive watermark.
- Show live progress on stderr for peer `send`, `receive`, `sync`, and Git
  push/fetch. This covers single payloads, work within resumable chunks,
  verified reusable chunks, and queued retries. Terminals enable progress by
  default; `--progress` forces newline-delimited output and `--no-progress`
  disables it. Updates report the phase, encoded bytes, fixed-width percentage,
  rate, ETA, and elapsed time without changing JSON or stdout results. Dead drop
  commands keep their existing output.
- Report resumable transfers with descriptor digests and bytes remaining in
  `dud peer show`, `dud doctor`, and JSON output. Add
  `dud peer abandon PEER --id DIGEST --yes` to discard a saved transfer.
- Add durable upload leases, chunk storage, retry-safe commits, and cleanup
  across the memory, SQLite/filesystem, and D1/R2 backends. Uploads reserve
  their full ciphertext size and stay out of the inbox until commit.

### Changed

- Support up to 1 GiB of plaintext per chunked peer delivery, bounded by the
  server's staged-byte quota, which defaults to 200 MiB per capability.
- Add numbered D1 migration `0002_chunk_uploads.sql` for resumable upload
  storage. Apply pending migrations before deploying the Worker; existing
  relationships are preserved. The self-hosted server applies its SQLite schema
  migration on startup.

## [2.1.0] - 2026-08-28

### Added

- Add incremental peer Git synchronization with explicit selection, automatic
  complete-checkpoint recovery, bounded pack validation, and a complete
  checkpoint after every 16 persisted incrementals.
- Install the client with Homebrew on macOS and Linux:
  `brew install wojciechpolak/dud/dud`. The formula builds from the release tag
  with the flags release binaries use, and installs `age`, `git`, and `qrencode`
  alongside it. The name must be qualified: Homebrew's own index carries an
  unrelated formula named `dud`, so a bare `brew install dud` resolves to that
  one, and the two cannot be installed at the same time.
- Publish the tap formula from each stable release.
  `scripts/render-homebrew-formula.mjs` renders it from the release tag and the
  checksum of that tag's archive, and `.github/workflows/homebrew.yml` commits
  the result to `wojciechpolak/homebrew-dud`. Pre-release tags never reach the
  tap, and the workflow can be dispatched by hand to backfill a stable tag.

## [2.0.2] - 2026-08-15

## Fixed

- Collect assets before publishing

## [2.0.1] - 2026-08-15

### Added

- Add peer transfers: pair devices, address them by local alias, and securely
  send, receive, and sync files while keeping dead drops available.
- Add peer Git synchronization with complete checkpoints, safe validation,
  status reporting, and recovery controls.
- Add deployment and recovery guidance, compatibility checks, diagnostics, and
  reproducible release artifacts.

### Changed

- **Breaking:** rename `DUD_SECRET_TOKEN` to `DUD_DROP_SECRET`, and name every
  environment variable after the mode it configures — `DUD_DROP_*` for dead
  drops, `DUD_PEER_*` for peers. Rename it wherever it is configured: a
  deployment left on the old name answers `503` on upload and flush.
- **Breaking:** drop the `curl` subprocess. The client carries its own transport
  in Go — DoH, exactly TLS 1.3, and ECH — so the image ships no `curl`,
  `DUD_CURL_BIN` and `DUD_CONNECT_TO` are inert, and `DUD_ECH_MODE` takes `hard`
  or `off` in place of `hard` or `grease`.
- Unify peer and dead drop transfers on the built-in hardened transport, with
  consistent protections and output, including JSON results across commands.
- Restructure the documentation: the README now covers deployment and a first
  transfer, while the dead drop commands and `/v1` API, the client reference,
  and the development workflows moved into `docs/`, indexed by
  [`docs/README.md`](docs/README.md).

### Security

- Protect peer transfers with mutually confirmed pairing, authenticated
  delivery, revocation, and replay defenses; quarantine incoming Git data before
  updating repository references.

## [1.4.0] - 2026-06-10

### Added

- Add git bundle sync commands
- Add shell-init completion support
- Allow runtime DUD_IMAGE overrides in shell-init

### Changed

- Rewrite client entrypoint in Go

## [1.3.1] - 2026-06-09

### Fixed

- Upload QR payload regression

## [1.3.0] - 2026-05-26

### Added

- Add self-hosted dud server
- Add bundled send and extract receive flows
- Add --version to dud client
- Add public-key encryption mode and key aliases

### Fixed

- Include age in docker pin updater

### Chore

- Bump curl to 8.20.0
- Update dependencies

## [1.2.0] - 2026-05-12

### Added

- Add streaming client I/O and shell init wrapper

## [1.1.0] - 2026-05-03

### Added

- Dashed file IDs in upload responses for better readability, while keeping
  downloads compatible with either dashed IDs or the original raw 32-character
  lowercase hex form.
- Human-friendly upload success output in the client, with `--json` available
  for raw machine-readable responses.
- Terminal QR code output for uploaded file IDs in the Docker client.

### Changed

- The Docker client image now includes `qrencode` to render upload IDs as
  terminal QR codes.

## [1.0.0] - 2026-04-19

Initial public release.

### Added

- Cloudflare Worker backend with four endpoints: health check, upload, download,
  and admin flush.
- Client-side encryption via `age --passphrase` (ChaCha20-Poly1305); only
  ciphertext is sent to the Worker.
- Configurable TTL per upload (`15m` to `7d`, default `24h`).
- `--delete-after-read` flag for one-time retrieval.
- Opportunistic expiration sweep on every request; `/v1/admin/flush` for
  on-demand cleanup.
- Docker client image with `curl` compiled from source with ECH support and
  `age` for decryption.
- Transport hardening: DoH, TLS 1.3, and Encrypted Client Hello (`hard` mode by
  default).
- Constant-time secret token comparison to prevent timing attacks.
- Defensive response headers (`X-Content-Type-Options`, `X-Frame-Options`).
- Streaming upload and download with no server-side buffering (supports files up
  to 100 MB).
- `install` and `shell-alias` subcommands for convenient host-side wrappers.
