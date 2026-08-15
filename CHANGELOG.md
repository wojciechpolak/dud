# Changelog

All notable changes to DUD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for public releases.

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
