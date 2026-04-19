# Changelog

All notable changes to DUD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for public releases.

## [Unreleased]

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
