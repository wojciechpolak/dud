# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in this project, please report it privately
using
[GitHub's security advisory feature](https://github.com/wojciechpolak/dud/security/advisories/new)
rather than opening a public issue.

I'm a solo developer. I'll do my best to respond and release a fix as quickly as
I can, but please allow reasonable time.

## Scope

In scope:

- Worker authentication or authorization bypass
- Cryptographic weaknesses in the upload/download flow
- Information disclosure (e.g. plaintext exposure, metadata leaks)
- Transport security bypasses in the Docker client

Out of scope:

- Vulnerabilities in third-party dependencies (Cloudflare, age, curl) — report
  those upstream
- Issues that require physical access to the host machine
- Social engineering

## Security Design

DUD is built with the following properties in mind:

- **Client-side encryption only.** The Worker never sees plaintext — only `age`
  ciphertext.
- **Passphrase never leaves the client.** Encryption and decryption happen
  inside the Docker container.
- **Transport hardening.** The client enforces DoH, TLS 1.3, and ECH before any
  data transfer.
- **Constant-time token comparison.** Upload and flush endpoints use
  constant-time comparison to prevent timing attacks on the shared secret.
