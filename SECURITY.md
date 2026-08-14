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
- Peer pairing, capability scoping, replay, or revocation bypass
- Cryptographic weaknesses in the upload/download flow
- Information disclosure (e.g. plaintext exposure, metadata leaks)
- Transport security bypasses in the Docker client

Out of scope:

- Vulnerabilities in third-party dependencies (Cloudflare, age, Git) — report
  those upstream
- Issues that require physical access to the host machine
- Social engineering
- Anything [`docs/threat-model-v2.md`](docs/threat-model-v2.md) records as known
  leakage or accepted exposure, unless the report shows the stated boundary does
  not actually hold

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
- **Scoped peer capabilities.** Peer authority is proof of possession, not a
  bearer token: a proof is bound to origin, path, method, body digest, slot,
  epoch, expiry, and a single-use nonce, so a captured request cannot be
  replayed or retargeted.
- **Authenticated peer senders.** A relationship is established by mutually
  confirmed pairing, and every delivery carries a descriptor signed by the key
  pinned then. A dead drop has no sender authentication: its object ID is the
  entire credential, so treat a dropped object as anonymous.
- **Protected server credentials.** Reusable peer verifier secrets are encrypted
  at rest under a deployment key, and object bearer credentials are stored only
  as salted hashes.
- **Closed by default.** The `/v2` routes are disabled unless enabled, and a
  peer deployment refuses to start unless it states an enrollment policy.
  Credentials do not cross the boundary: `DUD_DROP_SECRET` never authorizes a
  peer route, and no peer credential authorizes a dead drop route.

What a storage operator can still observe, what the local device state reveals,
and what a compromised endpoint costs are set out in
[`docs/threat-model-v2.md`](docs/threat-model-v2.md).

## Supported Versions

| Version | Supported                                                     |
| ------- | ------------------------------------------------------------- |
| 2.x     | Yes — current release line                                    |
| 1.x     | Security fixes only, for as long as the v1 routes ship in 2.x |
| < 1.0   | No                                                            |

Only the latest 2.x patch release is supported. Fixes are released forward;
there are no long-term-support branches. Dead drops are a permanent feature and
the v1 wire protocol is frozen rather than deprecated; were a future major
version ever to remove the routes, this file would state the security-fix cutoff
for the last v1-capable release. See
[`docs/migration-v1-v2.md`](docs/migration-v1-v2.md).

## Patch Policy

Target timelines from a confirmed report:

| Severity | Fix released within | Advisory                           |
| -------- | ------------------- | ---------------------------------- |
| Critical | 7 days              | GitHub advisory with a CVE request |
| High     | 30 days             | GitHub advisory                    |
| Medium   | next release        | `CHANGELOG.md` under **Security**  |
| Low      | next release        | `CHANGELOG.md` under **Security**  |

A high-severity finding is not waivable: it is fixed, or the affected surface is
disabled, before the next release ships.

Every release publishes checksums, an SBOM, and provenance attestations for its
binaries and container images; the verification commands are in the
[README](README.md#verifying-a-release) and the pins behind them are in
[`docs/supported-versions.md`](docs/supported-versions.md).

## Further Reading

- [`docs/protocol-v2.md`](docs/protocol-v2.md) — wire format and security
  properties
- [`docs/threat-model-v2.md`](docs/threat-model-v2.md) — adversaries and
  boundaries
- [`docs/README.md`](docs/README.md) — the full documentation index
