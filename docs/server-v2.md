# Running a DUD v2 Server

This document is the operator's reference for a v2 deployment: what the server
stores, how to bring it up on Cloudflare or on your own host, which knobs exist,
and what routine operation looks like.

For the wire format see [`protocol-v2.md`](protocol-v2.md); for what the server
is and is not trusted with see [`threat-model-v2.md`](threat-model-v2.md). The
step-by-step first deployment lives in the repository
[README](../README.md#quick-start) and is not repeated here.

## 1. What the server holds

A v2 server is a blind relay with an accounting ledger. It holds:

- **Metadata** — relationships, capability lookup records, delivery and control
  event rows, staged reservations, nonce claims, and quota counters. On
  Cloudflare this is D1; self-hosted it is SQLite.
- **Bodies** — opaque ciphertext. On Cloudflare this is R2; self-hosted it is
  the filesystem under the data directory.
- **Whole-state records** — revocations, encrypted verifier secrets, and pairing
  rendezvous records.

It never holds plaintext, a passphrase, an age identity, a device seed, or a
relationship secret. Verifier secrets are encrypted at rest under the deployment
key; bearer credentials are stored only as salted hashes.

## 2. Feature flags

Two flags decide which protocol versions a deployment serves. They are
independent, and all four combinations are valid:

| `DUD_DROP_ENABLED` | `DUD_PEER_ENABLED` | Deployment shape                               |
| ------------------ | ------------------ | ---------------------------------------------- |
| `true` (default)   | `false` (default)  | v1-only, the 1.x behavior unchanged            |
| `true`             | `true`             | dual-stack                                     |
| `false`            | `true`             | v2-only                                        |
| `false`            | `false`            | serves neither; useful only to park a hostname |

A v2-only deployment answers `404` on every `/v1/` route. A v1-only deployment
answers the v2 error document with code `4` on every `/v2/` route. Capability
discovery advertises exactly the protocols a deployment serves, so a client
never has to probe.

`GET /v2/capabilities` is the only unauthenticated v2 route and is safe to
expose to a health checker.

## 3. Credentials

Four credentials exist and each must be independently generated. The service
refuses to start if any two are equal.

| Name                      | Purpose                                  | Required                  |
| ------------------------- | ---------------------------------------- | ------------------------- |
| `DUD_DROP_SECRET`         | the dead drop upload and flush secret    | only with v1 enabled      |
| `DUD_PEER_DEPLOYMENT_KEY` | wraps verifier secrets at rest           | with v2 enabled           |
| `DUD_PEER_SECRET`         | authorizes creating a pairing invitation | with v2 enabled, see §3.1 |
| `DUD_PEER_ADMIN_SECRET`   | authorizes `/v2/admin/*`                 | optional                  |

`DUD_PEER_DEPLOYMENT_KEY` and `DUD_PEER_ADMIN_SECRET` are 32 bytes, base64url,
generated separately. They never leave the server, so nobody types them:

```sh
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

That command emits base64url. A hex value such as `openssl rand -hex 32` is
refused, because its 64 characters decode to 48 bytes rather than 32.

`DUD_PEER_SECRET` is different: it is a passphrase of at least 24 characters,
not encoded bytes, and it accepts two other forms besides. §3.1 says why.

`DUD_PEER_ADMIN_SECRET` only enables the online administrative routes. Leave it
unset if you prefer to administer the deployment offline (see §7), which is the
smaller attack surface.

### 3.1 Enrollment is closed by default

`POST /v2/pairing/rendezvous` is the only route that creates state for a caller
holding neither a capability nor a relationship. Without a credential, anyone
who learns the hostname can pair two of their own devices and use the deployment
as a relay. The per-relationship quota bounds that stranger separately and does
nothing for the deployment as a whole, and `/v2/capabilities/reissue` lets the
relationship renew itself with no operator involvement.

So a v2 deployment refuses to start until it states its policy: set
`DUD_PEER_SECRET`, or set `DUD_PEER_OPEN_ENROLLMENT=true` to accept pairing from
anyone who can reach the hostname. There is no default. Omitting both is a
startup error, never a silently open deployment.

Give `DUD_PEER_SECRET` to whoever may invite a device. It is the one v2
credential that has to exist on a client as well as on the server — it gets
carried to another machine, often by being typed — which is why it is a
passphrase and not 32 encoded bytes. Choose four or five random words; the floor
is 24 characters:

```sh
DUD_PEER_SECRET='squid-lantern-rotate-9-mango'
```

The passphrase itself never reaches the wire: the inviter sends
`Authorization: DUD2-Enroll <proof>`, where the proof is an HMAC — under a key
derived from the passphrase — bound to the rendezvous being created, so a proof
recovered from a request log authorizes nothing else. An invitee needs only the
pairing code, so pairing with someone else's device does not mean handing them a
deployment credential.

A captured proof is still something an attacker can test guesses against
offline, without the server. What makes that impractical is the derivation:
PBKDF2-HMAC-SHA256 at 600,000 iterations, so each guess costs a few hundred
milliseconds instead of a microsecond. Online guessing has its own bound, at 10
enrollment attempts per source per minute — fixed, not configurable — and a
refused request never spends the deployment-wide creation window.

#### The derived-key form, and why a Worker wants it

The server never needs the passphrase. It needs the 32-byte key the passphrase
stretches into, and `DUD_PEER_SECRET` accepts that key directly:

```sh
DUD_PEER_SECRET='dud2-enroll-key:_3iJ1c59CVqmBr68qGBeriqPHt5kLWa5j19Ql0PO31E'
```

Configured this way the deployment runs no key derivation at all. That matters
because the derivation does not fit in the 10 ms of CPU a Cloudflare free-tier
Worker invocation is allowed, and it would otherwise be paid on the first gated
invitation after a cold start. **On a free-tier Worker, use this form.**

It gives up nothing. The work factor exists to price an attacker's guesses, and
an attacker guesses passphrases, not keys, so moving the derivation off the
server leaves each guess exactly as expensive as before. Clients are unchanged:
they still hold the passphrase, still stretch it, and neither know nor care
which form the deployment holds.

Derive the key from the passphrase with either the client or the offline admin
CLI, whichever you have. Both read `DUD_PEER_SECRET` from the environment and
refuse it as an argument, where it would reach the shell history:

```sh
DUD_PEER_SECRET='squid-lantern-rotate-9-mango' dud peer enrollment-key
```

```sh
DUD_PEER_SECRET='squid-lantern-rotate-9-mango' node dist/src/v2-admin.js enrollment-key
```

Then feed the printed value to `wrangler secret put DUD_PEER_SECRET`.

#### Stating a lower work factor instead

An operator who would rather keep one typeable value everywhere can state a work
factor in the secret itself:

```sh
DUD_PEER_SECRET='dud2-enroll-kdf:60000:squid-lantern-rotate-9-mango'
```

The count travels with the secret to every device that holds it, so the two
sides cannot drift apart; a work factor configured separately could, and
enrollment refusals are deliberately indistinguishable, so that drift would be
unreadable. Accepted counts run from 10,000 to 10,000,000.

Below the 600,000 default this is a real reduction: at 60,000 an attacker
guesses ten times faster for the same money. The deployment therefore refuses to
start until you say you accept that, with
`DUD_PEER_ACCEPT_WEAK_ENROLLMENT_KDF=true`, and the client prints a warning
naming the count each time it invites. The derived-key form costs the server
just as little and asks for no such trade, so prefer it.

An open deployment derives no key and none of this applies to it.

Capability discovery reports the state as enforcement ID 3 — `0` open, `1`
secret required — and `dud capabilities` prints it as `enrollment`. A gated
deployment still advertises pairing (feature 3): pairing works, it just needs a
credential.

Losing `DUD_PEER_DEPLOYMENT_KEY` makes every stored verifier secret
undecryptable and forces every relationship to re-pair. Back it up like a
private key, and rotate it with the offline `rewrap-key` command rather than by
editing secrets.

## 4. Cloudflare deployment

The Worker needs both bindings when v2 is enabled and refuses to start without
them:

- `FILES` — the R2 bucket, holding v1 objects and v2 delivery bodies
- `DB` — the D1 database, holding all v2 metadata

Schema management is a single idempotent migration:

```sh
npx wrangler d1 migrations apply dud-v2 --remote
npx wrangler d1 migrations list dud-v2 --remote
```

Use `--local` to prepare the database that `npx wrangler dev` uses.

### Recreating the database

The schema is one file that is edited in place, so a schema change does not
migrate a database that already applied it; recreate each one. Wrangler recorded
the file in `d1_migrations` and skips it on the next apply, and every statement
in it is `IF NOT EXISTS`, so a database left alone keeps its old columns and
fails the affected routes with `D1_ERROR: … SQLITE_ERROR` while
`migrations list` still reports nothing pending.

Recreating drops every relationship, so each paired device has to pair again.

```sh
npx wrangler d1 execute dud-v2 --remote --file migrations/reset-d1.sql
npx wrangler d1 migrations apply dud-v2 --remote
```

Delivery bodies in R2 outlive the reset. The metadata that named them is gone,
so they become orphans under `deliveries/` and `staging/`, inert since request
handling never lists the bucket, but still billed. Delete those prefixes with
`wrangler r2` when the deployment had completed deliveries.

Maintenance runs opportunistically inside request handling, gated per isolate
and leased through D1 so concurrent isolates do not each sweep. There is no cron
to configure.

## 5. Self-hosted deployment

`dist/src/node-server.js` serves the same routes from one data directory:

```
<DUD_DATA_DIR>/
  blobs/            v1 object bodies
  meta/             v1 object metadata
  v2/
    v2.sqlite       all v2 metadata
    state.json      whole-state records
    nonces/         replay claims
    deliveries/     v2 delivery bodies
```

Back up the whole directory as a unit. Backing up `v2.sqlite` without the body
directory, or the reverse, produces a deployment whose metadata and bodies
disagree; §7 explains how to reconcile that.

`DUD_PUBLIC_BASE_URL` is required when v2 is enabled and must be a canonical
HTTPS origin: scheme, host, optional port, and nothing else. Every v2 request is
bound to that origin, so a mismatch between it and the hostname clients dial
rejects every authorization.

Put HTTPS in front of the server, either with a reverse proxy or with
`DUD_TLS_CERT_FILE` and `DUD_TLS_KEY_FILE`. The client requires exactly TLS 1.3
and rejects redirects.

### Transport modes

Clients run in one of two transport modes, and the terminology is fixed
throughout DUD:

- **`hard`** (the default) — Encrypted Client Hello is mandatory. The client
  refuses to transfer anything if ECH does not succeed.
- **`off`** — ECH is not attempted. The target hostname is visible in the TLS
  SNI. Everything else in the required transport profile still applies: HTTPS
  DoH, address-range checks, exactly TLS 1.3, and redirect rejection.

There is no intermediate or best-effort mode. Choose `hard` only if the hostname
really supports ECH and publishes the required HTTPS DNS records; otherwise
choose `off` deliberately and accept the documented SNI exposure.

## 6. Limits

Every limit has a compile-time default, and the self-hosted server takes a
`DUD_PEER_MAX_*` override for each one. The Worker reads none of them: on
Cloudflare the compiled defaults are the configuration, and a `DUD_PEER_MAX_*`
entry under `[vars]` changes nothing. The defaults are:

| Limit                      | Default | Environment variable                      |
| -------------------------- | ------- | ----------------------------------------- |
| object bytes               | 100 MiB | `DUD_PEER_MAX_OBJECT_BYTES`               |
| descriptor bytes           | 256 KiB | `DUD_PEER_MAX_DESCRIPTOR_BYTES`           |
| TTL seconds                | 30 days | `DUD_PEER_MAX_TTL_SECONDS`                |
| pending deliveries         | 64      | `DUD_PEER_MAX_PENDING_DELIVERIES`         |
| objects per capability     | 256     | `DUD_PEER_MAX_OBJECTS_PER_CAPABILITY`     |
| concurrent uploads         | 4       | `DUD_PEER_MAX_CONCURRENT_UPLOADS`         |
| requests per minute        | 60      | `DUD_PEER_MAX_REQUESTS_PER_MINUTE`        |
| staged bytes               | 200 MiB | `DUD_PEER_MAX_STAGED_BYTES`               |
| pairing envelope bytes     | 4 KiB   | `DUD_PEER_MAX_PAIRING_ENVELOPE_BYTES`     |
| pairing TTL seconds        | 1 hour  | `DUD_PEER_MAX_PAIRING_TTL_SECONDS`        |
| pairing creates per minute | 10      | `DUD_PEER_MAX_PAIRING_CREATES_PER_MINUTE` |
| pending pairings           | 256     | `DUD_PEER_MAX_PENDING_PAIRINGS`           |
| total bytes                | 10 GiB  | `DUD_PEER_MAX_TOTAL_BYTES`                |

Limits are published in the discovery document, so clients check their own
requests before sending. Staged bytes must permit at least one maximum-sized
object; the service refuses to start with a configuration that cannot.

Rate and storage accounting is shared wherever the deployment keeps a
whole-state ledger to share. The self-hosted server keeps one, so with v2
enabled its dead drop traffic is metered by the counters above and its dropped
objects count toward the total-bytes limit. The Worker keeps every peer record
in D1 and holds no such ledger, so its dead drop routes are metered and bounded
exactly as they are with v2 disabled; bound them at the edge if you need a
ceiling on them.

The dead drop side has its own settings, and they belong to the self-hosted
server. The Worker reads `APP_VERSION` from `[vars]` and compiles the rest, the
same way it does the peer limits above.

| Setting                    | Default      | Environment variable       |
| -------------------------- | ------------ | -------------------------- |
| default TTL                | `24h`        | `DUD_DEFAULT_TTL`          |
| maximum TTL                | `30d`        | `DUD_MAX_TTL`              |
| maximum upload bytes       | 100 MiB      | `DUD_MAX_UPLOAD_BYTES`     |
| objects per cleanup batch  | 100          | `DUD_CLEANUP_BATCH_SIZE`   |
| cleanup passes per flush   | 20           | `DUD_FLUSH_MAX_ITERATIONS` |
| service name in `/v1/test` | `dud`        | `DUD_SERVICE_NAME`         |
| data directory             | `./dud-data` | `DUD_DATA_DIR`             |
| listen address             | `127.0.0.1`  | `DUD_LISTEN_HOST`          |
| listen port                | `8787`       | `DUD_LISTEN_PORT`          |

The two TTL settings only ever narrow the window. `DUD_MAX_TTL` is itself
checked against the compiled 30 days and `DUD_DEFAULT_TTL` against
`DUD_MAX_TTL`, so a value above either ceiling fails startup rather than raising
it. An upload asking for more than `DUD_MAX_TTL` is refused with `400`, and one
larger than `DUD_MAX_UPLOAD_BYTES` with `413`.

The published server image sets `DUD_DATA_DIR=/data` and
`DUD_LISTEN_HOST=0.0.0.0` over the defaults above.

## 7. Administration

Online administration needs `DUD_PEER_ADMIN_SECRET` and covers relationship
revocation, capability rotation, and relationship status.

Offline administration needs only filesystem access to the data directory and is
the recommended path for a self-hosted deployment:

```sh
npm run v2:admin -- revoke --data-dir ./dud-data --relationship HEX \
    [--direction NAME] [--scope NAME]
npm run v2:admin -- rewrap-key --data-dir ./dud-data
npm run v2:admin -- reconcile --data-dir ./dud-data [--limit N] [--cursor TOKEN] \
    [--min-age SECONDS] [--apply] [--json]
npm run v2:admin -- enrollment-key
```

- **`revoke`** durably revokes a relationship, or one direction or scope of it.
  Revocation survives restart and rollback.
- **`rewrap-key`** rotates the deployment key. It reads the old key from
  `DUD_PEER_DEPLOYMENT_KEY` and the new one from `DUD_PEER_NEW_DEPLOYMENT_KEY`;
  neither is accepted on the command line. Deploy the new key only after the
  rewrap succeeds.
- **`reconcile`** walks one bounded page of the body namespace against the
  metadata that names it, in both directions, and prints a resume cursor when
  more pages remain. It reports only; `--apply` additionally deletes orphan
  bodies older than `--min-age`. Run it after restoring a partial backup.
- **`enrollment-key`** stretches the passphrase in `DUD_PEER_SECRET` and prints
  the derived key, in the form `DUD_PEER_SECRET` itself accepts. It needs no
  data directory, and the passphrase is not accepted on the command line. See
  §3.1.

## 8. Logging

`DUD_LOG_MODE` selects verbosity and `DUD_LOG_FORMAT` selects the shape:

- `DUD_LOG_MODE=normal` — startup banner plus access logs with the client
  address
- `DUD_LOG_MODE=minimal` — the same without the client address
- `DUD_LOG_MODE=silent` — no startup or access logs; errors are still reported
- `DUD_LOG_FORMAT=text` (default) — the single-line access log
- `DUD_LOG_FORMAT=json` — one JSON object per line

Both formats are redacted identically. Delivery and rendezvous identifiers
become `<redacted>` in paths, and anything identifier-shaped is stripped from
error messages.

A v2 request adds four phase timings to its JSON record:

```json
{
  "ts": "2026-08-07T09:15:04.221Z",
  "level": "info",
  "event": "request",
  "method": "POST",
  "path": "/v2/deliveries",
  "status": 200,
  "duration_ms": 41,
  "operation": "delivery-publish",
  "authorization_ms": 6.412,
  "metadata_ms": 9.83,
  "body_ms": 21.004,
  "handler_ms": 39.771
}
```

`operation` is a fixed route class, never the capability, slot, delivery, or
peer the request touched. `authorization_ms` covers proving the caller may act,
`metadata_ms` the transactional metadata work, `body_ms` moving payload bytes,
and `handler_ms` the whole route. The difference between `handler_ms` and the
three phases is framing, decoding, and response construction.

Embedders can consume the same records programmatically with `observeV2Timing`
on `createDudService`, `createNodeRequestHandler`, and the Worker service
builder.

The Worker writes no access log of its own; on Cloudflare use the platform's
logging, and note that it is outside DUD's redaction.

## 9. Health checks

- `GET /v1/test` on any deployment with v1 enabled
- `GET /v2/capabilities` on any deployment with v2 enabled

Neither requires a credential and neither reveals stored state.

From a paired client, `dud doctor` reports the effective origin, resolver, and
transport mode for every configured target, which layer each value came from,
the local state and tool health, and the result of a real transport check. Each
target gets its own section, and a peer target also carries its delivery status
block. It exits non-zero if anything failed. `dud doctor --json` reports the
same values as one document.

A peer target reports the transport its own profile pins, which is the origin
bound into its signed descriptors. The global target below follows
`DUD_BASE_URL`, while the peer keeps its pinned origin and the report names the
variable it overrode. A `pinned url` / `pinned doh` / `pinned ech` row appears
whenever an explicit `--url`, `--doh-url`, or `--ech-mode` displaced a pinned
value, so a diagnostic override is never silent.

```text
Device  laptop (770c82f6fcb47a0d00e859d402347584)
Config  /home/you/.dud/default/config/config.toml

Local state
  peers             1
  schema            v3
  issues            none
  admin capability  absent

Tools
  age         ok
  age-keygen  ok
  git         ok
  qrencode    ok

Origin: global
  url        https://dud.example.com               (environment)
  doh        https://cloudflare-dns.com/dns-query  (config)
  ech        hard                                  (environment)
  transport  ok (HTTP 200)

Origin: peer desktop
  url        https://desktop.example.com           (peer)
  doh        https://cloudflare-dns.com/dns-query  (config)
  ech        hard                                  (peer)
  transport  ok (HTTP 200)
  Note: DUD_BASE_URL set in the environment, but this peer pins its own
  transport; the pinned values are the ones in use.

  Delivery
    queued deliveries          0
    queued completions         0
    queued control events      0
    unacknowledged deliveries  4
    inbound waiting            no
    undrained control          no
    quarantined chains         none
    halted                     no
```

## 10. Related documents

- [`migration-v1-v2.md`](migration-v1-v2.md) — moving a deployment to v2
- [`recovery-v2.md`](recovery-v2.md) — rollback and failure recovery
- [`git-sync-v2.md`](git-sync-v2.md) — peer Git synchronization
- [`peer-setup.md`](peer-setup.md) — pairing two devices
