# DUD

Discreet upload / download with either a Cloudflare Worker backed by R2 or a
self-hosted Node server backed by local disk, plus a Go client — a Docker image
or a native binary — that carries its own HTTPS transport and uses `age` and
`age-keygen`.

## What this does

- Encrypts and decrypts every payload on the client with `age`: a passphrase or
  a recipient public key for a dead drop, the peer's hybrid post-quantum
  recipient for a peer transfer.
- Uploads only ciphertext. The server stores opaque bodies and bounded metadata
  and holds no key that opens them.
- Addresses a dead drop by an opaque ID handed to the recipient out of band, and
  a peer transfer by the local alias of a device you paired with once.
- Authenticates the sender of a peer transfer with its Ed25519 device identity,
  sequences deliveries against a hash chain the receiver acknowledges, and can
  revoke a relationship when a device or its state is lost.
- Synchronizes Git repositories over the same two paths — by opaque ID as a
  bundle in a dead drop, or to a peer as a complete authenticated checkpoint.
- Opportunistically cleans up expired or consumed objects during normal traffic,
  on both the R2 and filesystem backends.
- Verifies secure transport from the client with in-process DoH, exactly TLS
  1.3, and ECH, using `hard` by default, before either mode moves data.

> **Important.** There is no web UI, and there will not be one. A browser cannot
> enforce ECH hard mode, DoH, or exactly TLS 1.3 the way the DUD client does,
> and those checks are what the threat model rests on.

Stack:

- [Cloudflare Worker](https://workers.cloudflare.com/)
- [R2](https://www.cloudflare.com/developer-platform/products/r2/)
- [Node.js](https://nodejs.org/)
- [Docker](https://www.docker.com/)
- [age](https://github.com/FiloSottile/age)
- [DoH](https://en.wikipedia.org/wiki/DNS_over_HTTPS)
- [ECH](https://en.wikipedia.org/wiki/Server_Name_Indication#Encrypted_Client_Hello)

DUD assumes bring-your-own infrastructure: a Cloudflare Worker with R2 for a
managed edge deployment, or the Node server on your own host. No public shared
instance is required or assumed.

## Two ways to transfer: dead drops and peers

DUD has two transfer modes. Both ship permanently in the same binary, and
neither one is on its way out; they answer different questions.

A **dead drop** is addressed by an opaque ID. Encrypt to a passphrase or an
`age` recipient, upload, and hand the ID to the other side out of band. Nothing
is remembered between runs, and the ID is the whole credential.

A **peer** transfer is addressed by the local alias of a device you have paired
with. Pair once, and `dud send laptop` works from then on. Everything that
crosses the relationship is signed by the sender, sequenced, acknowledged, and
revocable.

| Property                     | Dead drop `upload -r`                | Peer `send PEER`                   |
| ---------------------------- | ------------------------------------ | ---------------------------------- |
| Payload encryption           | `age` recipient; X25519 unless `-pq` | `age` hybrid PQ recipient, always  |
| Post-quantum payloads        | opt-in, per upload                   | mandatory, signed `kem_alg`        |
| Sender authenticity          | none                                 | Ed25519, domain-separated          |
| Recipient key                | supplied per upload; static          | from pairing; per relationship     |
| Reaching the recipient       | opaque ID, shared out of band        | slot from relationship secret      |
| Replay / rollback resistance | none                                 | hash-chained sequences, watermarks |
| Revocation                   | none                                 | `peer revoke`, epochs, reissue     |

Payload confidentiality is the same primitive in both modes once a drop is made
to a post-quantum recipient: peer transfers encrypt to the hybrid
MLKEM768-X25519 recipient that `age-keygen -pq` also produces. What peer mode
adds sits around the cipher — sender authentication, freshness, revocation, and
no long-lived public identifier for anyone to correlate. What it costs is reach:
it only talks to devices you have paired with, which is why `dud send PEER`
rejects `--recipient` and `--passphrase`.

Neither mode has post-quantum signatures or forward secrecy. `age` offers no
post-quantum signature type, so sender authentication stays Ed25519, and peer
recipients derive from a long-lived device seed. See
[`docs/threat-model-v2.md`](docs/threat-model-v2.md) section 2 for the full
guarantee table and section 3.21 for the quantum reasoning.

A dead drop reaches someone you have not paired with, and it is the only way to
reach them. Pair when you expect to keep exchanging data with the same device.

The wire protocols behind the two modes are versioned `v1` and `v2`, and those
numbers still appear where they name something literal — the `/v1/` and `/v2/`
routes and the file names of the protocol documents. What an operator configures
is named by mode instead: `DUD_DROP_*` for dead drops, `DUD_PEER_*` for peers.
In prose the modes are called drops and peers.

## Quick start

A DUD setup is a client you install once and a server you deploy. Install the
client first: the deployment paths below end by pointing it at the hostname they
produced, and one of them derives a credential with it.

### Install the client

`dud` on the host can be either of two things, and both accept exactly the same
commands. The published Docker image plus a thin host wrapper is the default:

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-client:latest
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest install \
  | sudo tee /usr/local/bin/dud > /dev/null && sudo chmod +x /usr/local/bin/dud
```

The wrapper is what makes `dud` a command. Every invocation needs the same
`docker run` flags — an in-memory `/tmp` so intermediate plaintext never reaches
the overlay filesystem, the working directory at `/work`, the peer state
directories, `--cap-drop ALL` — and the wrapper supplies them and forwards the
exported `DUD_*` variables into the container.
[`docs/client.md`](docs/client.md#6-shell-wrapper) covers it in full, including
`shell-init`, which prints the same thing as a shell function for your
`~/.profile` instead of a script in `/usr/local/bin`.

A host that would rather not run Docker can use the native binary a release
publishes for Linux and macOS on both architectures. It expects `age`,
`age-keygen`, `git`, and `qrencode` on `PATH`, and keeps peer state in `~/.dud`
directly:

```sh
curl -fL -o dud https://github.com/wojciechpolak/dud/releases/latest/download/dud-linux-amd64
sudo install -m 0755 dud /usr/local/bin/dud
```

Release assets are plain HTTPS downloads, so no GitHub CLI is required.
`/releases/latest/download/` resolves to the newest stable release; a
pre-release tag is published as one and is never what that path returns, so name
a version explicitly with `/releases/download/vX.Y.Z/` to pin it. The asset name
selects the platform: `dud-linux-amd64`, `dud-linux-arm64`, `dud-darwin-amd64`,
or `dud-darwin-arm64`. With the GitHub CLI installed, the same download is:

```sh
gh release download vX.Y.Z --pattern 'dud-linux-amd64'
sudo install -m 0755 dud-linux-amd64 /usr/local/bin/dud
```

Verify what you install: see [Verifying a release](#verifying-a-release) below.
Skip both and every command in this README becomes one long `docker run` line;
[`docs/client.md`](docs/client.md#4-running-it) shows what those look like.

Once a deployment exists, point the client at it and confirm the transport:

```sh
export DUD_BASE_URL=https://your-dud-host.example.com
dud test
```

`dud test` succeeds only if the client reaches the service through its own DoH
resolution and exactly TLS 1.3, with an accepted ECH handshake under the default
`hard` mode. Every deployment path below finishes here.

### Deploy a server

Choose one:

- **Cloudflare Worker + R2** — the easiest managed deployment
- **Cloudflare Tunnel for self-hosted `dud-server`** — a private origin with a
  public Cloudflare-backed hostname and tested `DUD_ECH_MODE=hard`
- **Self-hosted without Cloudflare** — the most manual path, for operators
  managing their own HTTPS and DNS stack

#### 1. Cloudflare Worker + R2

Who this is for: operators who want the simplest Cloudflare-backed deployment
without running their own Node server. You need a Cloudflare account, a hostname
managed by Cloudflare, and Docker for the client image.

1. Clone the repository and install dependencies:

```sh
git clone https://github.com/wojciechpolak/dud.git
cd dud
npm ci
```

2. Sign in to Cloudflare and create the R2 bucket:

```sh
npx wrangler login
npx wrangler r2 bucket create dud-files
```

3. Create the D1 database that stores peer metadata:

```sh
npx wrangler d1 create dud-v2
```

The command prints a `database_id`. Copy it; step 5 pastes it into
`wrangler.toml`. R2 keeps holding the opaque ciphertext bodies, while D1 holds
only peer relationship, capability, delivery, and accounting records.

4. Create `wrangler.toml` from the checked-in example:

```sh
cp wrangler.example.toml wrangler.toml
```

5. Edit `wrangler.toml` before the first deployment:

- keep `name = "dud"` unless you want a different Worker name
- change `pattern = "dud.example.com"` if you want a different hostname
- keep `bucket_name = "dud-files"` only if that is the bucket you created
- keep the R2 binding name as `FILES`
- replace `database_id = "replace-with-d1-database-id"` with the ID from step 3,
  and keep the D1 binding name as `DB`
- keep or adjust `APP_VERSION`

A v1-only deployment — one that serves dead drops and nothing else — can instead
delete the whole `[[d1_databases]]` block. `replace-with-d1-database-id` names
no real database, so it has to be either replaced or removed;
`npx wrangler deploy --dry-run` does not catch it, because the ID is only
resolved against the account at deployment time.

6. Initialize the D1 schema:

```sh
npx wrangler d1 migrations apply dud-v2 --remote
npx wrangler d1 migrations list dud-v2 --remote
```

`migrations_dir` in `wrangler.toml` points at `migrations/d1`, which holds a
single idempotent schema file. Wrangler records what it applied, so the second
command reports no unapplied migrations once the schema is in place. Add
`--local` instead of `--remote` to prepare the local database that
`npx wrangler dev` uses.

7. Verify the repository and deploy:

```sh
npm run check
npx wrangler deploy
```

8. Configure the shared upload secret:

```sh
npx wrangler secret put DUD_DROP_SECRET
```

9. To serve peer transfers as well, set `DUD_PEER_ENABLED = "true"` under
   `[vars]` in `wrangler.toml` and add the peer secrets. The Worker refuses to
   start with `/v2` enabled and no `DB` binding, so complete steps 3, 5, and 6
   first.

`DUD_PEER_DEPLOYMENT_KEY` wraps stored verifier secrets and never leaves the
server, so nobody types it. It is 32 bytes, base64url:

```sh
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
npx wrangler secret put DUD_PEER_DEPLOYMENT_KEY
```

`DUD_PEER_SECRET` is what lets a device create a pairing invitation. Whoever
invites a device needs it too, which is why it is a passphrase of at least 24
characters and not encoded bytes. Give the Worker the key that passphrase
stretches into, not the passphrase itself: stretching costs more CPU than a
free-tier Worker invocation is allowed, and the key is all verification
consumes. Derive it with the client you installed above and paste the printed
`dud2-enroll-key:…` value:

```sh
DUD_PEER_SECRET='squid-lantern-rotate-9-mango' dud peer enrollment-key
npx wrangler secret put DUD_PEER_SECRET
```

Without `DUD_PEER_SECRET` the Worker refuses to start, unless you deliberately
set `DUD_PEER_OPEN_ENROLLMENT = "true"` to let anyone who learns the hostname
pair through the deployment.

`DUD_PEER_ADMIN_SECRET` is optional, is generated the same way as the deployment
key and independently of it, and only enables administrative operations such as
relationship revocation. Leaving it unset keeps that surface off and administers
the deployment offline instead:

```sh
npx wrangler secret put DUD_PEER_ADMIN_SECRET
```

Deploy once the secrets are in place:

```sh
npx wrangler deploy
```

10. Point the client at the Worker hostname and run `dud test`, as shown under
    [Install the client](#install-the-client).

The real `wrangler.toml` is gitignored so machine-specific IDs and future local
changes stay out of the repository.

#### 2. Cloudflare Tunnel for self-hosted `dud-server`

Who this is for: private LAN hosts or NAS systems that should stay self-hosted
while exposing a public Cloudflare-backed hostname for the DUD client. You need
a Cloudflare-managed hostname, a working
[Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/) (`cloudflared`),
and Docker.

1. Create a local `.env` file or export the upload secret:

```dotenv
DUD_DROP_SECRET=replace-me
```

2. Start the self-hosted server:

```sh
curl https://raw.githubusercontent.com/wojciechpolak/dud/master/docker-compose.yml | docker compose -f - up
```

Docker Compose stores server data in the named volume `dud_data` by default,
which avoids common host bind-mount permission issues.

3. Publish a public subdomain through Cloudflare Tunnel to the private server
   origin. Typical origins are `http://127.0.0.1:8787` when `cloudflared` runs
   on the same host, and `http://dud-server:8787` when it shares the Docker
   network.

4. Point the client at the tunnel hostname and run `dud test`.

This path has been tested successfully, showing TLS 1.3 and `ech: succeeded`
against the public hostname:

- `tls: TLSv1.3 ...`
- `ech: succeeded`
- `outer sni: cloudflare-ech.com`

Note that ECH protects the client-to-Cloudflare hop. Your origin remains private
behind the tunnel, but ECH itself does not apply to the Cloudflare-to-origin
connection.

#### 3. Self-hosted without Cloudflare

Who this is for: operators who want to run `dud-server` themselves and manage
their own HTTPS reverse proxy or direct TLS setup. You need a public hostname,
an HTTPS endpoint in front of `dud-server`, and Docker.

1. Create a local `.env` file or export the upload secret:

```dotenv
DUD_DROP_SECRET=replace-me
```

2. Start the self-hosted server. From a clone of the repository, where
   `docker-compose.yml` and the server build context are:

```sh
docker compose up -d
```

Without a clone, use the same one-liner as path 2, which runs the published
server image from the checked-in Compose file.

3. Publish the service through your own HTTPS stack, either with a reverse proxy
   in front of `dud-server` or with direct TLS via `DUD_TLS_CERT_FILE` and
   `DUD_TLS_KEY_FILE`.

4. Choose the transport mode. Use `export DUD_ECH_MODE=hard` only if your
   hostname really supports ECH and publishes the required HTTPS DNS records;
   otherwise use `export DUD_ECH_MODE=off`, which keeps every other check — DoH,
   the public address-range check, exactly TLS 1.3, and redirect rejection —
   while leaving the hostname visible in the TLS SNI.

5. Point the client at the hostname and run `dud test`.

#### Peer transfers on a self-hosted server

Both self-hosted paths above serve dead drops. Peer transfers need four more
settings, which the checked-in `docker-compose.yml` already passes through from
the same `.env`:

```dotenv
DUD_PEER_ENABLED=true
DUD_PUBLIC_BASE_URL=https://your-dud-host.example.com
DUD_PEER_DEPLOYMENT_KEY=<independent 32-byte base64url value>
DUD_PEER_SECRET=squid-lantern-rotate-9-mango
```

`DUD_PUBLIC_BASE_URL` is required with peers enabled and must be the canonical
HTTPS origin clients dial — scheme, host, optional port, nothing else. Every v2
request is bound to it, so a value that disagrees with the hostname in use
rejects every authorization. `DUD_PEER_SECRET` gates pairing enrollment and the
server refuses to start without it unless `DUD_PEER_OPEN_ENROLLMENT=true` says
the deployment accepts pairing from anyone who reaches the hostname. Generate
each credential independently of the others and of `DUD_DROP_SECRET`; the
service refuses to start if any two are equal.
[`docs/server-v2.md`](docs/server-v2.md#5-self-hosted-deployment) covers the
rest, including every credential in full and the data directory to back up as a
unit.

## First transfer

Both modes below assume the client from
[Install the client](#install-the-client) and a deployment to point it at.
`/work` in these examples is the directory you run `dud` from, which the wrapper
mounts under that name; a native binary takes ordinary host paths instead.

A dead drop. The recipient generates a key pair once; after that an upload and a
download are one command each, and only the printed object ID has to travel out
of band:

```sh
dud keygen --pq --out /work/alice.key -R /work/alice.recipient
dud upload --file /work/secret.pdf --ttl 48h -R /work/alice.recipient
dud download --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe -i /work/alice.key --out /work/secret.pdf
```

Full guide: [`docs/dead-drops-v1.md`](docs/dead-drops-v1.md).

A peer transfer, once both devices point at a v2-enabled deployment:

```sh
dud init --device desktop --url https://your-dud-host.example.com
dud peer invite laptop        # prints a pairing code and a QR code, then waits
dud send laptop --file /work/report.pdf
```

On the other device, `dud peer accept desktop` takes the code at a visible
prompt, and `dud receive desktop` drains everything waiting. Full guide:
[`docs/peer-setup.md`](docs/peer-setup.md).

`dud init` writes the device seed and peer graph under `~/.dud`, which the
wrapper mounts into the container; a drop command reads no configuration file
and leaves that directory untouched. Two device identities on one machine, or a
second deployment, need `DUD_PROFILE` — see
[`docs/client.md`](docs/client.md#3-running-more-than-one-deployment).

Running `dud` with no command in a terminal opens an interactive menu that
covers both modes.

## DUD Server

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-server:latest
docker run --rm -p 8787:8787 \
  -e DUD_DROP_SECRET=replace-me \
  -v "$PWD/dud-data:/data" \
  ghcr.io/wojciechpolak/dud/dud-server:latest
```

Container defaults are `DUD_DATA_DIR=/data`, `DUD_LISTEN_HOST=0.0.0.0`, and
`DUD_LISTEN_PORT=8787`. The image starts `node dist/src/node-server.js` under
`tini` as the non-root `dud` user; mount `/data` to persist uploads across
restarts. The checked-in `docker-compose.yml` already persists it in the named
volume `dud_data`.

`DUD_LOG_MODE` selects verbosity (`normal`, `minimal`, `silent`) and
`DUD_LOG_FORMAT` selects the shape (`text` or `json`). Both formats redact
object, delivery, and rendezvous identifiers, and a v2 record names a route
class rather than the capability, slot, or peer the request touched.

TTL, upload size, cleanup, and peer quota settings are environment variables on
this server; the Worker compiles the same defaults in and takes no override for
them. [`docs/server-v2.md`](docs/server-v2.md#6-limits) lists every one with its
default.

Build the images locally with:

```sh
./scripts/docker-build.sh --component client
./scripts/docker-build.sh --component server
```

Credentials, feature flags, limits, administration, and health checks are in
[`docs/server-v2.md`](docs/server-v2.md).

## Verifying a release

Every release publishes reproducible native binaries with checksums, an SPDX
SBOM, and a Sigstore provenance attestation, alongside signed container images
with their own SBOM attestation. Verify what you run.

Native binaries:

```sh
gh release download vX.Y.Z --pattern 'dud-*' --pattern 'SHA256SUMS'
sha256sum -c SHA256SUMS
gh attestation verify dud-linux-amd64 --repo wojciechpolak/dud
```

`SHA256SUMS` is a release asset like the binaries, so `curl` fetches it the same
way and `sha256sum --ignore-missing -c SHA256SUMS` checks whichever binaries you
downloaded. Verifying the provenance attestation is the step that needs `gh`.

Container images:

```sh
gh attestation verify \
  oci://ghcr.io/wojciechpolak/dud/dud-client:X.Y.Z \
  --repo wojciechpolak/dud
```

The binaries are built twice from the same source in the release workflow and
the build fails if the two differ, so you can rebuild any published binary and
expect the same checksum:

```sh
git checkout vX.Y.Z
npm run release:binaries
sha256sum dist/release/dud-*
```

Which upstream sources and base images a release was built from is recorded in
[`docs/supported-versions.md`](docs/supported-versions.md) and verified offline
by `npm run check:pins`.

## Documentation

[`docs/`](docs/README.md) is the index. The main entries:

- [`docs/peer-setup.md`](docs/peer-setup.md) — pairing two devices, sending, and
  receiving
- [`docs/dead-drops-v1.md`](docs/dead-drops-v1.md) — the drop commands and the
  `/v1` HTTP API
- [`docs/client.md`](docs/client.md) — client environment, configuration layers,
  profiles, and wrappers
- [`docs/server-v2.md`](docs/server-v2.md) — deployment, credentials, limits,
  administration, and logging
- [`docs/migration-v1-v2.md`](docs/migration-v1-v2.md) — moving a deployment
  from v1-only to dual-stack to v2-only
- [`docs/recovery-v2.md`](docs/recovery-v2.md) — rollback, revocation, key
  rotation, and failure recovery
- [`docs/git-sync-v2.md`](docs/git-sync-v2.md) — peer Git synchronization
- [`docs/protocol-v2.md`](docs/protocol-v2.md) — wire format and security
  properties
- [`docs/threat-model-v2.md`](docs/threat-model-v2.md) — adversaries and
  boundaries
- [`docs/supported-versions.md`](docs/supported-versions.md) — build toolchain,
  pinned sources, and the update policy
- [`docs/development.md`](docs/development.md) — repository layout, commands,
  and local testing

## Notes

- Both modes carry files up to 100 MB by default, which keeps the transfer path
  compatible with common Cloudflare request body limits.
- Public-key mode is the preferred way to make a dead drop, because it avoids
  relying on a human-memorable passphrase for file encryption. A peer transfer
  always encrypts to a key.
- The server is not the trust boundary for ECH. The client verifies secure
  transport before upload or download.
- Cleanup is cron-free. Expired and consumed objects are removed during normal
  traffic, and `dud flush` is available for an explicit cleanup pass.
- Every peer Git push is a complete checkpoint; there are no incremental bundle
  chains. A checkpoint the receiving client cannot apply is refused back to the
  peer instead of blocking the transfer queue behind it.

## License

- **Repository default:** [MIT License](./LICENSE) unless a more specific
  component license applies
