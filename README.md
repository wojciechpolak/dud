# DUD

Discreet upload / download with either a Cloudflare Worker backed by R2 or a
self-hosted Node server backed by local disk, plus a Dockerized client that uses
`curl`, `age`, and `age-keygen`.

## What this does

- Encrypts files locally with `age` before upload, using either a passphrase or
  recipient public keys.
- Uploads only ciphertext to the server.
- Returns an opaque ID that the recipient can use to fetch ciphertext.
- Decrypts locally after download with the shared passphrase or recipient
  private key.
- Opportunistically cleans up expired or consumed R2 objects during normal
  traffic.
- Verifies secure transport from the client with DoH, TLS 1.3, and `curl --ech`,
  using `hard` by default.

No web UI is provided by design. Browsers cannot enforce ECH hard mode, DoH, or
TLS 1.3 the way the Docker client does — the transport security guarantees that
define this tool's threat model require a controlled client stack.

Stack:

- [Cloudflare Worker](https://workers.cloudflare.com/)
- [R2](https://www.cloudflare.com/developer-platform/products/r2/)
- [Node.js](https://nodejs.org/)
- [Docker](https://www.docker.com/)
- [curl](https://curl.se/)
- [age](https://github.com/FiloSottile/age)
- [DoH](https://en.wikipedia.org/wiki/DNS_over_HTTPS)
- [ECH](https://en.wikipedia.org/wiki/Server_Name_Indication#Encrypted_Client_Hello)

Recommended mode:

- For the strongest async sharing model, prefer public-key mode with
  `dud upload -r ...` and `dud download -i ...`.
- Passphrase mode remains available for ad hoc sharing, but ciphertext can still
  be subjected to offline guessing if the passphrase is weak.
- `age` post-quantum recipients generated with `age-keygen -pq` are supported by
  the same public-key flow.

## Deployment targets

- Cloudflare Worker + R2 is available for people who want a managed edge
  deployment.
- A self-hosted Node server backed by local disk is now supported as the first
  non-Cloudflare backend.
- DUD assumes bring-your-own infrastructure. No public shared hosted instance is
  required or assumed.

## Quick start

Choose one of these deployment paths:

- `Cloudflare Worker + R2`: easiest managed deployment
- `Cloudflare Tunnel for self-hosted dud-server`: private origin with a public
  Cloudflare-backed hostname and tested `DUD_ECH_MODE=hard`
- `Self-hosted without Cloudflare`: most manual path, for operators managing
  their own HTTPS and DNS stack

### 1. Cloudflare Worker + R2

Who this is for: operators who want the simplest Cloudflare-backed deployment
without running their own Node server.

Minimum prerequisites:

- a Cloudflare account
- a hostname managed by Cloudflare
- Docker for the client image

Setup:

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

3. Create `wrangler.toml` from the checked-in example:

```sh
cp wrangler.example.toml wrangler.toml
```

4. Edit `wrangler.toml` before the first deployment:

- keep `name = "dud"` unless you want a different Worker name
- change `pattern = "dud.example.com"` if you want a different hostname
- keep `bucket_name = "dud-files"` only if that is the bucket you created
- keep the R2 binding name as `FILES`
- keep or adjust `APP_VERSION`

5. Verify the repo and deploy:

```sh
npm run check
npx wrangler deploy
```

6. Configure the shared upload secret:

```sh
npx wrangler secret put DUD_SECRET_TOKEN
```

7. Pull the client image and point it at the Worker hostname:

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-client:latest
export DUD_BASE_URL=https://your-dud-host.example.com
```

8. Confirm the transport path:

```sh
dud test
```

The real `wrangler.toml` is gitignored so machine-specific IDs and future local
changes stay out of the repository.

### 2. Cloudflare Tunnel for self-hosted `dud-server`

Who this is for: private LAN hosts or NAS systems that should stay self-hosted
while exposing a public Cloudflare-backed hostname for the Docker client.

Minimum prerequisites:

- a Cloudflare-managed hostname
- a working [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
  (`cloudflared`)
- Docker for `dud-server` and the client image

Setup:

1. Create a local `.env` file or export the upload secret:

```dotenv
DUD_SECRET_TOKEN=replace-me
```

2. Start the self-hosted server:

```sh
curl https://raw.githubusercontent.com/wojciechpolak/dud/master/docker-compose.yml | docker compose -f - up
```

Docker Compose stores server data in the named volume `dud_data` by default,
which avoids common host bind-mount permission issues.

3. Publish a public subdomain through Cloudflare Tunnel to the private server
   origin.

Typical origins are:

- `http://127.0.0.1:8787` when `cloudflared` runs on the same host
- `http://dud-server:8787` when `cloudflared` shares the Docker network

4. Pull the client image and point it at the public tunnel hostname:

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-client:latest
export DUD_BASE_URL=https://your-dud-host.example.com
```

5. Confirm the Cloudflare-backed transport path:

```sh
dud test
```

This path has been tested successfully with `dud test`, showing TLS 1.3 and
`ech: succeeded` against the public hostname.

Expected transport details include:

- `tls: TLSv1.3 ...`
- `ech: succeeded`
- `outer sni: cloudflare-ech.com`

Note that ECH protects the client-to-Cloudflare hop. Your origin remains private
behind the tunnel, but ECH itself does not apply to the Cloudflare-to-origin
connection.

### 3. Self-hosted without Cloudflare

Who this is for: operators who want to run `dud-server` themselves and manage
their own HTTPS reverse proxy or direct TLS setup.

Minimum prerequisites:

- a public hostname
- an HTTPS endpoint in front of `dud-server`
- Docker for `dud-server` and the client image

Setup:

1. Create a local `.env` file or export the upload secret:

```dotenv
DUD_SECRET_TOKEN=replace-me
```

2. Start the self-hosted server:

```sh
docker compose up -d
```

3. Publish the service through your own HTTPS stack, either with:

- a reverse proxy in front of `dud-server`
- or direct TLS via `DUD_TLS_CERT_FILE` and `DUD_TLS_KEY_FILE`

4. Pull the client image and point it at the public hostname:

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-client:latest
export DUD_BASE_URL=https://your-dud-host.example.com
```

5. Choose the transport mode:

- use `export DUD_ECH_MODE=hard` only if your hostname really supports ECH and
  publishes the required HTTPS DNS records
- otherwise use `export DUD_ECH_MODE=grease`

6. Confirm the endpoint:

```sh
dud test
```

This is the most manual deployment path in the README. It works well when you
already operate your own HTTPS and DNS stack, but it requires more setup than
the Cloudflare-backed options above.

## Local testing

These workflows are for local validation and development. They are not the main
deployment paths above.

### Host Caddy on localhost

For local browser/manual HTTPS testing, run Caddy directly on the host:

```sh
npm run dev:caddy
```

If your system does not already trust Caddy's local CA, run:

```sh
npm run dev:caddy:trust
```

This repo's [Caddyfile](./Caddyfile) proxies:

- `https://dud.localhost`
- to the Dockerized `dud-server` at `127.0.0.1:8787`

If you want to point the client at that local HTTPS endpoint:

```sh
export DUD_BASE_URL=https://dud.localhost
export DUD_ECH_MODE=grease
```

Important:

- host Caddy gives you local HTTPS, but not real ECH
- `DUD_ECH_MODE=hard` will not work against the default local `dud.localhost`
  setup
- `dud-client` uses DoH by default, so `dud.localhost` is best treated as a
  browser/manual HTTPS test target rather than a realistic end-to-end client
  test target

### Docker-only integration testing

If you want to exercise `dud-client -> HTTPS proxy -> dud-server` entirely in
Docker, start the optional integration Caddy service on the same Docker network:

```sh
docker compose --profile integration up -d
```

Then configure the client wrapper on the host so the `dud-client` container:

- joins the same Docker network
- trusts the internal Caddy local CA
- connects to the internal Caddy service without relying on public DNS

```sh
export DUD_BASE_URL=https://dud.local.test
export DUD_ECH_MODE=grease
export DUD_DOCKER_NETWORK=dud_dev
export DUD_CA_BUNDLE=/work/.dud-dev/caddy-data/pki/authorities/local/root.crt
export DUD_CONNECT_TO=dud.local.test:443:caddy:443
```

Then:

```sh
dud test
```

This mode is useful for local Dockerized integration testing, but it is still
not a realistic substitute for public-DNS validation or real ECH.

### Real ECH notes

For real ECH beyond local testing:

- use a public hostname that already has an A/AAAA record pointing to your
  server
- use DoH or DoT on the client side
- use a Caddy build with the right `caddy-dns` provider module
- configure the global `dns` and `ech` options in [Caddyfile](./Caddyfile)

Caddy's documentation notes that functioning ECH requires publishing HTTPS DNS
records and therefore a Caddy build with a DNS provider module.

### Repository layout

- `src/`: Worker code and Cloudflare adapters.
- `src/node-server.ts`: self-hosted Node server adapter.
- `src/filesystem.ts`: local-disk `BlobStore` implementation.
- `server/`: Docker packaging for the Node server image.
- `client/`: Docker client image and entrypoint script.
- `tests/`: Worker and client tests.

## DUD Client

Pull the published image:

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-client:latest
```

Default environment:

- `DUD_BASE_URL=https://dud.example.com`
- `DUD_DOH_URL=https://cloudflare-dns.com/dns-query`
- `DUD_ECH_MODE=hard`
- `DUD_SECRET_TOKEN` when using `upload` or `flush`

`DUD_ECH_MODE` accepts:

- `hard`: fail if ECH cannot be used
- `grease`: send ECH GREASE while allowing fallback behavior

The Dockerfile builds `curl` from source with ECH enabled using curl's
experimental ECH build path instead of relying on a distro package.

Examples:

```sh
docker run --rm -it -v "$PWD:/work" ghcr.io/wojciechpolak/dud/dud-client:latest test
```

The `test` command always prints a short summary including the DoH resolver, ECH
mode, negotiated TLS details, ALPN, and the ECH result reported by `curl`,
followed by the Worker's `/v1/test` JSON response.

```sh
docker run --rm -it --tmpfs /tmp:rw,noexec,nosuid,size=128m -e DUD_SECRET_TOKEN=YOUR_TOKEN -v "$PWD:/work" ghcr.io/wojciechpolak/dud/dud-client:latest upload --file /work/input.bin --ttl 24h
docker run --rm -it --tmpfs /tmp:rw,noexec,nosuid,size=128m -v "$PWD:/work" ghcr.io/wojciechpolak/dud/dud-client:latest download --id YOUR_ID --out /work/output.bin
printf '%s' 'secret message' | docker run --rm -i --tmpfs /tmp:rw,noexec,nosuid,size=128m -e DUD_SECRET_TOKEN=YOUR_TOKEN ghcr.io/wojciechpolak/dud/dud-client:latest upload --json
docker run --rm -i --tmpfs /tmp:rw,noexec,nosuid,size=128m ghcr.io/wojciechpolak/dud/dud-client:latest download --id YOUR_ID --stdout > output.bin
docker run --rm -it --tmpfs /tmp:rw,noexec,nosuid,size=128m -e DUD_SECRET_TOKEN=YOUR_TOKEN ghcr.io/wojciechpolak/dud/dud-client:latest flush
```

`upload` prints a human-friendly summary, a suggested `dud receive ...` command,
and a terminal QR code for that command by default. Add `--no-qr` to suppress
the QR block. For scripts or other machine-readable use cases, add `--json` to
print the raw upload response. Without `--file` or `-m`, `upload` reads
plaintext from stdin. `download` writes to a file with `--out`, to stdout with
`--stdout`, or extracts bundled archives with `--extract`.

Use `dud --version` to print the client version.

Encryption mode flags:

- `upload` defaults to passphrase mode unless you provide `--recipient` or
  `--recipient-file`
- `upload --recipient AGE_RECIPIENT` or `upload -r AGE_RECIPIENT` can be
  repeated
- `upload --recipient-file /work/recipients.txt` or
  `upload -R /work/recipients.txt` reads one or more age recipients from a file
- `download --identity /work/key.txt` or `download -i /work/key.txt` decrypts
  with an age identity file
- `keygen` creates a standard age key pair on stdout
- `keygen --out /work/key.txt` creates a standard age key pair in a file
- `keygen --pq` creates a post-quantum age key pair on stdout
- `keygen --pq --out /work/key.txt` creates a post-quantum age key pair in a
  file
- `keygen /work/key.txt` converts an identity file to recipient output on stdout
- `keygen -R /work/recipient.txt /work/key.txt` writes recipient output to a
  file

When you run `dud` with no command in an interactive terminal, it opens a small
menu for `test`, `upload`, `download`, `keygen`, and `flush`. Interactive upload
can use a file path, a one-line message, or typed/pasted text that finishes on
Ctrl-D, and it groups source-specific and encryption-specific prompts together.
Interactive download groups output-specific prompts before the optional identity
file prompt. Interactive keygen supports both generating new identities and
converting an existing identity into recipient output. If stdin is not a TTY, it
prints usage information and exits instead.

> **Security note**: `--tmpfs /tmp` keeps sensitive intermediate files
> (encrypted payloads, TLS traces) in memory only — they never reach the
> container's overlay filesystem and are gone when the container exits.

### Shell wrapper

To avoid repeating the full `docker run` flags, install a thin host wrapper:

```sh
# Wrapper script at /usr/local/bin/dud
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest install \
  | sudo tee /usr/local/bin/dud && sudo chmod +x /usr/local/bin/dud
```

Then: dud test, dud upload ..., etc.

Or print a shell function (add it to `~/.bashrc`, `~/.zshrc`, or `~/.profile`):

```shell
# 1. Review what will be added
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest shell-init

# 2. Append to your shell rc
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest shell-init >> ~/.profile
```

Or load it only for the current shell session:

```sh
eval "$(docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest shell-init)"
```

Both generated wrappers will automatically add `--env-file .env` when `./.env`
exists, and they also forward exported `DUD_BASE_URL`, `DUD_DOH_URL`,
`DUD_ECH_MODE`, and `DUD_SECRET_TOKEN` into the container. Exported shell
variables override values from `.env`.

Example `.env`:

```dotenv
DUD_SECRET_TOKEN=replace-me
# Optional overrides:
# DUD_BASE_URL=https://dud.example.com
# DUD_DOH_URL=https://cloudflare-dns.com/dns-query
# DUD_ECH_MODE=hard
```

Set `DUD_IMAGE` to override the image name embedded in the generated output.

## DUD Server

Pull the published server image:

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-server:latest
```

Run it with a persistent data volume:

```sh
docker run --rm -p 8787:8787 \
  -e DUD_SECRET_TOKEN=replace-me \
  -v "$PWD/dud-data:/data" \
  ghcr.io/wojciechpolak/dud/dud-server:latest
```

Container defaults:

- `DUD_DATA_DIR=/data`
- `DUD_LISTEN_HOST=0.0.0.0`
- `DUD_LISTEN_PORT=8787`

The image starts `node dist/src/node-server.js` under `tini` as the non-root
`dud` user. Mount `/data` if you want uploads to persist across container
restarts.

If you use Docker Compose, the checked-in `docker-compose.yml` already persists
`/data` in the named volume `dud_data`.

To reduce routine logs:

- `DUD_LOG_MODE=normal`: startup banner plus access logs with client IP
- `DUD_LOG_MODE=minimal`: startup banner plus access logs without client IP
- `DUD_LOG_MODE=silent`: suppress startup and access logs, while still keeping
  error logging

You can build images locally with the helper script:

```sh
./scripts/docker-build.sh --component client
./scripts/docker-build.sh --component server
```

## Example usage

### 1. Confirm the secure transport path

Run this before trusting the endpoint:

```sh
dud test
```

This command succeeds only if curl can reach the service with DoH, TLS 1.3, and
`--ech "$DUD_ECH_MODE"` using `hard` by default.

If you want to try GREASE mode instead:

```sh
docker run --rm -it \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  -e DUD_BASE_URL=https://dud.example.com \
  -e DUD_ECH_MODE=grease \
  -v "$PWD:/work" \
  ghcr.io/wojciechpolak/dud/dud-client:latest test
```

### 2. Upload a file, directory, or message as the sender

#### Passphrase mode

Suppose the sender wants to share `secret.pdf` and keep it available for 48
hours:

```sh
dud send --file /work/secret.pdf --ttl 48h
```

To suppress the terminal QR code and print only the text summary, add `--no-qr`:

```sh
dud upload --file /work/secret.pdf --ttl 48h --no-qr
```

The client will prompt for the passphrase through `age`. Pick a passphrase and
share it with the recipient out of band.

The upload response will look like this:

```text
Upload complete
ID: 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe
Expires: 2026-04-20T12:00:00.000Z
Delete after read: no
Receive: dud receive --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe --url https://dud.example.com
```

If you need the raw JSON instead, run the same command with `--json`.

You can also upload a one-line message directly:

```sh
dud upload -m "meet at the usual place" --ttl 24h --no-qr
```

Or stream plaintext from stdin:

```sh
printf '%s' 'streamed secret' | dud upload --json
```

If stdin is a TTY and you run `dud upload` without `--file` or `-m`, the client
accepts typed or pasted input until you press Ctrl-D, then prompts for the `age`
passphrase and uploads the encrypted payload.

To send multiple files or a directory tree, repeat `--file`. DUD creates a local
tar archive, encrypts it, and uploads only ciphertext:

```sh
dud send --file /work/report.pdf --file /work/photos --ttl 24h
```

The suggested receive command and QR code automatically include `--extract` for
bundle transfers.

Only two things need to be shared with the recipient:

- the `id`
- the passphrase

#### Public-key mode

First generate a recipient key pair. For standard age keys:

```sh
dud keygen --out /work/alice.key -R /work/alice.recipient
```

For post-quantum age keys:

```sh
dud keygen --pq --out /work/alice-pq.key -R /work/alice-pq.recipient
```

Then encrypt to the recipient's public key instead of a passphrase:

```sh
dud upload \
  --file /work/secret.pdf \
  --ttl 48h \
  -r "$(cat /work/alice.recipient)"
```

Or use a recipients file:

```sh
dud upload \
  --file /work/secret.pdf \
  --ttl 48h \
  -R /work/alice.recipient
```

In public-key mode, only the `id` needs to be shared with the recipient.

### 3. Download the file as the recipient

On another machine, the recipient can fetch and decrypt a passphrase-encrypted
upload like this:

```sh
dud receive \
  --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe \
  --out /work/received-secret.pdf
```

The client downloads ciphertext from the Worker, prompts for the passphrase, and
writes the decrypted file to `/work/received-secret.pdf`. It accepts the file ID
with or without dashes.

You do not run `age` separately on the host after download. The Docker client
container performs `age --decrypt` internally and writes the plaintext output to
the path given with `--out`.

To stream the decrypted plaintext to stdout instead, use `--stdout` and redirect
or pipe it as needed:

```sh
dud download \
  --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe \
  --stdout > /work/received-secret.pdf
```

For bundled transfers, add `--extract`. If you omit `--out-dir`, DUD extracts
into `./dud-<id>`:

```sh
dud receive \
  --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe \
  --extract \
  --out-dir /work/incoming
```

For public-key mode, pass the recipient identity file:

```sh
dud download \
  --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe \
  -i /work/alice.key \
  --out /work/received-secret.pdf
```

To print the recipient form of an existing identity to stdout, use:

```sh
dud keygen /work/alice.key
```

### 4. Optional one-time retrieval

If the sender wants the file to disappear after the first successful download,
add `--delete-after-read` during upload:

```sh
dud upload \
  --file /work/secret.pdf \
  --ttl 24h \
  --delete-after-read
```

After one successful retrieval, the same `id` will return `410 Gone`.

### 5. Flush expired objects manually

If you configured the Worker `DUD_SECRET_TOKEN` secret, you can force a cleanup
pass whenever you want:

```sh
dud flush
```

This deletes expired and already-consumed objects from R2 immediately and
returns a JSON response with `deletedCount`.

## API

### `GET /v1/test`

Returns readiness JSON:

```json
{
  "ok": true,
  "service": "dud",
  "host": "dud.example.com",
  "version": "1.2.0"
}
```

### `POST /v1/files`

Uploads an encrypted payload stream.

Request headers:

- `x-dud-secret-token`: must match the Worker `DUD_SECRET_TOKEN` secret
- `x-dud-ttl`: TTL such as `15m`, `24h`, `7d`. Default `24h`.
- `x-dud-delete-after-read`: `true` or `false`. Default `false`.
- `content-length`: optional but recommended.

Response:

```json
{
  "id": "3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe",
  "expiresAt": "2026-04-19T12:00:00.000Z",
  "deleteAfterRead": false
}
```

### `GET /v1/files/:id`

Streams ciphertext back when the file is still available.

The download endpoint accepts the file ID either as dashed groups of four
characters or as the original raw 32-character lowercase hex string.

- `404`: unknown ID
- `410`: expired or already consumed

### `POST /v1/admin/flush`

Deletes expired and already-consumed objects from R2 immediately.

Request headers:

- `x-dud-secret-token`: must match the Worker `DUD_SECRET_TOKEN` secret

Response:

```json
{
  "ok": true,
  "deletedCount": 3
}
```

## Notes

- v1 is designed for files up to 100 MB, which keeps the transfer path
  compatible with common Cloudflare request body limits.
- Public-key mode is the preferred async sharing mode because it avoids relying
  on a human-memorable passphrase for file encryption.
- The Worker is not the trust boundary for ECH. The client verifies secure
  transport before upload or download.
- Cleanup is cron-free. Expired and consumed objects are removed during normal
  traffic, and `flush` is available for an explicit cleanup pass.

## License

- **Repository default:** [MIT License](./LICENSE) unless a more specific
  component license applies
