# DUD

Discreet upload / download using a Cloudflare Worker on `dud.example.com`, R2
for storage, and a Dockerized client that uses `curl` plus `age`.

## What this does

- Encrypts files locally with `age --passphrase` before upload.
- Uploads only ciphertext to the Worker.
- Returns an opaque ID that the recipient can use to fetch ciphertext.
- Decrypts locally after download with the shared passphrase.
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
- [Docker](https://www.docker.com/)
- [curl](https://curl.se/)
- [age](https://github.com/FiloSottile/age)
- [DoH](https://en.wikipedia.org/wiki/DNS_over_HTTPS)
- [ECH](https://en.wikipedia.org/wiki/Server_Name_Indication#Encrypted_Client_Hello)

## First steps

These steps assume you want to deploy your own Cloudflare-backed DUD service,
but use a prebuilt Docker client image rather than building the client locally.

### 1. Clone the repository

```sh
git clone https://github.com/wojciechpolak/dud.git
cd dud
```

### 2. Install dependencies

```sh
npm ci
```

### 3. Sign in to Cloudflare

```sh
npx wrangler login
```

### 4. Create the storage resources

Create the R2 bucket:

```sh
npx wrangler r2 bucket create dud-files
```

### 5. Create your local `wrangler.toml`

Start from the checked-in example:

```sh
cp wrangler.example.toml wrangler.toml
```

Then edit `wrangler.toml` before the first deployment:

- keep `name = "dud"` unless you want a different Worker name
- change `pattern = "dud.example.com"` if you want to use a different hostname
- keep `bucket_name = "dud-files"` only if that is the bucket you created
- keep or adjust `APP_VERSION`

The real `wrangler.toml` is gitignored so machine-specific IDs and future local
changes stay out of the repository.

Important: Wrangler commands may suggest a different `binding` name such as
`dud_files`. In this repository, the Worker code expects this exact binding:

- R2 binding: `FILES`

So keep this shape in your local `wrangler.toml` unless you also change the
Worker code:

```toml
[[r2_buckets]]
binding = "FILES"
bucket_name = "dud-files"
```

### 6. Verify the repo before deploying

```sh
npm run check
```

### 7. Deploy the Worker

```sh
npx wrangler deploy
```

After deploy, make sure `dud.example.com` is actually routed through Cloudflare
and resolves to the Worker custom domain you configured.

### 8. Configure the shared secret token

Uploads and the manual `flush` command both require the same Worker secret:

```sh
npx wrangler secret put DUD_SECRET_TOKEN
```

The value of this secret is later passed to the Docker client as
`DUD_SECRET_TOKEN` when you want to upload files or run `flush`.

### 9. Pull the prebuilt client image

Pick the published image name you want to use and pull it once:

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-client:latest
```

## Repository layout

- `src/`: Worker code and Cloudflare adapters.
- `client/`: Docker client image and entrypoint script.
- `tests/`: Worker and client tests.

## API

### `GET /v1/test`

Returns readiness JSON:

```json
{
  "ok": true,
  "service": "dud",
  "host": "dud.example.com",
  "version": "1.1.0"
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

## Deploy

```sh
npm run check
npx wrangler deploy
```

## Docker client

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
docker run --rm -it --tmpfs /tmp:rw,noexec,nosuid,size=128m -e DUD_SECRET_TOKEN=YOUR_TOKEN ghcr.io/wojciechpolak/dud/dud-client:latest flush
```

`upload` prints a human-friendly summary and a terminal QR code for the returned
ID by default. Add `--no-qr` to suppress the QR block. For scripts or other
machine-readable use cases, add `--json` to print the raw upload response.

When you run `dud` with no command in an interactive terminal, it opens a small
menu for `test`, `upload`, `download`, and `flush`. If stdin is not a TTY, it
prints usage information and exits instead.

> **Security note**: `--tmpfs /tmp` keeps sensitive intermediate files
> (encrypted payloads, TLS traces) in memory only — they never reach the
> container's overlay filesystem and are gone when the container exits.

### Shell alias

To avoid repeating the full `docker run` flags, install a thin host wrapper:

```sh
# Wrapper script at /usr/local/bin/dud
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest install \
  | sudo tee /usr/local/bin/dud && sudo chmod +x /usr/local/bin/dud
```

Then: dud test, dud upload ..., etc.

Or as a shell alias (add to ~/.bashrc or ~/.zshrc)

```shell
# 1. Review what will be added
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest shell-alias

# 2. Append to your shell rc
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest shell-alias >> ~/.profile
```

Set `DUD_IMAGE` to override the image name embedded in the output.

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

### 2. Upload a file as the sender

Suppose the sender wants to share `secret.pdf` and keep it available for 48
hours:

```sh
dud upload --file /work/secret.pdf --ttl 48h
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
```

If you need the raw JSON instead, run the same command with `--json`.

Only two things need to be shared with the recipient:

- the `id`
- the passphrase

### 3. Download the file as the recipient

On another machine, the recipient can fetch and decrypt it like this:

```sh
dud download \
  --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe \
  --out /work/received-secret.pdf
```

The client downloads ciphertext from the Worker, prompts for the passphrase, and
writes the decrypted file to `/work/received-secret.pdf`. It accepts the file ID
with or without dashes.

You do not run `age` separately on the host after download. The Docker client
container performs `age --decrypt` internally and writes the plaintext output to
the path given with `--out`.

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

## Notes

- v1 is designed for files up to 100 MB, which keeps the transfer path
  compatible with common Cloudflare request body limits.
- The Worker is not the trust boundary for ECH. The client verifies secure
  transport before upload or download.
- Cleanup is cron-free. Expired and consumed objects are removed during normal
  traffic, and `flush` is available for an explicit cleanup pass.

## License

- **Repository default:** [MIT License](./LICENSE) unless a more specific
  component license applies
