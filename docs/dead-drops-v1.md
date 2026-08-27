# Dead drops

A dead drop is addressed by an opaque ID. Encrypt to a passphrase or an `age`
recipient, upload, and hand the ID to the other side out of band. Nothing is
remembered between runs, and the ID is the whole credential.

This is the only way to reach someone you have not paired with. When you expect
to keep exchanging data with the same device, pair it instead and use
[`peer-setup.md`](peer-setup.md).

Drop commands read no configuration file. They take their target from
`DUD_BASE_URL` or `--url`, and `DUD_PROFILE` does not apply to them.

## 1. Confirm the secure transport path

Run this before trusting an endpoint:

```sh
dud test
```

It succeeds only if the client reaches the service through its own DoH
resolution and exactly TLS 1.3, with an accepted ECH handshake under the default
`hard` mode.

`hard` requires the target's HTTPS DNS record to publish a valid ECH
configuration, and the TLS handshake must use it. Otherwise, the command fails.

`off` disables ECH for that connection. DoH resolution, the public address-range
check, exactly TLS 1.3, and redirect rejection still apply. The target hostname
travels in cleartext in the TLS SNI, so a passive observer learns which host you
are talking to. A self-hosted origin without an ECH-capable front end can use
DUD this way. The trade-off is recorded as `DUD-V2-DEC-001` in
[`threat-model-v2.md`](threat-model-v2.md).

Use `hard` when the origin supports ECH. Use `off` only when you accept SNI
exposure for that origin.

## 2. Upload a file, directory, or message

### Passphrase mode

To share `secret.pdf` and keep it available for 48 hours:

```sh
dud send --file /work/secret.pdf --ttl 48h
```

The client prompts for the passphrase through `age`. Pick one and share it with
the recipient out of band. The response looks like this:

```text
Upload complete
ID                 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe
Expires            2026-04-20T12:00:00.000Z
Delete after read  no
Receive            dud receive --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe --url https://dud.example.com
```

A terminal QR code for the suggested receive command follows it. Add `--no-qr`
to print only the text summary, or `--json` for the raw JSON.

Other payload sources:

```sh
dud upload -m "meet at the usual place" --ttl 24h --no-qr   # a one-line message
printf '%s' 'streamed secret' | dud upload --json           # stdin
dud send --file /work/report.pdf --file /work/photos        # a bundle
```

With a TTY and neither `--file` nor `-m`, `dud upload` accepts typed or pasted
input until Ctrl-D. Repeating `--file` creates a local tar archive, encrypts it,
and uploads only ciphertext; the suggested receive command and its QR code then
include `--extract`.

Only two things reach the recipient: the ID and the passphrase.

### Public-key mode

This is the preferred async sharing mode, because ciphertext protected by a weak
passphrase can still be attacked offline. Generate a recipient key pair:

```sh
dud keygen --out /work/alice.key -R /work/alice.recipient
dud keygen --pq --out /work/alice-pq.key -R /work/alice-pq.recipient
```

`--pq` produces the hybrid MLKEM768-X25519 recipient, which is the same
primitive peer transfers always use. Then encrypt to the recipient's public key
instead of a passphrase:

```sh
dud upload --file /work/secret.pdf --ttl 48h -r "$(cat /work/alice.recipient)"
dud upload --file /work/secret.pdf --ttl 48h -R /work/alice.recipient
```

`-r` / `--recipient` may repeat; `-R` / `--recipient-file` reads one or more
recipients from a file. Only the ID has to reach the recipient.

## 3. Download

```sh
dud receive --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe --out /work/secret.pdf
```

The client downloads ciphertext, prompts for the passphrase, and writes the
plaintext to `--out`. You never run `age` yourself on the host; the container
decrypts internally. IDs are accepted with or without dashes.

```sh
# to stdout
dud download --id 3df7-… --stdout > /work/secret.pdf

# a bundle; without --out-dir it extracts into ./dud-<id>
dud receive --id 3df7-… --extract --out-dir /work/incoming

# public-key mode
dud download --id 3df7-… -i /work/alice.key --out /work/secret.pdf
```

To print the recipient form of an existing identity:

```sh
dud keygen /work/alice.key
dud keygen -R /work/alice.recipient /work/alice.key
```

## 4. Retrieval that consumes the object

`--delete-after-read` makes the object disappear after the first successful
download; the same ID then returns `410 Gone`. It is opt-in, so an ordinary drop
stays fetchable until its TTL expires.

```sh
dud upload --file /work/secret.pdf --ttl 24h --delete-after-read
```

## 5. Git sync by ID

`dud git push` builds a complete bundle from local branches and tags and uploads
it through the normal encrypted path; `dud git fetch --id ID` downloads,
decrypts, verifies, and fetches it. `dud git send` and `dud git receive` are
aliases for the two.

On machine A, from the repository root:

```sh
dud git push -R /work/machine-b.recipient --ttl 24h --delete-after-read
```

The response suggests the matching fetch:

```text
Receive            dud git fetch --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe --url https://dud.example.com
```

On machine B, from an initialized clone or repository:

```sh
dud git fetch --id 3df7-… -i /work/machine-b.key --remote machine-a
```

`--remote NAME` imports into `refs/remotes/NAME/*`; without it, branches land in
`refs/remotes/dud/*`. Fetching never merges, rebases, checks out, resets, or
moves a local branch, so apply the imported branch deliberately:

```sh
git merge --ff-only machine-a/main
```

For repeated bidirectional sync, give each side the other's name. Use
`machine-a` on machine B and `machine-b` on machine A. The paired equivalent,
which adds sender authentication and ordering, is in
[`git-sync-v2.md`](git-sync-v2.md).

## 6. Flush expired objects

With `DUD_DROP_SECRET` configured, force a cleanup pass at any time:

```sh
dud flush
```

It deletes expired and already-consumed objects immediately and returns JSON
with `deletedCount`. Otherwise, cleanup runs during normal traffic.

## 7. The `/v1` HTTP API

### `GET /v1/test`

Returns readiness JSON:

```json
{
  "ok": true,
  "service": "dud",
  "host": "dud.example.com",
  "version": "2.0.2"
}
```

### `POST /v1/files`

Uploads an encrypted payload stream.

Request headers:

- `x-dud-secret-token`: must match the server's `DUD_DROP_SECRET`
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

Streams ciphertext back while the object is still available. The ID is accepted
either as dashed groups of four characters or as the raw 32-character lowercase
hex string.

- `404`: unknown ID
- `410`: expired or already consumed

### `POST /v1/admin/flush`

Deletes expired and already-consumed objects immediately. Requires the
`x-dud-secret-token` header.

```json
{
  "ok": true,
  "deletedCount": 3
}
```

## Related documents

- [`client.md`](client.md): client configuration, wrappers, and JSON output
- [`peer-setup.md`](peer-setup.md): pairing devices, the other transfer mode
- [`migration-v1-v2.md`](migration-v1-v2.md): what v1 and v2 do and do not share
  on one deployment
- [`server-v2.md`](server-v2.md): running the server behind these routes
