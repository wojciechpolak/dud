# Peer setup

A peer transfer is addressed by the local alias of a device you have paired
with. After pairing, `dud send laptop` works. Everything that crosses the
relationship is signed by the sender, sequenced, acknowledged, and revocable.
For dead drops addressed by an opaque ID, see
[`dead-drops-v1.md`](dead-drops-v1.md).

DUD pairs two devices through one short-lived 128-bit code. The inviter displays
the code as eight lowercase four-hex groups and as a QR code. The invitee types
the code at a visible controlling-TTY prompt. Both commands wait until the
signed, mutually authenticated relationship is active.

The pairing code is the only bootstrap secret. Do not put it in an argument,
environment variable, file, standard input, log, or support bundle. DUD stores
it only in the mode-`0600` pending state needed to resume an interrupted
command, and removes that state after activation, cancellation, or expiry.

## 1. Prerequisites

Initialize both devices against the same canonical HTTPS DUD origin:

```sh
dud init --device desktop --url https://dud.example.com
dud doctor
dud capabilities
```

The server must advertise `pairing` and `delivery-slots`. `dud capabilities`
also reports `enrollment`. When it says `secret-required`, the inviter needs
`DUD_PEER_SECRET` set to the enrollment passphrase the operator issued; when it
says `open`, anyone who reaches the hostname can pair. Either way the invitee
needs only the pairing code, so pairing with someone else's device never means
handing them a deployment credential.

Pairing carries no device identity to the server and does not use the server
administration capability. `DUD_PEER_ADMIN_SECRET` and `v2-admin-capability` are
reserved for actual server administration such as relationship revocation.

A pairing code names a rendezvous, not a server. Each side reaches the origin
its invocation resolves, so both must resolve the same one. `DUD_BASE_URL`
selects the origin before the relationship exists. The origin used for pairing
becomes the peer profile's pin and outranks that variable. To keep a separate
identity for another deployment, use `DUD_PROFILE` (see
[`client.md`](client.md#3-running-more-than-one-deployment)) rather than
repointing the configuration this device already paired with.

### Peer transfers need a public transport path

Every network command in either mode, including `dud test`, `upload`,
`download`, `flush`, `doctor`, `capabilities`, pairing, delivery, sync, and Git,
rejects `DUD_CONNECT_TO` and any origin that resolves to a loopback, private,
link-local, or otherwise reserved address. This prevents a production request
from bypassing authenticated DoH resolution and destination checks, so a local
Caddy on `dud.localhost` cannot serve peer transfers.

Give both devices a real HTTPS origin whose hostname resolves through DoH to
public addresses. A self-hosted server may stay on a laptop or LAN as long as it
is published through a public hostname, for example a Cloudflare Tunnel.

`hard` requires a valid ECH configuration in the hostname's HTTPS DNS record.
Explicit `off` drops that ECH requirement for development. Public DNS,
address-range, TLS 1.3, and redirect checks still apply.

## 2. Two devices, two profiles

Each device has its own local name and assigns a local alias to the other
device, so the aliases are viewed from opposite directions:

|                    | Terminal 1 / Device 1 | Terminal 2 / Device 2 |
| ------------------ | --------------------- | --------------------- |
| Local device name  | `desktop`             | `laptop`              |
| Alias for its peer | `laptop`              | `desktop`             |
| Sends to           | `laptop`              | `desktop`             |
| Receives from      | `laptop`              | `desktop`             |

On two real machines, each device has its own seed and state. Initialize each
with its own device name, then move on to §3.

Two device identities on **one** machine need two separate configuration worlds,
or both terminals would operate as the same device. `DUD_PROFILE` moves the
whole world to `~/.dud/NAME`, and the wrapper mounts that one directory into the
container:

```sh
# Terminal 1 / desktop
export DUD_PROFILE=desktop
export DUD_BASE_URL=https://your-v2-host.example.com
export DUD_ECH_MODE=hard

dud init --device desktop
dud doctor
dud capabilities
```

```sh
# Terminal 2 / laptop
export DUD_PROFILE=laptop
export DUD_BASE_URL=https://your-v2-host.example.com
export DUD_ECH_MODE=hard

dud init --device laptop
dud doctor
dud capabilities
```

Do not run either terminal from a directory holding a server `.env`. The wrapper
forwards a current-directory `.env` into the client container, and deployment
and administrative secrets do not belong there. Work in a clean directory
instead.

### Trying it against a server on the same machine

A server running locally can still take part, as long as it is reachable through
a public hostname. A Cloudflare
[Quick Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)
is enough for a development-only test and prints a random
`https://...trycloudflare.com` URL:

```sh
# Terminal 0: keep this process running
cloudflared tunnel --url http://127.0.0.1:8787
```

The public URL is assigned when the tunnel starts, so copy it into the server
configuration before starting `dud-server`:

```dotenv
# .env in the repository; generate the v2 secrets once, separately
DUD_DROP_SECRET=local-v1-development-secret
DUD_PEER_ENABLED=true
DUD_PEER_DEPLOYMENT_KEY=<32-byte-base64url-value>
DUD_PEER_SECRET=squid-lantern-rotate-9-mango
DUD_PUBLIC_BASE_URL=https://random-words.trycloudflare.com
```

```sh
docker compose up -d --build dud-server
```

Then point both terminals at that hostname. A Quick Tunnel has no ECH
configuration, so this is the case for `export DUD_ECH_MODE=off`; everything
else in the transport profile still applies. If the tunnel restarts its hostname
changes, so update `DUD_PUBLIC_BASE_URL`, restart the server, and initialize
fresh device state for the new canonical origin.

`DUD_PEER_SECRET` gates pairing enrollment and a v2 deployment refuses to start
without it unless `DUD_PEER_OPEN_ENROLLMENT=true` is set. It is a passphrase of
at least 24 characters, not encoded bytes, because it is the one credential that
also has to reach every device that may invite. A server can hold the derived
key instead, which is what a deployment too small to run the key derivation
wants; see [`server-v2.md`](server-v2.md#31-enrollment-is-closed-by-default).
`DUD_PEER_ADMIN_SECRET` is not needed for pairing; configure it only if this
deployment will expose administrative operations such as relationship
revocation.

## 3. Pair two devices

On the inviter:

```sh
dud peer invite laptop
```

`peer invite` creates the local `laptop` profile automatically; there is no
separate profile-creation step. The command always prints output shaped like
this and then waits:

```text
Pairing code: 4664-43e6-72d9-edf8-8e80-2a2f-2652-b33b

QR Code:
<terminal QR code>
Waiting for the peer to accept...
```

On the invited device, use the desired local alias for the inviter:

```sh
dud peer accept desktop
Pairing code: 4664-43e6-72d9-edf8-8e80-2a2f-2652-b33b
```

The prompt is visible and reads only from `/dev/tty`. A scanner or human may
enter the grouped form or the identical 32 lowercase hexadecimal characters
without dashes. Uppercase, whitespace, missing or extra characters, and other
characters are rejected. It never accepts the code through arguments,
environment variables, files, or standard input.

The QR code encodes exactly the displayed 39-character pairing code and nothing
else. The complete hybrid recipient travels through the server rendezvous in an
encrypted invitation envelope, so the scanned payload stays the same size no
matter how large the invitation is. The largest invitation a deployment can
produce, one with a 253-character origin and its maximum port, is about 1.7 KiB
and stays inside the 4 KiB envelope limit both the client and the server
enforce.

No confirmation command follows. Each device verifies the encrypted invitation,
role-separated binder, peer signature, contributory hybrid HPKE result, and full
transcript, then automatically submits its signed completion. The server issues
encrypted grants only after receiving both valid completions. Both waiting
commands finish when their local peer profile is active, and both sides should
then report an active peer:

```sh
dud peer show laptop     # on the desktop
dud peer show desktop    # on the laptop
```

If either command is interrupted, rerun the same command and alias. An unexpired
pending pairing resumes. An expired invite is discarded and `peer invite`
creates a fresh code.

For automation, `dud peer invite NAME --json` returns `pairing_code` and an
identical `qr_payload`; it does not print terminal QR graphics. Acceptance
remains intentionally interactive and never reads a code from JSON, argv, an
environment variable, a file, or standard input.

## 4. Sending and receiving

The argument is always the local alias for the other device.

```sh
dud send laptop -m 'hello from desktop'
dud send laptop --stdin < notes.txt
dud send laptop --file /work/report.pdf
```

`-m`, `--stdin`, and `--file` are three ways to name one source, so exactly one
of them belongs on a command line. `--stdin` reads to end of file, so a pipe, a
redirected file, or typed input finished with Ctrl-D all send the same text
payload. The relationship is bidirectional; either side can send.

```sh
dud receive desktop
dud receive laptop --out-dir /work/received
dud receive desktop --wait 1m
```

One `dud receive PEER` drains everything that peer has waiting, oldest first,
and reports each delivery. Sending three files means one receive, not three.
`--max N` stops after N deliveries, and `--wait DURATION` applies only while the
queue is still empty, so a receive never idles after it has started draining.

Deliveries are committed strictly in order and each one is acknowledged, so a
receive cannot take a later delivery while leaving an earlier one behind.
`--on-conflict` decides what happens when an output name is already taken by
different contents:

- `skip` (the default) leaves the file alone but still commits and acknowledges
  the delivery, so the queue keeps moving. The payload stays in the durable
  transfer store, and the report prints the
  `dud receive PEER --id DIGEST --out PATH` that writes it wherever you want.
- `refuse` stops the drain at the conflict. Everything committed ahead of it is
  reported; the conflicting delivery stays queued for a later run.
- `overwrite` replaces the file.

### What a receive leaves behind

A receive stages the decrypted payload in the world's own transfer store before
it writes anything, so that a run interrupted partway can resume without asking
the peer for the delivery again. That copy is removed as soon as the output
holds the same bytes. An ordinary receive leaves the file you asked for and
nothing else, and `--id` recovery reads that file back rather than a duplicate.

DUD retains a copy for a skipped output, a message sent to stdout, or the
archive behind an extracted collection. The receive report names the copy, and
the client prunes it when the delivery's transport lifetime ends (`--ttl` on the
sending side, seven days by default). `dud erase` removes the store outright.

A Git checkpoint sits in the same queue as files, and applying it needs a
repository that `receive` does not have. It stops the drain after committing
everything ahead of it, and the report names `dud git fetch PEER`.

`dud inbox [PEER]` reports what is waiting without committing anything. The
server answers an inbox read with the oldest pending delivery and nothing else,
so this shows that one delivery plus whether more sit behind it. A full queue
listing is not withheld here; the protocol never produces one. Reading the inbox
downloads that delivery's payload, which `receive` then fetches again.

`dud sync PEER` explicitly checks control messages and retries acknowledgements,
although normal peer operations do this automatically. Git checkpoints use the
same aliases:

```sh
dud git push laptop
dud sync desktop
dud git fetch desktop --associate   # --associate only on the first fetch
dud git status desktop
```

## 5. Reading the status block

`sync`, `doctor`, `peer show`, and `git status` always end with the same status
block, and `send`, `receive`, and the Git commands print it when `-v` is given
or when something needs attention, such as queued, undrained, quarantined, or
halted work. A routine transfer reports what it did in one line, and DUD reports
a stalled relationship. Whenever the block is printed, every counter appears,
including the zeros, so a healthy relationship and a stalled one use the same
layout:

```text
Status
  queued deliveries          0
  queued completions         0
  queued control events      0
  unacknowledged deliveries  4
  inbound waiting            no
  undrained control          no
  quarantined chains         none
  halted                     no
```

The three queue counters describe work this device still owes the server. They
are non-zero only when a publication failed and will be retried, so a successful
`send` leaves them at zero. Whether the peer collected a delivery is reported as
`unacknowledged deliveries`, which drops only after the peer receives the
delivery and this device collects its signed acknowledgement. No command waits
for that. `send` publishes the delivery and returns. The peer signs the
acknowledgement when it runs `receive`, and a later `sync`, `receive`, `inbox`,
or Git command on this device collects it. `undrained control`,
`quarantined chains`, and `halted` report a stalled control channel, chains
holding unpromoted input, and a relationship that refuses further traffic.

`inbound waiting` reports whether the last inbox read left deliveries behind.
Only a command that reads the inbox refreshes it, so after a `send` that row
still describes the previous check.

Other useful diagnostics:

```sh
dud peer list
dud config validate
dud doctor
dud capabilities
```

## 6. Recovery and revocation

Inspect state before revoking:

```sh
dud peer show laptop
dud doctor
```

Then revoke explicitly:

```sh
dud peer revoke laptop --yes
```

Revocation is an administration operation and therefore requires the private
server administration capability. A rollback alert, key replacement, lost seed,
or lost relationship state requires a fresh pairing code and a new relationship
ID.

Three commands sound similar and do quite different things. `dud peer revoke` is
an online protocol operation that preserves local recovery evidence,
`dud peer remove` removes a local profile, and `dud erase` scrubs selected local
artifacts without contacting the server or the peer.
[`recovery-v2.md`](recovery-v2.md) covers all three, along with stuck
relationships, quarantined chains, and corrupted local state.

## 7. Local disk protection

DUD keeps the seed, pending code, and peer state in private mode-`0600` files
under `~/.dud`. All of it is secret, so DUD keeps it outside directories that
sync conventions copy. Full-disk encryption is the expected baseline. Endpoint
compromise remains outside DUD's threat model.
