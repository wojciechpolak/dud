# Migrating a deployment from v1 to v2

This document describes the two wire protocols a _server_ speaks. Dead drops and
peer transfers are permanent client features; see the README for what each one
is for.

v1 and v2 can share a hostname and storage backend, but their identities,
credentials, objects, and local state stay separate. This document explains how
to run both routes and select a deployment shape.

See [`server-v2.md`](server-v2.md) for the operational reference and
[`recovery-v2.md`](recovery-v2.md) for undoing any of this.

## 1. What does not carry over

| v1                                                        | v2                                                 |
| --------------------------------------------------------- | -------------------------------------------------- |
| one shared `DUD_DROP_SECRET` authorizes every upload      | per-relationship capabilities, proof-of-possession |
| an object ID is the whole credential                      | reading needs a scoped capability and a slot proof |
| recipients identified by an age key you exchange yourself | peers identified by a mutually confirmed pairing   |
| no local state beyond environment variables               | a device seed and peer graph under `~/.dud`        |
| `dud upload` / `dud download` with an ID                  | `dud send PEER` / `dud receive PEER`               |

Capabilities authorize transfers. A v2 deployment holds one deployment-wide
credential, `DUD_PEER_SECRET`, which authorizes creating a pairing invitation
and nothing else. Once a pair is established, its capabilities authorize every
transfer between those two devices. See
[`server-v2.md`](server-v2.md#31-enrollment-is-closed-by-default).

A dropped object remains readable by a v1 client for as long as it exists, and a
v2 client cannot read it. DUD does not import dropped objects because they carry
no sender identity; importing one would fabricate authentication.

The dead drop commands, `dud upload`, `dud download`, `dud git push --id`,
`dud git fetch --id`, and `dud flush`, retain their behavior on a dual-stack
deployment, including their defaults, accepted object-ID forms, and subprocess
exit codes. They read `DUD_DROP_SECRET` from the server and each client
environment; use the same value in every location.

## 2. The three deployment shapes

The two feature flags described in
[`server-v2.md`](server-v2.md#2-feature-flags) select a deployment shape:

1. **v1-only** — the deployment serves dead drops only.
2. **dual-stack** — both protocols share one hostname, so the server serves
   drops and peer transfers. Existing v1 clients keep working unchanged while
   devices pair.
3. **v2-only** — `/v1/` is unavailable, so the deployment cannot accept a drop.

A dual-stack deployment is a supported end state. Use it while any v1 client
needs the deployment.

## 3. Moving to dual-stack

1. Provision the v2 metadata store: D1 on Cloudflare, SQLite in the data
   directory when self-hosted. On Cloudflare, apply the migration before
   enabling the flag; the Worker refuses to start with v2 enabled and no `DB`
   binding.
2. Generate `DUD_PEER_DEPLOYMENT_KEY` and `DUD_PEER_SECRET`, plus
   `DUD_PEER_ADMIN_SECRET` if you want the online administrative routes.
   Generate each independently of the others and of `DUD_DROP_SECRET`; the
   service refuses to start if any two are equal. `DUD_PEER_SECRET` gates
   pairing enrollment and is not optional: a v2 deployment refuses to start
   without it unless you set `DUD_PEER_OPEN_ENROLLMENT=true`. Configure a Worker
   with the derived key rather than the passphrase, which costs it no key
   derivation. See
   [`server-v2.md`](server-v2.md#31-enrollment-is-closed-by-default).
3. Set `DUD_PEER_ENABLED=true` and deploy.
4. Verify both surfaces:

```sh
curl -sS https://your-dud-host.example.com/v1/test
dud capabilities
```

Discovery must advertise protocols `[1, 2]`. If it advertises `[2]`, v1 is
disabled; if `/v2/capabilities` returns `404`, v2 is not enabled.

Enabling v2 changes v1 in exactly one way: v1 traffic is metered by the shared
v2 rate and storage counters. Its routes, statuses, and bodies are unchanged.

## 4. Moving the devices

Each device initializes once and then pairs with each peer:

```sh
dud init --device desktop --url https://your-dud-host.example.com
dud doctor
```

Pairing is a mutually confirmed exchange over a short-lived rendezvous; the
procedure and its confirmation step are in [`peer-setup.md`](peer-setup.md).
Pair every pair of devices that needs to exchange data; the peer graph is not
transitive, and there is no directory.

Once paired, the peer equivalents of the dead drop workflows are:

| dead drop                           | peer                                       |
| ----------------------------------- | ------------------------------------------ |
| `dud upload --file X` then share ID | `dud send PEER --file X`                   |
| `dud download --id ID --out X`      | `dud receive PEER --out X`                 |
| `dud git push --id` / `--id` fetch  | `dud git push PEER` / `dud git fetch PEER` |
| n/a                                 | `dud sync` (drain every active peer)       |

Keep `DUD_DROP_SECRET` in place until every device has paired. Peer state does
not affect the dead drop commands; they neither read nor write it.

## 5. Moving to v2-only

Do this only when no v1 client remains, and only if you are willing to give up
accepting dead drops on this deployment.

1. Confirm nothing is still using v1. Access logs record the request path, so a
   quiet window with no `/v1/` entries is the signal.
2. Let the remaining dropped objects expire, or sweep them:

```sh
dud flush
```

3. Set `DUD_DROP_ENABLED=false` and deploy.
4. Verify:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://your-dud-host.example.com/v1/test
dud capabilities
```

The first must print `404`; discovery must advertise protocols `[2]`.

5. Remove `DUD_DROP_SECRET`. It authorizes nothing once v1 is off, and it never
   authorized a v2 route.

Disabling v1 does not delete dropped objects. They stay in the blob store until
they expire or you remove them, and re-enabling v1 makes them reachable again,
which is what makes step 3 reversible.

## 6. Rolling back

Every step above is reversible, and rolling back does not corrupt state:

- Setting `DUD_DROP_ENABLED=true` again restores the full v1 surface, including
  objects uploaded before the cutover.
- Setting `DUD_PEER_ENABLED=false` makes `/v2/` unreachable while leaving all v2
  metadata and bodies untouched at rest, so re-enabling restores the exact prior
  state, including replay protection, which does not reset.
- A device that downgrades to a v1-only client leaves its peer configuration,
  seed, and peer graph untouched, so upgrading again finds the same identity.

[`recovery-v2.md`](recovery-v2.md) covers the failure cases in detail.

## 7. v1 protocol support

Dead drops let you reach someone you have not paired with. `v1-only` and
`dual-stack` are supported deployment shapes.

The v1 wire protocol receives security fixes. New protocol features belong in
v2. Design any drop-shaped requirement that needs a wire change as a v2 feature.

If a major version removes the routes, it must:

- release with `DUD_DROP_ENABLED` defaulting to `false` first, so a deployment
  can pin the old default for one more cycle
- announce removal in [`CHANGELOG.md`](../CHANGELOG.md), with the
  supported-version window in [`SECURITY.md`](../SECURITY.md) stating the
  security-fix cutoff for the last v1-capable release
- leave dropped objects intact at every point
