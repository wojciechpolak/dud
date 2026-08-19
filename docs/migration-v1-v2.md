# Migrating a deployment from v1 to v2

This is about the two wire protocols a _server_ speaks, not about retiring a
transfer mode. Dead drops and peer transfers are both permanent client features;
see the README for what each one is for.

DUD 2.0 is a clean break, not an upgrade in place. v1 and v2 share a hostname
and a storage backend but nothing else: no identity, no credential, no object,
and no local state carries across. This document says what that means in
practice, how to run both at once while you move, and how to finish the move.

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

Capabilities replace the shared secret for transfer, not for admission. A v2
deployment still holds one deployment-wide credential, `DUD_PEER_SECRET`, and it
authorizes creating a pairing invitation and nothing else. Once a pair is
established, every transfer between those two devices is authorized by their own
capabilities, and the enrollment secret has no further part in it. See
[`server-v2.md`](server-v2.md#31-enrollment-is-closed-by-default).

A dropped object stays readable by a v1 client for as long as it exists, and a
v2 client cannot read it. There is no import step, and none is planned: dropped
objects carry no sender identity, so importing one would fabricate
authentication that never existed.

The dead drop commands are not deprecated by v2. `dud upload`, `dud download`,
`dud git push --id`, `dud git fetch --id`, and `dud flush` keep their exact
behavior on a dual-stack deployment, including their defaults, accepted
object-ID forms, and subprocess exit codes. The shared secret they read is named
`DUD_DROP_SECRET`; a deployment coming from 1.x carries the same value over
under that name, on the server and in every client environment.

## 2. The three deployment shapes

Migration is a walk across the two feature flags described in
[`server-v2.md`](server-v2.md#2-feature-flags):

1. **v1-only** — where you start; the deployment serves dead drops only.
2. **dual-stack** — both protocols on one hostname, so the same server serves
   drops and peer transfers. Existing v1 clients keep working unchanged while
   devices pair.
3. **v2-only** — `/v1/` is gone, and with it the ability to accept a drop.

Nothing forces you past step 2. A dual-stack deployment is a supported end
state; run it as long as any v1 client matters to you.

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

Discovery must now advertise protocols `[1, 2]`. If it advertises `[2]`, v1 is
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

Keep `DUD_DROP_SECRET` in place until every device has paired. A device that has
initialized peer state can still run the drop commands; they neither read nor
write that state.

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

## 7. The v1 protocol is frozen, not deprecated

Dead drops answer a question peer transfers cannot: reaching someone you have
not paired with. That is not a transitional need, so no deprecation is planned
and `v1-only` and `dual-stack` are both supported end states.

Frozen means the v1 wire protocol receives security fixes, not features. New
protocol work happens in v2, and a drop-shaped need that requires a wire change
is a reason to reconsider the design rather than to extend v1.

If a future major version ever did remove the routes, the process would be:

- a release landing with `DUD_DROP_ENABLED` defaulting to `false` first, so a
  deployment can pin the old default for one more cycle
- removal announced in [`CHANGELOG.md`](../CHANGELOG.md), with the
  supported-version window in [`SECURITY.md`](../SECURITY.md) stating the
  security-fix cutoff for the last v1-capable release
- nothing deleting dropped objects on your behalf at any point
