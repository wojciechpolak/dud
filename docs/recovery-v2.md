# DUD v2 Recovery

What to do when something goes wrong: a bad deploy, a lost device, a corrupted
local state directory, a stuck peer relationship, or a partial backup. Each
section states the symptom, what is safe, and the procedure.

Operational background is in [`server-v2.md`](server-v2.md); the adversary model
behind these rules is in [`threat-model-v2.md`](threat-model-v2.md).

## 1. Principles

- **Rolling a flag back never destroys state.** Disabling v2 leaves its metadata
  and bodies untouched; disabling v1 leaves its objects in place.
- **Replay protection does not reset.** A nonce claimed before a rollback is
  still claimed after it. This is deliberate: an operator must not be able to
  reopen a replay window by restarting.
- **Revocation is durable.** It survives restart, rollback, and restore from a
  backup taken after the revocation.
- **Local erasure is local.** No client command deletes server data, a peer's
  copy, a backup, or a snapshot.
- **Recovery never re-derives an identity from a peer's word.** Anything a peer
  asserts about your keys is evidence to check, not a state change.

## 2. Rolling a server back

Symptom: a v2 deploy misbehaves and you want the previous surface.

```sh
# Cloudflare: set DUD_PEER_ENABLED = "false" under [vars], then
npx wrangler deploy

# Self-hosted
DUD_PEER_ENABLED=false  # restart the server
```

While rolled back:

- every `/v2/` route answers the v2 error document with code `4`
- v1 keeps serving its objects, uploads, downloads, and flush unchanged
- v1 traffic does not touch the v2 tree at rest

Rolling forward again restores the exact prior v2 state. If you also rolled the
_code_ back to a release before a schema change, apply the corresponding
migration again before re-enabling; the v2 schema is idempotent and safe to
re-apply.

Do not delete the v2 data while rolled back if you intend to roll forward. A
deployment that loses its metadata but keeps its bodies, or the reverse, needs
§7.

## 3. Downgrading a client

Symptom: you need to run a v1-only client on a device that has v2 state.

Nothing to do. The dead drop commands do not read or write the DUD root, so
`dud upload`, `dud download`, `dud git push --id`, `dud git fetch --id`, and
`dud flush` leave the device seed and peer graph byte-identical. Upgrading again
finds the same device identity.

The reverse direction — a v2 client against a v1-only server — refuses with a
message naming the dead drop alternative rather than silently downgrading:

```
server does not offer protocol v2; use an explicit dead-drop command
such as 'dud upload --file PATH' and share its object ID
```

That refusal happens before any local state is written, so a failed
`dud peer invite` leaves no pending pairing behind.

## 4. A stuck or halted peer relationship

Symptom: `dud sync` or `dud receive` reports the relationship is halted, or work
stays queued.

Start with status:

```sh
dud inbox PEER --json
dud git status PEER --json
dud doctor --json
```

The delivery status reports pending deliveries, pending completions, pending
control publications, unacknowledged deliveries, whether inbound work is
waiting, undrained control events, quarantined chains, and the halt reason if
any.

- **Undrained control events** usually clear on the next `dud sync`, which
  drains every active peer.
- **Unacknowledged deliveries** are not a fault. Every send is unacknowledged
  until the peer actually receives it.
- **Inbound waiting** reports what the last inbox read saw. Only a command that
  reads the inbox — `receive`, `inbox`, `git fetch` — refreshes it, so after a
  send it still describes the previous check. `dud inbox PEER` reads it now,
  without committing anything.
- **A halted relationship** means the client detected state it will not act on
  without a human. Read the halt reason before doing anything; it names the
  invariant that failed.

### A receive that stops before the queue is empty

`dud receive PEER` drains every waiting delivery in one run, so a run that ends
with work still queued says why in its `Stopped` block:

- **Git checkpoint:** applying one needs a repository this command does not
  have. Everything ahead of it is already committed; run the
  `dud git fetch PEER` the report names, then receive again.
- **Conflict**, under `--on-conflict refuse`. The named output already exists
  with different contents. Move it aside, or rerun with the default
  `--on-conflict skip`, which commits and acknowledges the delivery without
  writing the file.
- **Already applied:** the oldest delivery is one this device has committed and
  the server has not yet retired. The completion is queued; `dud sync PEER`
  retries it.

A delivery whose output was skipped is not lost: the plaintext stays in the
durable transfer store, and the report prints the command that writes it out.

```sh
dud receive PEER --id DESCRIPTOR_DIGEST --out /work/recovered --on-conflict overwrite
```

If the relationship is genuinely unusable, revoke and re-pair (§6) rather than
editing local state by hand.

## 5. Capability expiry and reissue

Symptom: a peer operation fails because the capability is no longer active.

Capabilities expire on their own schedule and the client reissues them through
`/v2/capabilities/reissue` as part of normal peer work, proving possession of
the relationship secret, not presenting an administrative credential. In the
usual case a plain `dud sync` restores service, and `dud peer show PEER --json`
reports the reissue count.

Reissue cannot recover from a _revoked_ relationship. That is the intended
asymmetry: expiry is routine, revocation is a decision.

## 6. Losing a device, or ending a relationship

Symptom: a device is lost, stolen, or decommissioned.

From a surviving device:

```sh
dud peer revoke laptop --yes
```

`dud peer revoke` is an online protocol operation. It durably revokes the
relationship on the server and preserves local recovery evidence, so you can
still see what the relationship was. An operator with data-directory access can
do the same offline:

```sh
npm run v2:admin -- revoke --data-dir ./dud-data --relationship HEX \
    [--direction NAME] [--scope NAME]
```

Three commands sound similar and do quite different things:

| Command           | Scope                                               |
| ----------------- | --------------------------------------------------- |
| `dud peer revoke` | online; revokes on the server, keeps local evidence |
| `dud peer remove` | local; removes the profile, no server contact       |
| `dud erase`       | local; scrubs selected artifacts, no server contact |

Revocation does not delete already-published bodies. Let them expire, or remove
them from the store directly.

To pair a replacement device, initialize it and pair again. It gets a new
identity, so a peer that still trusts the old one has to confirm the new pairing
in person. That confirmation is the whole reason a replacement cannot inherit
anything.

## 7. Corrupted or partially restored server state

Symptom: metadata and bodies disagree, usually after restoring `v2.sqlite`
without the body directory, or the reverse.

Both directions are detectable and neither is silently ignored: a delivery whose
body is missing is reported unavailable, and a body no metadata names is an
orphan that consumes quota.

Reconcile one bounded page at a time:

```sh
npm run v2:admin -- reconcile --data-dir ./dud-data --json
npm run v2:admin -- reconcile --data-dir ./dud-data --cursor TOKEN --json
```

It reports only. When the report looks right, apply it:

```sh
npm run v2:admin -- reconcile --data-dir ./dud-data --apply --min-age 3600
```

`--apply` deletes orphan bodies at least `--min-age` seconds old. The age floor
exists so a body staged by an in-flight upload is never mistaken for an orphan;
do not lower it below the time a large upload takes on your deployment.

Metadata rows whose body is gone are not repairable; the ciphertext is the data.
The sender still holds the plaintext, so the recovery is to send again.

Prevention: back up the data directory as one unit. On Cloudflare, D1 and R2
have independent backup schedules, so expect to reconcile after any restore that
did not capture both at the same moment.

## 8. Rotating the deployment key

Symptom: the deployment key may have been exposed.

```sh
DUD_PEER_DEPLOYMENT_KEY=<old> DUD_PEER_NEW_DEPLOYMENT_KEY=<new> \
  npm run v2:admin -- rewrap-key --data-dir ./dud-data
```

Neither key is accepted on the command line. Deploy the new key only after the
rewrap reports success, and keep the old key until then; a deployment running
the new key against un-rewrapped records cannot decrypt any verifier secret.

If the old key is lost outright, every relationship must re-pair. Nothing else
can decrypt a stored verifier secret, so there is no recovery path and no
intention of adding one.

## 9. Corrupted local client state

Symptom: `dud doctor` reports a local issue, or a command refuses to load the
configuration.

`dud doctor` checks directory permissions, the administrative capability file,
the schema version, and peer counts, and lists each problem under `issues` in
its `Local state` section. Two cases have specific fixes:

- **Group- or world-accessible files or directories:** the client fails closed
  rather than reading a configuration or seed that is not mode `0600`. Restore
  the permissions; do not work around it.
- **An unsupported schema version:** local v2 state cannot be migrated across a
  schema version change. Erase local v2 state, initialize again, and re-pair:

```sh
dud erase all --dry-run
dud erase all --yes
dud init --device desktop --url https://your-dud-host.example.com
```

`dud erase` is offline and destructive, so preview every scope with `--dry-run`
and replace it with `--yes` only once the plan looks right. Every scope also
supports `--json`.

| Scope       | Removes                                                                                                                                       |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `pairings`  | all incomplete pairing records and their pending or unpaired profiles                                                                         |
| `peer NAME` | that local profile, its relationship secrets, delivery state, and transfer state                                                              |
| `repo`      | `.git/dud`, local `dud.*` Git configuration, all `refs/dud/*`, and only those other refs DUD recorded that have not since changed or collided |
| `all`       | the whole world directory; `all --repo` cleans the current Git repository first                                                               |

Local erasure cannot delete server data, peer copies, backups, snapshots, or
physical media remnants, and it leaves unreachable Git objects for ordinary
`git gc` rather than pruning unrelated recoverable objects.

## 10. Quarantined Git checkpoints

Symptom: `dud git fetch PEER` reports quarantined deliveries.

A received bundle is verified in a bounded scratch repository before anything
touches the real object database. A quarantined checkpoint is one that failed
that verification; nothing from it entered your repository, and no ref moved.

Read the reason with:

```sh
dud git status PEER --json
```

[`git-sync-v2.md`](git-sync-v2.md) covers the specific failures — size, object
count, delta depth, wall time, disk budget, metadata mismatch, and history
rewrite — and what each one means about the sender.

## 11. Quarantined delivery chains

Symptom: `dud receive PEER` reports `gap before sequence N`, and repeats it on
every run.

Deliveries on a chain are strictly ordered, so a missing sequence stops the
chain instead of being quietly skipped. The chain is quarantined and stays
quarantined; nothing was lost locally, and later deliveries are still on the
server waiting behind the gap.

Read the reason with:

```sh
dud sync PEER --json
```

A gap means the skipped sequences are never going to arrive, usually because
they sat queued on the sender until their TTL lapsed. Resuming abandons them,
which is why nothing retries automatically and you have to ask:

```sh
dud peer resume PEER
```

It names each quarantined chain and its reason, then asks for the peer name
typed back before it changes anything. `--yes` skips the prompt for scripted
recovery. The approval authorizes exactly one forward jump and is spent by the
next delivery accepted on that chain, so a later gap stops the chain again and
is not waved through on the strength of the earlier approval.

Ordering still holds from the delivery that resumes the chain onward. It does
not cover what was skipped, and the skipped payloads are not recoverable; ask
the sender to send them again.

## 12. Related documents

- [`server-v2.md`](server-v2.md) — deployment and operations
- [`migration-v1-v2.md`](migration-v1-v2.md) — moving between deployment shapes
- [`git-sync-v2.md`](git-sync-v2.md) — peer Git synchronization
- [`threat-model-v2.md`](threat-model-v2.md) — why these rules are shaped this
  way
