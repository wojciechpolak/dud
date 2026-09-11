# DUD v2 recovery

Recovery procedures for a bad deploy, lost device, corrupted local state
directory, stuck peer relationship, or partial backup. Each section states the
symptom, what is safe, and the procedure.

Operational background is in [`server-v2.md`](server-v2.md); the adversary model
behind these rules is in [`threat-model-v2.md`](threat-model-v2.md).

## 1. Principles

- **Rolling a flag back never destroys state.** Disabling v2 leaves its metadata
  and bodies untouched; disabling v1 leaves its objects in place.
- **Replay protection does not reset.** A nonce claimed before a rollback is
  still claimed after it. An operator must not be able to reopen a replay window
  by restarting.
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

A v2 client against a v1-only server refuses with a message naming the dead drop
alternative rather than silently downgrading:

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
waiting, resumable uploads and downloads with their descriptor digests and
remaining bytes, undrained control events, quarantined chains, and the halt
reason if any.

- **Undrained control events** usually clear on the next `dud sync`, which
  drains every active peer.
- **Unacknowledged deliveries** are not a fault. Every send is unacknowledged
  until the peer actually receives it.
- **Inbound waiting** reports what the last inbox read saw. Only `receive`,
  `inbox`, or `git fetch` refreshes it, so after a send it still describes the
  previous check. `dud inbox PEER` reads it now, without committing anything.
- **A halted relationship** means the client detected state it will not act on
  without a human. Read the halt evidence before doing anything. JSON output
  names the watermark field, signed peer value, corresponding local value,
  control descriptor sequence and digest, and relationship ID.

An outgoing watermark is only an advertisement and cannot halt the relationship.
A rollback halt requires either a peer claim that exceeds a local send sequence
or a peer incoming-data watermark below an acknowledgement or refusal already
retained by this device. The acknowledgement being processed is not earlier
retained evidence because its watermark is signed before the sender persists
that receive step.

### Resetting trusted peers after a sequencing disagreement

Use a peer relationship reset only when both devices and their existing trust
binding remain trustworthy. Compromise, seed disclosure, or uncertainty about
the peer identity requires revocation and fresh pairing in §6.

On the first device, preview the exact abandoned work and then confirm:

```sh
dud peer reset PEER
dud peer reset PEER --yes
```

The preview counts queued small and chunked deliveries, ambiguous or pending
completions, queued control events, unacknowledged and inbound transfers,
quarantined chains, resumable transfers, and refused Git checkpoints. The first
confirmed command signs a proposal but does not activate it. On the other
device, run the command twice in the same way to inspect its own disposition and
sign acceptance. Either side can then repeat the exact recovery command shown by
`dud peer show PEER`, `dud doctor`, or JSON output:

```sh
dud peer reset PEER --yes
```

The command remains available while delivery is halted. It reads reset status
through the old signing identity without advancing either delivery chain. Once
the server has both signatures, it atomically creates the next generation and
revokes the old relationship. Retrying after a timeout or crash reads the same
signed transcript and activation receipt; it does not create a second
generation.

Before server activation, either operator may cancel the proposal:

```sh
dud peer reset PEER --cancel --yes
```

Cancellation after server activation is refused. If both devices proposed at the
same time, the lower reset ID is the winner and both status reads converge on
it.

Local activation preserves the alias, device trust, canonical origin, repository
ID, and DUD-managed remote-tracking refs. In the Git repository where the
command runs, it removes only that peer's incremental bases, acknowledgements,
pending checkpoint records, refused-checkpoint alerts, and associated quarantine
files. Both Git directions then require a complete checkpoint. The first
`dud git push PEER` sends one, and the receiver still requires `--allow-rewrite`
when the advertised refs rewrite accepted history.

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
- **Already applied.** The oldest delivery is one this device has committed and
  the server has not yet retired. The completion is queued; `dud sync PEER`
  retries it.

A delivery whose output was skipped remains in the durable transfer store. The
report prints the command that writes it out.

```sh
dud receive PEER --id DESCRIPTOR_DIGEST --out /work/recovered --on-conflict overwrite
```

If trust remains intact, use the peer relationship reset above rather than
editing state by hand. If trust is in doubt, revoke and re-pair (§6).

### An interrupted large transfer

An interrupted upload remains in the sender's private encrypted spool. Run:

```sh
dud sync PEER
```

The client verifies the saved chunks, reuses or recreates the upload lease, and
sends only the missing parts. The delivery has no server-visible sequence until
commit, so it cannot block the peer's inbox while it is incomplete.

An interrupted download remains in the receiver's private transfer directory.
Run the same receive command again:

```sh
dud receive PEER --out-dir /work/received
```

The client verifies every saved part before reuse, fetches only missing parts,
and atomically installs the complete output. The receive watermark stays at the
preceding sequence until that output commit succeeds.

To discard either checkpoint, read its 64-character descriptor digest from
`dud peer show PEER` or `dud doctor`, then run:

```sh
dud peer abandon PEER --id DESCRIPTOR_DIGEST --yes
```

For an upload, abandonment removes the unpublished server lease when reachable,
deletes the local spool, and restores the prior send-chain state. Only the
newest outbound sequence can be abandoned. A lost commit response leaves
publication ambiguous. Retrying the send resolves the same idempotent commit;
abandoning it deletes the local spool but retains the signed sequence and digest
so a different descriptor can never reuse that sequence. For a download,
abandonment deletes only the local staged chunks. The delivery remains
published, and the next receive downloads it from the beginning.

## 5. Capability expiry and reissue

Symptom: a peer operation fails because the capability is no longer active.

Capabilities expire on their own schedule and the client reissues them through
`/v2/capabilities/reissue` as part of normal peer work. It proves possession of
the relationship secret and does not present an administrative credential. A
plain `dud sync` restores service when the relationship is still valid, and
`dud peer show PEER --json` reports the reissue count.

Reissue cannot recover from a _revoked_ relationship. Expiry is routine;
revocation is a decision.

## 6. Losing a device, or ending a relationship

Symptom: a device is lost, stolen, or decommissioned.

From a surviving device:

```sh
dud peer revoke laptop --yes
```

`dud peer revoke` is an online protocol operation. It durably revokes the
relationship on the server and preserves local recovery evidence, so you can
still inspect the relationship. An operator with data-directory access can do
the same offline:

```sh
npm run v2:admin -- revoke --data-dir ./dud-data --relationship HEX \
    [--direction NAME] [--scope NAME]
```

A halted relationship takes the same command. The client does not drain or
advance either chain in that state. It uses the administrative capability to
revoke the server relationship, marks the local profile revoked after the server
confirms, and retains the halt evidence. For a relationship that is not halted,
failure to flush queued work or publish the signed peer notification does not
block the administrative revocation.

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
The sender must send the source again. A sender-side resumable spool can finish
an unpublished upload, but it cannot reconstruct a committed delivery body the
server lost.

Back up the data directory as one unit. On Cloudflare, D1 and R2 have
independent backup schedules. Reconcile after any restore that did not capture
both at the same moment.

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

[`git-sync-v2.md`](git-sync-v2.md) covers the specific failures: size, object
count, delta depth, wall time, disk budget, metadata mismatch, and history
rewrite. It also explains what each one means about the sender.

An incremental checkpoint whose authenticated base or prerequisite commit is
missing is refused rather than quarantined. The signed refusal requests a
complete checkpoint. Run `dud sync PEER` on the sender to collect it, then run
`dud git push PEER` from the repository. Automatic mode sends the complete
checkpoint; `dud sync` does not send Git data because it has no repository
context. `dud git status PEER` reports `complete checkpoint required  true`
until a later complete checkpoint is durably published.

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

- [`server-v2.md`](server-v2.md): deployment and operations
- [`migration-v1-v2.md`](migration-v1-v2.md): moving between deployment shapes
- [`git-sync-v2.md`](git-sync-v2.md): peer Git synchronization
- [`threat-model-v2.md`](threat-model-v2.md): why these rules are shaped this
  way
