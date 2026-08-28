# DUD Git synchronization

`dud git push PEER` and `dud git fetch PEER` move a Git repository between two
paired devices as encrypted bundles. The server sees one opaque ciphertext body
and never a ref name, a commit, or a path.

This document covers the model, the commands, what the receiver enforces before
anything touches its object database, and how to read a failure. Pairing itself
is in [`peer-setup.md`](peer-setup.md).

## 1. The model

- **Every checkpoint is a complete ref snapshot.** The object pack may be
  complete or incremental, but its signed metadata and bundle header always name
  the complete desired branch and tag state. DUD builds an incremental only from
  a checkpoint the peer acknowledged.
- **The transport is a peer delivery.** A checkpoint is an ordinary v2 delivery
  addressed to a peer alias, so it inherits capability scoping, rotating slots,
  and signed acknowledgements.
- **Only remote-tracking refs move.** A fetch promotes into
  `refs/remotes/<remote>/*` and nothing else. Your local branches, HEAD, working
  tree, and index are never touched by DUD.
- **Repository identity is explicit.** Each repository has a local identifier,
  and a peer's checkpoints are bound to the identifier you associated with that
  peer. Fetching from a different repository than the one you associated is a
  metadata mismatch, not a merge.

Both SHA-1 and SHA-256 repositories are supported. A SHA-1 repository produces a
version 2 bundle; a SHA-256 repository produces a version 3 bundle carrying its
`object-format` capability.

`dud git push` and `dud git fetch` reject shallow repositories. A Git bundle
does not carry `.git/shallow`, so a checkpoint from a shallow repository can
reference parent commits that the sender does not have. Fetch the missing
history, usually with `git fetch --unshallow`, before synchronizing.
`dud git status` still reports, because reading stored peer state neither packs
nor applies objects.

## 2. Sending a checkpoint

From the repository root:

```sh
dud git push laptop                       # every branch and tag
dud git push laptop --current             # the checked-out branch only
dud git push laptop --branch main --branch release
dud git push laptop --full
dud git push laptop --incremental
dud git push laptop --ttl 24h --json
```

- `--branch` may repeat and selects `refs/heads/<name>`.
- `--current` requires an attached branch and cannot be combined with
  `--branch`.
- `--ttl` defaults to 168 hours and cannot exceed 720 hours.
- Automatic mode is the default. It sends an incremental when the peer
  advertises feature 6 and the selected branches have an acknowledged base.
- `--full` always sends a complete object pack. `--incremental` requires a clean
  feature 6 advertisement and an acknowledged branch base. The two options are
  mutually exclusive.
- `--url`, `--doh-url`, and `--ech-mode` are rejected because a paired
  relationship pins its own origin and transport mode.

Only `refs/heads/*` and `refs/tags/*` are advertised. Any other namespace is
refused before the bundle is built.

Automatic mode sends a complete checkpoint for bootstrap, after a signed full
recovery request, when incremental packing adds no objects, or after 16
persisted incremental checkpoints since the last complete one. Explicit
`--incremental` bypasses the 16-checkpoint cadence but fails if its pack would
contain no objects. Deletion-only and ref-only changes therefore use a complete
checkpoint in automatic mode.

Text output names a `complete Git checkpoint` or an
`incremental Git checkpoint`. Push and fetch JSON include `checkpoint_mode` with
value `full` or `incremental`. Incremental results also include `base_sequence`.

## 3. Receiving a checkpoint

```sh
dud git fetch laptop --associate    # first fetch from this peer
dud git fetch laptop                # every later fetch
dud git fetch laptop --allow-rewrite
```

`--associate` is required exactly once per peer, and it is the step where you
accept that this peer's repository identity is the one you want tracked here.
Without it a first fetch refuses rather than guessing.

The remote name defaults to the peer alias, so `dud git fetch laptop` promotes
into `refs/remotes/laptop/*`. Merging stays an ordinary Git operation you
perform deliberately:

```sh
git merge --ff-only laptop/main
```

For bidirectional sync, give each side the other's alias. Use `laptop` on the
desktop and `desktop` on the laptop.

## 4. History rewrites

A checkpoint whose refs are not descendants of what you already have is a
rewrite. It is refused by default:

```
... requires --allow-rewrite
```

Re-run with `--allow-rewrite` only when you know the sender rewrote history on
purpose. Because a checkpoint is complete, approving a rewrite also removes
remote-tracking refs for branches the sender deleted; that is the point of a
checkpoint, and the reason the approval is explicit.

## 5. What the receiver enforces

Nothing from a peer reaches your real object database until it has passed every
check below in a bounded scratch repository. A failure discards the scratch
repository and leaves your refs and objects untouched.

**Before unpacking**

- the bundle is a regular file, non-empty, and within the local byte limit
- free space is at least three times the bundle size
- the bundle header's version, refs, and prerequisites match the signed
  encrypted metadata exactly
- complete checkpoints have no prerequisites
- incremental prerequisites are sorted, unique, and derived exactly from the
  authenticated, output-committed base checkpoint named by `base_sequence`
- every prerequisite commit exists in the real object database

**While unpacking**, Git runs with hooks disabled, all protocols denied except
the local file access it needs, one packing thread, bounded pack memory, and on
Linux an address-space `ulimit`. A complete checkpoint uses `bundle verify`,
`bundle unbundle`, and a full strict `fsck` in an empty scratch repository.

An incremental checkpoint takes a narrower path. DUD passes only the pack
section to `git index-pack --stdin --strict`, without `--fix-thin`, and exposes
the real object directory as a read-only alternate. It creates the signed refs
in scratch after indexing. It does not run `bundle verify` or a full `fsck`,
because those commands can walk unrelated packs in the real repository.

**After unpacking**

- `git fsck --strict --full --no-reflogs` passes
- the pack contains no more than the object-count limit, counting objects that
  no advertised ref reaches; `fsck` accepts dangling objects, so a hostile
  sender can pad a pack past them
- no delta chain is deeper than the delta-depth limit
- the expanded object store is within the disk budget

`verify-pack` runs only on indexes created in the scratch object directory.
Large or corrupt unrelated packs in the real repository are outside the
incremental validation scan.

Every Git subprocess runs under a wall-time limit, and its output is captured
into a bounded buffer. A failure is reported ASCII-quoted, so a hostile ref name
or error message cannot inject control characters into your terminal.

## 6. Local limits

Each limit has a fixed maximum and a per-repository Git configuration key that
may only make it stricter. A value above the maximum is a configuration error,
not a weaker limit.

| Key                     | Maximum | What it bounds                           |
| ----------------------- | ------- | ---------------------------------------- |
| `dud.gitBundleBytes`    | 100 MiB | bundle size                              |
| `dud.gitObjectCount`    | 500,000 | objects in the received packs            |
| `dud.gitDeltaDepth`     | 50      | delta chain depth                        |
| `dud.gitWallSeconds`    | 120     | wall time for any one Git subprocess     |
| `dud.gitMemoryBytes`    | 1 GiB   | address space and pack memory            |
| `dud.gitDiskMultiplier` | 3       | scratch disk as a multiple of the bundle |

Tighten them on a repository you fetch into from a peer you trust less:

```sh
git config dud.gitObjectCount 20000
git config dud.gitWallSeconds 30
```

## 7. Status and troubleshooting

```sh
dud git status            # every associated peer
dud git status laptop --json
```

The status reports the last received and last acknowledged sequence, the count
of incremental checkpoints since the last complete one, a pending complete
recovery request, per-branch divergence, pending outbound checkpoints, and any
quarantined deliveries with the reason each failed. Each peer gets its own
section:

```text
Repository  4f1c9a2b8e7d6c5b

Peer laptop
  remote                      laptop
  received sequence           7
  acknowledged sent sequence  6
  incremental checkpoints since full  3
  complete checkpoint required        false
  pending outbound            0
  queued completions          0
  undrained control           false
  quarantined chains          0
  halted                      false
  quarantined Git deliveries  none

  Divergence
    main  local-only 2, peer-only 0
```

| Message                                                          | What it means                                                              |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `Git bundle exceeds the local limit`                             | over `dud.gitBundleBytes`; raise the local limit or push fewer branches    |
| `Git bundle contains more than N objects`                        | over `dud.gitObjectCount`, counting unreachable objects                    |
| `Git bundle delta depth D exceeds the limit`                     | over `dud.gitDeltaDepth`; the sender packed unusually deep chains          |
| `Git operation exceeded the ... wall-time limit`                 | the repository is larger than the local time budget allows                 |
| `git ... does not support shallow repositories`                  | fetch the missing Git history and retry                                    |
| `Git quarantine requires N free bytes`                           | not enough free space for the 3x reservation                               |
| `Git bundle header does not match the signed encrypted metadata` | the bundle and its signed metadata disagree; treat the sender as hostile   |
| `Refused Git checkpoint N: ...`                                  | the checkpoint cannot be applied; the peer was told and the chain advanced |
| `incremental Git base checkpoint is unavailable`                 | the peer receives a signed request for a complete checkpoint               |
| `requires --allow-rewrite`                                       | the incoming history is not a descendant of what you have                  |
| `No pending Git checkpoint from PEER`                            | nothing to fetch; the sender has not pushed since your last fetch          |

A quarantined delivery never entered your repository. Once you understand why it
failed, either ask the sender to push again or drop it; there is nothing to
clean up on your side beyond the quarantine directory the client manages itself.

A refused checkpoint differs from a failed one. A failed checkpoint stays
pending. After fixing the cause, such as freeing disk space or raising a local
limit, fetching again picks it up. A refusal is final. This client cannot apply
the checkpoint, so it acknowledges the refusal and advances the chain. That
prevents one bad checkpoint from stalling later transfers. `dud git status PEER`
lists both, along with any checkpoint of yours the peer refused.

If the authenticated base or a prerequisite commit is unavailable, the refusal
adds a signed `full_checkpoint_required` hint. The next automatic
`dud git push PEER` sends a complete checkpoint. `dud sync` records the hint but
does not push because it has no repository context. Flat refusals and hints
attached to complete checkpoints do not trigger recovery.

## 8. What the server learns

A checkpoint is an opaque delivery body. The server learns its size, timing,
TTL, and relationship. Every v2 delivery exposes the same metadata, listed in
[`threat-model-v2.md`](threat-model-v2.md#4-known-metadata-leakage). The server
does not learn that the payload is a Git bundle, which branches it carries, or
anything about the commits.

The payload type is carried in the encrypted descriptor, so only the peer knows
to treat it as a bundle.

## 9. Dead drop Git sync

The same repository can also be moved by object ID, with no pairing and no
sender authentication. That form is unchanged on a dual-stack deployment and is
documented in [`dead-drops-v1.md`](dead-drops-v1.md#5-git-sync-by-id).

## 10. Related documents

- [`peer-setup.md`](peer-setup.md): pairing two devices
- [`recovery-v2.md`](recovery-v2.md): recovering a stuck relationship
- [`protocol-v2.md`](protocol-v2.md): descriptors, slots, and payload-type
  metadata
- [`threat-model-v2.md`](threat-model-v2.md): hostile object databases and ref
  input
