# Supported versions and update policy

This document records the versions DUD builds and runs against, and the sources
it pins. [`.github/supported-versions.json`](../.github/supported-versions.json)
is the machine-readable form. `npm run check:pins` verifies it against the files
that enforce each claim, so the document and build stay aligned.

Security support windows for DUD itself are in [`SECURITY.md`](../SECURITY.md).

## 1. Build toolchain

| Tool | Minimum | Enforced by     |
| ---- | ------- | --------------- |
| Node | 24.0.0  | `.node-version` |
| Go   | 1.26.6  | `client/go.mod` |

Older versions may work and are not tested. CI builds on exactly the versions
those two files name.

## 2. Runtime tools

These are the versions the client and server assume on the host or in the image.

| Tool   | Minimum | Why                                                                    |
| ------ | ------- | ---------------------------------------------------------------------- |
| Docker | 24.0.0  | buildx, and the `--tmpfs` and mount options the generated wrappers use |
| Git    | 2.38.0  | bundle version 3 and SHA-256 repositories                              |
| SQLite | 3.45.0  | `node:sqlite`, the self-hosted metadata store                          |

`dud doctor` reports whether `age`, `age-keygen`, `git`, and `qrencode` resolve
on the host. Its `Tools` section shows `ok` or `missing`, so a missing tool is
visible before it breaks a transfer. It does not report `curl`. Both transfer
modes carry their own transport in Go, and the image ships no HTTP subprocess.

## 3. Pinned sources

The client image builds `age` from source at an exact commit. The `# pin:`
annotations in `client/Dockerfile` record which tag each commit is.

| Source | Tag      | Why it is built from source         |
| ------ | -------- | ----------------------------------- |
| age    | `v1.3.1` | reproducible, no distribution drift |

The transport itself is not pinned here. It is the Go standard library, so DoH,
TLS 1.3, and ECH move with the Go toolchain the client is compiled with,
recorded in section 1.

Base images are pinned by digest, never by tag:

| Image  | Pinned by           |
| ------ | ------------------- |
| Debian | `ARG DEBIAN_DIGEST` |
| Node   | `ARG NODE_DIGEST`   |

Every GitHub Actions step is pinned to a full commit SHA with a version comment
beside it.

## 4. Update policy

- **Security fixes are pulled in immediately.** A fix in age, Git, Node, Go, or
  a base image is re-pinned and released without waiting for the next feature
  release.
- **Feature updates ship with the next release.** Re-pinning to a newer upstream
  tag is a reviewed change like any other.
- **A minimum version is raised only in a minor or major release**, never in a
  patch. Raising one is a breaking change for someone.
- **The update script re-pins sources.** `./scripts/update-docker-pins.sh`
  resolves tags to commits and rewrites both the SHAs and the `# pin:`
  annotations together, so the two cannot disagree.
- **Nothing tracks a moving reference.** No `:latest`, no branch name, no tag on
  the build path. `npm run check:pins` fails the build if one appears.

## 5. Verification

Everything above is checked offline, with no network access, by:

```sh
npm run check:pins
```

It verifies that every `FROM` selects an image by digest, every source checkout
names a full commit SHA, every `# pin:` annotation has a consumer and vice
versa, every workflow action is pinned to a commit SHA with a version comment,
and that every minimum version claimed in the manifest matches the file that
enforces it.

`npm run check` runs it alongside the formatting, lint, and test gates, and the
release workflow runs it again before anything is published.
