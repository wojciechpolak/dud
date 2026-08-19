# Development

Local validation and development workflows. These are not deployment paths; for
those see the [README](../README.md#quick-start).

## 1. Repository layout

- `src/` — Worker code and Cloudflare adapters
- `src/node-server.ts` — the self-hosted Node server adapter
- `src/filesystem.ts` — the local-disk `BlobStore` implementation
- `server/` — Docker packaging for the Node server image
- `client/` — the Docker client image and the Go CLI under `client/cmd/dud/`
- `tests/` — Node tests for the server; Go tests live beside the CLI sources
- `migrations/d1` — the single idempotent D1 schema file
- `migrations/reset-d1.sql` — drops that schema so it can be applied again
- `scripts/` — build, release, and offline verification gates

## 2. Commands

| Command                 | What it does                                       |
| ----------------------- | -------------------------------------------------- |
| `npm run build`         | TypeScript → `dist/`, Go client → `client/bin/dud` |
| `npm run build:client`  | only the Go binary                                 |
| `npm test`              | build, then `node --test tests/*.test.mjs`         |
| `npm run test:client`   | `go test ./...` for the CLI                        |
| `npm run check`         | the full gate CI runs                              |
| `npm run format`        | `oxfmt` plus `gofmt`                               |
| `npm run lint`          | `oxlint` plus `go vet`                             |
| `npm run check:pins`    | offline supply-chain pin verification              |
| `npm run check:docs`    | required documents, links, and terminology         |
| `npm run check:vectors` | protocol test vectors on both sides                |
| `npm run test:e2e:v2`   | Dockerized end-to-end integration                  |
| `npx wrangler dev`      | run the Worker locally                             |

Run a single test file:

```sh
node --test tests/worker.test.mjs
```

`npm run check` is `format:check`, `lint`, the three offline gates,
`test:client`, `test:client:race`, and `npm test`. Run it before handing off a
broad change; run `npm run test:e2e:v2` as well when deployment or end-to-end
peer behavior changes.

## 3. Coverage

```sh
npm run test:coverage
```

It prints only the overall totals and writes detailed, ignored reports under
`coverage/server/` and `coverage/client/`. Each directory contains
`coverage-summary.json`; the server also provides Istanbul
`coverage-final.json`, LCOV, and a readable `details.txt`, while the client
provides the native Go `coverage.out`, per-function text, and uncovered block
ranges in its JSON summary. Run one side with `npm run test:coverage:server` or
`npm run test:coverage:client`.

## 4. Host Caddy on localhost

For local browser or manual HTTPS testing, run Caddy on the host:

```sh
npm run dev:caddy
npm run dev:caddy:trust   # if the system does not trust Caddy's local CA yet
```

The repository [Caddyfile](../Caddyfile) proxies `https://dud.localhost` to the
Dockerized `dud-server` at `127.0.0.1:8787`.

This gives local HTTPS but not real ECH, so `DUD_ECH_MODE=hard` will not work
against it. `dud.localhost` also resolves to a loopback address, which the
client refuses for every command in either mode; treat it as a browser or manual
HTTPS target, not a client test target.

## 5. Docker-only integration testing

```sh
npm run test:e2e:v2
```

This is the supported end-to-end path. It builds a private Docker network on a
globally routable range, runs `dud-server` behind Caddy, serves DNS from a DoH
server inside that network, and drives the real `dud-client` image through it.
Both transfer modes use the same in-process transport there, with no host-side
DNS or connection overrides.

It rebuilds both images first, so a run cannot pass against source it never
executed, the failure that looks like a pass. An unchanged working tree makes
that a BuildKit cache hit of about a second, and the cache compares the build
inputs rather than the image timestamp, which is what keeps it honest while a
change is still uncommitted. `DUD_E2E_SKIP_BUILD=1` skips it and says loudly
what the resulting pass is worth; `DUD_E2E_CLIENT_IMAGE` and
`DUD_E2E_SERVER_IMAGE` name images the script did not build and therefore does
not check.

`DUD_CONNECT_TO` is inert: the in-process transport rejects it outright rather
than letting a request skip DoH resolution and the destination checks, so no
environment variable redirects a hostname to a local address. The "injected test
transport" named in that error is an internal Go test interface; release clients
have no flag or variable that enables it.

For a fully local automated check of peer behavior, use the suites directly; the
Go tests inject the restricted test transport, and the Node tests exercise the
peer service, storage, authorization, pairing, delivery, and protocol code:

```sh
npm run test:client
node --test tests/v2-*.test.mjs
```

`tests/v2-workerd.test.mjs` is the one suite that substitutes nothing: it
bundles the Worker the way Wrangler does, runs it on workerd, and gives it a
real D1 migrated from `migrations/d1` and a real R2 bucket. Reach for it
whenever a change depends on how the runtime behaves rather than on what the
code says: the type D1 returns for a column, what R2 requires of a stream, or
whether the checked-in schema still matches the queries.

## 6. Real ECH

Beyond local testing:

- use a public hostname that already has an A/AAAA record pointing at the server
- use DoH or DoT on the client side
- use a Caddy build with the right `caddy-dns` provider module
- configure the global `dns` and `ech` options in the [Caddyfile](../Caddyfile)

Caddy's documentation notes that functioning ECH requires publishing HTTPS DNS
records, and therefore a Caddy build with a DNS provider module.

## 7. Documentation rules

`npm run check:docs` is a gate, not a linter suggestion. It verifies that every
required document exists, that every relative link between Markdown files
resolves, and that the naming stays consistent:

- the two transfer modes are named, not numbered: a **dead drop** and a **peer**
  transfer. Neither is "legacy", and a drop is not "one-shot": a drop stays
  fetchable until its TTL expires unless `--delete-after-read` was set.
- a document may use the shorthand only after writing `dead drop` in full
- the two ECH modes are `hard` and `off`; no other name for them is accepted
- `v1` and `v2` stay where the number names something literal: routes, HKDF
  strings, on-disk names, deployment shapes, and file names
- environment variables are named by mode: `DUD_DROP_*` and `DUD_PEER_*`

Markdown is formatted by `oxfmt` at 80 columns with `proseWrap: always`, so run
`npm run format` after editing prose.
