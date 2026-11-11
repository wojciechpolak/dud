# Optical transfer receiver

This directory owns the camera PWA, QR and fountain workers, static build and
browser test harnesses. It reconstructs one bounded ciphertext session and saves
`dud-encrypted-capsule.age`. It accepts no decryption material and makes no
application network request during receipt or Save. Native `dud optical decrypt`
validates and recovers the capsule on a trusted host.

Follow the [user workflow](../../docs/optical.md),
[hosting guide](../../docs/server-v2.md#host-an-optical-transfer-receiver) and
[distribution guide](../../docs/optical-distribution.md) for installation. HTTPS
origin and service-worker trust are required for installation and updates. The
displayed build identifier does not authenticate the code running on the device.

## Sources and builds

- `src/` contains the application, image/matrix QR decoder, bounded fountain
  pipeline, capture lifecycle, diagnostics and workers.
- `public/` contains the static page and installation resources.
- `test/` contains Node tests; `testdata/` contains local immutable fixtures.
- `build.mjs` bundles repository code with esbuild and emits content-addressed
  assets, notices, manifest and service worker in `.work/pwa/`.
- `browser-runtime.mjs` supplies synthetic-camera and offline-host helpers for
  integration tests. These helpers are not included in receiver assets.

From the repository root, with the declared Node and Go toolchains:

```sh
npm ci
npm run build:optical:receiver
npm run check:optical:vectors
npm run test:optical
npm run check
```

`build:server` also embeds the PWA in a generated server module. Node and Worker
serve exactly those bytes. Do not edit generated files.
`build.mjs --output DIRECTORY` can create an asset tree for development. The
release distributes the PWA as embedded server assets. The build rejects
third-party browser runtime imports and WASM and limits the static cache to 8
MiB. [Dependencies and notices](../../docs/optical-dependencies.md) describe the
native and browser boundaries.

## Integration tools

Maintained Go fixtures live in the client module. Browser tests run them from
`client/`, including the renderer, malformed-frame image generator and native
capsule handoff helper:

```sh
go -C client run ./optical-sender/cmd/optical-sender --ciphertext CIPHERTEXT --renderer frames --frame-limit 10 --frames-dir EMPTY_DIRECTORY --block-size 1600 --qr-version 30 --qr-symbols 4 --fps 30
node --import ./tests/clean-env.mjs --test tests/optical-pwa-browser.test.mjs tests/optical-native-browser.test.mjs tests/optical-module.test.mjs
```

The fixture sender accepts raw opaque bytes and finite frame output for tests.
Use `dud optical send` for the supported encryption and display workflow. The
browser tests need Chrome or Chromium and ffmpeg in PATH, or `DUD_CHROME_BIN`
and `DUD_FFMPEG_BIN`. They exercise offline installation, local Save,
pause/reset, errors and native recovery with substituted cameras. A test that
skips for a missing browser or ffmpeg supplies no browser evidence.

The [verification procedure](../../docs/optical-verification.md) documents
`bench-isolated-memory.mjs`, sender measurements and physical phone/terminal
checks. `bench-memory.mjs` measures PNG-fed synthetic camera receipt with a
separate producer and instrumentation; its totals are not a phone memory
measurement. Its generated frames and reports go under `.work/` here.
`bench-qr-scan-cost.mjs` compares receiver source with an explicit Git baseline
and resolves the receiver source directory in that commit.

The [corpus generator](corpus/README.md) writes deterministic benchmark inputs
under `.work/corpus/`. Run it before `bench-memory.mjs`. The corpus integration
test instead uses a private temporary directory and checks complete native
optical recovery.
