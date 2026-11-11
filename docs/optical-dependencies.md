# Optical transfer dependencies and notices

Optical transfers use the native client for encryption and recovery and
repository TypeScript for browser capture and reconstruction. The two sides have
separate dependency and trust boundaries.

## Browser runtime and build tools

The receiver app, QR detector, BCH/Reed-Solomon decoder, fountain codec and
workers are repository code under MIT. Its production asset graph contains no
third-party browser library, age implementation, WASM or dynamic-evaluation
requirement. `server/optical-receiver/build.mjs` checks the graph, emits a
content-addressed repository notice and records every asset's length, type and
SHA-256. Two-build tests compare the manifest and every shipped byte.

TypeScript and esbuild are build tools pinned in `package.json` and the root
lockfile. Install them with `npm ci`; they are not browser runtime dependencies.
Node and the Go language/toolchain requirements are in
[supported versions](supported-versions.md). The
[receiver source guide](../server/optical-receiver/README.md) lists build and
test entry points. Chrome and ffmpeg are test-host dependencies, outside shipped
receiver assets.

## Native client and window helper

The client module pins age 1.3.1 for fixtures, Ebitengine 2.9.7 for the window
backend and the selected transitive Go modules in `client/go.mod` and
`client/go.sum`. The product CLI runs the host's external age executable for
payload encryption and decryption; install native X25519/hybrid-capable age.
Recipient and identity plugins are rejected by optical commands. Optical QR
encoding and raster composition use repository code and require no `qrencode`
executable. HTTP QR text has its own helper dependency.

Headless builds exclude window initialization. A desktop package contains both
`dud` and `dud-optical-window`, with its selected system libraries and compiler
recorded in provenance. Runtime dependencies, supported target selection and
installation are in [optical transfer distribution](optical-distribution.md). A
source build on an additional platform is not a tested desktop package.

Release packaging inventories the selected dependency graph, exact root and
nested licenses, selected source-header terms and embedded asset provenance. It
includes these notices beside the executable. Font and controller data must
match `scripts/optical-notices/provenance.json` and the supplemental terms in
`embedded-assets.txt`. Packaging fails for an unmatched asset or missing
required license. Keep the notices and provenance with each artifact.
