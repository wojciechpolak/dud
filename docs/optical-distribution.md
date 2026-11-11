# Optical transfer distribution

DUD release binaries keep HTTP dead drops, peer transfers, local capsule
recovery and terminal optical display on Linux, macOS and Windows, on amd64 and
arm64. The plain `dud-OS-ARCH` assets are headless. On Windows their names end
in `.exe`. `dud capabilities --local --json` reports that capability set without
reading peer configuration or contacting a server. `optical_window_build`
describes compiled window support; a desktop installation also needs its
matching helper and a graphical session. `optical_kitty` reports compiled Kitty
pixel-display support on Linux and macOS; the terminal must also answer the
graphics and pixel-size probes.

## Select an optical transfer client package

The capability matrix is `scripts/release-targets.json`. The desktop package is
`dud-darwin-arm64-desktop.tar.gz`, built on a native macOS arm64 host with Go
1.27.4, Xcode 26.5 build 17F42, SDK 26.5 and Apple clang 21.0.0 build
clang-2100.1.1.101. The CLI is compiled with cgo disabled. Its separate renderer
uses cgo and system Apple frameworks. Its recorded link inputs include Cocoa,
IOKit, CoreVideo, CoreFoundation, Security, AppKit, CoreGraphics, CoreServices
and Foundation, plus the system Objective-C, resolver and C runtimes. Ebitengine
uses the system Metal graphics implementation. Install both executables
together. Their startup remains separate so HTTP and peer commands need no
window server.

The six plain binaries, the Docker image and Homebrew source formula select
headless capabilities. Their optical window selection fails before reading input
or prompting for encryption. Select `--optical-renderer terminal` for the ANSI
adapter or `--optical-renderer kitty` for pixel display on Linux/macOS,
including Linux containers attached to a compatible host terminal with `-it`.
Docker wrappers check window selection before staging stdin; they do not mount a
host display or launch a native helper. Use a native desktop installation for an
optical window. Linux native windows require X11 development headers, runtime
libraries and target execution tests; Windows cross-compilation and source
selection do not establish a tested desktop installation. The matrix enables
only the macOS arm64 desktop package.

Verify the release checksum and provenance attestation through the release
channel before running a downloaded executable. After extracting a verified
desktop archive, install its complete capability set into an unused prefix:

```sh
tar -xzf dud-darwin-arm64-desktop.tar.gz -C VERIFIED_DIRECTORY
node scripts/install-release.mjs --from VERIFIED_DIRECTORY --variant desktop --prefix PREFIX
PREFIX/bin/dud capabilities --local --json
```

For a headless install, obtain the host's binary, `dud-OS-ARCH-provenance.json`
and `dud-OS-ARCH-NOTICES.txt` together and pass `--variant headless`. The
installer checks the host, capability set and binary digests and refuses
existing files. It stores exact notices and build provenance under
`PREFIX/share/dud`. `age`, `age-keygen` and `git` are external host
dependencies; HTTP QR text also uses `qrencode`. None of these executables is
included in the native packages.

The [dependency guide](optical-dependencies.md) describes browser/native graphs
and notice ownership. The
[receiver source guide](../server/optical-receiver/README.md) lists maintained
build and test entry points. Runtime capabilities do not promise physical camera
readability, phone memory or goodput; use the
[verification procedure](optical-verification.md) for those measurements.

## Reproduce optical transfer artifacts

```sh
./scripts/build-release-binaries.sh 3.0.0 --out EMPTY_HEADLESS_DIRECTORY
./scripts/build-release-binaries.sh 3.0.0 --desktop-host --out EMPTY_DESKTOP_DIRECTORY
```

The builder resolves the pinned Go toolchain once, disables toolchain and module
downloads during compilation, copies one fixed source snapshot into two roots
and uses separate empty build caches. Both builds use readonly modules,
`-trimpath`, `-buildvcs=false`, a fixed version and an empty build ID. Desktop
linking derives a stable Mach-O UUID from the source digest, version and helper
command and omits compiler debug paths. The native helper must pass its monitor
readiness handshake in both builds; an unavailable graphical session fails the
desktop build. Output comparison includes the exact binaries, notices and
provenance in deterministic archives. An existing nonempty output directory
fails instead of erasing build records. `SHA256SUMS` covers artifacts and their
accompanying records.

Each variant records selected module versions and sums, `go version -m` output,
source digests, Go and Node executable digests, Node/zlib versions and embedded
assets. Desktop provenance also records compiler digest, SDK path/version and
Xcode build. Exact root and nested license files and selected source-header
terms accompany each variant. The font raster and controller database must match
the pinned reproduction records in `scripts/optical-notices/provenance.json`;
their supplemental terms are in `embedded-assets.txt`. A new embedded asset or
missing module license fails packaging. Embedded asset provenance records exact
upstream revisions, generator digests, reproduction toolchain and output hashes.
A matching two-build result covers the stated compiler and SDK inputs, not an
independently reproduced compiler or SDK.

The release workflow builds the six headless assets. A desktop bundle is an
explicit native-host build and enters publication only with its target smoke
results and provenance. A cross-built native helper alone is insufficient.

## Optical transfer receiver hosting and trust

The release distributes the receiver PWA inside the server image. The server
build embeds the receiver assets and serves them at `/optical/` when
`DUD_OPTICAL_PWA_ENABLED=true`. The
[hosting guide](server-v2.md#host-an-optical-transfer-receiver) describes
deployment and offline installation.

Installation and updates require trust in the server image, HTTPS host and
installed service worker. A compromised host can replace the application,
service worker and displayed build identifier. Content hashes and build
identifiers help distinguish builds and keep their assets consistent; they do
not authenticate the code running in a phone browser. Offline availability
confirms installation, not the authenticity of installed code.
