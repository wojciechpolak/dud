# Optical transfer client packages

`optical` implements the
[dud/optical/1 contract](../../docs/protocol-optical.md). It owns frame
encoding/parsing, fountain recovery and the binary QR module grid. Its exported
`EncodeQRMatrix` returns caller-owned row-major modules without raster, window
or terminal operations.

`capsule` constructs and validates the private container. It imports
`client/drop` for prepared inputs and bounded archive inspection. HTTP dead drop
payloads and peer extraction retain their own formats and behavior.

`display` owns QR raster scaling, quiet zones, concurrent symbol encoding,
four-symbol composition, stripe scheduling and renderer adapters. `NewScheduler`
binds an immutable encoder to one local schedule. `RenderNext` emits a prepared
raster and its public frame plans. A rank-one session can repeat that raster.
The window adapter is selected by the `nativewindow` build tag. It starts the
sibling `dud-optical-window` helper and waits for bounded display preflight
before source preparation. The helper owns Ebitengine initialization, so absent
graphics cannot prevent HTTP commands from starting. The headless adapter
reports that the window renderer is unavailable. The direct backend in
`display/window` serves the helper and the development sender. Terminal output
uses four symbols, explicit ANSI black/white colors, complete quiet zones and
character-cell bounds. The Kitty adapter probes direct PNG support and pixel
bounds, fills the pixel area at a fitting integer module scale and streams
two-color PNG chunks without sharing files with the terminal emulator. Two image
IDs bound retained frames and keep a complete image visible during transmission.
The requested scale is a minimum, bounded by 16 pixels per module. QR generation
uses one pixel per module; palette expansion keeps larger displays out of the
RGBA generation buffers. Linux/macOS query handling restores terminal input
settings before age prompts; Docker uses the same byte stream through an
interactive TTY. Presentation pacing uses absolute deadlines and skips expired
periods. Ebitengine and its selected dependencies are pinned in the client
module. Build support and runtime packaging require the platform checks in the
[distribution guide](../../docs/optical-distribution.md).

Development sender and vector commands live under `cmd/`; native handoff,
malformed-frame image and corpus-check helpers live under `testtools/`. They
import the production packages and remain outside the shipped CLI commands.

## Local optical transfer client

Build the window-capable CLI and its helper together for the native host:

```sh
npm run build:client:optical
/tmp/dud-optical-client/dud optical send --file FILE --passphrase
```

Keep `dud-optical-window` beside `dud`. The CLI checks readiness before
consuming input or running age. The helper receives only a bounded ciphertext
file path and public display settings. A renderer close reports `display-ended`,
without claiming remote receipt. Source, container, ciphertext and recipient
staging files belong to the CLI and are removed on completion, error and
signals.

## Fixtures and checks

`testdata/format1` contains normative Go/TypeScript vectors. Its bytes are
checked by `npm run check:optical:vectors`. `testdata/format0` contains
immutable rejection vectors. `testdata/qr` contains exact independent QR oracle
matrices, including binary capacity boundaries. SHA-256 checks pin rejection
vectors, QR oracles and receiver camera fixtures.

The [deterministic corpus](../../server/optical-receiver/corpus/README.md)
covers UTF-8, binary files, collections and random/compressible payloads through
64 MiB. The Node integration test generates all 12 fixtures in a private
temporary directory and invokes `testtools/corpus-check` to verify lengths,
hashes and complete optical recovery. Missing or corrupt fixtures fail the test.
Client Go unit tests require only their local fixtures and do not invoke Node.

`cmd/bench-display` measures complete four-symbol generation, process CPU,
allocations, absolute-deadline pacing and rank-one raster reuse. The
[verification procedure](../../docs/optical-verification.md) describes its
measurement limits, isolated browser worker memory and physical phone/terminal
tests. Synthetic generator or worker results do not establish camera goodput or
phone memory.

From the repository root:

```sh
npm run check:optical:vectors
npm run test:optical
GOCACHE=/tmp/dud-go-build-cache go -C client test ./optical-sender/...
GOCACHE=/tmp/dud-go-build-cache go -C client test -race ./optical-sender/...
GOCACHE=/tmp/dud-go-build-cache go -C client test ./optical-sender -run='^$' -fuzz=FuzzParseFrame -fuzztime=10s
```

`npm run check` also checks formatting, module tidiness, declared pins,
analyzers, receiver interoperability and browser handoff. A standalone copied
client module test proves that the packages and their unit tests run with only
the client module's sources and fixtures. Fresh sender binaries and module
graphs must exclude `github.com/yeqown/go-qrcode/v2` and
`github.com/yeqown/reedsolomon`.

[QR oracle provenance](testdata/qr/README.md) describes the independent fixture
capture. [Dependencies and notices](../../docs/optical-dependencies.md) records
the shipping dependency boundaries and embedded asset provenance. The
[distribution guide](../../docs/optical-distribution.md) defines packaging and
verification. Repository implementations retain their MIT notices.
