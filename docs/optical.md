# Optical transfers

An optical transfer carries locally encrypted bytes from a native sender's
screen to a camera receiver. The PWA reconstructs opaque ciphertext and saves
it. Move that file to a trusted native host to decrypt and validate it. Optical
uses the [dud/optical/1 byte contract](protocol-optical.md), independent of the
DUD release number. HTTP dead drops and peer transfers retain their commands,
protocols, storage and trust semantics.

Use the [distribution guide](optical-distribution.md) to select and install a
client. The [receiver source guide](../server/optical-receiver/README.md) covers
builds and tests; the [verification procedure](optical-verification.md)
separates automated evidence from physical device measurements.

## Trust and installation

Use a trusted native `dud` binary for encryption and decryption. Load the PWA
from a trusted HTTPS origin, wait for offline installation to finish, then open
the installed receiver with networking off. Trust in the server image, HTTPS
host and installed service worker is required for installation and updates. A
compromised host can replace the page or service worker, including its displayed
build identifier. The build identifier and content hashes do not authenticate
the code running on the phone. Offline operation does not establish that the
installed code is trustworthy. Never enter a passphrase, age identity or other
decryption material in the PWA. The optical carrier does not authenticate who
displayed a capsule.

Anyone who records the display can attack a weak passphrase offline. Prefer a
hybrid age recipient when the sender already has it; exchange recipients and
passphrases outside the PWA. Optical performs no pairing or key exchange.

The server only hosts static receiver assets at `/optical/`, enabled with
`DUD_OPTICAL_PWA_ENABLED=true`; the default is false. The PWA is neither an HTTP
dead drop client nor a peer client. Receipt and Save make no application network
requests. Code installation and an explicit idle update can contact the static
host. Browser service-worker maintenance is separate from receipt. HTTP commands
retain their DoH, ECH and TLS transport requirements.

## Build and host an optical transfer receiver

Maintained browser sources, workers, build scripts and unit tests live in
`server/optical-receiver/`. `npm run build:server` type-checks those sources,
builds the static PWA in `server/optical-receiver/.work/pwa/` and generates
`server/src/optical-pwa-assets.generated.ts`. Node and Worker serve the same
embedded bytes. Server builds embed the receiver from
`server/optical-receiver/`.

Enable static hosting explicitly with `DUD_OPTICAL_PWA_ENABLED=true`; the
default is false. The receiver is available at `/optical/`, independently of
HTTP mode flags. Content-addressed assets, the build manifest and embedded
offline assets pin each build together. The build rejects third-party browser
dependencies and WASM and caps the offline asset cache at 8 MiB. Static hosting
accepts GET and HEAD and exposes no payload upload, download or API operation.

Use `/optical/` for bookmarks and installation on the home screen or desktop.
The installation manifest has a stable identity and launch address. Saved
`index.<build>.html` addresses resolve to the installed build even when that
file is absent from the host. The public HTML and manifest aliases disable HTTP
caching; the offline cache serves one build's content-addressed files together.

Open the receiver online and wait for `Receiver is available offline.` in the
footer before disconnecting. To install an update, use the footer's update
button with the camera off and save any completed capsule first. Offline
operation requires a completed installation and retained browser storage.
Closing the page discards received progress, including a paused transfer.

After deploying a server image with receiver hosting enabled, open the PWA
online and load the offered receiver update. Verify installation by closing the
app, enabling airplane mode, reopening it from its icon or bookmark, and
receiving and saving a capsule. Camera receipt, pause/resume, reset, Replay,
diagnostics and scan-image downloads use local resources. An offline update
check reports failure and leaves receipt available.

`npm run test:optical:receiver` runs the receiver tests against the built PWA.
`npm run check` also checks Node/Worker asset equality, reproducible isolated
production builds and installed/offline receipt in Chrome with a synthetic
camera. QR camera fixtures are excluded from the shipped assets.

Client artifact names, capability selection, runtime libraries, exact notices
and receiver hosting trust are described in
[Optical transfer distribution](optical-distribution.md).

## Send an optical transfer

The TUI offers **send → Optical → Send message / Send files**, defaulting to
Kitty and balanced. **tools → decrypt optical capsule** decrypts a receiver file
transferred to the host. The terminal is released for probing, age and display;
Q or Esc ends terminal presentation and returns to the interface.

The renderer selector includes `window` in `nativewindow` builds and `kitty` on
Linux and macOS. The standard client and Docker image offer terminal rendering.

Selecting `terminal` in the TUI uses scale 1. Its four-symbol ANSI display needs
at least 290 columns and 146 rows for balanced, or 370 columns and 186 rows for
high-rate. Check `stty size` inside the container after changing the terminal
font; it reports rows followed by columns.

```sh
dud optical send --file FILE --passphrase
dud optical send --file FILE --passphrase --optical-profile balanced
dud optical send -m MESSAGE --recipient RECIPIENT
dud optical send --file FILE --recipient-file RECIPIENTS
```

`optical send` always selects local optical sending. `upload --optical` and
`send --optical` also select optical sending. An initial peer alias, such as
`dud send laptop`, selects the peer command and rejects optical options.
`optical decrypt` processes a saved local capsule and never selects a peer.

Use one source kind: `-m MESSAGE`, one or more `--file PATH` arguments, or stdin
when neither is supplied. A single file keeps its basename as private metadata.
Repeated files or a directory form a tar collection using the dead drop input
helper. Messages use `message.txt`, stdin uses `stdin.bin`, collections use
`dud-collection.tar`. A missing or unreadable source, conflicting source kinds,
unsafe name or invalid archive fails before display. Empty stdin is a valid
stream payload. Message-option validation retains upload's nonempty-message
semantics. No raw-ciphertext option is exposed by the product command.

Optical collection preparation excludes generated AppleDouble sidecars and
removes local extended attributes, ACLs, file flags, ownership and timestamps.
The encrypted collection preserves source names, file bytes and portable
permission bits under the [optical archive policy](protocol-optical.md).

Encryption uses the dead drop age path: passphrase prompting by default or with
`--passphrase`, explicit X25519 or hybrid recipients, repeated `--recipient` /
`-r`, and `--recipient-file` / `-R`. Recipient-mode and passphrase conflicts
retain the existing dead drop rules. Optical accepts native X25519 and hybrid
recipients, including comments and blank lines in recipient files. It snapshots
those files before encryption. Plugin recipients are rejected because their
programs can fetch external key material. Secrets remain outside generated
arguments, JSON, diagnostic output and window titles. Container construction
happens before encryption; the sender checks the complete ciphertext limit
before QR allocation.

| Profile              | QR   | Block bytes | Symbols per display | Display FPS | Receiver                             |
| -------------------- | ---- | ----------: | ------------------: | ----------: | ------------------------------------ |
| `high-rate`, default | 40 L |       2,860 |                   4 |          60 | Tracked four-region scan, 60 FPS cap |
| `balanced`           | 30 L |       1,600 |                   4 |          30 | Full-frame scan, 30 FPS cap          |

Open Settings in the receiver to select the matching profile before starting:
**60 FPS tracked four QR** matches high-rate; **30 FPS full frame** matches
balanced. Both profiles send 25% initial repair symbols. Stripes with up to 31
blocks repeat sources and repairs; larger stripes send fresh maximum-degree
repairs in recovery cycles. The physical camera rate and achievable goodput
depend on devices and framing; FPS is a configured cap, not a receipt guarantee.

`--optical-renderer window|terminal|kitty` defaults to `window`. A headless
binary or unavailable graphical display fails before reading stdin, preparing
archives or prompting for encryption. It does not switch renderers
automatically. Select `terminal` explicitly for the terminal adapter, which also
checks its output capability before input preparation. A window build runs its
sibling `dud-optical-window` helper. Ebitengine initializes in that process,
keeping CLI startup independent of graphics. The helper checks the local monitor
before reporting readiness and never receives plaintext or decryption material.

Select `--optical-renderer kitty` on Linux or macOS to display pixel images in a
terminal implementing the
[Kitty Graphics Protocol](https://sw.kovidgoyal.net/kitty/graphics-protocol/).
This also works inside a Linux Docker container attached with `-it`. The sender
probes inline PNG support and pixel dimensions before reading input or prompting
for encryption. It sends complete, two-color PNGs through the terminal stream;
the emulator needs no access to container files or a host display socket. The
renderer fills the available pixel area with the largest integer module scale
that fits, up to 16 pixels per module, so font size does not determine whether
the QR layout fits. For Kitty, `--optical-scale` sets the minimum module scale;
the default minimum 2 requires 580×580 available pixels for balanced or 740×740
for high-rate. A 1740×960 area displays balanced at 870×870, using three pixels
per module. Enlarge the window or select a smaller minimum if the area is too
small. Unsupported terminals fail explicitly; there is no automatic renderer
switch. When a container PTY omits pixel dimensions, changing its cell grid ends
display so the sender can query fresh pixel bounds on restart. Ctrl-C ends
terminal display, deletes the sender's images and restores the alternate screen
and cursor.

```sh
dud optical send --file FILE --passphrase --optical-renderer kitty --optical-profile balanced
```

`--optical-quiet-zone` accepts 4..16 modules and defaults to 4;
`--optical-scale` accepts integer 1..16 and defaults to 2. A renderer must fit
all four symbols with complete quiet zones. Unsupported profiles, renderers,
ranges or output dimensions fail without reading input. Raw ciphertext, PNG
sequences, FPS overrides and benchmark knobs belong to development tools.

Window display waits for click, Space or Enter. Keep every symbol inside the
camera guide, hold both devices steady, and adjust brightness to preserve white
modules without glare. The default four-symbol rasters are 580×580 pixels for
balanced and 740×740 for high-rate. Preserve the whole 2×2 layout, crisp module
edges and each white quiet zone; avoid clipping, reflections and display
resampling. Terminal cell and font requirements are in the
[verification procedure](optical-verification.md#terminal-optical-transfer-verification).
Q, Escape or window close ends display. Ending display means only that local
presentation ended; it cannot prove the remote receiver saved or decrypted
anything. SIGINT cleans up owned files and display resources.

Explicit `--ttl`, `--delete-after-read`, `--url`, `--doh-url`, `--no-qr` and
`--id` are rejected on optical upload. Presence matters even if the supplied
value equals a default. Optical profile and renderer options require
`--optical`. Ambient HTTP server, DNS, TTL and secret settings do not prevent
optical work or cause network access. Dispatch optical before HTTP transport
construction or requiring `DUD_DROP_SECRET`.

## Receive and save an optical transfer

Open the installed PWA and press Start camera. Settings contains the camera and
profile choices; the default profile matches the high-rate sender. Camera
permission follows the Start gesture. The PWA recovers one session in memory,
shows overall recovery progress and verifies whole ciphertext length and
SHA-256. Unsupported senders produce the compatibility warning in the protocol
document; they allocate no stripe state. Reposition for unreadable QR images.
Return to the original sender for a mixed session or reset before receiving
another sender.

Pause releases the camera while retaining equations and the original 15-minute
deadline. Resume camera continues the same session and profile. A permission
failure on resume leaves it paused. Stop / reset discards incomplete or
completed bytes, releases workers and permits a different sender without
reloading. Backgrounding, page exit and fatal time/resource failures also
release the session. Reloading or closing the tab loses paused progress.

Save remains disabled until full verification. `Save encrypted capsule` writes
`dud-encrypted-capsule.age`, without interpreting received metadata or
previewing content. Save does not decrypt. A stopped incomplete receipt produces
no capsule. Do not update the PWA during receipt. Explicit updates load one
build's pinned assets together; ciphertext and camera data never enter the
offline asset cache. Diagnostics are optional local counters and timings,
without secrets or payloads. Expand Diagnostics for stripe progress, counters,
Download diagnostics, Save scan image and recorded-frame replay. Help contains
the camera instructions and privacy guidance. Update controls and the receiver
build identifier are in the footer. The interface follows the system's light or
dark appearance, including changes during receipt.

## Recover on a trusted native host

```sh
dud optical decrypt --file CAPSULE --out PATH --identity IDENTITY
dud optical decrypt --file CAPSULE --stdout --identity IDENTITY
dud optical decrypt --file CAPSULE --extract --out-dir DIR --identity IDENTITY
```

Omit `--identity` to use native age passphrase prompting. Optical decryption
reads exactly one local ciphertext file, not stdin or a camera, and performs no
HTTP fetch, DNS lookup or ID validation. It rejects `--id`, `--url`,
`--doh-url`, other network options, repeated input files and sender display
options. The explicit input file must be within `1..64 MiB` before decryption.

Choose exactly one output kind. `--out PATH` writes validated payload bytes,
including the tar bytes of a collection. `--stdout` emits the same bytes only
after complete validation. `--extract` requires a collection, uses `--out-dir`
instead of `--out`, and defaults to the working directory when no directory is
supplied. `--out-dir` without extraction and `--json` with `--stdout` fail. An
identity path must refer to a readable local identity file containing native
X25519 or hybrid keys. DUD snapshots and validates those keys before invoking
age. Plugin and encrypted identity files are rejected to keep recovery local.

Decrypt to a private staging file, validate the complete container, payload
length, SHA-256, type, safe display name and any collection archive, then commit
the output. Failed decryption, an unsupported version, truncation, trailing
data, invalid metadata or archive must emit no payload to stdout or final
destination. The private display name does not choose the destination path. An
existing `--out` destination is an error. Create it exclusively with mode 0600,
without following a destination symlink. A validation failure leaves it absent.
An output-I/O failure can leave a partial stdout write and reports failure.

Extraction validates the entire archive before creating entries, rejects
existing top-level paths, including implicit parents and Unicode-normalized
case-fold collisions, and creates regular files and directories using the
archive policy in the protocol. The chosen root may contain at most 100,000
entries so collision inspection stays bounded. Extraction cannot replace
symlinks or escape the chosen root. OS I/O failures can leave created entries
and must report failure; validation success is not a filesystem transaction.
Private staging files are removed on success, error and signals. Cleanup cannot
guarantee physical erasure from browser, filesystem or OS copies.

## Limits and local reports

The limit is 64 MiB of complete ciphertext. Container and age overhead reduce
the usable plaintext size and depend on name and recipients. The protocol
defines exact frame, equation, queue, work and 15-minute bounds. Measured
desktop memory and substituted-device rates do not establish a phone-memory
ceiling or universal throughput. The
[verification procedure](optical-verification.md) defines the required device
measurements and their interpretation.

Optical commands exit 0 for a completed local operation, 1 for a validation or
operational failure, 130 for SIGINT and 143 for SIGTERM. Optical encryption and
decryption subprocess failures map to the local error categories below, with
sanitized stderr; HTTP status exit codes do not apply to the optical branch.

`--json` writes one newline-terminated object to stdout after the operation.
Prompts and renderer output use the controlling terminal or stderr, keeping
stdout exclusively for the report. No private display name, type, payload size,
plaintext digest, recipient, identity or secret is included. The user-specified
final output path can appear in a successful decryption report. Signal exit
cannot promise a JSON report.

```json
{"mode":"optical","format":"dud/optical/1","operation":"upload","status":"display-ended","profile":"high-rate","renderer":"window","ciphertextBytes":2401}
{"mode":"optical","format":"dud/optical/1","operation":"decrypt","status":"recovered","output":"/chosen/path"}
{"mode":"optical","format":"dud/optical/1","operation":"decrypt","status":"failed","error":{"code":"decryption","message":"Optical capsule decryption failed"}}
```

Successful extraction uses status `recovered` and the actual absolute root as
`output`. Text reports use the same outcomes, and decryption names its actual
output path. Sending emits no server ID, expiry, remote receipt acknowledgement
or server download command. Failures contain only the common fields, `status`
and `error`, without partial success data.

| Error code             | Trigger                                                                             | Recovery                                        |
| ---------------------- | ----------------------------------------------------------------------------------- | ----------------------------------------------- |
| `usage`                | Invalid combination, explicit network flag, unsupported profile or renderer setting | Correct arguments                               |
| `input`                | Missing/unreadable source or identity file                                          | Correct local input                             |
| `ciphertext-limit`     | Empty or oversized ciphertext, including age overhead                               | Reduce payload or recipient count               |
| `encryption`           | Native encryption failure                                                           | Check encryption setup on the trusted host      |
| `renderer-unavailable` | Window build/display or terminal capability unavailable                             | Use a capable binary/display or select terminal |
| `renderer`             | Display preparation or rendering failure                                            | Correct display configuration and restart       |
| `unsupported-format`   | Unsupported private container version or magic                                      | Use a matching native decoder and sender        |
| `decryption`           | Authentication, identity or passphrase failure                                      | Check original secret and saved file            |
| `capsule`              | Invalid container metadata, size or digest                                          | Obtain an intact capsule                        |
| `archive`              | Collection validation or extraction-kind conflict                                   | Obtain a valid collection or choose byte output |
| `output`               | Existing destination, extraction collision or output I/O failure                    | Choose a writable unused destination            |

Frame parser codes in the protocol are decoder diagnostics, separate from these
CLI error codes. Failure reports never echo secrets, subprocess stderr or
private capsule metadata into JSON.
