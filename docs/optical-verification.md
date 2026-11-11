# Optical transfer verification

Automated tests establish byte correctness, bounded inputs and lifecycle
behavior. Synthetic desktop measurements establish generator and reconstruction
costs on the recorded host. Device claims require physical camera measurements
with exact saved ciphertext and native plaintext verification.

## Automated optical transfer checks

Run from the repository root:

```sh
npm run build:server
npm run check:optical:vectors
go -C client test ./optical-sender/... ./cmd/dud -run Optical
go -C client test -race ./optical-sender/... ./cmd/dud -run Optical
npm run test:optical:receiver
node --import ./tests/clean-env.mjs --test tests/optical-native-browser.test.mjs tests/optical-pwa-browser.test.mjs
npm run check
```

Run the full optical packages without a name filter for the QR arithmetic,
bitstream, matrix, raster, PNG and terminal tests:

```sh
go -C client test ./optical-sender/...
go -C client test ./optical-sender -run='^$' -fuzz=FuzzParseFrame -fuzztime=10s
go -C client test ./optical-sender -run='^$' -fuzz=FuzzQRMatrixBounds -fuzztime=10s
go -C client test ./optical-sender/capsule -run='^$' -fuzz=FuzzPrivateCapsuleDecode -fuzztime=10s
go -C client test ./optical-sender/capsule -run='^$' -fuzz=FuzzPrivateCapsuleFileNameAndPayload -fuzztime=10s
```

The native browser test captures the production CLI's encrypted output at a test
renderer boundary. It passes those bytes through the production PWA's synthetic
camera, saves the complete ciphertext and runs native CLI recovery. Its matrix
covers message, stdin, file and collection inputs with passphrase, X25519,
hybrid, recipient-file and repeated-recipient encryption. Its age test process
uses the real pinned age library, a fixed test passphrase and a reduced scrypt
work factor. This tests binary age interoperability and command wiring; it does
not measure a password prompt or passphrase encryption cost. Chrome, ffmpeg and
age-keygen are required. Missing tools produce an explicit skip.

The deterministic 16 MiB source case uses production browser fountain workers
without QR or camera capture. The ciphertext boundary case accepts exactly
67,108,864 encrypted bytes and rejects the next plaintext byte after container
and binary age overhead. These cases do not establish large camera transfers.
The separate browser lifecycle tests cover permission denial, installed offline
startup, pause, reset, another capsule, the receipt deadline and stale replies.

## Sender resource measurements for optical transfers

```sh
go -C client run ./optical-sender/cmd/bench-display -frames 1000 -scale 2 > display.json
```

Run each measurement without competing benchmark or test processes. Record the
Git revision, source diff or source hashes, OS, CPU, Go version, GOMAXPROCS,
power source and thermal state beside the JSON. Repeat after changing source or
settings. Keep failed attempts and raw timing arrays.

Both profiles use the same deterministic 16 MiB source, four symbols, quiet zone
4 and integer scale 2. The tool measures full scheduling, fountain frame
construction, concurrent QR encoding, rasterization and composition for 1,000
frames after 20 warm-ups. It reports process user plus system CPU, allocation
bytes/counts, median, p95 and generated frames per second. The p95 budgets are
33.333 ms for balanced and 16.667 ms for high-rate. Compare against these exact
thresholds when rounding would change the result.

A separate 1,000-frame run uses the production absolute-deadline pacer and host
timers. Its intervals, missed generation deadlines and timer lateness exclude
window presentation, GPU upload and terminal I/O. A rank-one message prepares
one display and reuses the raster. Its reference-reuse counters exclude the GUI
and terminal maintenance loops. Generator throughput is not received goodput.

## Isolated browser memory for optical transfers

```sh
npm run build:server
node server/optical-receiver/bench-isolated-memory.mjs 16 balanced memory-16-balanced.json
node server/optical-receiver/bench-isolated-memory.mjs 16 high-rate memory-16-high-rate.json
node server/optical-receiver/bench-isolated-memory.mjs 64 balanced memory-64-balanced.json
node server/optical-receiver/bench-isolated-memory.mjs 64 high-rate memory-64-high-rate.json
```

The compiled production fountain client and worker run in Chrome. An independent
producer worker generates batches of four binary frames and transfers their
buffers. Each stripe omits its last systematic block and replaces it with a
maximum-degree repair containing that block. Whole length and SHA-256 must
match. The queue must stay below 32 pending frames and four producer buffers.
Receipt runs offline after fixture preparation; host requests during receipt
fail the measurement.

DevTools carries only control and sampled heap metadata. The report separates
the receiver worker, producer worker and main page. V8 used/total heap and
backing storage are distinct counters; their individual maxima can occur at
different times. Raw samples retain timestamps, phase and queue state. A 100 ms
sampler can miss transient peaks and adds debugger overhead. A short receipt may
have only its preparation and completion samples.

The receiver worker excludes the synthetic producer's source copies, PNG/video
transport, QR workers, camera buffers, browser/GPU processes and native memory.
The main page owns the reconstructed ciphertext after completion. Saving also
requires Blob storage. Interpret these costs separately from whole-Chrome RSS;
adding process RSS can count shared pages more than once. Neither method proves
the 256 MiB phone-memory gate. A phone measurement must include its complete
receiver workload and documented native memory accounting.

## Physical optical transfer receiver procedure

Record the integrated Git revision, CLI version/capabilities, exact installed
receiver build and manifest, display, phone, OS and browser versions. Use
locally generated recipient keys and deterministic private fixtures. Keep keys
and plaintext out of receiver diagnostics. Record source length and SHA-256
before encryption. Use messages, stdin, single files and collections; include a
16 MiB source, and a ciphertext near 64 MiB after encryption overhead.

Install the PWA from a trusted HTTPS host using the
[hosting procedure](server-v2.md#host-an-optical-transfer-receiver), wait for
offline installation and allow camera permission once. Restart the installed
receiver with networking off. This checks offline operation and camera receipt;
it does not authenticate the installed code. Run the native CLI with an explicit
profile:

```sh
dud capabilities --local --json
dud optical send --file SOURCE --recipient RECIPIENT --optical-profile balanced
dud optical send --file SOURCE --recipient RECIPIENT --optical-profile high-rate
dud optical decrypt --file dud-encrypted-capsule.age --identity IDENTITY --out RECOVERED
```

For collections use `--extract --out-dir UNUSED_DIRECTORY`. Compare every file's
bytes, paths and permitted mode bits. Record full saved ciphertext length and
SHA-256, not a prefix. For a fixture run, set a private scratch directory as
TMPDIR and hash its unique `dud-optical-age-*` ciphertext while display is
active. Copy only that encrypted file to private evidence storage when an exact
binary comparison is needed. Native CLI cleanup must remove owned staging paths
after normal close and SIGINT. Confirm helper exit and camera-track release.

Start timing when presentation starts and stop at verified receipt completion.
Record plaintext goodput and ciphertext throughput separately. Export the
receiver diagnostics and record total received frames, independent equations,
repeated/rejected frames, progress gaps, retries and failure reasons. Received
frame overhead is
`(received frames / required independent equations - 1) * 100`. Include
pause/resume with the same sender, reset partway through, a second capsule,
background/foreground interruption, camera denial/retry and the 15-minute
deadline. Pause preserves the deadline; reset discards the session.

Run mounted and handheld cases under separate labels for both profiles. Record
resolution, distance, illumination, brightness, power source, battery before and
after, temperature or throttling signals and sustained receipt duration. Measure
enough unchanged baseline runs to compute a median. Record failed runs instead
of omitting them from the sample set.

The baseline is the 2020 MacBook Air built-in 13.3-inch 2560×1600 60 Hz display
and Pixel 7a rear camera at 1920×1080. Mount the phone perpendicular at 30 cm,
use 75% brightness and 300 to 500 lux indoor light without glare. Other
hardware, external displays, handheld position and lighting are separate
results. Cover Chrome and Firefox on Pixel 7a, plus Safari and Chrome on iPhone
13, with exact versions. The unchanged baseline gates are median goodput
≥102,400 B/s, 16 MiB receipt ≤180 s, received-frame overhead ≤25% and a 64 MiB
ciphertext phone memory peak ≤256 MiB. These gates require physical
measurements. Synthetic results do not pass them.

## Terminal optical transfer verification

For Kitty pixel display, use a terminal implementing the
[Kitty Graphics Protocol](https://sw.kovidgoyal.net/kitty/graphics-protocol/)
and answering pixel-size queries. Test Linux/macOS directly and a Linux Docker
container attached to the same host terminal. Keep the normal font size.

```sh
dud optical send --optical-renderer kitty --optical-profile balanced --file SOURCE --recipient RECIPIENT
docker run --rm -it --cap-drop ALL --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 -v "$PWD:/work:ro" -w /work DUD_CLIENT_IMAGE upload --optical --optical-renderer kitty --optical-profile balanced --file SOURCE --recipient RECIPIENT
```

Repeat with high-rate. At minimum scale 2, balanced needs 580×580 terminal
pixels and high-rate needs 740×740. Confirm the largest fitting integer module
scale is used, up to 16, in landscape, portrait and high-density terminal
windows. A 1740×960 area displays balanced at 870×870. Confirm unchanged module
edges and quiet zones, bounded image storage during a multi-frame transfer, and
deletion of owned images on Ctrl-C and output failure. Verify unsupported
terminals and insufficient pixels fail before reading stdin or prompting. Repeat
after resizing; a PTY that omits pixel dimensions requires restarting display
when its cell grid changes. Multiplexers must pass the graphics and query
sequences through to the emulator; the support probe rejects sessions that do
not answer them. Record actual presentation cadence and verified receiver
goodput separately from generation.

Treat camera readability and sustained terminal goodput as device-specific
experiments. Test the native CLI and headless Docker separately, with an
interactive TTY and `--optical-renderer terminal`. Build/select the exact local
image under test; a floating image tag cannot identify an integrated revision.

```sh
dud optical send --optical-renderer terminal --optical-profile balanced --optical-scale 1 --file SOURCE --recipient RECIPIENT
docker run --rm -it --cap-drop ALL --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 -v "$PWD:/work:ro" -w /work DUD_CLIENT_IMAGE upload --optical --optical-renderer terminal --optical-profile balanced --optical-scale 1 --file SOURCE --recipient RECIPIENT
```

Repeat with high-rate and integer scale 2 where the display permits it. Four
symbols require these minimum character dimensions with quiet zone 4:

| Profile   | Scale 1                | Scale 2                |
| --------- | ---------------------- | ---------------------- |
| balanced  | 290 columns × 146 rows | 580 columns × 291 rows |
| high-rate | 370 columns × 186 rows | 740 columns × 371 rows |

Each character represents one horizontal pixel and two vertical pixels using
`█`, `▀` and `▄`. Use a font whose cell height is twice its width, with
correctly aligned half-block glyphs. Disable line spacing, ligatures,
transparency, color filters and terminal reflow. Confirm explicit ANSI
foreground black/background white, no clipped rows, all quiet zones and no GUI
scaling that resamples module edges. Record font, cell dimensions, zoom,
terminal and display settings, actual columns/rows and raster scale. Larger
quiet zones increase the minimum size.

Follow the physical receipt and byte-comparison procedure for both profiles.
Record native versus Docker frame pacing, terminal output bottlenecks, camera
readability, goodput, pause/resume, reset and Ctrl-C cleanup. Verify the
terminal restores colors, cursor and alternate screen, and Docker exits with its
scratch files removed. Layout tests and successful TTY output cannot establish
terminal camera support. Device support claims require the recorded physical
results.
