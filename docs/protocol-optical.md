# Optical transfer protocol

`dud/optical/1` identifies the optical transfer format independently of the DUD
release number. This document defines its byte contract.
[Optical transfers](optical.md) defines the command and receiver contract. The
carrier transports one `age` ciphertext, with no pairing, server object, TTL,
receipt acknowledgement or sender authentication. HTTP dead drops and peer
payloads keep their own formats.

## Format identity and compatibility

Frames use magic `44 55 44 4f 50 54 31 00`, ASCII `DUDOPT1` and a zero byte, and
version byte `01`. Private containers use magic `44 55 44 43 41 50 31 00`, ASCII
`DUDCAP1` and a zero byte, and version `01`. Both the magic and version must
match. No negotiation, downgrade or automatic conversion occurs. Unknown feature
bits are rejected.

The format-0 magic `DUDOPT0\0` is recognized only to reject it with code
`version` and message
`unsupported optical sender; expected dud/optical/1, received format 0`. A
different version byte after valid format-1 magic uses that message with the
received integer. Invalid magic uses code `magic`. A native decoder rejects
`DUDCAP0\0` with
`unsupported optical capsule; expected dud/optical/1, received format 0`. No
payload or session allocation follows these failures. The PWA displays
`Unsupported optical format` and
`Point the camera at a DUD optical transfer sender using dud/optical/1.` It
keeps scanning for valid input within the same deadline.

Format-0 rejection vectors and QR oracle matrices live in the client testdata;
camera regressions live in the receiver testdata. Their bytes are pinned by
SHA-256 in the fixture tests. The parsers accept format 1 only. Changing only a
version byte is not a supported conversion.

No optical domain-separation string is consumed by HKDF or a key derivation.
`dud/optical/1` is a specification identifier, not a key-derivation input. Frame
selection consumes the session ID, stripe index and sequence directly as
specified below. The ciphertext uses `age`'s own cryptographic format. Optical
adds no encryption, MAC, signing key or shared secret.

## Integer and size rules

Integers are unsigned, big-endian. Offsets start at the beginning of their
respective byte sequence. Length checks precede size-dependent allocations. A
complete ciphertext has length `L` in `1..67,108,864` bytes. Source-block size
`B` is exactly 1,600 or 2,860. Each stripe holds at most 1,024 blocks.

```text
stripe capacity = B * 1024
stripe count = ceil(L / stripe capacity)
stripe offset = stripe index * stripe capacity
stripe length = min(stripe capacity, L - stripe offset)
source count K = ceil(stripe length / B)
```

Stripe indexes start at zero and are below stripe count. Stripe capacity is
1,638,400 or 2,928,640 bytes, giving at most 41 or 23 stripes respectively.
Split ciphertext in byte order. Zero-pad the final source block of each stripe
to `B` bytes. Trim recovery to the derived stripe length, concatenate stripes in
index order, and check exact length and SHA-256 of the unpadded ciphertext.

## Frame layout

Each frame is the entire binary byte segment of one Model 2 QR symbol. Its
header is 88 bytes, followed by `B` equation bytes and four CRC bytes.

| Offset | Width | Field                   | Required value                       |
| -----: | ----: | ----------------------- | ------------------------------------ |
|      0 |     8 | Magic                   | `DUDOPT1\0`                          |
|      8 |     1 | Version                 | `01`                                 |
|      9 |     1 | Reserved feature bits   | `00`, reject every set bit           |
|     10 |     2 | Header length           | 88                                   |
|     12 |    16 | Session ID              | Random public bytes                  |
|     28 |     4 | Sequence                | Unsigned sequence within a stripe    |
|     32 |     2 | Stripe index            | Derived range                        |
|     34 |     2 | Stripe count            | Derived from `L` and `B`             |
|     36 |     2 | Source count            | `K`                                  |
|     38 |     2 | Block size              | `B`                                  |
|     40 |     4 | Ciphertext length       | `L`                                  |
|     44 |     4 | Stripe offset           | Derived offset                       |
|     48 |     4 | Stripe length           | Derived length                       |
|     52 |     2 | Equation payload length | `B`                                  |
|     54 |     2 | Degree                  | Selected block count                 |
|     56 |    32 | Ciphertext digest       | SHA-256 over all `L` bytes           |
|     88 |   `B` | Equation                | XOR of selected padded source blocks |
| `88+B` |     4 | CRC-32                  | Over all preceding frame bytes       |

CRC-32 is IEEE, reflected polynomial `0xedb88320`, initial `0xffffffff`, final
XOR `0xffffffff`, serialized big-endian. CRC detects damaged frames. SHA-256
detects corrupted reconstruction. Neither authenticates the sender.

A sender draws a fresh 16-byte session ID with a cryptographic random source for
each display run. It is no credential. One receipt binds session ID, ciphertext
length, digest, block size and stripe count at the first valid frame. Frames
with another ID or inconsistent metadata cannot contribute equations. Restarting
the sender requires resetting the receiver before accepting that session.

Parsers check minimum framing, magic/version/features, header length, block
size, exact frame length, equation length, CRC, ciphertext bound, stripe
count/index, stripe offset/length, source count and degree, in that order.
Shared session metadata is checked before retaining an equation. No extra header
or tail bytes are accepted.

## QR capacity and geometry

The encoder uses one binary byte segment, mode `0100`, a 16-bit byte count, no
ECI, a four-bit terminator, then alternating `ec` / `11` padding codewords. Both
profiles use level L, 30 parity codewords per Reed-Solomon block, all eight mask
candidates and integer module rendering. Mask selection changes QR raster bytes
without changing frame bytes.

| Profile     | QR version | Modules per side | Data codewords | Binary capacity | Frame bytes | Segment plus terminator | Padding codewords |
| ----------- | ---------: | ---------------: | -------------: | --------------: | ----------: | ----------------------: | ----------------: |
| `balanced`  |       30 L |              137 |          1,735 |           1,732 |       1,692 |             1,695 bytes |                40 |
| `high-rate` |       40 L |              177 |          2,956 |           2,953 |       2,952 |             2,955 bytes |                 1 |

The segment costs 4 mode bits + 16 count bits + 8 bits per frame byte + 4
terminator bits, exactly three bytes of overhead. Thus every header, payload and
CRC byte fits, including the high-rate frame's one-byte capacity margin. Version
30 uses five 115-data and ten 116-data blocks, plus three remainder bits.
Version 40 uses nineteen 118-data and six 119-data blocks, with no remainder
bits.

Four equal square symbols form a two-by-two display. Each has a white quiet zone
on all four edges of 4..16 modules and an integer raster scale of 1..16.
Defaults are quiet zone 4 and scale 2. Display size per side is
`2 * (modules + 2 * quiet zone) * scale`. Rendering must preserve these edges
and integer pixels without interpolation or cropped modules.

## Fountain selection

For `0 <= sequence < K`, select that source block alone, with degree 1. For
repair sequences, all arithmetic keeps only the low 32 bits. Logical shifts fill
with zero.

```text
mix32(x):
  x = x XOR (x >> 16)
  x = x * 0x21f0aaad
  x = x XOR (x >> 15)
  x = x * 0x735a2d97
  return x XOR (x >> 15)

state = 0x6d2b79f5
for byte in session ID, in wire order:
  state = mix32(state XOR byte)
state = mix32(state XOR stripe index)
state = mix32(state XOR sequence)
next():
  state = mix32(state + 0x9e3779b9)
  return state
```

The first `next() % 1000` chooses degree. Cap degree at `K`.

| Draw     | Degree |
| -------- | -----: |
| 0..499   |      2 |
| 500..749 |      3 |
| 750..874 |      4 |
| 875..937 |      5 |
| 938..968 |      6 |
| 969..984 |      7 |
| 985..999 |     31 |

Draw indexes with `next() % K`, discard repeats, and keep drawing until the
degree is met. Sort indexes ascending and XOR the corresponding padded blocks.
Degree 31 permits full rank after missing the systematic pass when `K > 31`.
Exclusively even-degree equations cannot span every source block. When
`K <= 31`, maximum-degree repairs all XOR the same complete set of sources.

Each stripe's initial schedule contains `K` systematic symbols and
`R = ceil(K * 25 / 100)` repair symbols, with sequences `K..K+R-1` for repair.
At position `p` in that schedule, emit repair when
`floor((p+1)*R/(K+R)) > floor(p*R/(K+R))`; otherwise emit the next systematic
symbol. Stripes with `K <= 31` repeat that complete schedule, including the
systematic sequences, so missed sources remain recoverable. For `K > 31`,
subsequent cycles contain `R` fresh degree-31 repairs per stripe. Search
ascending sequences beginning at `K+R`, then after the last emitted sequence.
Each search inspects at most 4,096 candidates without exceeding `0xffffffff`;
failure stops display, with no sequence wrap.

Interleave stripes by choosing the smallest `emitted symbols / K`, using integer
cross-multiplication and the lower stripe index to break ties. Group consecutive
symbols into four-symbol displays. A one-source-block session can repeat its
prepared symbols because every equation is the complete padded ciphertext.
Display cadence and recovery scheduling do not affect parser acceptance.

## Receipt and resource limits

Receive one session in memory. Solve independent GF(2) equations per stripe.
Dependent equations add no progress; a zero coefficient row with a nonzero
payload is a fatal contradiction. Frames for a recovered stripe add no rank.
Save becomes available only after all stripes recover, exact length agrees and
the complete ciphertext SHA-256 matches. Save writes exactly those bytes as
`dud-encrypted-capsule.age`, media type `application/octet-stream`.

| Limit                                           |                                                      Value |
| ----------------------------------------------- | ---------------------------------------------------------: |
| Active sessions                                 |                                                          1 |
| Source blocks per stripe                        |                                                      1,024 |
| Maximum repair degree                           |                                                         31 |
| Active stripes                                  |                                                         41 |
| Decoded QR frames per run, including rejections |                                                    216,000 |
| Distinct stripe/sequence pairs                  |                                                    131,072 |
| Retained independent equations                  |                                                     41,944 |
| Per-stripe work                                 |                              `512 * K * B` byte operations |
| Session work                                    | `min(512 * ceil(L/B) * B, 34,359,738,368)` byte operations |
| Capture session deadline                        |                                                 900,000 ms |
| QR workers                                      |                               1..4, no waiting image queue |
| Fountain workers                                |                               1, at most 32 pending frames |
| Static build cache                              |                                                      8 MiB |

Charge frame length on every decoder attempt, coefficient plus payload byte
length on each elimination XOR, and block size on each recovery XOR. Per-stripe
work excludes frame parsing; the global meter includes both. Reject a work step
before exceeding its limit. Count equations held by unfinished stripes; release
them when a stripe has been solved. Bounds remain in force for duplicates and
hostile input.

The camera deadline starts when receipt starts, even before a valid frame.
Transfer accounting also limits elapsed time from the first valid frame. Pause
stops camera tracks and submissions, lets queued work drain and preserves
equations, workers, profile and the original deadline. Resume cannot extend it.
Stop / reset discards the session, verified unsaved ciphertext and progress,
terminates workers and invalidates stale replies. Backgrounding, suspension,
page exit, device/camera interruption and fatal errors release owned resources.
Reload or tab close loses a paused session. No camera or payload data enters
persistent browser storage; the service worker caches build assets only.

The equation typed-storage ceiling is 72,475,296 bytes. With the final 64 MiB
joining buffer, the conservative codec ceiling is 139,584,160 bytes. This
excludes JavaScript objects, worker images, transient allocations and browser
overhead. It is not a measured phone-memory or throughput guarantee.

## Private container

Encrypt this entire deterministic container with binary `age` before making
frames. It is specific to optical; HTTP dead drops and peer messages do not
adopt it. The browser neither parses it nor decrypts it.

| Offset | Width | Field             | Required value                            |
| -----: | ----: | ----------------- | ----------------------------------------- |
|      0 |     8 | Magic             | `DUDCAP1\0`                               |
|      8 |     1 | Version           | `01`                                      |
|      9 |     1 | Payload type      | 1 message, 2 stream, 3 file, 4 collection |
|     10 |     1 | Archive format    | 0 none, 1 tar                             |
|     11 |     1 | Reserved          | `00`                                      |
|     12 |     2 | Header length     | 64                                        |
|     14 |     2 | UTF-8 name length | `N`, 1..255 bytes                         |
|     16 |     8 | Plaintext size    | `P`, exact payload size                   |
|     24 |     8 | Payload length    | `P`, same value                           |
|     32 |    32 | Payload digest    | SHA-256 of exact payload bytes            |
|     64 |   `N` | Display name      | Valid UTF-8 path component                |
| `64+N` |   `P` | Payload           | Exact bytes, no trailing data             |

The name is not empty, `.` or `..`, contains neither `/` nor `\`, and contains
no U+0000..U+001F or U+007F. It is private display metadata, not an instruction
to choose an output path. Messages, streams and files require archive 0;
collections require archive 1. Empty payloads are allowed; ciphertext is
nonempty. Both size fields must agree with the exact decoded length. A native
host checks all fields, digest and archive before making plaintext output
available.

The payload ceiling is 64 MiB, subject to the stricter complete-ciphertext
ceiling. For a binary age file with header length `H`, through its MAC newline,
and container length `C = 64+N+P`, ciphertext length is
`H + 16 + C + 16 * max(1, ceil(C/65536))`. Recipient count and type change `H`.
There is no universal 64 MiB usable plaintext promise. Measure the complete
ciphertext and reject length outside `1..67,108,864` before fountain allocation.
Archives and compression selected by input preparation precede container
construction; optical coding does not compress ciphertext. Collection payloads
use tar, without an added compression layer.

Collection validation reuses `client/drop` archive rules: at most 100,000
entries and 64 path components, canonical relative paths, no Windows device
names or forbidden components, no links or special files, NFC plus Unicode
case-fold collision checks, at most 100 MiB per regular file and extracted total
bounded by the declared tar size and 1 GiB. Optical hierarchy validation also
limits aggregate path components to 200,000 and cumulative hierarchy-prefix
bytes to 64 MiB. PAX permits only `path`. GNU headers and ownership fields are
accepted as inert metadata. Extraction never applies ownership. Optical archives
require two zero end blocks and only whole zero record padding after them. Every
implicit parent must agree in spelling and normalized case with its other uses,
and a regular file cannot be a parent. Directories have mode 0755; regular files
use 0755 when owner-execute is set, otherwise 0644. These archive rules do not
redefine peer extraction.

Native sender preparation suppresses generated AppleDouble files and removes
local extended attributes, ACLs, file flags, ownership and timestamps before
writing the private container. It retains file bytes and portable permission
bits. The resulting archive follows the same validation rules as every received
capsule.

## Executable vectors

[Format-1 Go vectors](../client/optical-sender/testdata/format1/go-vectors.json)
and
[format-1 TypeScript vectors](../client/optical-sender/testdata/format1/typescript-vectors.json)
freeze complete frame bytes, SHA-256, selection, stripe boundaries, both
profiles and rejection categories. `npm run check:optical:vectors` regenerates
both and requires exact equality with their committed files. Across languages,
only `generatedBy` differs. The JSON `format` field identifies the vector
schema; frame byte 8 is the optical version. Archived format-0 vectors also have
JSON schema value 1 and are distinguished by their path and actual wire bytes.

The same vectors compare complete private containers for a file, empty stream,
binary message with a UTF-8 name and empty tar collection. Their TypeScript
generator is a development tool excluded from the browser runtime. Native tests
validate every field and re-encode the TypeScript bytes exactly.

The native capsule golden test fixes the entire `note.txt` / `hello` container,
including digest, lengths and payload. Compatibility tests feed archived
format-0 frames and container bytes directly into the maintained parsers and
require rejection before exposing payload. QR image tests retain exact format-0
camera bytes while checking that the optical parser rejects them.
