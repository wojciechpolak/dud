# Demo recordings

The VHS tapes render the GIFs embedded in the repository README. CLI network
recordings use two `tmux` panes and a private Docker transport fixture. Local
recordings use a freshly built native client and disposable state without a
payload server or a phone.

| Tape                      | Interface | Coverage                                                               |
| ------------------------- | --------- | ---------------------------------------------------------------------- |
| `dead-drop.tape`          | CLI       | Recipient encryption, upload and download by ID                        |
| `peer-pairing.tape`       | CLI       | Device initialization and pairing                                      |
| `peer-overview.tape`      | CLI       | Pairing, file send and receive                                         |
| `peer-transfer.tape`      | CLI       | Message send and receive                                               |
| `peer-file-transfer.tape` | CLI       | File send and receive                                                  |
| `peer-git-sync.tape`      | CLI       | Git checkpoint push and fetch                                          |
| `tui-overview.tape`       | TUI       | Dead drop and optical forms, capsule recovery form, peer and Git menus |

The TUI overview explores forms and menus without submitting transfers.

## CLI dead drop and peer recordings

Record the asset from the repository root with:

```sh
./scripts/record-peer-transfer-demo.sh
```

Pass a tape path to regenerate one of the other assets:

```sh
./scripts/record-peer-transfer-demo.sh docs/demos/peer-file-transfer.tape
./scripts/record-peer-transfer-demo.sh docs/demos/peer-git-sync.tape
./scripts/record-peer-transfer-demo.sh docs/demos/peer-overview.tape
./scripts/record-peer-transfer-demo.sh docs/demos/peer-pairing.tape
./scripts/record-peer-transfer-demo.sh docs/demos/dead-drop.tape
```

The recorder requires Docker, VHS, `tmux`, and `expect`. It builds the local
client and server images unless `DUD_DEMO_SKIP_BUILD=1` selects images already
available on the host. The fixture creates its own Docker network and state
directory, then removes both when the recording ends. Git repositories use
Docker volumes so Git sees stable repository ownership on Docker Desktop; the
recorder removes those volumes too.

The fixture uses a private CA, local DoH and `DUD_ECH_MODE=off`. These
recordings demonstrate command workflows; they do not demonstrate a public ECH
handshake.

## Local TUI recording

```sh
./scripts/record-local-demo.sh
```

The recorder requires Go, VHS and its `ttyd`, FFmpeg and Chromium dependencies.
It builds into a private scratch directory, clears ambient `DUD_*` settings and
removes its isolated state and input files after recording. The checked-in tapes
write GIFs; VHS also supports MP4 output.

## Optical sender in Kitty

```sh
python3 scripts/record-optical-kitty-demo.py
```

The recorder requires macOS 15 or later with Screen Recording permission, the
Xcode command-line tools, Python 3, Go, `age`, FFmpeg and a graphical Kitty
build with the `kitty @ screenshot` remote command. It opens its own Kitty
instance with an isolated configuration and a private Unix control socket. It
generates a 256 KiB file, navigates the production TUI, selects **kitty** and
**balanced**, and encrypts with a public demo passphrase. The larger input
produces changing QR frames; a small message can reuse one static display.

The native ScreenCaptureKit helper continuously records that window by its
window ID, including Kitty graphics, with mouse cursor and click capture
disabled. A private intermediate video preserves a 30 FPS timeline; the final
GIF is limited to 6 FPS to keep its size small. A screenshot identifies when the
sender starts displaying QR images, but does not supply video frames. Before
finishing, the recorder checks a three-second region of the intermediate video
for at least 75 distinct black-and-white QR patterns, excluding text and the
cursor. This rejects sparse captures even if their container advertises 30 FPS.
The recording does not establish camera goodput. It closes its own window and
removes its input, state and capture files after recording.

The output is [`optical-kitty.gif`](../assets/optical-kitty.gif), 960 pixels
wide. Height follows the captured window's aspect ratio. Intermediate videos are
removed with the scratch directory. Ending display does not confirm remote
receipt.

VHS's virtual terminal rejects the sender's Kitty graphics probe; running VHS
inside Kitty does not give its recorded terminal those capabilities. The Kitty
recorder uses the native terminal directly.
