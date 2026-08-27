# DUD Client

The client is one static Go binary. It performs DNS-over-HTTPS resolution,
candidate-address classification, exactly TLS 1.3, and ECH inside the `dud`
binary. It needs no HTTP subprocess and ships none. Both transfer modes use it.

Most installs use the Docker image, which also contains the `age`, `age-keygen`,
`git`, and `qrencode` helpers the binary calls:

```sh
docker pull ghcr.io/wojciechpolak/dud/dud-client:latest
```

§6 turns that image into a `dud` command on the host, so you settle the flags
every run needs once instead of typing them each time.

A release also publishes the same binary natively for Linux and macOS on both
architectures. Those are ordinary release assets, downloadable with any HTTPS
client:

```sh
curl -fL -o dud https://github.com/wojciechpolak/dud/releases/latest/download/dud-linux-amd64
sudo install -m 0755 dud /usr/local/bin/dud
```

`/releases/latest/download/` resolves to the newest stable release; a
pre-release tag is published as one and is never what that path returns, so pin
a version with `/releases/download/vX.Y.Z/` to hold a host on a known build. The
asset name selects the platform: `dud-linux-amd64`, `dud-linux-arm64`,
`dud-darwin-amd64`, or `dud-darwin-arm64`. The GitHub CLI fetches the same
assets, and is what checks the release's provenance attestation:

```sh
gh release download vX.Y.Z --pattern 'dud-linux-amd64' --pattern 'SHA256SUMS'
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify dud-linux-amd64 --repo wojciechpolak/dud
```

`SHA256SUMS` is a release asset like the binaries, so `curl` fetches it the same
way and the `sha256sum -c` line above stands on its own. Every published binary
is built twice from the same source and rebuilds to the same bytes; see
[Verifying a release](../README.md#verifying-a-release).

On macOS and Linux, Homebrew installs the same client and brings the helpers it
calls out to along with it:

```sh
brew install wojciechpolak/dud/dud
```

The name has to be spelled in full. Homebrew's own index carries an unrelated
formula named `dud`, a data versioning tool by a different author. A bare
`brew install dud` resolves to that formula. Both install a `dud` executable
into the same Homebrew prefix, so only one of the two can be installed at a
time; `brew uninstall dud` removes whichever is there. `upgrade`, `reinstall`,
and `uninstall` need the qualified name too:

```sh
brew upgrade wojciechpolak/dud/dud
```

The formula builds from the source archive of a release tag with the flags the
release binaries are built with, so `dud --version` reports the version the
formula installed. It declares `age`, `git`, and `qrencode` as dependencies and
needs `go` only while building. The tap publishes no bottles, so `brew install`
compiles the client on the machine it runs on rather than fetching a prebuilt
one, which also means the provenance attestation above covers the published
binaries, not a Homebrew build. The tap is
[wojciechpolak/homebrew-dud](https://github.com/wojciechpolak/homebrew-dud), and
each stable release regenerates its formula.

A host that already runs the container through `shell-init` (§6) has `dud` as a
shell function in its profile, and a shell function is resolved before anything
on `PATH`. Installing the formula on that host changes nothing about what `dud`
does until the function is removed from the profile and the shell restarted, and
the installed binary stays reachable by its full path meanwhile. `type dud` says
which of the two a shell will run.

Running the binary directly requires `age`, `age-keygen`, `git`, and `qrencode`
on `PATH`. Homebrew's formula provides them; an unpacked release asset does not.
It also omits the generated wrappers' hardening (§6): the container boundary,
the in-memory `/tmp`, and the pinned helper lookup. `DUD_AGE_BIN`,
`DUD_AGE_KEYGEN_BIN`, `DUD_GIT_BIN`, and `DUD_QRENCODE_BIN` name each helper for
a host that keeps them somewhere other than `PATH`. In exchange the paths are
the host's own, so `/work` in every example below becomes an ordinary path and
`~/.dud` is read in place. The two forms accept identical commands, options, and
environment variables.

## 1. Environment

| Variable             | Default                                | Applies to                            |
| -------------------- | -------------------------------------- | ------------------------------------- |
| `DUD_BASE_URL`       | `https://dud.example.com`              | both modes                            |
| `DUD_DOH_URL`        | `https://cloudflare-dns.com/dns-query` | both modes                            |
| `DUD_ECH_MODE`       | `hard`                                 | both modes                            |
| `DUD_DROP_SECRET`    | unset                                  | `upload` and `flush`                  |
| `DUD_PEER_SECRET`    | unset                                  | `peer invite` on a gated deployment   |
| `DUD_HOME`           | `~/.dud`                               | peer commands; see §3                 |
| `DUD_PROFILE`        | unset                                  | peer commands; see §3                 |
| `DUD_IMAGE`          | the published image                    | the generated wrappers                |
| `DUD_CA_BUNDLE`      | unset                                  | a CA bundle path inside the container |
| `DUD_AGE_BIN`        | `age`                                  | payload encryption and decryption     |
| `DUD_AGE_KEYGEN_BIN` | `age-keygen`                           | `keygen`                              |
| `DUD_GIT_BIN`        | `git`                                  | `dud git *`                           |
| `DUD_QRENCODE_BIN`   | `qrencode`                             | `upload` and `peer invite` QR codes   |
| `DUD_DOCKER_NETWORK` | unset                                  | the generated wrappers                |
| `DUD_CONNECT_TO`     | unset                                  | rejected; setting it fails every run  |

`DUD_ECH_MODE` accepts exactly two values:

- `hard`: require real ECH and fail the request if the connection cannot use it
- `off`: do not request ECH at all, leaving the target hostname visible in the
  TLS SNI

The four helper selectors apply to a binary run directly. The generated wrappers
pin them to the image's own executables (§6), so setting one in the shell or in
`.env` does not change what the container runs.

`DUD_CONNECT_TO` names no supported behavior. The transport refuses to start
when it is set, so it cannot be used to redirect a connection past the DoH
resolution and address checks that every transfer depends on.

Only the inviter needs `DUD_PEER_SECRET`; an invitee accepts with the pairing
code alone. It is normally the passphrase the operator issued.
`dud peer enrollment-key` converts one into the derived-key form a deployment
can hold without running the key derivation itself; see `server-v2.md` §3.1.
That form works here too, so a device can be given the key instead of the
passphrase.

## 2. Where each setting comes from

Peer commands resolve the base URL, DoH URL, and ECH mode from the first layer
that sets each one:

1. the command line (`--url`, `--doh-url`, `--ech-mode`)
2. the peer profile in `config.toml` (`base_url`, `doh_url`, `ech_mode`)
3. the environment (`DUD_BASE_URL`, `DUD_DOH_URL`, `DUD_ECH_MODE`)
4. the local configuration (the same keys outside any peer table)
5. the compiled defaults above

The peer profile sits above the environment on purpose. A paired relationship
pins its own canonical origin, which is bound into every signed descriptor,
while the `DUD_*` variables are ambient; they are also the only way to point
dead drop commands at a deployment, since those commands read no configuration
file. A shell that exports `DUD_BASE_URL` for drops therefore keeps working for
drops without retargeting any paired peer.

Peer-scoped commands (`send`, `receive`, `sync`, `git push|fetch|status`) reject
`--url`, `--doh-url`, and `--ech-mode` for the same reason. `dud doctor` and
`dud peer show` print the effective value of each option together with the layer
it came from; where an explicit override displaced a pinned value they also
print the pinned one, and they name any `DUD_*` variable the profile overrode.

An alias that is not paired yet pins nothing, so `peer invite` and `peer accept`
still follow the environment: exporting `DUD_BASE_URL` for one invitation is how
a peer gets paired against a deployment other than the one `config.toml` names.
The origin that invitation used becomes the profile's pin.

## 3. Running more than one deployment

A world directory is one world: one device identity, one seed, one optional
`v2-admin-capability`, and one peer graph. The peers inside it may each be
pinned to a different origin, so several servers need no extra setup for
transfers, but pairing starts from the origin the world itself resolves, and the
device identity is shared by everything in it. Testing a second deployment is
therefore a second world, not a second peer.

`DUD_PROFILE` selects one. It names a directory under the DUD root,
`~/.dud/NAME`, and the wrapper mounts that one directory into the container:

```sh
DUD_PROFILE=test dud init --device laptop-test --url https://other.example.com
DUD_PROFILE=test dud doctor
```

The name must be 1 to 64 characters, start with a letter or digit, and continue
with letters, digits, `.`, `_`, or `-`, because it becomes a directory name.
Leaving `DUD_PROFILE` unset selects `~/.dud/default`, and the worlds never see
each other: exactly one of them is mounted, so a container opened for one
profile cannot read another's seed or peer graph. Dead drop commands read no
configuration file, so a profile changes nothing for them; point those at a
deployment with `DUD_BASE_URL`.

### Where peer state lives

| Purpose       | Path on the host        | Path inside the container |
| ------------- | ----------------------- | ------------------------- |
| Configuration | `~/.dud/default/config` | `/dud/default/config`     |
| Runtime state | `~/.dud/default/state`  | `/dud/default/state`      |
| Working files | the current host folder | `/work`                   |

Everything a world holds is secret. The configuration directory carries the
device master seed, and the state directory carries pairing material and any
received plaintext that DUD alone holds. They share one root because no sync
convention needs to copy either directory. `~/.config` is a path dotfile
managers routinely commit to a repository, and a device seed must never travel
that way.

`DUD_HOME` moves the root. Leave it unset for normal use; the wrapper creates
the private directories and maps them itself. Each machine gets its own seed and
state, so two real devices need no variables at all; use `DUD_PROFILE` rather
than `DUD_HOME` when one machine needs a second world.

Removing `~/.dud` removes every world, but it is not a complete erasure. Peer
state inside a Git repository lives in that repository's own `.git/dud`, and the
client image stays in the local Docker store. `dud erase` reports what it
removed, what it retained, and what it cannot reach, including copies already
held by a peer or the server. See `recovery-v2.md` §7.

## 4. Running it

```sh
docker run --rm -it -v "$PWD:/work" ghcr.io/wojciechpolak/dud/dud-client:latest test
```

The `test` command prints the DoH resolver, ECH mode, negotiated TLS details,
ALPN, and the ECH result read from the TLS connection state, followed by the
server's `/v1/test` JSON response.

```sh
docker run --rm -it --tmpfs /tmp:rw,noexec,nosuid,size=128m -e DUD_DROP_SECRET=YOUR_TOKEN -v "$PWD:/work" ghcr.io/wojciechpolak/dud/dud-client:latest upload --file /work/input.bin --ttl 24h
docker run --rm -it --tmpfs /tmp:rw,noexec,nosuid,size=128m -v "$PWD:/work" ghcr.io/wojciechpolak/dud/dud-client:latest download --id YOUR_ID --out /work/output.bin
printf '%s' 'secret message' | docker run --rm -i --tmpfs /tmp:rw,noexec,nosuid,size=128m -e DUD_DROP_SECRET=YOUR_TOKEN ghcr.io/wojciechpolak/dud/dud-client:latest upload --json
```

> **Security note**: `--tmpfs /tmp` keeps sensitive intermediate files
> (encrypted payloads, TLS traces) in memory only; they never reach the
> container's overlay filesystem and are gone when the container exits.

Repeating those flags by hand is what the shell wrapper in §6 exists to avoid.

Use `dud --version` to print the client version.

## 5. JSON output

Every command that reports a result accepts `--json`: `test`, `upload`,
`download`, `git push`, `git fetch`, `git status`, `flush`, `keygen`, `init`,
`doctor`, `capabilities`, `config`, `migrate`, `erase`, `peer *`, `sync`,
`inbox`, `send`, and `receive`.

Where a payload already owns stdout, the two cannot share the stream.
`download --json` is rejected with `--stdout`, and `keygen --json` requires
`--out` rather than writing a private key next to a JSON document.

## 6. Shell wrapper

To avoid repeating the full `docker run` flags, install a thin host wrapper:

```sh
# Wrapper script at /usr/local/bin/dud
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest install \
  | sudo tee /usr/local/bin/dud > /dev/null && sudo chmod +x /usr/local/bin/dud
```

Or print a shell function and add it to `~/.bashrc`, `~/.zshrc`, or
`~/.profile`:

```sh
# 1. Review what will be added
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest shell-init

# 2. Append to your shell rc
docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest shell-init >> ~/.profile
```

Or load it only for the current shell session:

```sh
eval "$(docker run --rm ghcr.io/wojciechpolak/dud/dud-client:latest shell-init)"
```

Both wrappers add `--env-file .env` when `./.env` exists, and forward exported
`DUD_BASE_URL`, `DUD_DOH_URL`, `DUD_ECH_MODE`, `DUD_DROP_SECRET`,
`DUD_PEER_SECRET`, `DUD_CA_BUNDLE`, and `DUD_CONNECT_TO` into the container.
Exported shell variables override values from `.env`. `DUD_HOME` is always set
to the root the container mounts, and `DUD_PROFILE` is always passed, empty
included, because the host decides which world directory is mounted and a value
arriving from `.env` must not point the container at a directory that was never
mounted. For the same reason, `.env` cannot choose which executable the
container runs: `DUD_AGE_BIN`, `DUD_AGE_KEYGEN_BIN`, `DUD_GIT_BIN`,
`DUD_QRENCODE_BIN`, `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, and `LD_AUDIT` are
pinned to the image's own values after `--env-file`, so a helper always resolves
to an image binary and never to something under the bind-mounted `/work`.
Exported shell variables do not lift the pin either; to run a different helper,
run the `dud` binary directly rather than through a wrapper.

```dotenv
# Example .env
DUD_DROP_SECRET=replace-me
# Optional overrides:
# DUD_PEER_SECRET=squid-lantern-rotate-9-mango
# DUD_BASE_URL=https://dud.example.com
# DUD_DOH_URL=https://cloudflare-dns.com/dns-query
# DUD_ECH_MODE=hard
```

Set `DUD_IMAGE` before `shell-init` to change the generated fallback image, or
set it later in your shell to override the image the generated function runs.

Because the wrapper forwards a current-directory `.env`, do not run the client
from a directory holding a server `.env`: deployment and administrative secrets
do not belong in a client container.

### What the generated wrappers harden

- the container runs as the calling user, with `--cap-drop ALL` and
  `--security-opt no-new-privileges`
- `/tmp` is a `noexec,nosuid` tmpfs, so intermediate plaintext never reaches the
  overlay filesystem
- the config and state roots are mounted writable, because `dud init`, pairing,
  and delivery bookkeeping write them
- the working directory and, inside a Git repository, the Git common directory
  are mounted writable, because downloads and fetches write there
- an absolute readable `DUD_CA_BUNDLE` is bind-mounted **read-only** at the same
  path, so the variable stays valid inside the container; a relative path keeps
  resolving under `/work`
- staged stdin is bind-mounted **read-only** and removed from the host as soon
  as the container exits
- helper executable selectors, `PATH`, and the dynamic-loader overrides are
  pinned to image values, so a repository `.env` cannot make the client execute
  code from the worktree it mounts next to the seed and peer graph

## 7. Interactive menu

Running `dud` with no command in an interactive terminal opens a menu organized
around verbs: `send`, `receive`, `git`, `peers`, `status`, `setup`, and `tools`.
Each transfer verb asks for its target first. The menu lists paired peers and
the `dead drop — share by ID` entry. A positional peer alias or a leading flag
makes the same peer-transfer or drop selection on the command line. Typing a
peer alias at the target step is a shortcut. Without an initialized device or
paired peers, the target step offers the dead drop entry alone, points at
`setup`, and defaults to it.

Both send paths share one payload step, so the target never changes what can be
sent: a short one-line message, longer text typed or pasted until Ctrl-D, or
repeated file and directory paths that the command bundles. The words `test`,
`upload`, `download`, `keygen`, `git`, and `flush` remain accepted at the top
level and reach the same operations with the same prompts.

Every prompt below the top level offers `b` to go back one step and `q` to quit,
so no step is a dead end that only Ctrl-C can leave. The menu returns to the top
level after each successful command, so one session can run several. `q`, `b`
out of the top-level verb, or end of input leaves it successfully, and a command
that fails ends the session with that command's exit status. If stdin is not a
TTY, it prints usage information and exits instead.

## Related documents

- [`dead-drops-v1.md`](dead-drops-v1.md): the drop commands in full
- [`peer-setup.md`](peer-setup.md): pairing, sending, and receiving with peers
- [`recovery-v2.md`](recovery-v2.md): `dud erase`, stuck relationships, and
  local state problems
- [`supported-versions.md`](supported-versions.md): the tools the client assumes
  on the host
