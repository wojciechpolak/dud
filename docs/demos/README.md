# Demo recordings

The tapes render the GIFs embedded in the repository README. Each tape uses two
`tmux` panes inside VHS's one virtual terminal, while the recording script
supplies isolated paired device state and a private transport fixture.

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
directory, then removes both when the recording ends.
