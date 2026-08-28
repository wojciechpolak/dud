// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "fmt"

func (a *app) usage() {
	fmt.Fprint(a.out, `Usage:
  dud --version
  dud install        Print a host wrapper script to stdout
  dud shell-init     Print a shell function definition to stdout

Dead-drop commands (addressed by an opaque ID, shared out of band):
  dud test [--json] [--url URL] [--doh-url URL]
  dud upload [--file PATH ... | -m TEXT] [--ttl 24h] [--delete-after-read] [--passphrase | --recipient AGE_RECIPIENT | --recipient-file PATH] [--json] [--no-qr] [--url URL] [--doh-url URL]
  dud download --id ID (--out PATH | --stdout | --extract [--out-dir PATH]) [--identity PATH] [--json] [--url URL] [--doh-url URL]
  dud git push [--ttl 24h] [--delete-after-read] [--passphrase | --recipient AGE_RECIPIENT | --recipient-file PATH] [--json] [--no-qr] [--url URL] [--doh-url URL]
  dud git fetch --id ID [--identity PATH] [--remote NAME] [--json] [--url URL] [--doh-url URL]
  dud flush [--json] [--url URL] [--doh-url URL]
  dud keygen [--pq] [--out PATH] [-R PATH] [--json]
  dud keygen [INPUT] [--out PATH | -R PATH] [--json]

Peer commands (addressed by the local alias of a paired device):
  dud init --device NAME [--url URL] [--doh-url URL] [--ech-mode hard|off] [--json]
  dud doctor [--url URL] [--doh-url URL] [--ech-mode hard|off] [--json]
  dud capabilities [--url URL] [--doh-url URL] [--ech-mode hard|off] [--json]
  dud config show|validate [--json]
  dud migrate [--json]
  dud erase pairings (--yes | --dry-run) [--json]
  dud erase peer NAME (--yes | --dry-run) [--json]
  dud erase repo (--yes | --dry-run) [--json]
  dud erase all [--repo] (--yes | --dry-run) [--json]
  dud peer invite NAME [--expires DURATION] [--json]
  dud peer accept NAME [--json]
  dud peer list [--json]
  dud peer show NAME [--json]
  dud peer rename OLD NEW [--json]
  dud peer resume NAME [--yes] [--json]
  dud peer revoke NAME --yes [--json]
  dud peer remove NAME --yes [--json]
  dud peer enrollment-key [--json]
  dud sync [PEER] [--json]
  dud inbox [PEER] [--json]
  dud send PEER (--file PATH ... | -m TEXT | --stdin) [--name NAME] [--ttl 168h] [--delete-after-read] [-v] [--json]
  dud receive PEER [--out PATH | --out-dir DIR] [--wait DURATION] [--max N] [--on-conflict skip|refuse|overwrite] [--no-extract] [-v] [--json]
  dud receive PEER --id DESCRIPTOR_DIGEST [--out PATH] [--on-conflict overwrite] [--json]
  dud git push PEER [--branch NAME ... | --current] [--full | --incremental] [--ttl 168h] [-v] [--json]
  dud git fetch PEER [--associate] [--allow-rewrite] [-v] [--json]
  dud git status [PEER] [--json]

Peer receive:
  'dud receive PEER' drains deliveries oldest first and reports each one.
  --max N limits the drain. --wait waits only when the queue starts empty.
  DUD commits and acknowledges each delivery before taking the next one.

  --on-conflict handles an output name already used by different contents:
    skip       Keep the file but commit the delivery. This is the default.
               Recover its payload with
               'dud receive PEER --id DIGEST --out PATH'.
    refuse     Stop the drain at the conflict.
    overwrite  Replace the file.

  A Git checkpoint stops the drain because it needs a repository. The report
  points to 'dud git fetch PEER'. Earlier deliveries stay committed.
  'dud inbox' shows the oldest waiting delivery without committing it. The
  server exposes only that delivery, not the full queue.

Peer status reporting:
  'dud sync', 'dud doctor', 'dud peer show', and 'dud git status' always print
  delivery counters. 'dud send', 'dud receive', and peer Git commands print them
  only with -v or when work remains queued, undrained, quarantined, halted, or
  in the inbox. --json always includes every counter.

  A send returns after publishing. It does not wait for the peer. The peer signs
  an acknowledgement when it receives the delivery. 'dud sync PEER' collects
  that acknowledgement.

Aliases:
  dud send, dud receive          a positional peer alias selects the peer
                                 command; a leading flag selects upload or
                                 download, so both spellings reach both modes
  dud git send, dud git receive  aliases for dud git push and dud git fetch

Environment:
  DUD_BASE_URL        Base Worker URL. Default: https://dud.example.com
  DUD_DOH_URL         DNS-over-HTTPS resolver.
                      Default: https://cloudflare-dns.com/dns-query
  DUD_ECH_MODE        ECH mode. Allowed: hard, off. Default: hard
  DUD_DROP_SECRET     Shared secret required for dead drop upload and flush
  DUD_PEER_SECRET     Enrollment secret for creating invitations on a gated
                      deployment. Only the inviter needs it. The invitee uses
                      the pairing code. Run 'dud peer enrollment-key' to turn
                      an operator passphrase into a derived key the server can
                      store without running the key derivation
  DUD_CA_BUNDLE       Optional CA bundle path inside the client container.
                      Generated wrappers mount an absolute host path read-only
                      at the same path. Relative paths resolve under /work
  DUD_CONNECT_TO      Inert: the in-process transport rejects it outright
  DUD_DOCKER_NETWORK  Optional docker network for install/shell-init wrappers
  DUD_GIT_BIN         Git binary used by dud git commands. Default: git
  DUD_HOME            Directory holding every peer world. Default: ~/.dud
  DUD_IMAGE           Docker image used by install/shell-init output
  DUD_PROFILE         Peer world under the DUD root. NAME starts with a letter
                      or digit and may also contain '.', '_', or '-'. Dead drop
                      commands ignore it and read no configuration file

Peer network options:
  DUD resolves the base URL, DoH URL, and ECH mode in this order:
  command line, peer profile, environment, local configuration, compiled
  default.

  Signed descriptors bind a paired peer to its origin. DUD_* variables may
  point dead drop commands elsewhere, but they cannot retarget a paired peer.
  Commands that target a paired peer reject --url, --doh-url, and --ech-mode.
  'dud doctor' and 'dud peer show' report where each value came from, any value
  pinned by the profile, and any DUD_* variable the profile overrode.

Peer local state:
  Config: $DUD_HOME/default/config (default: ~/.dud/default/config)
  State:  $DUD_HOME/default/state  (default: ~/.dud/default/state)
  DUD_PROFILE=NAME moves both directories under $DUD_HOME/NAME. A peer world
  contains one device identity, one seed, and one peer graph. Use another
  profile for another deployment. The whole DUD root is secret. Do not sync it.

  Every network operation rejects DUD_CONNECT_TO. Both modes require a
  canonical HTTPS origin, HTTPS DoH, and TLS 1.3. ECH uses hard mode unless you
  select off.
`)
}
