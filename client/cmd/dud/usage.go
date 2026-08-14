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
  dud git push PEER [--branch NAME ... | --current] [--ttl 168h] [-v] [--json]
  dud git fetch PEER [--associate] [--allow-rewrite] [-v] [--json]
  dud git status [PEER] [--json]

Peer receive:
  One 'dud receive PEER' drains every delivery waiting from that peer, oldest
  first, and reports each one. --max N stops after N. --wait applies only while
  the queue is empty, so it never idles after a drain has started.
  Deliveries are committed in order and each is acknowledged, so a receive
  cannot take a later delivery while skipping an earlier one. --on-conflict
  decides what happens when an output name is already taken by different
  contents: 'skip' (the default) leaves the file alone but still commits and
  acknowledges the delivery, so the queue keeps moving and the payload stays
  recoverable with 'dud receive PEER --id DIGEST --out PATH'; 'refuse' stops
  the drain there; 'overwrite' replaces the file.
  A Git checkpoint in the queue stops the drain, because applying it needs a
  repository; the report names 'dud git fetch PEER' and everything ahead of it
  is already committed.
  'dud inbox' reports the oldest waiting delivery without committing it. The
  server answers with the oldest delivery only, so there is no full queue
  listing to show.

Peer status reporting:
  'dud sync', 'dud doctor', 'dud peer show', and 'dud git status' always print
  the delivery counters, which is what those commands are for. 'dud send',
  'dud receive', and the peer Git commands print them only when -v is given or
  when something is queued, undrained, quarantined, halted, or still waiting in
  the inbox, so a routine transfer reports what it did in one line. --json is
  unaffected: it always carries every counter, with or without -v.
  No command waits for the peer's signed acknowledgement. A send publishes the
  delivery and returns; the peer signs an acknowledgement when it receives, and
  'dud sync PEER' collects it here.

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
  DUD_PEER_SECRET     Enrollment secret required to create a peer invitation
                      on a deployment that gates enrollment. Only the inviter
                      needs it; an invitee accepts with the pairing code
                      alone. Usually the passphrase the operator issued;
                      'dud peer enrollment-key' converts one into the
                      derived-key form a server can hold without running the
                      key derivation itself
  DUD_CA_BUNDLE       Optional CA bundle path inside the client container. The
                      generated wrappers bind an absolute host path read-only
                      at the same path; a relative path resolves under /work
  DUD_CONNECT_TO      Inert: the in-process transport rejects it outright
  DUD_DOCKER_NETWORK  Optional docker network for install/shell-init wrappers
  DUD_GIT_BIN         Git binary used by dud git commands. Default: git
  DUD_HOME            Directory holding every peer world. Default: ~/.dud
  DUD_IMAGE           Docker image used by install/shell-init output
  DUD_PROFILE         Selects a separate peer world: the whole world moves to
                      NAME under the DUD root. Starts with a letter or digit
                      and continues with letters, digits, '.', '_', or '-'.
                      Dead drop commands read no configuration file and
                      ignore it

Peer network options:
  Effective base URL, DoH URL, and ECH mode resolve in one fixed order:
  command line, peer profile, environment, local configuration, compiled
  default. A paired peer therefore keeps the transport it was paired against:
  the DUD_* variables are ambient, and they also point dead drop commands at a
  deployment, so they never retarget a relationship whose origin is bound into
  its signed descriptors. Peer-scoped commands reject --url, --doh-url, and
  --ech-mode for the same reason. 'dud doctor' and 'dud peer show' report the
  layer each effective value came from, what the profile pinned when the two
  differ, and which DUD_* variables the profile overrode.

Peer local state:
  Config: $DUD_HOME/default/config (default: ~/.dud/default/config)
  State:  $DUD_HOME/default/state  (default: ~/.dud/default/state)
  DUD_PROFILE=NAME moves the whole world to $DUD_HOME/NAME. Each world holds
  one device identity, one seed, and one peer graph, so a second deployment is
  a second profile rather than a second peer. All of it is secret, so it sits
  under one root no convention asks anyone to synchronize.
  Every network operation, in either mode, rejects DUD_CONNECT_TO and requires
  a canonical HTTPS origin, HTTPS DoH, exactly TLS 1.3, and ECH hard mode
  unless off was explicitly selected.
`)
}
