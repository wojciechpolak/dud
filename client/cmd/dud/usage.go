// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "fmt"

func (a *app) usage() {
	fmt.Fprint(a.out, `Usage:
  dud --version
  dud test [--url URL] [--doh-url URL]
  dud upload [--file PATH ... | -m TEXT] [--ttl 24h] [--delete-after-read] [--passphrase | --recipient AGE_RECIPIENT | --recipient-file PATH] [--json] [--no-qr] [--url URL] [--doh-url URL]
  dud download --id ID (--out PATH | --stdout | --extract [--out-dir PATH]) [--identity PATH] [--url URL] [--doh-url URL]
  dud send ...
  dud receive ...
  dud git push [--ttl 24h] [--delete-after-read] [--passphrase | --recipient AGE_RECIPIENT | --recipient-file PATH] [--json] [--no-qr] [--url URL] [--doh-url URL]
  dud git fetch --id ID [--identity PATH] [--remote NAME] [--url URL] [--doh-url URL]
  dud git send ...
  dud git receive ...
  dud flush [--url URL] [--doh-url URL]
  dud keygen [--pq] [--out PATH] [-R PATH]
  dud keygen [INPUT] [--out PATH | -R PATH]
  dud install        Print a host wrapper script to stdout
  dud shell-init     Print a shell function definition to stdout

Environment:
  DUD_BASE_URL   Base Worker URL. Default: https://dud.example.com
  DUD_DOH_URL    DNS-over-HTTPS resolver. Default: https://cloudflare-dns.com/dns-query
  DUD_ECH_MODE   curl ECH mode. Allowed: hard, grease. Default: hard
  DUD_SECRET_TOKEN  Shared secret required for upload and flush
  DUD_CA_BUNDLE  Optional CA bundle path inside the client container
  DUD_CONNECT_TO Optional curl --connect-to mapping for local integration tests
  DUD_DOCKER_NETWORK  Optional docker network for install/shell-init wrappers
  DUD_GIT_BIN    Git binary used by dud git commands. Default: git
  DUD_IMAGE      Docker image used by install/shell-init output
`)
}
