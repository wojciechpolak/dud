# DUD v2 threat model

This document states DUD v2's protections and limits. Every control described
here is implemented and released in DUD 2.0.0.
[`protocol-v2.md`](protocol-v2.md) specifies the mechanism behind each property
claimed here.

Read the limits as carefully as the guarantees. A tool whose value is discretion
is damaged more by one overstated promise than by any number of admitted gaps.

## 1. Core Assumption

**The server is an untrusted ciphertext rendezvous.** It is assumed to be
curious, and may be actively malicious. It stores and forwards bytes it cannot
read. Every claim below is written against a server that is hostile unless
stated otherwise.

Plaintext encryption and decryption happen only on clients. Filenames, payload
types, peer names, Git refs, and private keys never reach the server.

## 2. What Is Protected

| Property                       | Mechanism                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------ |
| Payload confidentiality        | hybrid post-quantum `age` recipient encryption                                 |
| Descriptor confidentiality     | same; metadata is inside the encrypted descriptor                              |
| Sender authenticity            | Ed25519 signature over a domain-separated input                                |
| Peer authentication at pairing | 128-bit one-time code, role binders, contributory HPKE, and signed completions |
| Replay and rollback resistance | hash-chained sequences, durable watermarks, peer-echoed marks                  |
| Slot-identifier unlinkability  | rotating HMAC-derived slots per 24-hour epoch                                  |
| Transport confidentiality      | DoH, TLS 1.3 exactly, ECH hard by default                                      |
| Least-privilege authorization  | per-direction, per-scope, possession-bound requests                            |

## 3. Adversaries

### 3.1 Malicious or Curious Storage Operator

**Can:** observe request timing, frequency, and volume; observe ciphertext and
descriptor sizes; observe expiry and consume policy; observe the source address;
correlate one relationship across every slot epoch through the stable
server-side verifier record; withhold, reorder, duplicate, or replay committed
deliveries; retain bytes after a delete or expiry.

**Cannot:** read payloads or descriptors; forge a delivery that verifies; learn
peer aliases, filenames, or Git refs; correlate slots across epochs by slot
identifier alone; cause a rolled-back delivery to be accepted silently, because
peer-echoed watermarks expose it and a non-fast-forward peer ref update requires
confirmation.

**Residual:** deletion and expiry are not cryptographic guarantees. A malicious
operator or its backups may retain ciphertext indefinitely. Short TTLs and
delete-after-read reduce the volume at risk; they do not prove erasure.

### 3.2 Passive Network Observer

**Can:** observe connection timing and volume; observe the DoH resolver's
hostname when system bootstrap is used.

**Cannot:** observe the DUD target hostname when hard mode succeeds, because it
is resolved over DoH and hidden by ECH on the actual target request.

**Residual:** with an explicit `DUD_ECH_MODE=off` selection the target hostname
is visible in the TLS SNI. This is a documented, user-selected trade-off
(`DUD-V2-DEC-001`) that exists so a self-hosted origin without an ECH-capable
front end can use v2 at all.

A self-hosted DoH resolver can expose more than it hides. A distinctive resolver
hostname in a system DNS query is more identifying than the DUD origin it hides.
`dud doctor` reports this; pinned bootstrap addresses remove it.

**Traffic fingerprint:** every request in either transfer mode leaves the same
Go client, so the observable handshake and framing are uniform: one stack, and
`h2` in both modes, so no `http/1.1` connection stands out against the HTTP/2
majority. None of that hides the fact of a connection. This adversary still sees
timing and volume.

### 3.3 TLS-Terminating Provider

In the default deployment the operator terminates TLS. ECH hides the target
hostname from network observers, not from the endpoint. This adversary has every
capability of §3.1.

### 3.4 Stolen Object ID

**Cannot** retrieve an object. Object read requires a scoped, possession-bound
capability; an ID alone is not authorization. The server `MUST NOT` reveal
whether an unauthorized object exists.

### 3.5 Stolen Write Capability

**Can:** write to one direction and slot window until expiry or revocation;
consume quota; create pending deliveries.

**Cannot:** read, list, delete, acknowledge, or administer; forge a signature,
so anything written is rejected by the receiver at signature verification;
outlive its slot epoch.

**Residual:** a backend that advertises best-effort reservations can let a
racing holder overshoot a quota. The overshoot stays bounded; it is not an
unbounded write. Both shipped adapters advertise atomic: the filesystem one uses
an exclusive crash-safe metadata transaction, and R2 uses strongly consistent
conditional ETag compare-and-swap with bounded retries. Clients still read the
advertised enforcement class and assume nothing about an adapter that has not
declared one.

### 3.6 Stolen Read Capability

**Can:** read one expected slot window.

**Cannot:** upload; delete; acknowledge; derive a write capability; read outside
its slot epoch. Payloads remain encrypted to a recipient the holder does not
have, so a stolen read capability yields ciphertext, not plaintext.

### 3.7 Malicious Known Peer

Explicitly in scope. Sender signatures establish identity, not trustworthiness.

**Can:** send hostile archives, hostile Git bundles, malformed descriptors, and
resource-amplifying payloads; observe when their deliveries are collected.

**Cannot:** escape the extraction sandbox (hard links, symlinks, special files,
absolute paths, traversal, setuid/setgid, and case-folding or normalization
collisions are all rejected, and extraction is staged with no-follow resolution
and an atomic rename into a non-existing destination); contaminate the Git
object database, because bundles are unbundled and validated in a scratch
repository and promoted by an explicit refspec; move a local branch or the
working tree; rewrite a peer remote-tracking ref without confirmation.

**Residual:** a peer can correlate nothing about the device's other
relationships, because identities are per-relationship (`DUD-V2-DEC-005`), but a
peer necessarily learns what that peer is sent.

### 3.8 Unknown Sender

Deliveries signed by an unrecognised key are displayed separately and `MUST NOT`
be auto-extracted or auto-imported. A known-peer delivery signed by an
unexpected key is rejected outright.

### 3.9 Compromised Endpoint

An attacker with the unlocked master seed and active relationship state has
everything: they can decrypt every relationship's payloads, sign as the device,
derive slots, and use or re-issue capabilities. A seed recovered without the
relationship state still derives the device's encryption and signing keys, but
not the contributory directional relationship secrets; that relationship must be
paired again.

DUD supports revocation and re-pairing but **cannot** make an actively
compromised endpoint trustworthy. This is out of scope by construction.

### 3.10 Local Disk Recovery

Covers a powered-off or discarded device, where key material may be protected
but metadata is not.

**Exposed:** the peer communication graph. `config.toml`, delivery history,
transfer state, and `.git/dud/peers/*` record peer aliases, pseudonymous device
IDs, sequences, timestamps, and acknowledged ref tips. This reconstructs who a
device communicates with, how often, and when: precisely the correlation the
slot design hides from the operator. Pairing state also contains the two
directional relationship secrets, because the contributory HPKE result cannot be
reconstructed from the seed and transcript alone.

**Mitigated by:** mode-`0700` directories; retention bounded by maximum object
TTL plus skew; and encryption at rest to a seed-derived key **when the master
seed is itself passphrase-, keystore-, TPM-, or hardware-protected**.

Encryption at rest is deliberately _not_ offered when the seed is a plaintext
mode-`0600` file. An attacker who can read the state can read the seed beside it
and the mode-`0600` relationship state, so wrapping would protect nothing while
presenting as protection. Full-disk encryption is the expected baseline in that
mode. Private directories are mode `0700`, private files are mode `0600`, and
the peer graph and directional secrets remain recoverable from an unencrypted
powered-off disk.

### 3.11 Traffic Analysis

Timing, frequency, ciphertext size, and polling behaviour remain observable.
Fixed-size chunking reduces individual-file size leakage; final-chunk padding is
optional because it costs bandwidth and storage.

A user who needs unlinkability of a device's traffic in general needs a
network-level anonymity layer that DUD does not provide. No protocol decision
here substitutes for one.

### 3.12 Denial of Service

Bounded by quotas, rate limits, request-size enforcement, and receiver-side
budgets for ciphertext bytes, plaintext bytes, chunks, files, Git objects, CPU,
memory, time, and disk. Capability failures are rate-limited.

Not defended: an operator can deny service to its own users at will.

### 3.13 Archive and Parser Attacks

Descriptors are deterministic CBOR with duplicate-key rejection,
indefinite-length rejection, and hard limits enforced before allocation.
Archives are bounded by the sender's own **signed** plaintext size with a 1 GB
cap, plus entry-count and path-depth limits. Descriptor and invitation parsing
are fuzzed.

### 3.14 Malicious Server, Code Substitution, and Relay

An attacker who replaces the displayed or scanned pairing code can steer the
victim to a different rendezvous. A malicious storage server can substitute,
withhold, replay, or relay any envelope or protocol message it stores.

**Defended by** a cryptographically random 128-bit one-time code. The server
stores only its hash-derived locator and an XChaCha20-Poly1305 encrypted
invitation whose associated data binds the locator, configured canonical origin,
protocol version, and expiry. Code-derived, role-separated HMAC binders cover
acceptance and key confirmation and are included in the signed transcript. The
code-derived relationship PSK is mixed with both contributory HPKE exports.
Substitution or a two-leg relay therefore produces binder, signature,
transcript, or relationship-secret mismatch rather than two usable
relationships.

Both devices use their already configured canonical DUD origin. The encrypted
invitation must contain that identical origin; pairing never introduces or
prompts for a different server.

### 3.15 Invitation Acceptance Race

The first valid acceptance atomically claims the invitation. An identical retry
is idempotent; a different acceptance loses the claim. Races, transcript
mismatch, expiry, and partial pairing are hard failures. No relationship gains
durable delivery capabilities until key confirmation and both signed completion
messages verify.

### 3.16 Restored or Rolled-Back Local State

**Detected** by four peer-echoed watermarks carried in signed control
descriptors: inbound and outbound marks for both data and control chains. A peer
reporting a mark ahead of local state proves the local side rewound; a peer
reporting a mark behind an acknowledgement held signed locally proves the peer
rewound. Detection is symmetric.

On detection the relationship halts and is revoked. The only recovery is fresh
out-of-band pairing under a new relationship ID. A non-zero key epoch is
rejected outright, because an in-band resync would need a two-party activation
state machine that DUD 2.0 does not specify, and half of one is worse than none.
Separately, a non-fast-forward update to a peer remote-tracking ref requires
explicit confirmation, so replay-driven rollback is never silent.

**Residual:** detection happens at the next peer contact. A device that is
rolled back and then operated entirely offline against a malicious server can
accept a replayed delivery in the meantime, subject to the ref-rewrite
confirmation. Catching it earlier would take an OS-keystore or TPM monotonic
counter, and the containerized client cannot count on either.

Seed derivation is not a rollback hazard. It is deterministic, so a restored
seed regenerates identical relationship keys. The sequence watermarks are the
hazard because they are durable separately from the seed.

### 3.17 SSRF and DNS Rebinding via Peer-Provided Origins

Origins are canonical HTTPS with a DNS hostname; IP literals, userinfo, query
strings, fragments, and encoded-host ambiguity are rejected. Redirects are
disabled. A bounded pure-Go DNS-wire resolver queries A, AAAA, and HTTPS/SVCB
over DoH. Every returned address is rejected before connection if any answer is
loopback, private, link-local, multicast, unspecified, documentation-only,
benchmarking, reserved, or a metadata-service address. The validated addresses
reach the connection only through the client's own `DialContext`, which ignores
the hostname it is given, and resolution plus classification is repeated on
every retry.

### 3.18 Compromised or Replayed Authorization

No stable root capability, device key, relationship identifier, or long-lived
bearer appears on the wire. Authorization is bound to method, origin, path, body
digest, direction, slot, slot epoch, scope, expiry, and a single-use nonce, and
does not survive its slot epoch.

**Residual:** the server holds one encrypted proof-of-possession verifier key
per `(relationship, direction, scope)`. It can therefore correlate the
relationship across all slot epochs even though every wire authorization is
nonce-bound and every public slot changes. The 24-hour rotation limits replay
and credential exposure; it is not an anonymity boundary. This is explicitly
accepted by `DUD-V2-DEC-007`. Full operator unlinkability would require a
different anonymous-credential design and a network anonymity layer.

### 3.19 Malicious Git Object Database and Ref Input

Bundles are unbundled into a temporary scratch repository, validated with strict
object checking and `git check-ref-format`, and bounded by bundle bytes, object
count, delta depth, wall time, memory, and disk. Hooks, external helpers,
submodule recursion, and unsafe protocols are disabled. Promotion is an ordinary
fetch with an explicit refspec into `refs/remotes/<peer>/*`, so branch selection
and tag isolation follow from the refspec.

Quarantine lives under the repository's bind-mounted `.git/dud/`, never `/tmp`,
because the wrapper's 128 MB tmpfs cannot hold a 100 MB bundle plus a scratch
repository plus the promoted copy.

A checkpoint this device cannot apply is refused outright, per `protocol-v2.md`
§7.6. The refusal advances the data-chain watermark and prevents a denial of
service. A peer or operator able to plant one unprocessable checkpoint at the
head of the chain could otherwise silence the relationship in both directions,
since no other command consumes a `git-bundle` delivery.

Advancing a watermark past a delivery that was never applied is only safe under
a closed list of causes, so the causes are enumerated and never inferred from
the mere fact that something failed. A delivery may be refused when its signed
metadata describes behaviour this release does not implement, when its bundle
header contradicts its signed metadata, or when it exceeds a bounded local limit
on size, object count, or delta depth. Each of those verdicts is fixed by signed
content or by durable local policy, and a retry cannot change it.

A delivery is **not** refused when verification fails for any other reason.
Exhausted disk space, an exceeded wall-time budget, a memory limit, and a
transport failure stay ordinary errors, because a later attempt could succeed
and refusing would discard a valid checkpoint. A payload whose digest
contradicts its signed descriptor, a failed `fsck`, and a malformed pack also
stay ordinary errors: those are the hostile-input cases this section exists to
catch, and treating them as refusals would let an operator who corrupts a single
delivery induce the receiver to skip past it permanently. The refusal is
recorded durably before it is sent, so a device that stops in between reaches
the same verdict on its next attempt.

### 3.20 Uninvited Enrollment

**Enrollment is gated unless the operator opens it.**
`POST /v2/pairing/rendezvous` is the only route that creates state for a caller
holding neither a capability nor a relationship. A deployment refuses to start
unless it states which policy it runs: `DUD_PEER_SECRET`, or an explicit
`DUD_PEER_OPEN_ENROLLMENT=true`. There is no default, so no deployment becomes
open by omission.

**What gating buys.** Without it, anyone who learns the hostname can pair two of
their own devices and use the deployment as a relay. The existing limits do not
contain that: quota is keyed by relationship, so the per-relationship byte
budget bounds each stranger separately and leaves the deployment as a whole
unbounded. Only the global creation window and the live-record cap are
deployment-wide, and both expire with the rendezvous; neither says anything
about the relationship it produced. `/v2/capabilities/reissue` then lets that
relationship renew itself with no operator involvement.

**What it does not buy.** The proof authorizes creating an invitation, not
holding one. Anyone the operator gives the secret to can enroll any number of
relationships, so it is an admission control, not a per-device authorization or
an audit trail. It is `HMAC-SHA256` over the rendezvous locator and expiry, so
the secret never reaches the wire and a proof taken from a request log
authorizes only the rendezvous it already named; someone who obtains the secret
itself is an enrolled caller from then on.

**Why a passphrase, and what that costs.** This is the only v2 credential that
must exist on a client as well as on the server, so it is carried between
machines and usually typed. It is therefore UTF-8 text with a 24-character
floor, and the HMAC key is stretched from it instead of being configured as raw
bytes.

That choice has a real cost, and the mitigation is specific to it. A proof is a
deterministic MAC over public values, so anyone who captures one from a request
log, observation point, or intermediary can test passphrase guesses against it
offline, at their own pace, without the server and without spending the
per-source throttle. No arrangement of the protocol prevents that; short of a
PAKE, what bounds it is the cost of a single guess. The key is therefore derived
with PBKDF2-HMAC-SHA256 at 600,000 iterations, which puts each guess in the
hundreds of milliseconds instead of under a microsecond, turning an exhaustive
sweep of a four-or-five-word passphrase from hours into an impractical amount of
compute. The salt is a fixed domain string. Nothing deployment-specific goes
into it: one deployment holds a single secret, not a database of them, so a
per-deployment salt would add little on top of the work factor while binding
enrollment to a hostname operators do change. An operator who would rather have
entropy than stretching can use 32 random bytes as the passphrase.

**Who pays the work factor.** The cost is meant to fall on an attacker, and an
attacker guesses passphrases. The server's own derivation is incidental: it
stretches the same passphrase only because that is what it was configured with.
So `DUD_PEER_SECRET` also accepts the derived key itself, under a
`dud2-enroll-key:` prefix, and a deployment configured that way verifies proofs
without deriving anything. This leaves the attacker's cost per guess unchanged
because the devices that hold the passphrase still stretch it. It also lets a
gated deployment run where one derivation exceeds the CPU budget of one request.
`server-v2.md` §3.1 covers the operator's side of it.

The third form, `dud2-enroll-kdf:<iterations>:<passphrase>`, does lower the
attacker's cost, proportionally: at 60,000 iterations a guess is ten times
cheaper than at 600,000. It exists for the operator who wants one typeable value
everywhere, it is refused unless the deployment sets
`DUD_PEER_ACCEPT_WEAK_ENROLLMENT_KDF`, and the client warns whenever it derives
under one. The count lives inside the secret so that it reaches every device the
secret does. A work factor configured per device could disagree between the two
sides, and that disagreement would surface only as the enrollment refusal that
also means "wrong secret", the same reason a deployment-specific salt was
rejected above.

Online guessing is bounded separately, at 10 enrollment attempts per source per
minute, fixed and not configurable. A refused request never spends the
deployment-wide creation window, since nothing else would slow a network-speed
guesser down.

Nothing about enrollment weakens the pairing handshake: an invitee still
authenticates with the out-of-band code, and a gated deployment learns no more
about a relationship than an open one, because the server remains an untrusted
ciphertext rendezvous under §1.

**Residual:** an open deployment is a deliberate configuration, not a defect,
and every §3.12 bound still applies to it. Operators who run one should expect
to be a relay for strangers.

### 3.21 Future Quantum Adversary

**Payload confidentiality is protected.** v2 peer descriptors and payloads use
MLKEM768-X25519 hybrid recipients, and relationship secrets come from mutual
HPKE export over the same KEM. Ciphertext captured today is not a
harvest-now-decrypt-later target.

**Signatures are not.** `age` provides no post-quantum signature type, so sender
authentication remains Ed25519. This asymmetry is deliberate: a forged signature
is only useful before verification, so recorded traffic does not let a future
adversary forge a delivery that was already accepted, whereas recorded
ciphertext does yield plaintext.

Algorithm identifiers are reserved in the descriptor and transcript, so
migrating signatures later is a value change rather than a protocol version
bump.

**Dependency note:** the confidentiality path rests on `age` v1.3.x and
`filippo.io/hpke` v0.4.0, the only implementations of these primitives DUD uses.
Both are pinned to exact versions, recorded in the supply-chain component list,
and covered by the patch policy in [`SECURITY.md`](../SECURITY.md).

## 4. Known Metadata Leakage

Even with everything above, an operator may observe:

- source network address, depending on deployment and proxy;
- the target hostname in the TLS SNI, for any origin used with ECH explicitly
  turned off;
- the DoH resolver's hostname, when system bootstrap is used;
- request timing and frequency;
- ciphertext and descriptor sizes;
- expiry and consume policy;
- chunk count;
- cross-epoch relationship correlation through the server-side verifier record;
- polling behaviour;
- recipient type, from the `age` envelope format. Stanza count is always one:
  peer delivery is one-to-one and a descriptor names exactly one recipient, so
  the count reveals nothing beyond that fixed fact.

## 5. Out of Scope

- Making an actively compromised endpoint trustworthy.
- Proving a storage operator erased bytes.
- Hiding a device's traffic from an observer who sees its source address.
- Defending a user who enters a pairing code obtained from an attacker instead
  of the intended device.
- Anonymity at the network layer.

## 6. Non-Goals That Are Security-Relevant

DUD deliberately does not add a browser interface, server-side decryption,
indexing, previews, search, or a public directory of users, peers, inboxes, or
objects. Each would create a class of attack that no amount of protocol design
removes. There is no automatic merge, rebase, reset, checkout, or force-update
of local Git branches, and no arbitrary plugin execution from received
envelopes.
