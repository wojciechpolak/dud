# DUD v2 Protocol

Normative specification of the v2 wire protocol as released in DUD 2.0.0. It
describes what two implementations have to agree on, not how either is built.
The threat model behind it is [`threat-model-v2.md`](threat-model-v2.md).

Everything below is implemented and served, apart from incremental Git and
chunked transfer: their descriptor keys and feature IDs are reserved, and a
2.0.0 server advertises neither.

## 1. Conventions

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are used as in RFC 2119.

`||` is concatenation. `H(x)` is SHA-256. `HKDF(ikm, salt, info, n)` is
HKDF-SHA256 producing `n` bytes. Byte strings are shown in lowercase hex.

Every field length in this document is a hard limit, not a guideline. A receiver
`MUST` reject input exceeding it rather than truncating.

## 2. Versioning and Algorithm Agility

Every algorithm-selecting root structure — invitation, acceptance, and
descriptor — carries:

| Field     | Type | Meaning                                   |
| --------- | ---- | ----------------------------------------- |
| `v`       | uint | protocol version; `2` for this document   |
| `kem_alg` | uint | recipient encryption algorithm identifier |
| `sig_alg` | uint | signature algorithm identifier            |

Registered values for DUD 2.0.0:

| Identifier | Value | Algorithm                                        |
| ---------- | ----: | ------------------------------------------------ |
| `kem_alg`  |     1 | MLKEM768-X25519 (X-Wing) `age` hybrid recipients |
| `sig_alg`  |     1 | Ed25519                                          |

Values `0` and everything above `1` are reserved. A 2.0.0 implementation `MUST`
reject an unrecognised `kem_alg` or `sig_alg` rather than ignoring it, and
`MUST NOT` negotiate: both fields are covered by the signature, so an attempted
downgrade is a verification failure and not a protocol option.

Key-confirmation and signed-completion maps bind `full_transcript_hash`; the
full transcript contains both algorithm identifiers. They therefore do not
repeat the identifiers as independent fields that could disagree.

Reserving these identifiers is why `DUD-V2-SEC-015` carries a `freeze` gate. It
is what makes a future migration, including to a post-quantum signature scheme,
a value change rather than a new protocol version.

## 3. Encoding

All signed or transmitted structures use **deterministic CBOR**, RFC 8949 §4.2
core deterministic encoding. Local files are out of scope: `config.toml` is TOML
and per-peer Git state is JSON, because nothing signs them.

A decoder `MUST` be configured to reject duplicate map keys and
indefinite-length items, and `MUST` enforce these limits before any allocation
proportional to a declared length:

| Limit               |  Value |
| ------------------- | -----: |
| total encoded bytes | 262144 |
| nesting depth       |      8 |
| array elements      |   4096 |
| map pairs           |    128 |
| text/byte string    |  65536 |

These are protocol constants. A peer must be able to produce a structure the
recipient will accept, so an implementation `MUST NOT` tighten them locally.

Integer keys `0` through `127` are the frozen core namespace. An implementation
`MUST` reject an unknown key in that range. Keys `128` and above are extension
keys and are optional unless the structure carries core key `0`,
`critical_extensions`, as an array containing that extension key. A receiver
`MUST` reject a structure when `critical_extensions` names an extension key it
does not implement. It `MUST` also reject duplicate, non-integer, core, or
out-of-range entries in `critical_extensions`. Extension keys are unsigned
integers from 128 through 65535 inclusive.

This rule gives a receiver an unambiguous way to distinguish an unknown optional
extension from an unknown required one. Adding a required core field needs a new
protocol version; adding a required extension does not.

The total-size cap is enforced before CBOR decoding, using a bounded reader or
an already bounded byte slice. The decoder enforces nesting, array, and map
limits. Per-field schema validation enforces the 65536-byte string limit after
decoding; the prior total-size cap keeps that allocation bounded.

## 4. Identity

### 4.1 Master Seed

A device holds exactly one **user-managed root secret**: a 32-byte master seed,
generated at `dud init` from a CSPRNG. It `MUST NOT` be transmitted, in any
form, ever.

The contributory pairing result cannot be re-derived from that seed alone: each
side lacks the other side's private key and one HPKE sender's ephemeral
randomness. The two directional relationship secrets are therefore durable
per-relationship state. They receive the same storage protection as the seed:
encrypted under a seed-derived local wrapping key when the seed is protected, or
mode-`0600` beside a plaintext seed, where wrapping would add no protection.
Loss of relationship state while retaining only the seed requires fresh pairing;
capability re-issuance in [§9.6](#96-capability-recovery) restores server
authorization, not the end-to-end relationship secret.

The global device ID and device name exist only as local labels for
`config.toml` and `dud doctor`. They `MUST NOT` appear on the wire.

### 4.2 Relationship Identity Derivation

Everything a peer observes is derived per relationship and per key epoch. The
inviter generates the random `relationship_id` before creating an invitation;
that invitation proposes the identifier, and a successful pairing adopts it.
Because every invitation gets a fresh identifier, two invitations from one
device remain unlinkable by their derived keys:

```text
info = "dud/v2/identity|" || relationship_id || "|" || key_epoch
raw  = HKDF(ikm = master_seed, salt = "", info = info, 32)
```

`relationship_id` is a lowercase-hex 128-bit value fixed at pairing. `key_epoch`
is a decimal integer starting at 0. DUD 2.0.0 supports only epoch 0; the field
is reserved so a later authenticated identity-rotation protocol does not need a
schema change.

The 32 bytes `raw` are the `age` hybrid identity directly. The C2SP `age`
specification defines an MLKEM768-X25519 identity as `read(CSPRNG, 32)`, so
substituting derived bytes is exact rather than an approximation. Encode `raw`
as Bech32 with HRP `AGE-SECRET-KEY-PQ-` to obtain the identity, and take the
recipient as `PrivateKeyToPublicKey(raw)`.

The signing key and pseudonymous device ID use the same construction with
distinct `info` labels:

```text
"dud/v2/signing|"  || relationship_id || "|" || key_epoch   -> 32 bytes -> Ed25519 seed
"dud/v2/deviceid|" || relationship_id || "|" || key_epoch   -> 16 bytes -> pseudonymous device ID
```

Domain separation is by label, so no derived output can be computed from
another.

The signing key identifier carried in descriptors is derived from the public
key, not separately:

```text
sender_key_id = SHA-256(signing_public_key)[0:8]
```

It exists so a receiver can select the expected key before verifying, and it is
covered by the signature like any other field.

**Encoding note.** `direction` appears twice in different encodings, and using
the wrong one silently derives a different secret. In the descriptor it is the
uint `0` or `1` ([§7](#7-descriptors)). In every KDF `info` string it is the
literal text `inviter->invitee` or `invitee->inviter`. An implementation
`MUST NOT` substitute one for the other.

An implementation `MUST NOT` shell out to `age-keygen` on this path.
`DUD_AGE_KEYGEN_BIN` remains for dead drop keygen only.

### 4.3 Key Epoch and Slot Epoch

These are two different things and conflating them voids the privacy property of
[§8](#8-delivery-slots).

| Epoch          | Advances on                            | Cadence           |
| -------------- | -------------------------------------- | ----------------- |
| **key epoch**  | future authenticated identity rotation | fixed at 0 in 2.0 |
| **slot epoch** | the passage of 24 hours                | daily             |

The key epoch keys identity derivation and appears in the signature input. DUD
2.0 `MUST` reject a non-zero value. In-band identity rotation is not specified
in 2.0: replacement revokes the old relationship and performs fresh out-of-band
pairing under a new random relationship ID, as described in
[§9.5](#95-identity-replacement).

The slot epoch keys slot derivation and request authorization. It is computed
from wall-clock time alone:

```text
slot_epoch = floor(unix_seconds / 86400)
```

It `MUST NOT` depend on the key epoch, on delivery sequence, or on any
per-relationship state, so that an adversary cannot stall rotation by stalling
traffic.

## 5. Pairing Codes and Invitations

A pairing code is exactly 128 bits from a cryptographically secure random
source. Its canonical display is eight lowercase four-hex groups, for example
`4664-43e6-72d9-edf8-8e80-2a2f-2652-b33b`. Parsing removes dashes and then
requires exactly 32 lowercase hexadecimal characters. Uppercase, whitespace, and
any other character are invalid.

The code derives domain-separated rendezvous, invitation-envelope, role-binder,
and relationship-PSK material with SHA-256 and HKDF-SHA256. The invitation is a
bootstrap credential; it is not an authorization to deliver anything.

| Field                  | Type  | Notes                                         |
| ---------------------- | ----- | --------------------------------------------- |
| `v`                    | uint  | 2                                             |
| `kem_alg`, `sig_alg`   | uint  | see [§2](#2-versioning-and-algorithm-agility) |
| `invitation_id`        | bytes | 32, random                                    |
| `relationship_id`      | bytes | 16, random; proposed epoch-0 relationship     |
| `inviter_pairing_id`   | bytes | 16, per-invitation pseudonym                  |
| `age_recipient`        | bytes | 1216, per-invitation hybrid recipient         |
| `signing_public_key`   | bytes | 32, per-invitation Ed25519 public key         |
| `canonical_origin`     | text  | canonical HTTPS origin                        |
| `bootstrap_capability` | bytes | opaque, single-use                            |
| `nonce`                | bytes | 32, random                                    |
| `expires_at`           | uint  | Unix seconds                                  |

The invitation proposes a fresh `relationship_id`, generated by the inviter
alongside `invitation_id`. Both sides derive their epoch-0 relationship
identities with the ordinary construction in
[§4.2](#42-relationship-identity-derivation):

```text
HKDF(master_seed, "", "dud/v2/identity|" || relationship_id || "|0", 32)
```

On successful pairing these remain the relationship keys at `key_epoch = 0`. An
invitation that expires or is never accepted leaves a fresh relationship
identifier and keys that are never used again. The identifier is inside the
encrypted invitation and later inside encrypted descriptors. Before acceptance,
the server stores only a hash-derived locator and encrypted envelope. The
identifier is never used in an object/slot path or exposed as a public mailbox
name.

### 5.1 Invitation Encryption

The invitation is deterministic CBOR encrypted with XChaCha20-Poly1305 under the
code-derived invitation-envelope key. Associated data is deterministic CBOR
binding protocol version `2`, the 32-byte locator, configured canonical origin,
and `expires_at`. The public envelope is at most 4096 bytes and contains only
version, locator, 24-byte nonce, ciphertext, expiry, and salted bearer
verifiers.

Human-readable invite output always displays the canonical text code and a
terminal QR encoding exactly that string. JSON output contains `pairing_code`
and an identical `qr_payload` without terminal graphics. The scanned payload is
therefore always 39 characters and never grows with the invitation: a complete
hybrid-recipient invitation carrying the longest legal canonical origin is about
1.7 KiB, which the 4096-byte envelope holds with room to spare.

### 5.2 Invitation Lifetime

Default expiry is 15 minutes. A server `MUST` reject an invitation whose
`expires_at` exceeds one hour from creation. The cap is server-enforced rather
than advisory so that a long-lived bootstrap credential cannot exist even when a
client asks for one.

Consumption `MUST` be an atomic claim: the first valid acceptance wins. An
identical retry of that acceptance is idempotent and returns the same state. A
different acceptance `MUST` fail with `invitation_claimed` and `MUST NOT` create
or replace a relationship. Invitation races, transcript mismatch, expiry, and
partial pairing are hard failures and `MUST` be displayed as such.

### 5.3 Invitation Input Channels

The code is accepted only by `dud peer accept NAME` from its visible
controlling- TTY prompt. It is never accepted from arguments, environment
variables, files, or standard input. A mode-`0600` pending-state file may retain
it solely to resume the same interrupted command and alias; it is deleted after
activation, cancellation, or expiry.

## 6. Pairing

Pairing has three cryptographic messages followed by two signed automatic
completions. Two cryptographic messages are not sufficient: the inviter cannot
encapsulate to the invitee until the acceptance reveals the invitee's recipient.

```text
1. encrypted invitation server -> invitee, located by the entered code
2. acceptance       invitee -> inviter   carries enc_B
3. key confirmation inviter -> invitee   carries enc_A
4. signed completion inviter -> server
5. signed completion invitee -> server
```

Steps 4 and 5 may arrive in either order. One device cannot complete for the
other. The server activates and returns durable delivery capabilities only after
both valid completions are stored.

Every pairing structure is a deterministic-CBOR map. Core key `0` has the
extension meaning from [§3](#3-encoding). The invitation uses these integer
keys:

| Key | Field                  | Type        |
| --: | ---------------------- | ----------- |
|   1 | `v`                    | uint        |
|   2 | `kem_alg`              | uint        |
|   3 | `sig_alg`              | uint        |
|   4 | `invitation_id`        | bytes, 32   |
|   5 | `relationship_id`      | bytes, 16   |
|   6 | `inviter_pairing_id`   | bytes, 16   |
|   7 | `age_recipient`        | bytes, 1216 |
|   8 | `signing_public_key`   | bytes, 32   |
|   9 | `canonical_origin`     | text        |
|  10 | `bootstrap_capability` | bytes, 32   |
|  11 | `inviter_nonce`        | bytes, 32   |
|  12 | `expires_at`           | uint        |

The acceptance signed map uses:

| Key | Field                        | Type                                        |
| --: | ---------------------------- | ------------------------------------------- |
|   1 | `v`                          | uint                                        |
|   2 | `kem_alg`                    | uint                                        |
|   3 | `sig_alg`                    | uint                                        |
|   4 | `invitation_id`              | bytes, 32                                   |
|   5 | `relationship_id`            | bytes, 16                                   |
|   6 | `invitee_pairing_id`         | bytes, 16                                   |
|   7 | `invitee_age_recipient`      | bytes, 1216                                 |
|   8 | `invitee_signing_public_key` | bytes, 32                                   |
|   9 | `invitee_nonce`              | bytes, 32                                   |
|  10 | `invitation_digest`          | bytes, 32                                   |
|  11 | `enc_B`                      | bytes, 1120                                 |
|  12 | `status_capability_hash`     | bytes, 32; SHA-256 of invitee status bearer |
|  13 | `invitee_role_binder`        | bytes, 32                                   |
|  14 | `rendezvous_locator`         | bytes, 32                                   |

The key-confirmation signed map uses:

| Key | Field                  | Type        |
| --: | ---------------------- | ----------- |
|   1 | `v`                    | uint        |
|   2 | `invitation_id`        | bytes, 32   |
|   3 | `relationship_id`      | bytes, 16   |
|   4 | `acceptance_digest`    | bytes, 32   |
|   5 | `enc_A`                | bytes, 1120 |
|   6 | `full_transcript_hash` | bytes, 32   |
|   7 | `inviter_role_binder`  | bytes, 32   |

`invitation_digest` is SHA-256 of the complete deterministic-CBOR invitation
map, including its bootstrap capability. `acceptance_digest` is SHA-256 of the
deterministic-CBOR acceptance map, excluding its alongside signature. These
definitions are not hashes of the displayed pairing code or HTTP wrapper.

The signed-completion map uses:

| Key | Field                  | Type                       |
| --: | ---------------------- | -------------------------- |
|   1 | `v`                    | uint                       |
|   2 | `invitation_id`        | bytes, 32                  |
|   3 | `relationship_id`      | bytes, 16                  |
|   4 | `full_transcript_hash` | bytes, 32                  |
|   5 | `role`                 | uint; 0 inviter, 1 invitee |
|   6 | `completed_at`         | uint                       |

For every signed pairing map:

```text
map_digest = SHA-256(deterministic_cbor(map))
sig_input  = "dud/v2/pairing/" || message_name || 0x00 || map_digest
signature  = Ed25519(message_signing_key, sig_input)
```

`message_name` is exactly `acceptance`, `key-confirmation`, or
`pairing-complete`. The signature is carried alongside the map and is never a
member of the map it signs. “Pairing signing key” means the epoch-0 Ed25519
relationship signing key whose public key is in the transcript, not
`*_pairing_id`. Acceptance is signed by the invitee's key, key confirmation by
the inviter's key, and each completion by the corresponding role's key.

### 6.1 Transcript

The **pre-transcript** is the following deterministic-CBOR map. It binds every
agreed field except the two encapsulated keys:

| Key | Field                        | Type                              |
| --: | ---------------------------- | --------------------------------- |
|   1 | `v`                          | uint                              |
|   2 | `kem_alg`                    | uint                              |
|   3 | `sig_alg`                    | uint                              |
|   4 | `invitation_id`              | bytes, 32                         |
|   5 | `relationship_id`            | bytes, 16                         |
|   6 | `canonical_origin`           | text                              |
|   7 | `inviter_pairing_id`         | bytes, 16                         |
|   8 | `invitee_pairing_id`         | bytes, 16                         |
|   9 | `inviter_age_recipient`      | bytes, 1216                       |
|  10 | `invitee_age_recipient`      | bytes, 1216                       |
|  11 | `inviter_signing_public_key` | bytes, 32                         |
|  12 | `invitee_signing_public_key` | bytes, 32                         |
|  13 | `inviter_nonce`              | bytes, 32                         |
|  14 | `invitee_nonce`              | bytes, 32                         |
|  15 | `expires_at`                 | uint                              |
|  16 | `key_epoch`                  | uint; 0 at initial pairing        |
|  17 | `capability_scope`           | text; exactly `bootstrap` in v2.0 |
|  18 | `rendezvous_locator`         | bytes, 32                         |
|  19 | `invitee_role_binder`        | bytes, 32                         |

The **full transcript** is a deterministic-CBOR map with the same keys and
values plus key 20 `enc_A` and key 21 `enc_B`, each a 1120-byte byte string.
`enc_A` always precedes `enc_B` by key assignment; neither role may reorder the
semantic labels. This is not an ad-hoc concatenated string.

Binding is split across two stages because binding it in one would be circular:
the invitee must derive before `enc_A` exists. The pre-transcript hash is the
HPKE `info`; the full transcript hash is the salt of the final combine and is
the object both signatures cover. Neither encapsulated key can be substituted
without changing the derived secret and failing signature verification.

### 6.2 Key Agreement

Key agreement uses **RFC 9180 HPKE secret export**, not a raw KEM shared secret.
`filippo.io/hpke`, the module `age` itself depends on, does not export
`encap`/`decap`; `Sender.Export` and `Recipient.Export` are the public interface
and are the construction analysed for deriving keys from a KEM without sending a
payload. The AEAD is `ExportOnly` (`0xFFFF`) because nothing is ever sealed.

```text
info = H(pre_transcript)
kdf  = HKDF-SHA256
aead = ExportOnly

invitee : enc_B, S = HPKE.NewSender(inviter_recipient, kdf, aead, info)
          ss_B     = S.Export("dud/v2/pairing", 32)
inviter : R        = HPKE.NewRecipient(enc_B, own_identity, kdf, aead, info)
          ss_B     = R.Export("dud/v2/pairing", 32)

inviter : enc_A, S = HPKE.NewSender(invitee_recipient, kdf, aead, info)
          ss_A     = S.Export("dud/v2/pairing", 32)
invitee : R        = HPKE.NewRecipient(enc_A, own_identity, kdf, aead, info)
          ss_A     = R.Export("dud/v2/pairing", 32)

relationship_secret[direction] =
    HKDF(ikm  = ss_A || ss_B || relationship_psk,
         salt = H(full_transcript),
         info = "dud/v2/relationship|" || direction || "|" || key_epoch,
         32)
```

`direction` is the literal text `inviter->invitee` or `invitee->inviter`. Each
direction's secret is independent; neither can be derived from the other.
`key_epoch` is the ASCII digit `0` in DUD 2.0.

`enc_A` and `enc_B` are 1120 bytes each.

The construction is contributory: neither side alone determines the result. Two
sides that disagree on any bound field derive incompatible secrets and cannot
communicate, rather than pairing successfully with the wrong peer.

Before a device submits its signed completion, it `MUST` durably persist the
full transcript and both final directional relationship secrets. A restart can
then resume completion/status polling without reconstructing HPKE sender
randomness. The pending state is deleted on decline, mismatch, cancellation, or
expiry; on two-sided completion it becomes active relationship state atomically
with the capability grant. The transcript alone is not sufficient recovery
material.

**Last-mover property, accepted.** The second party to encapsulate sees the
first encapsulated key and could grind randomness to bias the combined output.
Both parties legitimately hold the result, and it is never used as a commitment,
a beacon, or a source of randomness any third party relies on, so a biased value
gives its producer nothing it does not already have.

### 6.3 Code Authentication and Completion

The invitation-envelope, invitee-binder, inviter-binder, and relationship-PSK
keys use distinct HKDF info labels. The invitee binder authenticates the
acceptance fields other than `enc_B` and the binder itself. The inviter binder
authenticates `full_transcript_hash`. Each binder is included in its role's
signed map and in the full transcript.

After signature, binder, transcript, and HPKE verification succeeds locally,
each client automatically signs and submits its completion map. There is no
manual comparison command, escape flag, or second human approval.

The first valid acceptance atomically claims the invitation. An identical retry
is idempotent. A different acceptance receives `invitation_claimed`; it never
replaces the pending acceptance. The inviter does not become bound to the first
responder: an incomplete claim expires or is explicitly cancelled, and no
durable capability exists before both completions.

No durable delivery capability is issued until both signed completions succeed.

## 7. Descriptors

Every v2 delivery is an `age`-encrypted, signed descriptor plus ciphertext
payload. The server stores only those.

**Encryption.** The encoded descriptor and its signature are encrypted with
`age` to exactly one recipient: the peer's relationship recipient for the
current key epoch, derived per [§4.2](#42-relationship-identity-derivation). The
payload is encrypted separately to the same recipient.

Peer delivery is one-to-one, so 2.0.0 has no recipient sets and no recipient-set
identifier. A descriptor `MUST` name exactly one `recipient_device_id`. This is
deliberate scope: multi-recipient delivery would change what the `age` envelope
leaks about recipient count, which [`threat-model-v2.md`](threat-model-v2.md)
states as fixed at one.

The descriptor is a CBOR map with **integer keys**. Integer keys keep the
encoding compact and make deterministic ordering unambiguous: RFC 8949 §4.2
sorts by encoded key bytes, which for small unsigned integers is numeric order.

| Key | Field                 | Type  | Notes                                                     |
| --: | --------------------- | ----- | --------------------------------------------------------- |
|   0 | `critical_extensions` | array | optional; extension keys required to process              |
|   1 | `v`                   | uint  | 2                                                         |
|   2 | `kem_alg`             | uint  | see [§2](#2-versioning-and-algorithm-agility)             |
|   3 | `sig_alg`             | uint  | see [§2](#2-versioning-and-algorithm-agility)             |
|   4 | `descriptor_id`       | bytes | 16, random                                                |
|   5 | `payload_type`        | uint  | see below                                                 |
|   6 | `relationship_id`     | bytes | 16                                                        |
|   7 | `direction`           | uint  | 0 = `inviter->invitee`, 1 = `invitee->inviter`            |
|   8 | `chain`               | uint  | 0 = data, 1 = control                                     |
|   9 | `key_epoch`           | uint  |                                                           |
|  10 | `seq`                 | uint  | strictly monotonic within `(direction, chain)`            |
|  11 | `prev_digest`         | bytes | 32, digest of the previous descriptor in the chain        |
|  12 | `sender_device_id`    | bytes | 16, pseudonymous                                          |
|  13 | `sender_key_id`       | bytes | 8, identifies the signing key within the epoch            |
|  14 | `recipient_device_id` | bytes | 16, pseudonymous                                          |
|  15 | `canonical_origin`    | text  | see [§10.1](#101-canonical-origin)                        |
|  16 | `created_at`          | uint  | Unix seconds                                              |
|  17 | `transport_policy`    | map   | signed requested policy; see [§7.4](#74-transport-policy) |
|  18 | `payload_hash`        | bytes | 32, of the plaintext                                      |
|  19 | `chunk_hashes`        | array | ordered ciphertext hashes; exactly one entry in 2.0.0     |
|  20 | `display_name`        | text  | optional                                                  |
|  21 | `archive_format`      | uint  | optional; 0 = none, 1 = tar                               |
|  22 | `plaintext_size`      | uint  | optional; bounds extraction                               |
|  23 | `type_meta`           | map   | optional; payload-type-specific metadata                  |
|  24 | `chunk_size`          | uint  | **2.0.0 rejects on presence**                             |
|  25 | `chunk_ids`           | array | **2.0.0 rejects on presence**                             |
|  26 | `incremental_base`    | bytes | **2.0.0 rejects on presence**                             |

`expires_at` is not a top-level descriptor field. It lives once inside the
signed nested transport policy ([§7.4](#74-transport-policy)).

The signature is **not** a map entry. It is carried alongside the encoded map,
because it cannot be inside the bytes it signs.

Before `age` encryption, the descriptor plaintext is this deterministic-CBOR
envelope:

| Key | Field            | Type                     |
| --: | ---------------- | ------------------------ |
|   1 | `descriptor_map` | map; the exact map below |
|   2 | `signature`      | bytes, 64                |

The complete envelope is encrypted as one `age` file. A receiver decrypts,
decodes, verifies the signature, then retrieves and decrypts the separately
referenced payload object.

Payload types and their chains:

| Value | Type              | Chain   |
| ----: | ----------------- | ------- |
|     1 | `message`         | data    |
|     2 | `file`            | data    |
|     3 | `collection`      | data    |
|     4 | `git-bundle`      | data    |
|     5 | `acknowledgement` | control |
|     6 | `peer-control`    | control |

### 7.1 Two Chains Per Direction

Each direction carries exactly two independent chains, each with its own
monotonic sequence, predecessor digest, replay cache, and durable high-water
mark. Nothing orders one chain against the other; an acknowledgement references
the data descriptor it acknowledges by digest, never by sequence.

A sequence number is assigned **at commit**, as one atomic local step under a
per-chain lock, and only once every payload byte is committed. An interrupted or
cancelled transfer consumes no sequence number, so a gap can only be produced by
a server withholding or reordering a committed delivery.

Every chain begins at `seq = 1` with `prev_digest` equal to 32 zero bytes.
Thereafter `seq` is exactly the previous accepted sequence plus one and
`prev_digest` is the SHA-256 digest of the previous descriptor map.

Receiver handling is deterministic:

- `seq` below the durable watermark is stale and rejected;
- `seq` equal to an idempotently completed entry is accepted only when the full
  descriptor digest matches the recorded digest, and produces no second output;
- the same `seq` with a different digest is a fork and quarantines that chain;
- `seq` greater than `watermark + 1` is a gap and quarantines that chain;
- a valid next descriptor advances the durable watermark only at output commit.

Because a gap quarantines the chain, a server `MUST` hand pending deliveries to
a reader in the order it accepted them. The inbox returns the oldest unretired
delivery for a slot, and "oldest" means the earliest publication, not the
smallest wall-clock stamp: publication times are whole seconds and delivery IDs
are opaque, so neither can order two publications inside one second. A server
therefore keeps its own per-relationship, per-direction insertion counter and
orders by it. The server cannot read `seq` — it is inside the encrypted
descriptor — so this ordering is what makes the receiver's gap rule detect a
withheld or reordered delivery rather than fire on a healthy relationship.

The local durable receive state machine is:

```text
received -> descriptor-verified -> payload-verified -> output-committed
         -> acknowledgement-queued -> acknowledgement-confirmed
```

Every transition is an atomic state write. Restart resumes from the last
recorded transition. Output commit and acknowledgement queueing are one local
transaction: after an output is visible, a retry can only resend its
acknowledgement, never reproduce the output. Sender state advances only after a
matching signed acknowledgement is confirmed.

### 7.2 Signature Input

```text
descriptor_digest = SHA-256(deterministic_cbor(descriptor_map))
sig_input         = "dud/v2/descriptor" || 0x00 || descriptor_digest
signature         = Ed25519(signing_key, sig_input)
```

There is no concatenation format. Every value that must be bound — relationship,
direction, chain, key epoch, sequence, predecessor, sender, recipient, origin,
payload hash, transport policy — is a **field of the map**, so the signature
covers them by covering the encoding.

This is deliberate. An ad-hoc concatenation is where length-extension and field
confusion bugs live, and it requires every implementation to agree on a
serialization that exists nowhere else. Binding by digest-of-the-canonical-
encoding reuses the determinism already required by [§3](#3-encoding).

Verification `MUST` occur before any payload byte is written or extracted.

### 7.3 Rejection Rules

A receiver `MUST` reject, before payload processing, any descriptor that is
duplicate, stale, forked, gapped, wrong-direction, wrong-recipient,
wrong-origin, or wrong-relationship.

A 2.0.0 receiver `MUST` also reject on the **presence** of key 24
(`chunk_size`), key 25 (`chunk_ids`), or key 26 (`incremental_base`), regardless
of value. Those keys are reserved for chunked transfer and incremental Git.
Their presence means the sender expects behaviour this release does not
implement, and processing such a delivery partially is worse than refusing it.

These rejections all concern the descriptor itself. A descriptor that is valid
but describes payload behaviour this release does not implement is not rejected
here; it is refused by its payload-type handler under
[§7.6](#76-refusing-a-delivery), which is what allows the sender to be told and
the chain to advance.

A 2.0.0 receiver also rejects any descriptor whose `key_epoch` is not zero.

`chunk_hashes` (key 19) is not such a signal: 2.0.0 uses it with exactly one
entry. A receiver `MUST` reject a `chunk_hashes` array with more than one entry.

### 7.4 Transport Policy

The canonical transport policy is a nested CBOR map with integer keys, embedded
as descriptor key 17. Its requested values are therefore signed directly. Its
digest is the compact identifier used by claim and acknowledgement operations.

| Key | Field                 | Type | Notes                                       |
| --: | --------------------- | ---- | ------------------------------------------- |
|   1 | `expires_at`          | uint | Unix seconds                                |
|   2 | `consume`             | uint | 0 = none, 1 = delete-after-read, 2 = strict |
|   3 | `claim_lease_seconds` | uint | 300 by default                              |
|   4 | `ack_mode`            | uint | 0 = none, 1 = after output commit           |

```text
policy_digest = SHA-256(deterministic_cbor(transport_policy))
```

Comparison between the signed policy and server-visible commit metadata uses a
split rule:

- **exact equality** for consume policy, claim semantics, acknowledgement
  semantics, and every field with no meaningful ordering. Any difference is a
  rejection.
- **safe dominance** for `expires_at` alone: server-visible expiry `MAY` be
  earlier than signed, and `MUST NOT` be later.

Dominance applies only where the stricter direction is unambiguous, so a backend
that clamps a TTL downward does not fail a transfer that was never unsafe.

A client `MUST` reject a response advertising weaker semantics than it
requested. Claim and acknowledgement operations `MUST` bind `policy_digest`. The
server stores both the requested policy digest and its effective public policy;
it never replaces the signed requested map inside the encrypted descriptor.

### 7.5 Payload-Type Metadata

`type_meta` (key 23) is a CBOR map with integer keys whose meaning depends on
`payload_type`. It is covered by the signature like any other field.

The key-namespace rule of [§2](#2-versioning-and-algorithm-agility) applies to
`type_meta` exactly as it does to the descriptor: keys `0` through `127` are the
frozen core namespace and an unknown one `MUST` be rejected, while keys `128`
and above are extension keys that a receiver `MUST` ignore when it does not
implement them. One convention covers both structures, so adding a payload-type
field in a later release does not break deployed peers.

Descriptor validation checks the _structure_ of `type_meta`: its key set, field
types, and lengths. It `MUST NOT` reject a structurally valid `type_meta`
because the release does not implement the behaviour it describes. That verdict
belongs to the payload-type handler, which holds the chain state needed to
answer the sender. The distinction matters: a descriptor rejected during
validation cannot be acknowledged, so it stays at the head of its chain forever,
while one refused by its handler is answered with `result = 1` and the chain
moves on. See [§7.6](#76-refusing-a-delivery).

For `message` (1) and `file` (2), `type_meta` is absent.

For `collection` (3):

| Key | Field         | Type  | Notes                                         |
| --: | ------------- | ----- | --------------------------------------------- |
|   1 | `entry_count` | uint  | top-level entries, for pre-extraction display |
|   2 | `names`       | array | top-level logical names, text                 |

For `acknowledgement` (5):

| Key | Field             | Type  | Notes                                       |
| --: | ----------------- | ----- | ------------------------------------------- |
|   1 | `acked_seq`       | uint  | data-chain sequence acknowledged            |
|   2 | `acked_digest`    | bytes | 32, digest of the descriptor acknowledged   |
|   3 | `result`          | uint  | 0 committed, 1 rejected                     |
|   4 | `output_digest`   | bytes | 32, digest of the committed logical result  |
|   5 | `hwm_out_data`    | uint  | sender's outgoing data-chain watermark      |
|   6 | `hwm_out_control` | uint  | sender's outgoing control-chain watermark   |
|   7 | `hwm_in_data`     | uint  | sender's incoming data-chain watermark      |
|   8 | `hwm_in_control`  | uint  | sender's incoming control-chain watermark   |
|   9 | `result_meta`     | map   | optional; payload-type acknowledgement data |
| 128 | `peer_features`   | array | optional; feature IDs the sender implements |

For `result = 1`, `output_digest` is 32 zero bytes and `result_meta` is absent.

`peer_features` (key 128) is an extension key and therefore optional. It carries
the registered feature IDs of [§11.2](#112-capability-discovery) that the
acknowledging device implements _as a peer_, which is a different question from
what the server will relay. Capability discovery is a client-to-server
mechanism; two peers never speak to each other except through delivered
descriptors, so an acknowledgement is the only place this can travel. A receiver
that does not implement the key ignores it. A sender that does not see a clean
list `MUST` assume the 2.0.0 baseline and `MUST NOT` infer support from silence:
an absent list means the peer said nothing, not that it supports nothing beyond
the baseline by choice. A 2.0.0 device advertises `[5]`. Acknowledgements apply
to data-chain deliveries; acknowledgement and peer-control descriptors are never
themselves acknowledged, preventing an acknowledgement loop.

The four watermark fields are present on every acknowledgement and every
`peer-control` message. They are relative to the control-message sender and
therefore cover both chains in both directions without ambiguous direction
names. A value ahead of the recipient's corresponding local state proves local
rollback. A value behind a signed acknowledgement retained by the recipient
proves peer rollback. Either proof halts the entire relationship until a fresh
out-of-band pairing creates a new relationship ID. The old relationship is
revoked and never resumed from the rewound state.

For `peer-control` (6):

| Key | Field             | Type                                        |
| --: | ----------------- | ------------------------------------------- |
|   1 | `operation`       | uint; 1 revoke                              |
|   2 | `hwm_out_data`    | uint                                        |
|   3 | `hwm_out_control` | uint                                        |
|   4 | `hwm_in_data`     | uint                                        |
|   5 | `hwm_in_control`  | uint                                        |
|   6 | `reason`          | uint; 0 unspecified, 1 replaced, 2 rollback |

The outer descriptor signature authenticates revocation. DUD 2.0 has no
peer-control operation for identity rotation or rollback resync; defining one
requires a later protocol amendment with a complete two-party activation state
machine.

For `git-bundle` (4):

| Key | Field            | Type  | Notes                                                    |
| --: | ---------------- | ----- | -------------------------------------------------------- |
|   1 | `repository_id`  | bytes | 16                                                       |
|   2 | `object_format`  | uint  | 1 SHA-1, 2 SHA-256                                       |
|   3 | `bundle_version` | uint  | 2 or 3                                                   |
|   4 | `refs`           | map   | full ref name to 20- or 32-byte object ID                |
|   5 | `prerequisites`  | array | prerequisite object IDs; empty for a 2.0 full checkpoint |

Every ref name is validated with `git check-ref-format` before bundle
processing. Object-ID lengths must match `object_format`.

A 2.0.0 `git-bundle` descriptor has no `incremental_base` core field, and its
`prerequisites` array is empty. The two are enforced at different layers, and
deliberately so. `incremental_base` is a core descriptor key, so its presence is
rejected during validation by the rule in [§7.3](#73-rejection-rules). A
non-empty `prerequisites` array is _structurally valid_ — it is the shape an
incremental sender legitimately produces — so it parses, and the Git handler
then refuses the delivery under [§7.6](#76-refusing-a-delivery). Nothing reaches
Git unvalidated either way; the difference is that the second case can be
answered.

Incremental Git is therefore signalled by `prerequisites` alone. Key 26 stays
reserved and stays rejected on presence: it duplicates what the signed
`prerequisites` array already carries, and leaving it untouched keeps the frozen
wire vector for a reserved core key intact.

For a successful Git acknowledgement, `result_meta` is:

| Key | Field           | Type                                |
| --: | --------------- | ----------------------------------- |
|   1 | `repository_id` | bytes, 16                           |
|   2 | `fetched_refs`  | map from full ref name to object ID |
|   3 | `prerequisites` | array of object IDs                 |

### 7.6 Refusing a Delivery

A receiver that has verified a delivery's descriptor but cannot commit its
payload `MUST` be able to say so. It acknowledges with `result = 1`, advances
its receive watermark past the delivery, and records the refusal durably. The
sender learns the delivery was seen and refused, which is a different state from
one still in flight.

Without this, a delivery no receiver could apply would sit at the head of its
chain permanently: the watermark advances only at output commit, and a chain
whose head never commits accepts nothing behind it. Because a `git-bundle`
delivery is also not consumable by any other command, one such delivery would
silence the whole relationship rather than one transfer.

A refusal is permitted only when the cause is a deterministic function of signed
content or of a durable local limit — metadata the release cannot implement, a
payload contradicting its own signed metadata, or a bounded resource limit the
receiver enforces by policy. It `MUST NOT` be issued for an environment-
dependent failure such as exhausted disk space, an exceeded time budget, or a
transport error, because a later attempt could succeed and the delivery would
have been discarded for nothing.

A refusal `MUST NOT` be issued for a payload that contradicts its signed
descriptor by digest. That is evidence of tampering in transit rather than of a
sender that built the delivery wrong, and refusing it would let an operator who
corrupts one delivery persuade the receiver to skip past it for good. Such a
delivery stays uncommitted and is reported.

The refusal is written to durable state before it is sent, so a device that
stops in between refuses identically on its next attempt rather than losing the
verdict. Because the permitted causes are deterministic, repeating the judgment
reaches the same answer.

## 8. Delivery Slots

```text
slot = HKDF(ikm  = relationship_secret[direction],
            salt = "",
            info = "dud/v2/slot|" || chain_name || "|" || slot_epoch,
            16)
```

`chain_name` is `data` or `control`.

A receiver polls the current slot plus a recovery window of at least the maximum
object TTL, which at a 24-hour slot epoch and a 30-day maximum TTL is
approximately 30 slots.

**What this provides.** Rotating slots remove a permanent public mailbox name
and make storage keys from different epochs unlinkable without the relationship
secret or the server authorization database. They do not make traffic unlinkable
from the service operator. The operator can correlate a relationship across
epochs through its verifier-key record, and independently observes source
addresses and timing. Authorization values still rotate daily to limit replay
and credential exposure. See [`threat-model-v2.md`](threat-model-v2.md).

## 9. Authorization

### 9.1 Scopes

Scopes are independent and least-privileged. A capability in one scope
`MUST NOT` grant or derive another.

| Scope         | Grants                                          |
| ------------- | ----------------------------------------------- |
| `bootstrap`   | accept exactly one invitation, nothing else     |
| `pair-status` | poll/approve one role in one pending invitation |
| `write`       | send to one direction and slot window           |
| `read`        | list and read one expected slot window          |
| `ack`         | acknowledge or consume retrieved deliveries     |
| `admin`       | create, revoke, inspect, rotate capabilities    |

### 9.2 Capability Tokens

For reusable relationship scopes `write`, `read`, and `ack`, the server issues
an opaque 32-byte `token_secret` per `(relationship, direction, scope)` at
pairing and at each capability rotation. It is provisioned inside the
relationship-recipient-encrypted capability grant and is never used as a bearer.
Bootstrap, pairing-status, object, claim, and administrative credentials are the
narrow bearers specified in [§11.1](#111-common-wire-rules); they do not use
this derivation.

`token_secret` is a proof-of-possession verifier key, not a bearer value: seeing
it in server storage would permit forgery, but observing a request does not
reveal it. The server stores verifier keys encrypted at rest under a deployment
key and never logs or returns them. Bearer bootstrap credentials are stored only
as salted hashes. This is the "equivalent verifier" branch of the storage
requirement; a one-way hash alone cannot verify future request MACs.

Every reusable relationship scope is bound to the actual derived delivery slot;
release 2.0 has no un-slotted relationship scope.

The identifier presented on the wire rotates every slot epoch:

```text
cap_id = HMAC-SHA256(token_secret,
         "dud/v2/capid|" || direction || "|" || scope || "|"
         || slot || "|" || slot_epoch)[0:16]
```

The server can index this because it holds the verifier keys it issued: at each
epoch boundary it recomputes the expected `cap_id` for every live token. No
stable capability value appears on the wire, and no request value survives its
slot epoch.

The service operator can nevertheless correlate a relationship **across all
epochs**, because the verifier-key record is stable and was issued during
pairing. Rotation therefore limits replay and credential exposure; it does not
provide unlinkability from the operator. Rotating slot identifiers prevent a
stable public mailbox name and prevent correlation from a storage-key snapshot
without the authorization database. They do not make requests anonymous to the
server that authorizes them.

### 9.3 Request Authorization

Possession is proven per request, in the style of RFC 9421:

```text
auth_key = HKDF(token_secret, "",
           "dud/v2/authkey|" || direction || "|" || scope || "|"
           || slot || "|" || slot_epoch, 32)

auth_mac = HMAC-SHA256(auth_key,
             "dud/v2/auth" || 0x00 || method || 0x00 || canonical_origin
             || 0x00 || normalized_path || 0x00
             || body_digest || 0x00 || direction || 0x00 || scope
             || 0x00 || slot || 0x00 || slot_epoch
             || 0x00 || nonce || 0x00 || exp)
```

`body_digest` is SHA-256 of the request body, or 32 zero bytes when there is
none. `nonce` is 16 random bytes and `MUST` be single-use within `exp`. `exp` is
Unix seconds and `MUST NOT` exceed the end of `slot_epoch`.

For an opaque request body, the sender transmits the committed digest as:

```text
DUD-Content-SHA256: <64 lowercase hexadecimal characters>
```

The server uses that value to verify request authorization before reading
payload bytes, reserves the declared `Content-Length` (or the maximum object
size when it is absent), hashes the body while streaming it to staging, and
publishes only if the streamed digest and byte count match. The same header on a
`HEAD` response reports the committed ciphertext digest. CBOR request bodies are
small and are hashed from their bounded deterministic encoding before
authorization. A digest header is not an integrity substitute for the MAC: it is
an authenticated input and a streaming commitment.

In these inputs `direction` and `scope` are the lowercase ASCII names registered
in this document, `slot` is the 16 raw slot bytes, and `slot_epoch` and `exp`
are unsigned 64-bit big-endian integers. `normalized_path` is the
percent-encoded absolute path emitted by the endpoint table, with no query
component. HTTP methods are uppercase ASCII. No locale-dependent or decimal
serialization participates in a MAC.

A capability value `MUST NOT` appear in a URL or query parameter. The server
`MUST` compare in constant time and `MUST` rate-limit failures.

### 9.4 Revocation

Revocation is a durable property of the `(relationship, direction, scope)`
tuple, recorded server-side and independent of whether a token exists then.
Revoking invalidates every future `cap_id`, because they derive from a token
secret the server marks dead.

### 9.5 Identity Replacement

DUD 2.0 replaces identity by revoking the old relationship and performing the
complete out-of-band pairing protocol with a fresh random `relationship_id`.
There is no in-band key-rotation or rollback-resync message in 2.0, and
`key_epoch` remains zero. An implementation `MUST NOT` improvise such a message:
two-party activation, retries, and mixed-epoch delivery need a separately frozen
state machine.

### 9.6 Capability Recovery

A device that still holds its master seed recovers lost capabilities by proof of
possession: it re-derives the relationship signing key and proves possession to
the server, which issues fresh capabilities for that relationship. This adds no
exposure, since anyone able to perform it already holds the seed.

Revocation `MUST` be recorded server-side as a durable property of the
relationship, distinct from the absence of a capability, and re-issuance for a
revoked relationship `MUST` fail. Without that distinction, recovery silently
undoes every revocation.

## 10. Transport

Every v2 request, including unauthenticated capability discovery, `MUST` satisfy
all of:

```text
canonical HTTPS origin with a DNS hostname
+ HTTPS DoH resolution, no system-DNS fallback for the target
+ TLS minimum 1.3 and maximum 1.3
+ ECH accepted on the actual request, unless the user selected off
+ no cross-origin redirects
+ destination not loopback, link-local, private, multicast, or metadata-service
```

Failure of any term aborts before secrets or payload bytes are sent. There is no
production `--insecure`, system-DNS, plaintext HTTP, TLS-1.2, or direct-IP
fallback.

`DUD_ECH_MODE=off` is the single user-selectable relaxation. It relaxes ECH and
nothing else, is never automatic, and is never a retry after a hard-mode
failure.

### 10.1 Canonical Origin

The signature input binds `canonical_origin`, so two implementations that
normalize differently would fail to interoperate without any visible error.
Normalization is therefore fixed:

1. the scheme `MUST` be `https`, compared case-insensitively and emitted
   lowercase;
2. userinfo, query, and fragment `MUST` be rejected;
3. a path other than empty or `/` `MUST` be rejected; the emitted form has no
   trailing slash;
4. a trailing root label (`example.com.`) is rejected; an internationalized host
   is processed with the UTS #46 non-transitional lookup profile, STD3 rules,
   label validation, the Bidi rule, and full DNS-length validation, then emitted
   as lowercase A-labels;
5. an IP literal, v4 or v6, `MUST` be rejected: an origin is a DNS hostname;
6. a port must be a decimal integer from 1 through 65535; `443` is omitted and
   any other valid port is retained as `:port`.

Vectors are in [§12.5](#125-canonical-origin-normalization).

**DoH bootstrap.** The DoH provider's own hostname resolves through the system
resolver by default; pinned bootstrap addresses are supported for stricter
deployments. A configured pin that fails is a hard error and `MUST NOT` fall
back to the system resolver. Only the resolver's hostname is ever exposed this
way, never the DUD origin.

### 10.2 Required Client Transport Profile

The Go client performs every network operation in-process with the Go standard
library. It shells out to no HTTP binary and does not add cgo. The profile is
mandatory for v2, and the `/v1` routes take the same path. To enforce address
policy before connection, the client never hands the target hostname to a
resolver it does not control:

1. A pure-Go resolver sends bounded DNS wire-format queries to the configured
   HTTPS DoH endpoint for A, AAAA, and HTTPS/SVCB records. The DoH HTTP exchange
   uses `net/http` over a `crypto/tls` configuration pinned to exactly TLS 1.3,
   with certificate verification, no proxy, no redirects, and either system
   bootstrap for the resolver hostname or the configured pinned bootstrap
   addresses.
2. The resolver validates response IDs, names, types, lengths, alias chains,
   CNAME/SVCB loop limits, TTLs, and total response size. It rejects malformed,
   truncated, inconsistent, or ambiguous answers.
3. Every returned target address is classified before any target connection. If
   any candidate is loopback, private, link-local, multicast, unspecified,
   documentation-only, benchmarking, reserved, or a configured metadata-service
   address, the resolution fails closed. Mixed public/private answers are
   rejected rather than silently dropping the private member.
4. The resolver extracts a valid ECHConfigList from the HTTPS/SVCB answer. In
   hard mode, absence or invalidity is a hard failure. With ECH off it records
   the absence and continues.
5. The target request goes through a per-origin `net/http` client whose
   `DialContext` dials only the validated addresses and discards the hostname it
   is handed. Hard mode installs the extracted ECHConfigList as the TLS
   `EncryptedClientHelloConfigList`. The user cannot provide or override either
   value.
6. Redirect following is disabled. Retries repeat the entire DoH, address, and
   ECH validation sequence and never reuse an address after its DNS TTL.

The production helper rejects `DUD_CONNECT_TO`; only the test transport can
inject addresses. DoH bodies, headers, and redirect count all have explicit
bounds, as do bounded response bodies — which is every v2 control message.

Time is bounded per phase rather than by one whole-request deadline, because a
100 MB dead drop transfer is legitimately longer than any control-plane budget.
DoH resolution keeps the whole-operation timeout. A request carrying a streamed
body or returning a streamed response is bounded instead by its connect, TLS
handshake, and response-header deadlines plus an idle-progress deadline: it may
run as long as it keeps moving bytes, and a stall longer than the idle window
cancels it. A stream that fails short of its end retires the pooled connection
that produced it.

This profile is the required resolution of `DUD-V2-SEC-007`. ECH is a
`crypto/tls` client feature, so a build whose Go toolchain cannot install an
externally obtained ECHConfigList cannot serve hard mode at all; weakening the
address or ECH requirement is not a fallback.

## 11. HTTP Endpoints

### 11.1 Common Wire Rules

All CBOR request and response bodies use:

```text
Content-Type: application/dud+cbor; version=2
Accept: application/dud+cbor; version=2
```

Opaque ciphertext upload/download bodies use `application/octet-stream`. Private
responses carry `Cache-Control: no-store`. Request bodies, including raw
ciphertext, are covered by the body digest in [§9.3](#93-request-authorization).
Opaque request bodies carry that digest in `DUD-Content-SHA256`; successful
`HEAD` responses use the same header for the committed ciphertext digest.
Requests with a query component are rejected.

Path parameters use lowercase hexadecimal with no prefix or separators:

| Parameter       | Raw size | Path characters |
| --------------- | -------: | --------------: |
| invitation ID   | 32 bytes |              64 |
| object/entry ID | 16 bytes |              32 |
| delivery slot   | 16 bytes |              32 |

Uppercase, odd-length, percent-encoded, or wrong-length alternatives are
rejected rather than normalized. This makes the exact `normalized_path` used by
request authorization equal to the literal registered route with substituted
lowercase parameters.

Proof-of-possession requests carry:

```text
DUD-Authorization: DUD2 <base64url-no-padding(auth_cbor)>
```

where `auth_cbor` is deterministic CBOR:

| Key | Field    | Type      |
| --: | -------- | --------- |
|   1 | `cap_id` | bytes, 16 |
|   2 | `nonce`  | bytes, 16 |
|   3 | `exp`    | uint      |
|   4 | `mac`    | bytes, 32 |

The decoded header is limited to 128 bytes and the encoded header value to 256
ASCII characters. `exp` must be no earlier than `now - 300`, no later than
`now + 300`, and no later than the end of its slot epoch. Nonces are retained
through `exp + 300` and a repeat is rejected.

The deliberately narrow bootstrap, pairing-status, object, claim, and
administrative bearers carry:

```text
Authorization: DUD2-Bearer <base64url-no-padding(32 raw bytes)>
```

They are never accepted in `DUD-Authorization`. The v1 secret is rejected on
every v2 route. Bootstrap and pairing-status bearers expire with the invitation;
object and claim bearers expire with the object or lease. The configured v2
administrative bearer is distinct from every v1 credential.

Successful bodies use only the schemas below. Empty success has no body. Errors
use deterministic CBOR:

| Key | Field         | Type                                      |
| --: | ------------- | ----------------------------------------- |
|   1 | `code`        | uint; registered below                    |
|   2 | `message`     | text, at most 256 bytes; safe for display |
|   3 | `retry_after` | uint seconds, optional                    |

| Code | Name                  | HTTP status |
| ---: | --------------------- | ----------: |
|    1 | `invalid_request`     |         400 |
|    2 | `unauthorized`        |         401 |
|    3 | `forbidden`           |         403 |
|    4 | `not_found`           |         404 |
|    5 | `conflict`            |         409 |
|    6 | `invitation_claimed`  |         409 |
|    7 | `expired`             |         410 |
|    8 | `unsupported_feature` |         422 |
|    9 | `too_large`           |         413 |
|   10 | `rate_limited`        |         429 |
|   11 | `quota_exceeded`      |         429 |
|   12 | `policy_mismatch`     |         409 |
|   13 | `replay_or_fork`      |         409 |
|   14 | `internal`            |         500 |

Object routes return the same `not_found` response for an absent object and an
invalid bearer, so existence is not disclosed. Error messages never contain
capabilities, full object IDs, relationship IDs, or peer metadata.

### 11.2 Capability Discovery

`GET /v2/capabilities` is unauthenticated at the application layer and still
uses the complete transport contract in [§10](#10-transport). It returns
deterministic CBOR:

| Key | Field         | Type                                           |
| --: | ------------- | ---------------------------------------------- |
|   1 | `protocols`   | array of uint; `[1, 2]` on a dual-stack server |
|   2 | `features`    | sorted array of registered uint feature IDs    |
|   3 | `limits`      | map from registered uint limit ID to uint      |
|   4 | `enforcement` | map from registered enforcement ID to uint     |

Feature IDs:

|  ID | Feature         |
| --: | --------------- |
|   1 | objects         |
|   2 | scoped-auth     |
|   3 | pairing         |
|   4 | delivery-slots  |
|   5 | git-full        |
|   6 | git-incremental |
|   7 | chunked-upload  |
|   8 | strict-consume  |

A 2.0.0 server `MUST NOT` advertise IDs 6, 7, or 8 unless that feature and its
backend conformance suite are present.

Limit IDs and 2.0 defaults:

|  ID | Limit                                 |   Default |
| --: | ------------------------------------- | --------: |
|   1 | maximum object bytes                  | 104857600 |
|   2 | maximum descriptor bytes              |    262144 |
|   3 | maximum TTL seconds                   |   2592000 |
|   4 | pending deliveries per slot           |        64 |
|   5 | objects per capability per slot epoch |       256 |
|   6 | concurrent uploads per capability     |         4 |
|   7 | requests per capability per minute    |        60 |
|   8 | staged bytes per capability           | 209715200 |
|   9 | pairing envelope bytes                |      4096 |

Enforcement IDs:

|  ID | Meaning                       | Values                                       |
| --: | ----------------------------- | -------------------------------------------- |
|   1 | quota/reservation enforcement | 1 best-effort, 2 atomic                      |
|   2 | consume enforcement           | 0 none, 1 delete-after-read, 2 strict atomic |
|   3 | enrollment enforcement        | 0 open, 1 enrollment secret required         |

Enforcement ID 3 reports whether `POST /v2/pairing/rendezvous` requires the
proof of [§11.3](#113-pairing). It is orthogonal to feature ID 3: a gated
deployment still advertises pairing, because pairing works — it needs a
credential. A client that does not read this entry ignores it under the
unknown-value rule below and learns the same thing from the refusal.

Unknown feature, limit, or enforcement **values** are optional registry entries
and are ignored; this is separate from unknown CBOR map keys, which follow
[§3](#3-encoding). A client never infers a feature from a limit and must see the
feature ID that gates an operation before using that operation. This response
`MUST NOT` expose backend identity, account IDs, object counts, or peer counts.

### 11.3 Pairing

```text
POST   /v2/pairing/rendezvous
GET    /v2/pairing/rendezvous/:locator
POST   /v2/pairing/rendezvous/:locator/accept
POST   /v2/pairing/rendezvous/:locator/key-confirm
POST   /v2/pairing/rendezvous/:locator/complete
GET    /v2/pairing/rendezvous/:locator/status
DELETE /v2/pairing/rendezvous/:locator
```

Rendezvous creation is the only operation that creates state for a caller
holding neither a capability nor a relationship. A deployment `MAY` gate it on
an enrollment passphrase held by the operator, and advertises which it does as
enforcement ID 3 in [§11.2](#112-capability-discovery). A gated deployment
requires

```text
Authorization: DUD2-Enroll base64url(proof)
key   = PBKDF2-HMAC-SHA256(password = utf8(passphrase), salt = "dud/v2/enrollment-key",
                           iterations = 600000, dkLen = 32)
proof = HMAC-SHA256(key, "dud/v2/enrollment|" || locator || uint64(expires_at))
```

where `locator` is the 32 raw bytes of key 2 and `expires_at` is the uint64 of
key 5, big-endian. The configured secret is UTF-8 text rather than encoded
bytes, because it is carried to every device that may invite, and an
implementation `MUST` read it in one of three forms:

| Form                                        | Key                                       |
| ------------------------------------------- | ----------------------------------------- |
| `<passphrase>`                              | as above, at 600000 iterations            |
| `dud2-enroll-key:<key>`                     | `base64url(key)`, 32 bytes, used verbatim |
| `dud2-enroll-kdf:<iterations>:<passphrase>` | as above, at the stated count             |

A passphrase is at least 24 characters and carries no leading or trailing
whitespace, in either form that contains one; a stated iteration count is a
decimal integer from 10000 to 10000000. Both sides `MUST` use exactly the salt
above and the work factor the secret names — a proof produced under a different
one is simply a wrong proof — and both `SHOULD` derive the key once per process
rather than per request. The parameters are carried inside the secret precisely
so that the two sides cannot be configured with different ones.

The three forms exist because only the passphrase needs stretching: the key is
what verification consumes, so a deployment holding the key alone verifies
proofs without deriving anything, while an attacker guessing the passphrase pays
the same work factor either way. Binding the proof to the rendezvous keeps the
secret off the wire, so a proof recovered from a request log authorizes nothing
else, and the deliberate cost of the derivation is what keeps that proof from
being a cheap offline verifier for the passphrase. The server compares in
constant time and verifies before admission, so a rejected request consumes no
creation window, and before any existence check, so the refusal never discloses
that a locator is taken. Every failure is error code `2`, and a server `MUST`
bound enrollment attempts per source so that a passphrase cannot be guessed at
network speed; exceeding that bound is error code `10`. An open deployment
ignores the header. Only the inviter needs the secret; `accept` and every later
step are authorized by the pairing code and the bearers derived from it.

The client encrypts the invitation and sends:

| Key | Field                     | Type      |
| --: | ------------------------- | --------- |
|   1 | `v`                       | uint, 2   |
|   2 | `locator`                 | bytes, 32 |
|   3 | `envelope_nonce`          | bytes, 24 |
|   4 | `envelope_ciphertext`     | bytes     |
|   5 | `expires_at`              | uint      |
|   6 | `bootstrap_verifier`      | map       |
|   7 | `inviter_status_verifier` | map       |

The envelope maximum is 4 KiB; lifetime defaults to 15 minutes and cannot exceed
one hour. Creation is limited by trusted platform source metadata and a global
counter, with at most 256 live records. Forwarded headers supplied by callers
are never rate-limit identity. An identical retry is idempotent; any different
record at the same locator conflicts. Success is `201` with
`{1: created_at, 2: expires_at}`. `GET` returns version, nonce, ciphertext, and
expiry without authentication.

The `accept` request uses the bootstrap bearer and this wrapper:

| Key | Field                       | Type                                            |
| --: | --------------------------- | ----------------------------------------------- |
|   1 | `invitation_map`            | map from [§5](#5-pairing-codes-and-invitations) |
|   2 | `acceptance_map`            | map from [§6](#6-pairing)                       |
|   3 | `signature`                 | bytes, 64                                       |
|   4 | `invitee_status_capability` | bytes, 32                                       |

The server verifies that
`SHA-256(invitee_status_capability) == status_capability_hash` in the signed
acceptance map before atomically claiming the invitation. Success and identical
retry are `202` with no body; a different acceptance is `invitation_claimed`.

The `key-confirm` endpoint carries `enc_A` and is therefore part of key
agreement. Its request is `{1: key_confirmation_map, 2: signature}` and requires
the inviter status bearer. `complete` is called once by each role with
`{1: completion_map, 2: signature}` and that role's status bearer. Both return
`202` with no body and are idempotent only for an identical signed map. The role
field must match the status bearer; `completed_at` must fall within the
invitation lifetime with the 300-second clock-skew allowance.

`status` requires a role-specific status bearer, never the shared bootstrap
bearer. Its response is:

| Key | Field                       | Type                               |
| --: | --------------------------- | ---------------------------------- |
|   1 | `phase`                     | uint                               |
|   2 | `acceptance_envelope`       | map, optional; inviter role only   |
|   3 | `key_confirmation_envelope` | map, optional; invitee role only   |
|   4 | `inviter_completed`         | bool                               |
|   5 | `invitee_completed`         | bool                               |
|   6 | `capability_grant`          | bytes, optional; active phase only |

Phases are `0 waiting-acceptance`, `1 waiting-key-confirmation`,
`2 waiting-completions`, `3 active`, `4 cancelled`, and `5 expired`. Handshake
envelopes use `{1: signed_map, 2: signature}`. The response never returns the
other role's status bearer or grant.

On activation, key 6 is an `age` ciphertext encrypted to the caller role's
relationship recipient. Its deterministic-CBOR plaintext is:

| Key | Field              | Type                       |
| --: | ------------------ | -------------------------- |
|   1 | `v`                | uint, 2                    |
|   2 | `relationship_id`  | bytes, 16                  |
|   3 | `role`             | uint; 0 inviter, 1 invitee |
|   4 | `key_epoch`        | uint, 0                    |
|   5 | `canonical_origin` | text                       |
|   6 | `grants`           | array of grant maps        |

Each grant map is `{1: direction, 2: scope, 3: token_secret}`, using descriptor
direction uints, lowercase scope text, and a 32-byte token secret. Each role
receives `write` for its outbound direction plus `read` and `ack` for its
inbound direction. The server provisions each secret once, stores the verifier
encrypted, and may return the same stored encrypted grant until the invitation
expires.

`DELETE` requires a role status bearer and returns `204`. Cancellation deletes
pending handshake material. Clients delete their pending code state after
cancellation or expiry.

### 11.4 Unserved Object and Slot Endpoints

2.0 has no object or slot surface: `/v2/objects`, `/v2/objects/:id`,
`/v2/objects/:id/claim`, `/v2/objects/:id/ack`, `/v2/slots/:slot/objects`, and
`/v2/slots/:slot/ack` are unserved paths a server answers with `unavailable`,
and there is no `upload` capability scope. Every message, file, collection, Git,
acknowledgement, revocation, sync, and recovery flow uses the granular delivery,
inbox, and inline-control endpoints. Peer capabilities are only `write`, `read`,
and `ack`.

### 11.5 Capability Recovery and Administration

```text
POST /v2/capabilities/reissue
POST /v2/admin/relationships/revoke
POST /v2/admin/relationships/rotate-capabilities
POST /v2/admin/relationships/status
```

Re-issuance exists for a device that retains its master seed but lost server
authorization. It is the only v2 relationship request that transmits
`relationship_id` outside encrypted peer content; this exception does not place
the ID in a URL or rotating-slot request, and the server already recorded it at
pairing.

The unauthenticated-at-HTTP-layer request is `{1: reissue_map, 2: signature}`.
The deterministic-CBOR signed map is:

| Key | Field              | Type                                 |
| --: | ------------------ | ------------------------------------ |
|   1 | `v`                | uint, 2                              |
|   2 | `relationship_id`  | bytes, 16                            |
|   3 | `role`             | uint; 0 inviter, 1 invitee           |
|   4 | `nonce`            | bytes, 32                            |
|   5 | `expires_at`       | uint; no more than 5 minutes ahead   |
|   6 | `scopes`           | sorted array of lowercase scope text |
|   7 | `canonical_origin` | text                                 |

```text
reissue_digest = SHA-256(deterministic_cbor(reissue_map))
sig_input      = "dud/v2/capability-reissue" || 0x00 || reissue_digest
signature      = Ed25519(epoch_0_relationship_signing_key, sig_input)
```

The server verifies the recorded role key, origin, expiry, nonce, assigned
scopes, and durable revocation state. It rate-limits by relationship and source.
Success rotates the requested verifier secrets and returns
`{1: capability_grant bytes}`, using the encrypted grant format from
[§11.3](#113-pairing). Repeating a nonce is `replay_or_fork`; a revoked scope is
`forbidden`. This restores server authorization only, not missing directional
relationship secrets.

Administrative routes require the distinct v2 administrative bearer. Their
request maps are:

| Route                 | Body                                                             |
| --------------------- | ---------------------------------------------------------------- |
| `revoke`              | `{1: relationship_id, 2: direction optional, 3: scope optional}` |
| `rotate-capabilities` | `{1: relationship_id, 2: direction, 3: scope}`                   |
| `status`              | `{1: relationship_id}`                                           |

Omitting both optional fields from `revoke` revokes the complete relationship;
otherwise the provided tuple is revoked. Rotation invalidates the current
verifier and requires the affected device to use re-issuance. Status returns
only `{1: relationship_revoked bool, 2: tuples}`, where each tuple is
`{1: direction, 2: scope, 3: revoked bool, 4: rotated_at uint}`. No route
returns a token secret, bearer, verifier, peer alias, or local device name.

## 12. Test Vectors

Generated by [`main.go`](../tests/vectors/protocol-v2/main.go) against
`filippo.io/hpke` v0.4.0 and `filippo.io/age` v1.3.1. Regenerate with:

```sh
cd tests/vectors/protocol-v2 && go run . > vectors.txt
```

`npm run check:vectors` regenerates the file and fails on any difference, so a
committed change to the vectors is always a deliberate one.

The complete output is
[`vectors.txt`](../tests/vectors/protocol-v2/vectors.txt).

### 12.1 Identity Derivation

```text
inviter_master_seed  = a0a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
relationship_id      = 0123456789abcdef0123456789abcdef
key_epoch            = 0
inviter_identity_raw = 5ced3a4fc8e68debd74dd16fbc2ce5438140c76cc289d38fafc992ec101afc40
inviter_identity     = AGE-SECRET-KEY-PQ-1TNKN5N7GU6X7H46D69HMCT89GWQ5P3MVC2YA8RA0EXFWCYQ6L3QQELH8KS
```

The generator asserts that derivation is reproducible, and that it diverges when
either `key_epoch` or `relationship_id` changes.

The same fixture encodes the invitation map and derives the rendezvous locator:

```text
pairing_code          = 0001-0203-0405-0607-0809-0a0b-0c0d-0e0f
rendezvous_locator    = 5d2847ed1cdec16c884dd847d64262f4fb4ea177388cf16bc4e777d2408f0f58
invitation_cbor_len   = 1434 bytes
invitation_digest     = 75a90bfe89994d7b4b94db42f97132c0aa349b84472b9ad8f56652577e93e6a3
```

The generator verifies canonical grouping and locator derivation. Client tests
assert that terminal and JSON QR payloads exactly equal the displayed code.

The signed acceptance fixture includes the invitee status bearer hash added by
the HTTP closure:

```text
status_capability_hash = d7aabf0508c8fc88c26d9ef1abe15513a901ca944ad1e844ce2c411df4adaf4c
acceptance_cbor_len     = 2632 bytes
acceptance_map_digest   = ee1e5d0358f20844fa1396db9809d1adbaef93584d0a5019a8c01da306f3c820
acceptance_signature    = 3c44b9799b1488df277538af4f9c2a17043c18abd70f208333db004d60f9982ed
                          d75dd04467812c4a6862b2e9d45393c147e4b958421492bb7b99b99b5619b00
```

### 12.2 Pre-Transcript to HPKE Info

```text
pre_transcript_cbor_len = 2720 bytes
info                    = 4525c6aa3966cf722bc407c521c671685b241d6c333438c27fff504d9cc5d4b3
```

The full deterministic-CBOR encoding is in
[`vectors.txt`](../tests/vectors/protocol-v2/vectors.txt). It contains exactly
the 17 fields registered in [§6.1](#61-transcript), including both 1216-byte
hybrid recipients.

### 12.3 Final Combine

Given fixed export outputs, so the vector is reproducible:

```text
ss_A                 = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ss_B                 = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
full_transcript_cbor_len = 4968 bytes
full_transcript_hash = 05bb4dce1a2aa98e6bb1400a0e15b5404e309418a1482c5977797a5ebd581042

relationship_secret[inviter->invitee] = b35eca3a51e904c251075085035621d4b9f31cb89bf002472080741ec4ea2b59
relationship_secret[invitee->inviter] = 8d89f56c00b1d3aacc3929bdb32cac1fd5883bf901ca762205b3bf59bd5a5251
```

### 12.4 Slot Derivation

```text
slot[data, epoch=20340] = aa1ffc9ed895fea7554cd21ce7534d6c
slot[data, epoch=20341] = 128f612c176d067216649f80c79f4b37
```

### 12.5 Canonical Origin Normalization

```text
https://DUD.Example.COM        -> https://dud.example.com
https://dud.example.com:443/   -> https://dud.example.com
https://dud.example.com:8443   -> https://dud.example.com:8443
https://bücher.example         -> https://xn--bcher-kva.example

http://dud.example.com         -> REJECT (scheme must be https)
https://u:p@dud.example.com    -> REJECT (userinfo not permitted)
https://dud.example.com/v2     -> REJECT (path not permitted)
https://192.0.2.1              -> REJECT (IP literal not permitted)
https://dud.example.com?x=1    -> REJECT (query and fragment not permitted)
https://dud.example.com.       -> REJECT (trailing root label not permitted)
https://dud.example.com:65536  -> REJECT (port must be 1..65535)
```

### 12.6 Transport Policy Digest

```text
policy{expires_at=1800000000, consume=1, claim_lease_seconds=300, ack_mode=1}
policy_cbor   = a4011a6b49d20002010319012c0401
policy_digest = 491ac90f507d83f2635cbe478e5daa8f7b032fcdb74ae3b7ab84b3442fbfd66c
```

### 12.7 Descriptor Encoding and Signature

```text
descriptor_cbor_len = 270 bytes
descriptor_digest   = a7fded7b013742a2570df123b34ed9a1be421fe71b4beaf0bd17902a8170ed71
sig_input           = "dud/v2/descriptor" || 0x00 || descriptor_digest
signing_seed        = 909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
signing_public_key  = d2eb993b63143528e70dcdc7eb9ca21010dd769be95250c2c5babfad15d458e2
sender_key_id       = 0e311dc453ca6267
signature           = e46017ec70a77cd031aa51a443243e20f79cb0eec5636a29777a207d885741f0
                      2d497f710abc25362a989d40937c989b28577250317b875544ffcbfd30fd110f
```

The full CBOR encoding is in
[`vectors.txt`](../tests/vectors/protocol-v2/vectors.txt). The generator asserts
that the signature verifies, that re-encoding is byte-stable, that
`sender_key_id` is the required SHA-256 prefix of `signing_public_key`, and that
the strict decoder of [§3](#3-encoding) accepts the result. The fixture uses the
required SHA-256-derived sender-key ID.

### 12.8 Extension Criticality

```text
unknown core key 27               -> REJECT
unknown optional extension 128    -> IGNORE
unknown critical extension 128    -> REJECT
```

This exercises the core/extension split and key 0 `critical_extensions`
semantics from [§3](#3-encoding).

### 12.9 Capability Discovery

```text
capabilities_cbor   = a4018201020285010203040503a9011a06400000021a00040000031a00278d00
                      04184005190100060407183c081a0c8000000919100004a201020201
capabilities_digest = eab6e4b3ca29c4995c8dbe5319d31e46ca0c82a8fc9a04ef30f62fea5b793f34
```

### 12.10 What Cannot Be Pinned

`filippo.io/hpke` v0.4.0 exports no deterministic-randomness variant of
`NewSender`, so `enc_A` and `enc_B` cannot be fixed as vectors. Conformance for
key agreement is therefore a **property test** rather than a vector:

- a sender's `Export` and the corresponding recipient's `Export` agree;
- both directions agree independently;
- a tampered pre-transcript yields a different secret.

The generator asserts all three. An implementation claiming conformance `MUST`
reproduce the deterministic vectors above and `MUST` pass these properties.

## 13. Limits Summary

| Limit                                             | Value                           |
| ------------------------------------------------- | ------------------------------- |
| descriptor bytes                                  | 262144                          |
| descriptor nesting / arrays / map pairs / strings | 8 / 4096 / 128 / 65536          |
| pairing envelope bytes                            | 4096                            |
| invitation default / max expiry                   | 15 min / 1 h                    |
| live rendezvous records                           | 256                             |
| slot epoch                                        | 24 h                            |
| clock-skew allowance                              | plus or minus 5 min             |
| sequence acceptance window                        | 1000 ahead of watermark         |
| control drain budget                              | 8 requests, 10 s                |
| backoff                                           | 1 s to 5 min cap, jittered      |
| claim lease                                       | 5 min                           |
| pending deliveries per slot                       | 64                              |
| concurrent uploads / rate                         | 4 / 60 per minute               |
| Git bundle bytes / objects / delta depth          | 100 MB / 500000 / 50            |
| Git wall time / memory / disk                     | 120 s / 1 GB / 3x bundle        |
| extraction total bytes                            | signed plaintext size, cap 1 GB |
| extraction entries / depth                        | 100000 / 64                     |
