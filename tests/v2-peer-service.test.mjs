// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign as signEd25519,
} from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { CipherSuite, ExportOnly, HkdfSha256 } from '@hpke/core';
import { XWing } from '@hpke/hybridkem-x-wing';

import {
  bytesToHex,
  decryptV2TokenSecret,
  deriveV2DailyCapabilityLookupId,
  encodeBase64Url,
} from '../dist/src/v2-auth.js';
import { decodeCbor, encodeCbor, requireCborMap } from '../dist/src/cbor.js';
import { encryptV2AgeGrant } from '../dist/src/v2-age.js';
import { sha256 } from '../dist/src/sha256.js';
import { MemoryV2Store } from '../dist/src/v2-memory.js';
import {
  MemoryV2BodyStore,
  MemoryV2Repository,
} from '../dist/src/v2-memory-repository.js';
import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import { WorkerV2Store } from '../dist/src/v2-worker-store.js';
import {
  V2_ADMIN_SECRET,
  V2_DEPLOYMENT_KEY,
  V2_ENROLLMENT_SECRET,
  V2_NOW_MS,
  V2_ORIGIN,
  createV2TestService,
  enrollmentHeader,
} from './v2-helpers.mjs';

const textEncoder = new TextEncoder();

function fixed(start, length) {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function concat(...parts) {
  const output = new Uint8Array(
    parts.reduce((length, part) => length + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function decodeMap(bytes) {
  return requireCborMap(
    decodeCbor(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)),
    Array.from({ length: 33 }, (_, index) => index),
    [],
  );
}

function ed25519Key(seed) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(seed),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(privateKey).export({
    format: 'der',
    type: 'spki',
  });
  return {
    privateKey,
    publicKey: new Uint8Array(spki.subarray(spki.byteLength - 32)),
  };
}

function signPairing(name, map, key) {
  const digest = sha256(encodeCbor(map));
  return new Uint8Array(
    signEd25519(
      null,
      concat(textEncoder.encode(`dud/v2/pairing/${name}\0`), digest),
      key,
    ),
  );
}

function signReissue(map, key) {
  const digest = sha256(encodeCbor(map));
  return new Uint8Array(
    signEd25519(
      null,
      concat(textEncoder.encode('dud/v2/capability-reissue\0'), digest),
      key,
    ),
  );
}

function pairingVerifier(bearer, saltStart) {
  const salt = fixed(saltStart, 16);
  return new Map([
    [1, salt],
    [2, sha256(concat(textEncoder.encode('dud/v2/bearer\0'), salt, bearer))],
  ]);
}

async function hybridKey(seed) {
  const kem = new XWing();
  const pair = await kem.generateKeyPairDerand(seed);
  return {
    kem,
    pair,
    publicKey: new Uint8Array(await kem.serializePublicKey(pair.publicKey)),
  };
}

function bearerRequest(path, bearer, method = 'GET', body) {
  const headers = {
    authorization: `DUD2-Bearer ${encodeBase64Url(bearer)}`,
    accept: 'application/dud+cbor; version=2',
  };
  if (body !== undefined) {
    headers['content-type'] = 'application/dud+cbor; version=2';
    headers['content-length'] = String(body.byteLength);
  }
  return new Request(`${V2_ORIGIN}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body }),
  });
}

async function rendezvousCreateRequest(locator, options = {}) {
  const now = Math.floor(V2_NOW_MS / 1000);
  const bootstrap = options.bootstrap ?? fixed(0x50, 32);
  const status = options.status ?? fixed(0x70, 32);
  const expiresAt = options.expiresAt ?? now + 900;
  const body = encodeCbor(
    new Map([
      [1, 2],
      [2, locator],
      [3, options.nonce ?? fixed(0xd0, 24)],
      [4, options.ciphertext ?? fixed(0xe0, 128)],
      [5, expiresAt],
      [6, pairingVerifier(bootstrap, options.bootstrapSalt ?? 0x51)],
      [7, pairingVerifier(status, options.statusSalt ?? 0x71)],
    ]),
  );
  const authorization =
    options.authorization === null
      ? undefined
      : (options.authorization ??
        (await enrollmentHeader(locator, expiresAt, options.enrollmentSecret)));
  return new Request(`${V2_ORIGIN}/v2/pairing/rendezvous`, {
    method: 'POST',
    headers: {
      'content-type': 'application/dud+cbor; version=2',
      'content-length': String(body.byteLength),
      ...(authorization ? { authorization } : {}),
    },
    body,
  });
}

async function establishPairing(service, overrides = {}) {
  const now = Math.floor(V2_NOW_MS / 1000);
  const invitationId = fixed(0x10, 32);
  const relationshipId = fixed(0x30, 16);
  const bootstrap = fixed(0x50, 32);
  const inviterStatus = fixed(0x70, 32);
  const inviteeStatus = fixed(0x90, 32);
  const inviterHybrid = await hybridKey(fixed(0xa0, 32));
  const inviteeHybrid = await hybridKey(fixed(0xc0, 32));
  const inviterSigning = ed25519Key(fixed(0x20, 32));
  const inviteeSigning = ed25519Key(fixed(0x40, 32));
  const locator = sha256(
    concat(textEncoder.encode('test-rendezvous\0'), invitationId),
  );

  const invitation = new Map([
    [1, 2],
    [2, 1],
    [3, 1],
    [4, invitationId],
    [5, relationshipId],
    [6, fixed(0x11, 16)],
    [7, inviterHybrid.publicKey],
    [8, inviterSigning.publicKey],
    [9, V2_ORIGIN],
    [10, bootstrap],
    [11, fixed(0x61, 32)],
    [12, now + 900],
  ]);
  const createBody = encodeCbor(
    new Map([
      [1, 2],
      [2, locator],
      [3, fixed(0xd0, 24)],
      [4, fixed(0xe0, 128)],
      [5, now + 900],
      [6, pairingVerifier(bootstrap, 0x51)],
      [7, pairingVerifier(inviterStatus, 0x71)],
    ]),
  );
  const create = await service.fetch(
    new Request(`${V2_ORIGIN}/v2/pairing/rendezvous`, {
      method: 'POST',
      headers: {
        'content-type': 'application/dud+cbor; version=2',
        'content-length': String(createBody.byteLength),
        authorization: await enrollmentHeader(locator, now + 900),
      },
      body: createBody,
    }),
  );
  assert.equal(create.status, 201);

  const pre = new Map([
    [1, 2],
    [2, 1],
    [3, 1],
    [4, invitationId],
    [5, relationshipId],
    [6, V2_ORIGIN],
    [7, fixed(0x11, 16)],
    [8, fixed(0x22, 16)],
    [9, inviterHybrid.publicKey],
    [10, inviteeHybrid.publicKey],
    [11, inviterSigning.publicKey],
    [12, inviteeSigning.publicKey],
    [13, fixed(0x61, 32)],
    [14, fixed(0x81, 32)],
    [15, now + 900],
    [16, 0],
    [17, 'bootstrap'],
    [18, locator],
    [19, fixed(0x91, 32)],
  ]);
  const info = sha256(encodeCbor(pre));
  const exportSuite = new CipherSuite({
    kem: new XWing(),
    kdf: new HkdfSha256(),
    aead: new ExportOnly(),
  });
  const inviterPublic = await exportSuite.kem.importKey(
    'raw',
    inviterHybrid.publicKey.buffer,
    true,
  );
  const senderB = await exportSuite.createSenderContext({
    recipientPublicKey: inviterPublic,
    info,
  });
  const encB = new Uint8Array(senderB.enc);
  const acceptance = new Map([
    [1, 2],
    [2, 1],
    [3, 1],
    [4, invitationId],
    [5, relationshipId],
    [6, fixed(0x22, 16)],
    [7, inviteeHybrid.publicKey],
    [8, inviteeSigning.publicKey],
    [9, fixed(0x81, 32)],
    [10, sha256(encodeCbor(invitation))],
    [11, encB],
    [12, sha256(inviteeStatus)],
    [13, fixed(0x91, 32)],
    [14, locator],
  ]);
  const acceptanceSignature = signPairing(
    'acceptance',
    acceptance,
    inviteeSigning.privateKey,
  );
  const acceptBody = encodeCbor(
    new Map([
      [1, invitation],
      [2, acceptance],
      [3, acceptanceSignature],
      [4, inviteeStatus],
    ]),
  );
  const accept = await service.fetch(
    bearerRequest(
      `/v2/pairing/rendezvous/${bytesToHex(locator)}/accept`,
      bootstrap,
      'POST',
      acceptBody,
    ),
  );
  assert.equal(accept.status, 202);

  const inviteePublic = await exportSuite.kem.importKey(
    'raw',
    inviteeHybrid.publicKey.buffer,
    true,
  );
  const senderA = await exportSuite.createSenderContext({
    recipientPublicKey: inviteePublic,
    info,
  });
  const encA = new Uint8Array(senderA.enc);
  const full = new Map(pre);
  full.set(20, encA);
  full.set(21, encB);
  const transcriptHash = sha256(encodeCbor(full));
  const confirmation = new Map([
    [1, 2],
    [2, invitationId],
    [3, relationshipId],
    [4, sha256(encodeCbor(acceptance))],
    [5, encA],
    [6, transcriptHash],
    [7, fixed(0x92, 32)],
  ]);
  const confirmationBody = encodeCbor(
    new Map([
      [1, confirmation],
      [
        2,
        signPairing(
          'key-confirmation',
          confirmation,
          inviterSigning.privateKey,
        ),
      ],
    ]),
  );
  const confirm = await service.fetch(
    bearerRequest(
      `/v2/pairing/rendezvous/${bytesToHex(locator)}/key-confirm`,
      inviterStatus,
      'POST',
      confirmationBody,
    ),
  );
  assert.equal(confirm.status, 202);

  const completeRole = async (role, statusBearer, signingKey) => {
    const completion = new Map([
      [1, 2],
      [2, invitationId],
      [3, relationshipId],
      [4, overrides.transcriptHash ?? transcriptHash],
      [5, role],
      [6, now],
    ]);
    const body = encodeCbor(
      new Map([
        [1, completion],
        [2, signPairing('pairing-complete', completion, signingKey)],
      ]),
    );
    return service.fetch(
      bearerRequest(
        `/v2/pairing/rendezvous/${bytesToHex(locator)}/complete`,
        statusBearer,
        'POST',
        body,
      ),
    );
  };

  return {
    acceptBody,
    completeRole,
    bootstrap,
    encA,
    encB,
    invitation,
    invitationId,
    locator,
    inviteeHybrid,
    inviteeSigning,
    inviteeStatus,
    inviterHybrid,
    inviterSigning,
    inviterStatus,
    relationshipId,
    transcriptHash,
  };
}

test('server age grant decrypts with the Go hybrid relationship identity', async () => {
  const masterSeed = fixed(0x42, 32);
  const relationshipId = fixed(0x24, 16);
  const info = `dud/v2/identity|${bytesToHex(relationshipId)}|0`;
  const identitySeed = new Uint8Array(
    hkdfSync(
      'sha256',
      masterSeed,
      new Uint8Array(),
      textEncoder.encode(info),
      32,
    ),
  );
  const kem = new XWing();
  const pair = await kem.generateKeyPairDerand(identitySeed);
  const recipient = new Uint8Array(
    await kem.serializePublicKey(pair.publicKey),
  );
  let randomOffset = 0x11;
  const ciphertext = await encryptV2AgeGrant(
    textEncoder.encode('server-to-go capability grant'),
    recipient,
    (length) => {
      const result = fixed(randomOffset, length);
      randomOffset = (randomOffset + length) & 0xff;
      return result;
    },
  );
  const go = spawnSync(
    'go',
    ['test', './cmd/dud', '-run', '^TestV2ServerAgeGrantInteropFixture$'],
    {
      cwd: new URL('../client/', import.meta.url),
      encoding: 'utf8',
      env: {
        ...process.env,
        DUD_TEST_AGE_CIPHERTEXT: encodeBase64Url(ciphertext),
        GOCACHE: '/tmp/dud-go-build-cache',
      },
    },
  );
  assert.equal(go.status, 0, `${go.stdout}\n${go.stderr}`);
});

test('enrolled rendezvous creation is bounded, rate-limited, and idempotent', async () => {
  const store = new MemoryV2Store();
  const { service } = await createV2TestService(store, {
    limits: {
      maxPairingEnvelopeBytes: 128,
      maxPairingTtlSeconds: 900,
      maxPairingCreatesPerMinute: 1,
      maxPendingPairings: 2,
    },
  });
  const firstLocator = fixed(0x01, 32);
  assert.equal(
    (
      await service.fetch(
        await rendezvousCreateRequest(firstLocator),
        undefined,
        'source-a',
      )
    ).status,
    201,
  );
  assert.equal(
    (
      await service.fetch(
        await rendezvousCreateRequest(firstLocator),
        undefined,
        'source-a',
      )
    ).status,
    201,
  );
  const rateLimited = await service.fetch(
    await rendezvousCreateRequest(fixed(0x02, 32)),
    undefined,
    'source-a',
  );
  assert.equal(rateLimited.status, 429);
  assert.equal(decodeMap(await rateLimited.arrayBuffer()).get(1), 10);

  const oversized = await service.fetch(
    await rendezvousCreateRequest(fixed(0x03, 32), {
      ciphertext: fixed(0x10, 129),
    }),
    undefined,
    'source-b',
  );
  assert.equal(oversized.status, 400);
  const overlong = await service.fetch(
    await rendezvousCreateRequest(fixed(0x04, 32), {
      expiresAt: Math.floor(V2_NOW_MS / 1000) + 901,
    }),
    undefined,
    'source-c',
  );
  assert.equal(overlong.status, 400);

  assert.equal(
    (
      await service.fetch(
        await rendezvousCreateRequest(fixed(0x05, 32)),
        undefined,
        'source-d',
      )
    ).status,
    201,
  );
  const full = await service.fetch(
    await rendezvousCreateRequest(fixed(0x06, 32)),
    undefined,
    'source-e',
  );
  assert.equal(full.status, 429);
  assert.equal(decodeMap(await full.arrayBuffer()).get(1), 11);
});

test('rendezvous creation refuses every proof but the one that names it', async () => {
  const { service } = await createV2TestService(new MemoryV2Store());
  const now = Math.floor(V2_NOW_MS / 1000);
  const locator = fixed(0x11, 32);

  const missing = await service.fetch(
    await rendezvousCreateRequest(locator, { authorization: null }),
    undefined,
    'source-a',
  );
  assert.equal(missing.status, 401);
  assert.equal(decodeMap(await missing.arrayBuffer()).get(1), 2);

  // A proof issued for one rendezvous authorizes no other, so the proof a
  // stranger captures from a request log opens only what it already opened.
  const otherLocator = await service.fetch(
    await rendezvousCreateRequest(locator, {
      authorization: await enrollmentHeader(fixed(0x12, 32), now + 900),
    }),
    undefined,
    'source-a',
  );
  assert.equal(otherLocator.status, 401);

  // The same replay against a different lifetime for the same locator: the
  // proof covers the expiry too, so it does not carry over.
  const otherExpiry = await service.fetch(
    await rendezvousCreateRequest(locator, {
      expiresAt: now + 800,
      authorization: await enrollmentHeader(locator, now + 900),
    }),
    undefined,
    'source-a',
  );
  assert.equal(otherExpiry.status, 401);

  const wrongSecret = await service.fetch(
    await rendezvousCreateRequest(locator, {
      enrollmentSecret: 'pässwort-mit-ümlaut-2024-korrekt',
    }),
    undefined,
    'source-a',
  );
  assert.equal(wrongSecret.status, 401);

  const created = await service.fetch(
    await rendezvousCreateRequest(locator),
    undefined,
    'source-a',
  );
  assert.equal(created.status, 201);
});

test('a deployment holding the derived key authorizes clients holding the passphrase', async () => {
  // This is the configuration a free-tier Worker runs: the operator stretched
  // the passphrase once, elsewhere, and the deployment holds only the result, so
  // verifying a proof costs it no key derivation. Clients are unchanged and know
  // nothing about it, which is exactly what has to be true.
  const { deriveV2EnrollmentKey, formatV2EnrollmentKey } =
    await import('../dist/src/v2-auth.js');
  const { service } = await createV2TestService(new MemoryV2Store(), {
    enrollmentSecret: formatV2EnrollmentKey(
      await deriveV2EnrollmentKey(V2_ENROLLMENT_SECRET),
    ),
  });
  const created = await service.fetch(
    await rendezvousCreateRequest(fixed(0x11, 32)),
    undefined,
    'source-a',
  );
  assert.equal(created.status, 201);

  // And it is still the same gate: another passphrase does not open it.
  const wrongSecret = await service.fetch(
    await rendezvousCreateRequest(fixed(0x12, 32), {
      enrollmentSecret: 'pässwort-mit-ümlaut-2024-korrekt',
    }),
    undefined,
    'source-b',
  );
  assert.equal(wrongSecret.status, 401);
});

test('a stated work factor is agreed through the secret itself', async () => {
  // The count travels inside the value, so a client configured with it derives
  // what the deployment derives without a second variable to keep in step.
  const weak = `dud2-enroll-kdf:10000:${V2_ENROLLMENT_SECRET}`;
  const { service } = await createV2TestService(new MemoryV2Store(), {
    enrollmentSecret: weak,
    acceptWeakEnrollmentKdf: true,
  });
  const created = await service.fetch(
    await rendezvousCreateRequest(fixed(0x11, 32), {
      enrollmentSecret: weak,
    }),
    undefined,
    'source-a',
  );
  assert.equal(created.status, 201);

  // The same passphrase at the default work factor is a different key, so a
  // client that ignored the stated count would be refused rather than admitted.
  const mismatched = await service.fetch(
    await rendezvousCreateRequest(fixed(0x12, 32), {
      enrollmentSecret: V2_ENROLLMENT_SECRET,
    }),
    undefined,
    'source-b',
  );
  assert.equal(mismatched.status, 401);
});

test('failed enrollment proofs are throttled per source', async () => {
  const { service } = await createV2TestService(new MemoryV2Store());
  // Refusals do not spend the deployment-wide creation window by design, so
  // their source-scoped admission budget remains independent.
  const guess = async (attempt, source) =>
    (
      await service.fetch(
        await rendezvousCreateRequest(fixed(0x60, 32), {
          enrollmentSecret: 'pässwort-mit-ümlaut-2024-korrekt',
        }),
        undefined,
        source,
      )
    ).status;
  const statuses = [];
  for (let attempt = 0; attempt < 12; attempt++) {
    statuses.push(await guess(attempt, 'source-guesser'));
  }
  assert.deepEqual(
    statuses,
    [...Array(10).fill(401), 429, 429],
    'a source must get a bounded number of guesses per minute',
  );
  // The throttle is per source, so one guesser cannot lock anyone else out.
  assert.equal(await guess(0, 'source-elsewhere'), 401);
  assert.equal(
    (
      await service.fetch(
        await rendezvousCreateRequest(fixed(0x61, 32)),
        undefined,
        'source-elsewhere',
      )
    ).status,
    201,
  );
});

test('a refused enrollment consumes no rendezvous creation window', async () => {
  const { service } = await createV2TestService(new MemoryV2Store(), {
    limits: { maxPairingCreatesPerMinute: 1 },
  });
  // The deployment-wide window is the only bound rendezvous creation has before
  // a relationship exists. If an unauthenticated caller could spend it, gating
  // enrollment would hand that caller a denial of service instead of closing
  // one.
  for (let attempt = 0; attempt < 4; attempt++) {
    const refused = await service.fetch(
      await rendezvousCreateRequest(fixed(0x20 + attempt, 32), {
        authorization: null,
      }),
      undefined,
      'source-flood',
    );
    assert.equal(refused.status, 401);
  }
  const created = await service.fetch(
    await rendezvousCreateRequest(fixed(0x30, 32)),
    undefined,
    'source-flood',
  );
  assert.equal(created.status, 201);
});

test('an existing locator is not disclosed to an unenrolled caller', async () => {
  const { service } = await createV2TestService(new MemoryV2Store());
  const taken = fixed(0x40, 32);
  assert.equal(
    (await service.fetch(await rendezvousCreateRequest(taken))).status,
    201,
  );
  // Conflicting with a live record is error 5. Answering that to a caller
  // without a proof would turn creation into an oracle for locators in flight.
  const conflict = await service.fetch(
    await rendezvousCreateRequest(taken, {
      authorization: null,
      nonce: fixed(0xd1, 24),
    }),
  );
  assert.equal(conflict.status, 401);
  assert.equal(decodeMap(await conflict.arrayBuffer()).get(1), 2);
});

test('open enrollment is reachable only through the explicit opt-in', async () => {
  const { service } = await createV2TestService(new MemoryV2Store(), {
    openEnrollment: true,
  });
  const created = await service.fetch(
    await rendezvousCreateRequest(fixed(0x50, 32), { authorization: null }),
  );
  assert.equal(created.status, 201);
  // An open deployment ignores a proof rather than failing on it: nothing is
  // configured to check it against.
  assert.equal(
    (
      await service.fetch(
        await rendezvousCreateRequest(fixed(0x51, 32), {
          enrollmentSecret: 'pässwort-mit-ümlaut-2024-korrekt',
        }),
      )
    ).status,
    201,
  );
});

test('capability discovery reports both enrollment enforcement values', async () => {
  const gated = await createV2TestService(new MemoryV2Store());
  const open = await createV2TestService(new MemoryV2Store(), {
    openEnrollment: true,
  });
  const read = async ({ service }) => {
    const response = await service.fetch(
      new Request(`${V2_ORIGIN}/v2/capabilities`),
    );
    assert.equal(response.status, 200);
    const document = decodeMap(await response.arrayBuffer());
    // Pairing still works on a gated deployment; it just needs a credential,
    // so feature 3 stays advertised in both states.
    assert.ok(document.get(2).includes(3));
    return document.get(4).get(3);
  };
  assert.equal(await read(gated), 1);
  assert.equal(await read(open), 0);
});

test('the rendezvous carries a maximum-size hybrid invitation envelope', async () => {
  const store = new MemoryV2Store();
  const { service } = await createV2TestService(store);
  const locator = fixed(0x07, 32);
  // A complete hybrid-recipient invitation is roughly 1.7 KiB; the envelope
  // limit is the hard bound a client may reach, so the largest envelope a
  // client can produce has to survive creation and anonymous retrieval.
  const ciphertext = fixed(0x20, 4096);
  const created = await service.fetch(
    await rendezvousCreateRequest(locator, { ciphertext }),
    undefined,
    'source-max',
  );
  assert.equal(created.status, 201);
  const retrieved = await service.fetch(
    new Request(`${V2_ORIGIN}/v2/pairing/rendezvous/${bytesToHex(locator)}`, {
      method: 'GET',
      headers: { accept: 'application/dud+cbor; version=2' },
    }),
  );
  assert.equal(retrieved.status, 200);
  const envelope = decodeMap(await retrieved.arrayBuffer());
  assert.deepEqual(envelope.get(3), ciphertext);
  const oversized = await service.fetch(
    await rendezvousCreateRequest(fixed(0x08, 32), {
      ciphertext: fixed(0x20, 4097),
    }),
    undefined,
    'source-max',
  );
  assert.equal(oversized.status, 400);
});

test('pairing is race-safe and activates only after two signed completions', async () => {
  const store = new MemoryV2Store();
  const { service } = await createV2TestService(store);
  const pairing = await establishPairing(service);
  const invitationPath = `/v2/pairing/rendezvous/${bytesToHex(pairing.locator)}`;

  const before = await service.fetch(
    bearerRequest(`${invitationPath}/status`, pairing.inviterStatus),
  );
  assert.equal(before.status, 200);
  const beforeMap = decodeMap(await before.arrayBuffer());
  assert.equal(beforeMap.get(1), 2);
  assert.equal(beforeMap.has(6), false);

  const inviterCompletion = await pairing.completeRole(
    0,
    pairing.inviterStatus,
    pairing.inviterSigning.privateKey,
  );
  assert.equal(inviterCompletion.status, 202);
  const oneSided = decodeMap(
    await (
      await service.fetch(
        bearerRequest(`${invitationPath}/status`, pairing.inviterStatus),
      )
    ).arrayBuffer(),
  );
  assert.equal(oneSided.get(4), true);
  assert.equal(oneSided.get(5), false);
  assert.equal(oneSided.has(6), false);

  const inviteeCompletion = await pairing.completeRole(
    1,
    pairing.inviteeStatus,
    pairing.inviteeSigning.privateKey,
  );
  assert.equal(inviteeCompletion.status, 202);
  const active = decodeMap(
    await (
      await service.fetch(
        bearerRequest(`${invitationPath}/status`, pairing.inviteeStatus),
      )
    ).arrayBuffer(),
  );
  assert.equal(active.get(1), 3);
  assert.ok(active.get(6) instanceof Uint8Array);
  assert.match(
    new TextDecoder().decode(active.get(6).subarray(0, 22)),
    /^age-encryption\.org\/v1/,
  );
  assert.equal(Object.keys((await store.readState()).capabilities).length, 6);
});

test('pairing rejects a conflicting rendezvous claim and transcript completion', async () => {
  const store = new MemoryV2Store();
  const { service } = await createV2TestService(store);
  const pairing = await establishPairing(service);
  const id = bytesToHex(pairing.locator);
  const altered = decodeMap(pairing.acceptBody);
  const alteredAcceptance = requireCborMap(
    altered.get(2),
    Array.from({ length: 15 }, (_, index) => index),
    [],
  );
  alteredAcceptance.set(9, fixed(0xee, 32));
  altered.set(
    3,
    signPairing(
      'acceptance',
      alteredAcceptance,
      pairing.inviteeSigning.privateKey,
    ),
  );
  const conflicting = encodeCbor(altered);
  const response = await service.fetch(
    bearerRequest(
      `/v2/pairing/rendezvous/${id}/accept`,
      pairing.bootstrap,
      'POST',
      conflicting,
    ),
  );
  assert.equal(response.status, 409);
  assert.equal(decodeMap(await response.arrayBuffer()).get(1), 6);

  const wrongTranscript = Uint8Array.from(pairing.transcriptHash);
  wrongTranscript[0] ^= 1;
  const completion = new Map([
    [1, 2],
    [2, pairing.invitationId],
    [3, pairing.relationshipId],
    [4, wrongTranscript],
    [5, 0],
    [6, Math.floor(V2_NOW_MS / 1000)],
  ]);
  const body = encodeCbor(
    new Map([
      [1, completion],
      [
        2,
        signPairing(
          'pairing-complete',
          completion,
          pairing.inviterSigning.privateKey,
        ),
      ],
    ]),
  );
  const mismatch = await service.fetch(
    bearerRequest(
      `/v2/pairing/rendezvous/${id}/complete`,
      pairing.inviterStatus,
      'POST',
      body,
    ),
  );
  assert.equal(mismatch.status, 400);
  assert.deepEqual(Object.keys((await store.readState()).capabilities), []);
});

test('capability reissue proves the recorded role key, rotates, rejects replay, and preserves revocation', async () => {
  const repository = new MemoryV2Repository();
  const { pairing, service, store } = await activeRelationship({ repository });
  const now = Math.floor(V2_NOW_MS / 1000);
  const relationshipId = bytesToHex(pairing.relationshipId);
  const original = Object.values((await store.readState()).capabilities).find(
    (entry) =>
      entry.relationshipId === relationshipId &&
      entry.direction === 'inviter->invitee' &&
      entry.scope === 'write' &&
      !entry.revoked,
  );
  assert.ok(original);

  const reissueMap = new Map([
    [1, 2],
    [2, pairing.relationshipId],
    [3, 0],
    [4, fixed(0xd0, 32)],
    [5, now + 60],
    [6, ['write']],
    [7, V2_ORIGIN],
  ]);
  const body = encodeCbor(
    new Map([
      [1, reissueMap],
      [2, signReissue(reissueMap, pairing.inviterSigning.privateKey)],
    ]),
  );
  const request = () =>
    new Request(`${V2_ORIGIN}/v2/capabilities/reissue`, {
      method: 'POST',
      headers: {
        accept: 'application/dud+cbor; version=2',
        'content-type': 'application/dud+cbor; version=2',
        'content-length': String(body.byteLength),
      },
      body,
    });
  const issued = await service.fetch(request());
  assert.equal(issued.status, 200);
  const grant = decodeMap(await issued.arrayBuffer()).get(1);
  assert.ok(grant instanceof Uint8Array);
  assert.match(
    new TextDecoder().decode(grant.subarray(0, 22)),
    /^age-encryption\.org\/v1/,
  );
  const rotatedState = await store.readState();
  assert.equal(rotatedState.capabilities[original.id].revoked, true);
  assert.equal(
    Object.values(rotatedState.capabilities).filter(
      (entry) =>
        entry.relationshipId === relationshipId &&
        entry.direction === 'inviter->invitee' &&
        entry.scope === 'write' &&
        !entry.revoked,
    ).length,
    1,
  );
  const oldSecret = await decryptV2TokenSecret(V2_DEPLOYMENT_KEY, original);
  const epoch = Math.floor(now / 86_400);
  const oldLookup = await deriveV2DailyCapabilityLookupId(oldSecret, epoch);
  assert.equal(
    (await repository.findCapabilityLookup(oldLookup, epoch)).revokedAt,
    now,
  );
  const replacement = Object.values(rotatedState.capabilities).find(
    (entry) =>
      entry.relationshipId === relationshipId &&
      entry.direction === 'inviter->invitee' &&
      entry.scope === 'write' &&
      !entry.revoked,
  );
  assert.ok(replacement);
  const replacementSecret = await decryptV2TokenSecret(
    V2_DEPLOYMENT_KEY,
    replacement,
  );
  const replacementLookup = await deriveV2DailyCapabilityLookupId(
    replacementSecret,
    epoch,
  );
  assert.equal(
    (await repository.findCapabilityLookup(replacementLookup, epoch)).id,
    replacement.id,
  );

  const replay = await service.fetch(request());
  assert.equal(replay.status, 409);
  assert.equal(decodeMap(await replay.arrayBuffer()).get(1), 13);

  const revokeBody = encodeCbor(new Map([[1, pairing.relationshipId]]));
  assert.equal(
    (
      await service.fetch(
        bearerRequest(
          '/v2/admin/relationships/revoke',
          V2_ADMIN_SECRET,
          'POST',
          revokeBody,
        ),
      )
    ).status,
    204,
  );
  const revokedMap = new Map(reissueMap);
  revokedMap.set(4, fixed(0xe0, 32));
  const revokedBody = encodeCbor(
    new Map([
      [1, revokedMap],
      [2, signReissue(revokedMap, pairing.inviterSigning.privateKey)],
    ]),
  );
  const revoked = await service.fetch(
    new Request(`${V2_ORIGIN}/v2/capabilities/reissue`, {
      method: 'POST',
      headers: {
        accept: 'application/dud+cbor; version=2',
        'content-type': 'application/dud+cbor; version=2',
        'content-length': String(revokedBody.byteLength),
      },
      body: revokedBody,
    }),
  );
  assert.equal(revoked.status, 403);
});

test('capability reissue meters invalid proofs by trusted request source', async () => {
  const { pairing, service } = await activeRelationship({
    limits: { maxRequestsPerMinute: 2 },
  });
  const now = Math.floor(V2_NOW_MS / 1000);
  const reissueMap = new Map([
    [1, 2],
    [2, pairing.relationshipId],
    [3, 0],
    [4, fixed(0xc0, 32)],
    [5, now + 60],
    [6, ['write']],
    [7, V2_ORIGIN],
  ]);
  const body = encodeCbor(
    new Map([
      [1, reissueMap],
      // This reaches the recorded-key verification boundary without proving
      // possession of the relationship signing key.
      [2, fixed(0xd0, 64)],
    ]),
  );
  const request = () =>
    new Request(`${V2_ORIGIN}/v2/capabilities/reissue`, {
      method: 'POST',
      headers: {
        accept: 'application/dud+cbor; version=2',
        'content-type': 'application/dud+cbor; version=2',
        'content-length': String(body.byteLength),
      },
      body,
    });

  assert.equal((await service.fetch(request(), false, 'source-a')).status, 403);
  assert.equal((await service.fetch(request(), false, 'source-a')).status, 403);
  const limited = await service.fetch(request(), false, 'source-a');
  assert.equal(limited.status, 429);
  assert.equal(decodeMap(await limited.arrayBuffer()).get(1), 10);
  assert.equal((await service.fetch(request(), false, 'source-b')).status, 403);
});

async function activeRelationship(options = {}) {
  const store = new MemoryV2Store();
  const { service } = await createV2TestService(store, options);
  const pairing = await establishPairing(service);
  assert.equal(
    (
      await pairing.completeRole(
        0,
        pairing.inviterStatus,
        pairing.inviterSigning.privateKey,
      )
    ).status,
    202,
  );
  assert.equal(
    (
      await pairing.completeRole(
        1,
        pairing.inviteeStatus,
        pairing.inviteeSigning.privateKey,
      )
    ).status,
    202,
  );
  const state = await store.readState();
  const relationship = bytesToHex(pairing.relationshipId);
  const capability = async (direction, scope) => {
    const record = Object.values(state.capabilities).find(
      (entry) =>
        entry.relationshipId === relationship &&
        entry.direction === direction &&
        entry.scope === scope,
    );
    assert.ok(record);
    return {
      record,
      secret: await decryptV2TokenSecret(V2_DEPLOYMENT_KEY, record),
    };
  };
  return { capability, pairing, service, store };
}

test('granular pairing, reissue and administration never read whole state', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-granular-'));
  const repository = new SQLiteV2Repository(directory);
  await repository.initialize();
  t.after(async () => {
    repository.close();
    await rm(directory, { recursive: true, force: true });
  });
  // WorkerV2Store fails closed on every whole-state read and rewrite, so a
  // pairing flow that depended on one would fail here.
  const { service } = await createV2TestService(new WorkerV2Store(), {
    repository,
    pairingRepository: repository,
    bodyStore: new MemoryV2BodyStore(),
    granularOnly: true,
  });
  const pairing = await establishPairing(service);
  for (const [role, status, key] of [
    [0, pairing.inviterStatus, pairing.inviterSigning.privateKey],
    [1, pairing.inviteeStatus, pairing.inviteeSigning.privateKey],
  ]) {
    assert.equal((await pairing.completeRole(role, status, key)).status, 202);
  }
  const active = decodeMap(
    await (
      await service.fetch(
        bearerRequest(
          `/v2/pairing/rendezvous/${bytesToHex(pairing.locator)}/status`,
          pairing.inviterStatus,
        ),
      )
    ).arrayBuffer(),
  );
  assert.equal(active.get(1), 3);
  assert.ok(active.get(6) instanceof Uint8Array);

  const now = Math.floor(V2_NOW_MS / 1000);
  const reissueMap = new Map([
    [1, 2],
    [2, pairing.relationshipId],
    [3, 0],
    [4, fixed(0xd8, 32)],
    [5, now + 60],
    [6, ['write']],
    [7, V2_ORIGIN],
  ]);
  const reissueBody = encodeCbor(
    new Map([
      [1, reissueMap],
      [2, signReissue(reissueMap, pairing.inviterSigning.privateKey)],
    ]),
  );
  const reissueRequest = () =>
    new Request(`${V2_ORIGIN}/v2/capabilities/reissue`, {
      method: 'POST',
      headers: {
        accept: 'application/dud+cbor; version=2',
        'content-type': 'application/dud+cbor; version=2',
        'content-length': String(reissueBody.byteLength),
      },
      body: reissueBody,
    });
  assert.equal((await service.fetch(reissueRequest())).status, 200);
  assert.equal((await service.fetch(reissueRequest())).status, 409);

  const relationshipBody = encodeCbor(new Map([[1, pairing.relationshipId]]));
  const admin = (path, body = relationshipBody) =>
    service.fetch(bearerRequest(path, V2_ADMIN_SECRET, 'POST', body));
  const status = await admin('/v2/admin/relationships/status');
  assert.equal(status.status, 200);
  assert.equal(decodeMap(await status.arrayBuffer()).get(1), false);
  assert.equal(
    (
      await admin(
        '/v2/admin/relationships/rotate-capabilities',
        encodeCbor(
          new Map([
            [1, pairing.relationshipId],
            [2, 0],
            [3, 'write'],
          ]),
        ),
      )
    ).status,
    204,
  );
  assert.equal((await admin('/v2/admin/relationships/revoke')).status, 204);
  const revoked = await admin('/v2/admin/relationships/status');
  assert.equal(decodeMap(await revoked.arrayBuffer()).get(1), true);

  // A rejected administrative request charges its window through the
  // repository rather than a whole-state rewrite.
  const unauthorized = await service.fetch(
    bearerRequest(
      '/v2/admin/relationships/status',
      fixed(0x01, 32),
      'POST',
      relationshipBody,
    ),
  );
  assert.equal(unauthorized.status, 403);
});
