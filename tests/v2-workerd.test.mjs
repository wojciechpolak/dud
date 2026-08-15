// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// The Worker, on workerd, against a real D1 database and a real R2 bucket.
//
// Every other suite substitutes one of those three: the handler runs in Node,
// D1 is `node:sqlite` behind an adapter, and R2 is an in-memory store. Each
// substitution has hidden a defect that reached the deployment and broke every
// v2 request against it — D1 returning BLOB columns as `Array<number>` rather
// than `Uint8Array`, and a bootstrap edited after it had been applied, so the
// live tables were missing `deliveries.sequence` and
// `staged_bodies.reserved_bytes`. Both are asserted below.
//
// The bundle is built the way Wrangler builds it and handed to Miniflare as an
// explicit module, which keeps the dynamic `import('crypto')` inside @hpke
// unresolved exactly as it is in production: workerd never evaluates that
// branch, because `globalThis.crypto` is always defined.

import assert from 'node:assert/strict';
import test from 'node:test';
import { build } from 'esbuild';
import { Miniflare } from 'miniflare';

import { encodeCbor, decodeCbor } from '../dist/src/cbor.js';
import { V2_INBOX_RESPONSE_KEYS } from '../dist/src/v2-delivery-frame.js';
import { sha256 } from '../dist/src/sha256.js';
import { D1V2Repository } from '../dist/src/v2-d1-repository.js';
import { readD1Migrations } from './d1-local.mjs';
import {
  buildDeliveryRequest,
  buildInboxRequest,
  registerCapability,
  requestedPolicy,
  V2_DATA_SLOT,
  V2_DEPLOYMENT_KEY,
  V2_RELATIONSHIP_CAPABILITIES,
} from './v2-delivery-fixtures.mjs';

const ORIGIN = 'https://dud.example.com';
const CBOR_CONTENT_TYPE = 'application/dud+cbor; version=2';
const RELATIONSHIP = 'relationship';
const PAYLOAD = Uint8Array.from({ length: 4096 }, (_, index) => index & 0xff);

const base64url = (bytes) =>
  Buffer.from(bytes).toString('base64url').replace(/=+$/, '');

const textEncoder = new TextEncoder();

function fixed(start, length) {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function concat(...parts) {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

/** The salted bearer commitment a rendezvous carries for each side. */
function pairingVerifier(bearer, saltStart) {
  const salt = fixed(saltStart, 16);
  return new Map([
    [1, salt],
    [2, sha256(concat(textEncoder.encode('dud/v2/bearer\0'), salt, bearer))],
  ]);
}

/**
 * Boots one Worker over a fresh D1 and R2, migrated from the checked-in
 * bootstrap so a schema the deployment would reject fails here too.
 */
async function startWorker(t) {
  const bundle = await build({
    entryPoints: ['src/index.ts'],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    conditions: ['workerd', 'worker', 'browser'],
    write: false,
    logLevel: 'error',
  });
  const miniflare = new Miniflare({
    compatibilityDate: '2026-05-03',
    modules: [
      {
        type: 'ESModule',
        path: 'index.js',
        contents: bundle.outputFiles[0].text,
      },
    ],
    d1Databases: { DB: 'dud-v2' },
    r2Buckets: ['FILES'],
    bindings: {
      APP_VERSION: '2.0.1',
      DUD_DROP_ENABLED: 'true',
      DUD_DROP_SECRET: 'workerd-suite-v1-secret',
      DUD_PEER_ENABLED: 'true',
      DUD_PEER_OPEN_ENROLLMENT: 'true',
      DUD_PEER_DEPLOYMENT_KEY: base64url(V2_DEPLOYMENT_KEY),
    },
  });
  t.after(() => miniflare.dispose());

  const database = await miniflare.getD1Database('DB');
  for (const migration of await readD1Migrations()) {
    for (const statement of migration
      .split('\n')
      .filter((line) => !line.trim().startsWith('--'))
      .join('\n')
      .split(';')
      .map((value) => value.trim())
      // D1 rejects PRAGMA; it enforces foreign keys itself.
      .filter((value) => value && !value.startsWith('PRAGMA'))) {
      await database.prepare(statement).run();
    }
  }
  return {
    database,
    fetch: async (request) =>
      miniflare.dispatchFetch(request.url, {
        method: request.method,
        headers: request.headers,
        body:
          request.method === 'GET' ? undefined : await request.arrayBuffer(),
      }),
  };
}

/** Registers the capabilities a pairing would have published. */
async function grantCapabilities(database, expiresAt) {
  const repository = new D1V2Repository(database);
  for (const capability of V2_RELATIONSHIP_CAPABILITIES) {
    await registerCapability(repository, {
      ...capability,
      relationshipId: RELATIONSHIP,
      expiresAt,
    });
  }
}

async function cborBody(response) {
  return decodeCbor(new Uint8Array(await response.arrayBuffer()));
}

test('a pairing rendezvous survives the round trip through D1', async (t) => {
  const worker = await startWorker(t);
  const now = Math.floor(Date.now() / 1000);
  const locator = fixed(0x10, 32);
  const nonce = fixed(0xd0, 24);
  const ciphertext = fixed(0xe0, 128);
  const body = encodeCbor(
    new Map([
      [1, 2],
      [2, locator],
      [3, nonce],
      [4, ciphertext],
      [5, now + 900],
      [6, pairingVerifier(fixed(0x50, 32), 0x51)],
      [7, pairingVerifier(fixed(0x70, 32), 0x71)],
    ]),
  );
  const created = await worker.fetch(
    new Request(`${ORIGIN}/v2/pairing/rendezvous`, {
      method: 'POST',
      headers: {
        'content-type': CBOR_CONTENT_TYPE,
        'content-length': String(body.byteLength),
      },
      body,
    }),
  );
  assert.equal(created.status, 201, 'rendezvous was not created');

  // Reading it back decodes `encrypted_grant`, which D1 hands over as
  // `Array<number>`. A decoder that demands `Uint8Array` refuses every
  // rendezvous the moment one exists, which is what broke `peer invite`.
  const retrieved = await worker.fetch(
    new Request(
      `${ORIGIN}/v2/pairing/rendezvous/${Buffer.from(locator).toString('hex')}`,
    ),
  );
  assert.equal(retrieved.status, 200, 'stored rendezvous was not readable');
  const record = await cborBody(retrieved);
  assert.deepEqual(record.get(2), nonce);
  assert.deepEqual(record.get(3), ciphertext);
});

// A dual-stack Worker serves dead drops out of R2 while D1 holds every peer
// record, so there is no whole-state document to meter a drop against and the
// Worker store refuses whole-state reads outright. A drop route that charged
// one answered 500 to `test`, `upload`, `download`, and `flush` alike; the
// substituted suites keep a working in-memory store, so only this one sees it.
test('dead drop routes serve a dual-stack Worker', async (t) => {
  const worker = await startWorker(t);
  const health = await worker.fetch(new Request(`${ORIGIN}/v1/test`));
  assert.equal(health.status, 200, 'the health route refused a dual-stack GET');
  assert.equal((await health.json()).ok, true);

  const uploaded = await worker.fetch(
    new Request(`${ORIGIN}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'content-length': String(PAYLOAD.byteLength),
        'x-dud-secret-token': 'workerd-suite-v1-secret',
        'x-dud-ttl': '1h',
      },
      body: PAYLOAD,
    }),
  );
  assert.equal(uploaded.status, 201, 'the upload route refused a drop');
  const id = (await uploaded.json()).id;

  const downloaded = await worker.fetch(
    new Request(`${ORIGIN}/v1/files/${id}`),
  );
  assert.equal(downloaded.status, 200, 'the drop was not readable');
  assert.deepEqual(new Uint8Array(await downloaded.arrayBuffer()), PAYLOAD);

  // Flushing sweeps expirations and prunes v2 state, which is the other place
  // a drop request reaches the store.
  const flushed = await worker.fetch(
    new Request(`${ORIGIN}/v1/admin/flush`, {
      method: 'POST',
      headers: { 'x-dud-secret-token': 'workerd-suite-v1-secret' },
    }),
  );
  assert.equal(flushed.status, 200, 'the flush route refused a sweep');
  assert.equal((await flushed.json()).ok, true);
});

test('a delivery published on workerd comes back out of the inbox', async (t) => {
  const worker = await startWorker(t);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 300;
  await grantCapabilities(worker.database, expiresAt);

  // Reserving the staging row needs `staged_bodies.reserved_bytes`, and
  // publishing needs `deliveries.sequence`; a database missing either fails
  // here with the SQLITE_ERROR the deployment returned.
  const published = await worker.fetch(
    await buildDeliveryRequest({
      payload: PAYLOAD,
      policy: requestedPolicy(expiresAt),
      proofExpiresAt: expiresAt,
    }),
  );
  assert.equal(published.status, 200, 'delivery was not accepted');
  const deliveryId = (await cborBody(published)).get(1);
  assert.equal(deliveryId.byteLength, 16);

  const inbox = await worker.fetch(
    await buildInboxRequest({ proofExpiresAt: expiresAt }),
  );
  assert.equal(inbox.status, 200, 'inbox refused the read');
  const frame = new Uint8Array(await inbox.arrayBuffer());
  assert.deepEqual(frame.subarray(0, 4), textEncoder.encode('DUD2'));

  // The R2 body rides back after the CBOR header, whose length the frame
  // declares. It went through a FixedLengthStream on the way in, which only
  // workerd enforces.
  const headerLength = new DataView(frame.buffer, frame.byteOffset).getUint32(
    4,
    false,
  );
  const header = decodeCbor(frame.subarray(8, 8 + headerLength));
  assert.deepEqual(
    header.get(V2_INBOX_RESPONSE_KEYS.slot),
    V2_DATA_SLOT,
    'inbox returned another slot',
  );
  assert.deepEqual(
    header.get(V2_INBOX_RESPONSE_KEYS.deliveryId),
    deliveryId,
    'inbox returned another delivery',
  );
  assert.equal(
    header.get(V2_INBOX_RESPONSE_KEYS.payloadLength),
    PAYLOAD.byteLength,
  );
  assert.deepEqual(frame.subarray(8 + headerLength), PAYLOAD);
});
