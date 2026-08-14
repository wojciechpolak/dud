// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeCbor, encodeCbor } from '../dist/src/cbor.js';
import {
  createV2CapabilityRecord,
  decryptV2TokenSecret,
  encodeBase64Url,
  rewrapV2VerifierKeys,
} from '../dist/src/v2-auth.js';
import { offlineRevokeV2Relationship } from '../dist/src/v2-admin.js';
import { MemoryV2Store } from '../dist/src/v2-memory.js';
import { WorkerV2Store } from '../dist/src/v2-worker-store.js';
import { makeContext, textStream } from './helpers.mjs';
import {
  createV2TestService,
  V2_ADMIN_SECRET,
  V2_DEPLOYMENT_KEY,
  V2_ENROLLMENT_SECRET,
  V2_NOW_MS,
  V2_ORIGIN,
  V2_RELATIONSHIP_ID,
  V2_TOKEN_SECRET,
} from './v2-helpers.mjs';

function decodeResponse(response) {
  return response
    .arrayBuffer()
    .then((buffer) => decodeCbor(new Uint8Array(buffer)));
}

/** Seeds one capability directly into the whole-state store. */
async function seedLegacyCapability(store, randomBytes) {
  const record = await createV2CapabilityRecord(V2_DEPLOYMENT_KEY, {
    relationshipId: V2_RELATIONSHIP_ID,
    direction: 'inviter->invitee',
    scope: 'write',
    tokenSecret: V2_TOKEN_SECRET,
    createdAt: Math.floor(V2_NOW_MS / 1000) - 60,
    expiresAt: Math.floor(V2_NOW_MS / 1000) + 86_400,
    randomBytes,
  });
  await store.transaction((state) => {
    state.capabilities[record.id] = record;
  });
  return record;
}

test('v2 endpoints are unreachable until explicitly enabled', async () => {
  const { createDudService } = await import('../dist/src/service.js');
  const { MemoryBlobStore } = await import('./helpers.mjs');
  const service = createDudService({ blobStore: new MemoryBlobStore() });
  const response = await service.fetch(
    new Request(`${V2_ORIGIN}/v2/capabilities`),
    makeContext(),
  );
  assert.equal(response.status, 404);
});

// Store initialization starts when the service is constructed and is awaited
// only by the requests that need it, so on a v2-only deployment nothing may
// ever await it. A failure in that window must stay attached to the promise:
// unhandled, it would end the whole process instead of failing one request.
test('a failed store initialization never escapes as an unhandled rejection', async () => {
  const { createDudService } = await import('../dist/src/service.js');
  const { MemoryBlobStore } = await import('./helpers.mjs');
  class FailingV2Store extends MemoryV2Store {
    async initialize() {
      throw new Error('store initialization failed');
    }
  }
  const service = createDudService({
    blobStore: new MemoryBlobStore(),
    v2Store: new FailingV2Store(),
    config: {
      secretToken: 'legacy-secret',
      v1Enabled: true,
      v2Enabled: true,
      v2DeploymentKey: encodeBase64Url(V2_DEPLOYMENT_KEY),
      v2AdminSecret: encodeBase64Url(V2_ADMIN_SECRET),
      v2Secret: V2_ENROLLMENT_SECRET,
    },
  });
  // Nothing has awaited initialization yet. An unattached rejection surfaces
  // by this point and fails the test, which is exactly the regression.
  await new Promise((resolve) => setTimeout(resolve, 10));
  // The failure is still reported to the first request that needs the store,
  // so keeping the process alive costs no visibility into what went wrong.
  await assert.rejects(
    service.fetch(
      new Request(`${V2_ORIGIN}/v2/pairing/rendezvous`, { method: 'POST' }),
      makeContext(),
    ),
    /store initialization failed/,
  );
});

test('v2 limit configuration fails closed on unsafe quota relationships', async () => {
  const { createDudService } = await import('../dist/src/service.js');
  const { MemoryBlobStore } = await import('./helpers.mjs');
  assert.throws(
    () =>
      createDudService({
        blobStore: new MemoryBlobStore(),
        config: {
          v2Limits: {
            maxObjectBytes: 100,
            maxStagedBytes: 99,
          },
        },
      }),
    /must permit one maximum-sized object/,
  );
});

test('v2 deployment and administrative credentials must be distinct', async () => {
  const { createDudService } = await import('../dist/src/service.js');
  const { MemoryBlobStore } = await import('./helpers.mjs');
  const shared = encodeBase64Url(V2_DEPLOYMENT_KEY);
  assert.throws(
    () =>
      createDudService({
        blobStore: new MemoryBlobStore(),
        v2Store: new MemoryV2Store(),
        config: {
          v2Enabled: true,
          v2DeploymentKey: shared,
          v2AdminSecret: shared,
        },
      }),
    /must be distinct/,
  );
  assert.throws(
    () =>
      createDudService({
        blobStore: new MemoryBlobStore(),
        v2Store: new MemoryV2Store(),
        config: {
          secretToken: shared,
          v2Enabled: true,
          v2DeploymentKey: encodeBase64Url(new Uint8Array(32)),
          v2AdminSecret: shared,
        },
      }),
    /must be distinct/,
  );
  assert.throws(
    () =>
      createDudService({
        blobStore: new MemoryBlobStore(),
        v2Store: new MemoryV2Store(),
        config: {
          v2Enabled: true,
          v2DeploymentKey: encodeBase64Url(new Uint8Array(32)),
          v2Secret: shared,
          v2AdminSecret: shared,
        },
      }),
    /must be distinct/,
  );
});

test('a v2 deployment refuses to start without a stated enrollment policy', async () => {
  const { createDudService } = await import('../dist/src/service.js');
  const { MemoryBlobStore } = await import('./helpers.mjs');
  const base = {
    v2Enabled: true,
    v2DeploymentKey: encodeBase64Url(V2_DEPLOYMENT_KEY),
    v2AdminSecret: encodeBase64Url(V2_ADMIN_SECRET),
  };
  const start = (config) =>
    createDudService({
      blobStore: new MemoryBlobStore(),
      v2Store: new MemoryV2Store(),
      config: { ...base, ...config },
    });
  // Omitting the credential is the case that would otherwise leave a
  // deployment relaying for anyone who learns its hostname, so it is refused
  // rather than defaulted.
  assert.throws(() => start({}), /DUD_PEER_SECRET is required/);
  assert.doesNotThrow(() => start({ v2Secret: V2_ENROLLMENT_SECRET }));
  // Guessable and malformed enrollment passphrases fail before service startup.
  assert.throws(() => start({ v2Secret: 'short' }), /at least 24 characters/);
  assert.throws(
    () => start({ v2Secret: ` ${V2_ENROLLMENT_SECRET}` }),
    /whitespace/,
  );
  assert.doesNotThrow(() => start({ v2OpenEnrollment: true }));
});

test('a v2 deployment reads every accepted form of the enrollment secret', async () => {
  const { createDudService } = await import('../dist/src/service.js');
  const { MemoryBlobStore } = await import('./helpers.mjs');
  const { deriveV2EnrollmentKey, formatV2EnrollmentKey } =
    await import('../dist/src/v2-auth.js');
  const start = (config) =>
    createDudService({
      blobStore: new MemoryBlobStore(),
      v2Store: new MemoryV2Store(),
      config: {
        v2Enabled: true,
        v2DeploymentKey: encodeBase64Url(V2_DEPLOYMENT_KEY),
        v2AdminSecret: encodeBase64Url(V2_ADMIN_SECRET),
        ...config,
      },
    });
  // The derived key needs no stretching at startup, which is the whole point of
  // the form: a Worker invocation has too little CPU to finish the derivation.
  const derived = formatV2EnrollmentKey(
    await deriveV2EnrollmentKey(V2_ENROLLMENT_SECRET),
  );
  assert.doesNotThrow(() => start({ v2Secret: derived }));
  // A truncated or mistyped key is refused here rather than at the first
  // invitation, where every enrollment failure is deliberately the same refusal.
  assert.throws(
    () => start({ v2Secret: `${derived.slice(0, -1)}` }),
    /dud2-enroll-key:/,
  );
  assert.throws(
    () => start({ v2Secret: 'dud2-enroll-key:not base64url at all' }),
    /dud2-enroll-key:/,
  );
  // A stated work factor below the default is a deliberate trade, so it is
  // refused until the operator says so, and accepted once they do.
  const weak = `dud2-enroll-kdf:10000:${V2_ENROLLMENT_SECRET}`;
  assert.throws(() => start({ v2Secret: weak }), /ACCEPT_WEAK_ENROLLMENT_KDF/);
  assert.doesNotThrow(() =>
    start({ v2Secret: weak, v2AcceptWeakEnrollmentKdf: true }),
  );
  // At or above the default it needs no acknowledgement.
  assert.doesNotThrow(() =>
    start({ v2Secret: `dud2-enroll-kdf:600000:${V2_ENROLLMENT_SECRET}` }),
  );
  // A count outside the bounds is malformed rather than weak, so no
  // acknowledgement makes it acceptable.
  for (const value of [
    'dud2-enroll-kdf:1:',
    'dud2-enroll-kdf:99999999999:',
    'dud2-enroll-kdf::',
    'dud2-enroll-kdf:0x2710:',
  ]) {
    assert.throws(
      () =>
        start({
          v2Secret: `${value}${V2_ENROLLMENT_SECRET}`,
          v2AcceptWeakEnrollmentKdf: true,
        }),
      /iteration count between/,
      `accepted ${value}`,
    );
  }
  // The passphrase floor still applies behind a stated work factor.
  assert.throws(
    () => start({ v2Secret: 'dud2-enroll-kdf:600000:short' }),
    /at least 24 characters/,
  );
  // Carrying a key rather than a passphrase must not let one of the two
  // server-only credentials be reused here: the prefix makes the strings differ,
  // so the bytes are what has to be compared.
  for (const reused of [V2_DEPLOYMENT_KEY, V2_ADMIN_SECRET]) {
    assert.throws(
      () => start({ v2Secret: formatV2EnrollmentKey(reused) }),
      /must be distinct/,
      `reused ${encodeBase64Url(reused)}`,
    );
  }
});

test('enabling v2 preserves the v1 service surface', async () => {
  const { service } = await createV2TestService(new MemoryV2Store());
  const response = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/test`),
    makeContext(),
  );
  assert.equal(response.status, 200);
  assert.equal((await response.json()).ok, true);
});

test('dual-stack v1 traffic inherits v2 rate and shared-storage accounting', async () => {
  const rateLimited = await createV2TestService(new MemoryV2Store(), {
    limits: { maxRequestsPerMinute: 1 },
  });
  const firstTest = await rateLimited.service.fetch(
    new Request(`${V2_ORIGIN}/v1/test`),
    makeContext(),
    'source-a',
  );
  assert.equal(firstTest.status, 200);
  const limitedTest = await rateLimited.service.fetch(
    new Request(`${V2_ORIGIN}/v1/test`),
    makeContext(),
    'source-a',
  );
  assert.equal(limitedTest.status, 429);
  assert.equal(limitedTest.headers.get('retry-after'), '60');
  const otherSource = await rateLimited.service.fetch(
    new Request(`${V2_ORIGIN}/v1/test`),
    makeContext(),
    'source-b',
  );
  assert.equal(otherSource.status, 200);

  const store = new MemoryV2Store();
  const { service } = await createV2TestService(store, {
    limits: {
      maxObjectBytes: 8,
      maxStagedBytes: 8,
      maxTotalBytes: 8,
    },
  });
  const uploadContext = makeContext();
  const legacyUpload = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/files`, {
      method: 'POST',
      headers: {
        'content-length': '6',
        'content-type': 'application/octet-stream',
        'x-dud-delete-after-read': 'true',
        'x-dud-secret-token': 'legacy-secret',
      },
      body: textStream('legacy'),
      duplex: 'half',
    }),
    uploadContext,
  );
  assert.equal(legacyUpload.status, 201);
  const legacyId = (await legacyUpload.json()).id.replaceAll('-', '');
  let state = await store.readState();
  assert.equal(state.legacyCommittedBytes, 6);
  assert.equal(state.legacyObjects[legacyId].ciphertextSize, 6);

  const overSharedQuota = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/files`, {
      method: 'POST',
      headers: {
        'content-length': '4',
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'legacy-secret',
      },
      body: textStream('four'),
      duplex: 'half',
    }),
    makeContext(),
  );
  assert.equal(overSharedQuota.status, 429);
  assert.match((await overSharedQuota.json()).error, /quota exceeded/);

  const downloadContext = makeContext();
  const consumed = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/files/${legacyId}`),
    downloadContext,
  );
  assert.equal(consumed.status, 200);
  assert.equal(await consumed.text(), 'legacy');
  await downloadContext.flush();
  state = await store.readState();
  assert.equal(state.legacyCommittedBytes, 0);
  assert.equal(state.legacyObjects[legacyId], undefined);
});

// The rate window and the shared quota above are whole-state records. A
// deployment that keeps every peer record in granular repositories holds no
// whole-state document at all, and its store refuses to read or rewrite one, so
// a dead drop route that charged that ledger would fail every request rather
// than serve it. Drops there meter and account exactly as with peer mode off.
test('dead drops serve a deployment that keeps no whole state', async () => {
  const { service } = await createV2TestService(new WorkerV2Store(), {
    limits: {
      maxRequestsPerMinute: 1,
      maxObjectBytes: 8,
      maxStagedBytes: 8,
      maxTotalBytes: 8,
    },
  });
  for (const attempt of [1, 2]) {
    const health = await service.fetch(
      new Request(`${V2_ORIGIN}/v1/test`),
      makeContext(),
      'source-a',
    );
    assert.equal(health.status, 200, `health request ${attempt} was refused`);
  }

  const uploadContext = makeContext();
  const uploaded = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/files`, {
      method: 'POST',
      headers: {
        'content-length': '6',
        'content-type': 'application/octet-stream',
        'x-dud-delete-after-read': 'true',
        'x-dud-secret-token': 'legacy-secret',
      },
      body: textStream('legacy'),
      duplex: 'half',
    }),
    uploadContext,
  );
  assert.equal(uploaded.status, 201);
  await uploadContext.flush();

  // The same second upload the whole-state deployment refuses over its shared
  // quota: there is no ledger here that a drop has already spent.
  const secondContext = makeContext();
  const second = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/files`, {
      method: 'POST',
      headers: {
        'content-length': '4',
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'legacy-secret',
      },
      body: textStream('four'),
      duplex: 'half',
    }),
    secondContext,
  );
  assert.equal(second.status, 201);
  await secondContext.flush();

  const downloadContext = makeContext();
  const consumed = await service.fetch(
    new Request(
      `${V2_ORIGIN}/v1/files/${(await uploaded.json()).id.replaceAll('-', '')}`,
    ),
    downloadContext,
  );
  assert.equal(consumed.status, 200);
  assert.equal(await consumed.text(), 'legacy');
  // Consuming a one-time drop releases its accounting and runs the v2 prune,
  // both of which the whole-state store would refuse.
  await downloadContext.flush();

  const flushed = await service.fetch(
    new Request(`${V2_ORIGIN}/v1/admin/flush`, {
      method: 'POST',
      headers: { 'x-dud-secret-token': 'legacy-secret' },
    }),
    makeContext(),
  );
  assert.equal(flushed.status, 200);
  assert.equal((await flushed.json()).ok, true);
});

test('capability discovery advertises only implemented features and atomic quotas', async () => {
  const { service } = await createV2TestService(new MemoryV2Store());
  const response = await service.fetch(
    new Request(`${V2_ORIGIN}/v2/capabilities`),
    makeContext(),
  );
  assert.equal(response.status, 200);
  assert.equal(
    response.headers.get('content-type'),
    'application/dud+cbor; version=2',
  );
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await decodeResponse(response);
  assert.deepEqual(body.get(1), [1, 2]);
  assert.deepEqual(body.get(2), [2, 3, 5, 9, 10, 11]);
  assert.equal(body.get(3).get(1), 104857600);
  assert.equal(body.get(4).get(1), 2);
  assert.equal(body.get(4).get(2), 0);
});

test('administrative authorization failures are rate limited', async () => {
  const store = new MemoryV2Store();
  const { service } = await createV2TestService(store, {
    limits: { maxRequestsPerMinute: 1 },
  });
  const invalidRequest = () =>
    new Request(`${V2_ORIGIN}/v2/admin/relationships/status`, {
      method: 'POST',
      headers: {
        authorization: `DUD2-Bearer ${encodeBase64Url(new Uint8Array(32))}`,
        'content-type': 'application/dud+cbor; version=2',
      },
      body: encodeCbor(new Map([[1, V2_RELATIONSHIP_ID]])),
    });
  assert.equal(
    (await service.fetch(invalidRequest(), makeContext())).status,
    403,
  );
  const limited = await service.fetch(invalidRequest(), makeContext());
  assert.equal(limited.status, 429);
  assert.equal((await decodeResponse(limited)).get(3), 60);
});

test('administrative CBOR bodies are capped while streaming', async () => {
  const { service } = await createV2TestService(new MemoryV2Store(), {
    limits: { maxDescriptorBytes: 16 },
  });
  const response = await service.fetch(
    new Request(`${V2_ORIGIN}/v2/admin/relationships/status`, {
      method: 'POST',
      headers: {
        authorization: `DUD2-Bearer ${encodeBase64Url(V2_ADMIN_SECRET)}`,
        'content-type': 'application/dud+cbor; version=2',
      },
      body: textStream('x'.repeat(1024)),
      duplex: 'half',
    }),
    makeContext(),
  );
  assert.equal(response.status, 400);
});

test('offline revocation and deployment-key rewrap preserve the security boundary', async () => {
  const store = new MemoryV2Store();
  const { randomBytes } = await createV2TestService(store);
  const capability = await seedLegacyCapability(store, randomBytes);
  const newKey = Uint8Array.from({ length: 32 }, (_, index) => 0x20 + index);
  assert.equal(
    await rewrapV2VerifierKeys(store, V2_DEPLOYMENT_KEY, newKey, (length) =>
      Uint8Array.from({ length }, (_, index) => 0x70 + index),
    ),
    1,
  );
  const rewrapped = (await store.readState()).capabilities[capability.id];
  assert.deepEqual(
    await decryptV2TokenSecret(newKey, rewrapped),
    V2_TOKEN_SECRET,
  );
  await assert.rejects(
    decryptV2TokenSecret(V2_DEPLOYMENT_KEY, rewrapped),
    /failed authentication/,
  );

  assert.equal(
    await offlineRevokeV2Relationship(
      store,
      V2_RELATIONSHIP_ID,
      Math.floor(V2_NOW_MS / 1000),
      'inviter->invitee',
    ),
    1,
  );
  assert.equal(
    (await store.readState()).capabilities[capability.id].revoked,
    true,
  );
});
