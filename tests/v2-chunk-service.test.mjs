// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  buildV2DeliveryProof,
  deriveV2DailyCapabilityLookupId,
  encodeBase64Url,
} from '../dist/src/v2-auth.js';
import { encodeCbor } from '../dist/src/cbor.js';
import { sha256 } from '../dist/src/sha256.js';
import { FilesystemV2BodyStore } from '../dist/src/v2-filesystem-body-store.js';
import { MemoryV2BodyStore } from '../dist/src/v2-memory-body-store.js';
import { MemoryV2Repository } from '../dist/src/v2-memory-repository.js';
import { R2V2BodyStore } from '../dist/src/v2-r2.js';
import {
  decodeV2InboxResponseFrame,
  V2_INBOX_RESPONSE_KEYS,
} from '../dist/src/v2-delivery-frame.js';
import { V2_CBOR_CONTENT_TYPE } from '../dist/src/v2-http.js';
import {
  attachHandler,
  decodeBody,
  fill,
  hex,
  registerCapability,
  V2_DATA_SLOT,
  V2_NOW,
  V2_ORIGIN,
  V2_REPOSITORY_BACKENDS,
  V2_TOKENS,
} from './v2-delivery-fixtures.mjs';
import { MockR2Bucket } from './v2-helpers.mjs';

globalThis.FixedLengthStream ??= class FixedLengthStream extends (
  TransformStream
) {
  constructor() {
    super();
  }
};

const CHAIN = 0;
const EPOCH = Math.floor(V2_NOW / 86_400);
const EMPTY_DIGEST = new Uint8Array(32);

const productionBodyStores = [
  [
    'filesystem',
    async (t) => {
      const directory = await mkdtemp(join(tmpdir(), 'dud-v2-part-write-'));
      t.after(() => rm(directory, { recursive: true, force: true }));
      return new FilesystemV2BodyStore(directory);
    },
  ],
  ['r2', async () => new R2V2BodyStore(new MockR2Bucket())],
];

async function authorization({
  method,
  path,
  digest,
  nonce,
  now = V2_NOW,
  tokenSecret = V2_TOKENS.write,
  scope = 'write',
}) {
  const proof = await buildV2DeliveryProof({
    tokenSecret,
    capabilityLookupId: await deriveV2DailyCapabilityLookupId(
      tokenSecret,
      EPOCH,
    ),
    direction: 'inviter->invitee',
    scope,
    chain: CHAIN,
    slot: V2_DATA_SLOT,
    slotEpoch: EPOCH,
    method,
    canonicalOrigin: V2_ORIGIN,
    normalizedPath: path,
    operationIndex: 0,
    requestDigest: digest,
    nonce,
    expiresAt: now + 60,
  });
  return `DUD2 ${encodeBase64Url(proof)}`;
}

function cborRequest(path, body, auth) {
  return new Request(`${V2_ORIGIN}${path}`, {
    method: 'POST',
    headers: {
      'content-type': V2_CBOR_CONTENT_TYPE,
      'content-length': String(body.byteLength),
      'dud-authorization': auth,
    },
    body,
  });
}

function createBody(parts, operationId = fill(40)) {
  return encodeCbor(
    new Map([
      [1, operationId],
      [2, CHAIN],
      [3, V2_DATA_SLOT],
      [4, EPOCH],
      [
        5,
        parts.map(
          (part) =>
            new Map([
              [1, part.id],
              [2, part.body.byteLength],
              [3, sha256(part.body)],
            ]),
        ),
      ],
      [6, parts.reduce((total, part) => total + part.body.byteLength, 0)],
    ]),
  );
}

async function createUpload(fixture, parts, nonce = fill(41)) {
  const path = '/v2/deliveries/uploads';
  const body = createBody(parts);
  return fixture.route(
    cborRequest(
      path,
      body,
      await authorization({
        method: 'POST',
        path,
        digest: sha256(body),
        nonce,
      }),
    ),
    path,
  );
}

async function partRequest({
  uploadId,
  part,
  method,
  nonce,
  body = part.body,
  now = V2_NOW,
}) {
  const partId = hex(part.id);
  const path = `/v2/deliveries/uploads/${uploadId}/chunks/${partId}`;
  const digest = method === 'PUT' ? sha256(part.body) : EMPTY_DIGEST;
  const headers = {
    'dud-authorization': await authorization({
      method,
      path,
      digest,
      nonce,
      now,
    }),
  };
  if (method === 'PUT') {
    headers['content-type'] = 'application/octet-stream';
    headers['content-length'] = String(body.byteLength);
    headers['dud-content-sha256'] = hex(digest);
  }
  return {
    path,
    request: new Request(`${V2_ORIGIN}${path}`, {
      method,
      headers,
      ...(method === 'PUT' ? { body } : {}),
    }),
  };
}

for (const [name, createRepository] of V2_REPOSITORY_BACKENDS) {
  test(`${name} resumes a delivery-scoped chunk upload`, async (t) => {
    const repository = await createRepository(t);
    await registerCapability(
      repository,
      {
        id: `chunk-${name}`,
        scope: 'write',
        direction: 'inviter->invitee',
        tokenSecret: V2_TOKENS.write,
        relationshipId: `chunk-${name}`,
        expiresAt: V2_NOW + 7_200,
      },
      EPOCH,
    );
    const fixture = attachHandler(repository, new MemoryV2BodyStore(), {
      handler: {
        maximumConcurrentUploads: 2,
        maximumStagedBytes: 1_024,
      },
    });
    const parts = [
      { id: fill(51), body: Uint8Array.of(1, 2, 3) },
      { id: fill(52), body: Uint8Array.of(4, 5, 6, 7) },
    ];

    const created = await createUpload(fixture, parts);
    assert.equal(created.status, 201);
    const createdBody = await decodeBody(created);
    const uploadId = hex(createdBody.get(1));
    assert.deepEqual(
      createdBody.get(3),
      parts.map((part) => part.id),
    );

    const put = await partRequest({
      uploadId,
      part: parts[0],
      method: 'PUT',
      nonce: fill(42),
    });
    assert.equal((await fixture.route(put.request, put.path)).status, 204);

    const substitutedRetry = await partRequest({
      uploadId,
      part: parts[0],
      method: 'PUT',
      nonce: fill(48),
      body: Uint8Array.of(9, 9, 9),
    });
    assert.equal(
      (await fixture.route(substitutedRetry.request, substitutedRetry.path))
        .status,
      400,
    );

    const status = await partRequest({
      uploadId,
      part: parts[0],
      method: 'HEAD',
      nonce: fill(43),
    });
    const present = await fixture.route(status.request, status.path);
    assert.equal(present.status, 200);
    assert.equal(
      present.headers.get('dud-content-sha256'),
      hex(sha256(parts[0].body)),
    );
    assert.equal(present.headers.get('content-length'), '3');

    const missingStatus = await partRequest({
      uploadId,
      part: parts[1],
      method: 'HEAD',
      nonce: fill(44),
    });
    assert.equal(
      (await fixture.route(missingStatus.request, missingStatus.path)).status,
      404,
    );

    fixture.setNow(V2_NOW + 10);
    const renewPath = `/v2/deliveries/uploads/${uploadId}/renew`;
    const renewBody = encodeCbor(new Map([[1, fill(45)]]));
    const renewed = await fixture.route(
      cborRequest(
        renewPath,
        renewBody,
        await authorization({
          method: 'POST',
          path: renewPath,
          digest: sha256(renewBody),
          nonce: fill(46),
          now: V2_NOW + 10,
        }),
      ),
      renewPath,
    );
    assert.equal(renewed.status, 200);
    assert.equal((await decodeBody(renewed)).get(2), false);

    const deletePath = `/v2/deliveries/uploads/${uploadId}`;
    const deleted = await fixture.route(
      new Request(`${V2_ORIGIN}${deletePath}`, {
        method: 'DELETE',
        headers: {
          'dud-authorization': await authorization({
            method: 'DELETE',
            path: deletePath,
            digest: EMPTY_DIGEST,
            nonce: fill(47),
            now: V2_NOW + 10,
          }),
        },
      }),
      deletePath,
    );
    assert.equal(deleted.status, 204);
  });
}

for (const [name, createRepository] of V2_REPOSITORY_BACKENDS) {
  test(`${name} commits and reads a chunked delivery`, async (t) => {
    const repository = await createRepository(t);
    const relationshipId = `chunk-commit-${name}`;
    await registerCapability(
      repository,
      {
        id: `chunk-write-${name}`,
        scope: 'write',
        direction: 'inviter->invitee',
        tokenSecret: V2_TOKENS.write,
        relationshipId,
        expiresAt: V2_NOW + 7_200,
      },
      EPOCH,
    );
    await registerCapability(
      repository,
      {
        id: `chunk-read-${name}`,
        scope: 'read',
        direction: 'inviter->invitee',
        tokenSecret: V2_TOKENS.read,
        relationshipId,
        expiresAt: V2_NOW + 7_200,
      },
      EPOCH,
    );
    const bodyStore = new MemoryV2BodyStore();
    const rejections = [];
    const handler = {
      maximumConcurrentUploads: 2,
      maximumStagedBytes: 1_024,
      maximumTotalBytes: 1_024,
      maximumPendingDeliveries: 2,
      maximumObjectsPerCapability: 2,
      observeRejection: (rejection) => rejections.push(rejection),
    };
    let fixture = attachHandler(repository, bodyStore, { handler });
    const parts = [
      { id: fill(71), body: Uint8Array.of(1, 2, 3) },
      { id: fill(72), body: Uint8Array.of(4, 5, 6, 7) },
    ];
    const uploadId = hex(
      (await decodeBody(await createUpload(fixture, parts, fill(73)))).get(1),
    );
    for (const [index, part] of parts.entries()) {
      const upload = await partRequest({
        uploadId,
        part,
        method: 'PUT',
        nonce: fill(74 + index),
      });
      assert.equal(
        (await fixture.route(upload.request, upload.path)).status,
        204,
      );
    }

    const commitPath = `/v2/deliveries/uploads/${uploadId}/commit`;
    const commitBody = encodeCbor(
      new Map([
        [1, fill(76)],
        [2, Uint8Array.of(9, 8, 7)],
        [
          3,
          new Map([
            [1, V2_NOW + 600],
            [2, 1],
            [3, 300],
            [4, 1],
          ]),
        ],
      ]),
    );
    const commitRequest = async (nonce) =>
      cborRequest(
        commitPath,
        commitBody,
        await authorization({
          method: 'POST',
          path: commitPath,
          digest: sha256(commitBody),
          nonce,
        }),
      );
    const committed = await fixture.route(
      await commitRequest(fill(77)),
      commitPath,
    );
    assert.equal(committed.status, 200, JSON.stringify(rejections));
    const deliveryId = hex((await decodeBody(committed)).get(1));
    if (repository.reopen) {
      fixture = attachHandler(await repository.reopen(), bodyStore, {
        handler,
      });
    }
    const retry = await fixture.route(
      await commitRequest(fill(78)),
      commitPath,
    );
    assert.equal(retry.status, 200);
    assert.equal((await decodeBody(retry)).get(2), true);

    const inboxResponse = await fixture.inbox({
      epoch: EPOCH,
      nonce: fill(80),
    });
    assert.equal(inboxResponse.status, 200, JSON.stringify(rejections));
    const inbox = decodeV2InboxResponseFrame(
      new Uint8Array(await inboxResponse.arrayBuffer()),
    );
    assert.equal(inbox.payload.byteLength, 0);
    assert.deepEqual(
      inbox.header.get(V2_INBOX_RESPONSE_KEYS.chunkManifest),
      parts.map(
        (part) =>
          new Map([
            [1, part.id],
            [2, part.body.byteLength],
            [3, sha256(part.body)],
          ]),
      ),
    );

    const partId = hex(parts[1].id);
    const downloadPath = `/v2/deliveries/${deliveryId}/chunks/${partId}`;
    const downloaded = await fixture.route(
      new Request(`${V2_ORIGIN}${downloadPath}`, {
        method: 'GET',
        headers: {
          'dud-authorization': await authorization({
            method: 'GET',
            path: downloadPath,
            digest: EMPTY_DIGEST,
            nonce: fill(79),
            tokenSecret: V2_TOKENS.read,
            scope: 'read',
          }),
        },
      }),
      downloadPath,
    );
    assert.equal(downloaded.status, 200);
    assert.deepEqual(
      new Uint8Array(await downloaded.arrayBuffer()),
      parts[1].body,
    );
    assert.equal(
      downloaded.headers.get('dud-content-sha256'),
      hex(sha256(parts[1].body)),
    );

    const wrongRelationshipToken = fill(90, 32);
    await registerCapability(
      repository,
      {
        id: `chunk-wrong-read-${name}`,
        scope: 'read',
        direction: 'inviter->invitee',
        tokenSecret: wrongRelationshipToken,
        relationshipId: `chunk-other-${name}`,
        expiresAt: V2_NOW + 7_200,
      },
      EPOCH,
    );
    const missingDeliveryPath = `/v2/deliveries/${'f'.repeat(32)}/chunks/${partId}`;
    const missingPartPath = `/v2/deliveries/${deliveryId}/chunks/${'e'.repeat(32)}`;
    const deniedRequest = async (path, auth) =>
      fixture.route(
        new Request(`${V2_ORIGIN}${path}`, {
          method: 'GET',
          ...(auth === undefined
            ? {}
            : { headers: { 'dud-authorization': auth } }),
        }),
        path,
      );
    const responseShape = async (response) => ({
      status: response.status,
      contentType: response.headers.get('content-type'),
      body: hex(new Uint8Array(await response.arrayBuffer())),
    });
    const deniedCases = [
      await deniedRequest(downloadPath),
      await deniedRequest(downloadPath, 'DUD2 !'),
      await deniedRequest(
        missingDeliveryPath,
        await authorization({
          method: 'GET',
          path: missingDeliveryPath,
          digest: EMPTY_DIGEST,
          nonce: fill(81),
          tokenSecret: V2_TOKENS.read,
          scope: 'read',
        }),
      ),
      await deniedRequest(
        downloadPath,
        await authorization({
          method: 'GET',
          path: downloadPath,
          digest: EMPTY_DIGEST,
          nonce: fill(82),
          tokenSecret: fill(91, 32),
          scope: 'read',
        }),
      ),
      await deniedRequest(
        downloadPath,
        await authorization({
          method: 'GET',
          path: downloadPath,
          digest: EMPTY_DIGEST,
          nonce: fill(83),
          tokenSecret: wrongRelationshipToken,
          scope: 'read',
        }),
      ),
      await deniedRequest(
        missingPartPath,
        await authorization({
          method: 'GET',
          path: missingPartPath,
          digest: EMPTY_DIGEST,
          nonce: fill(84),
          tokenSecret: fill(92, 32),
          scope: 'read',
        }),
      ),
    ];
    const deniedShape = await responseShape(deniedCases[0]);
    assert.equal(deniedShape.status, 401);
    for (const response of deniedCases.slice(1)) {
      assert.deepEqual(await responseShape(response), deniedShape);
    }
    assert.equal(
      (
        await deniedRequest(
          missingPartPath,
          await authorization({
            method: 'GET',
            path: missingPartPath,
            digest: EMPTY_DIGEST,
            nonce: fill(85),
            tokenSecret: V2_TOKENS.read,
            scope: 'read',
          }),
        )
      ).status,
      404,
    );

    const expiredBodyKeys = [];
    let maintenance;
    for (let attempt = 0; attempt < 10; attempt++) {
      maintenance = await fixture.repository.runMaintenance(V2_NOW + 601, 1);
      assert.ok(maintenance.expiredBodyKeys.length <= 1);
      expiredBodyKeys.push(...maintenance.expiredBodyKeys);
      if (maintenance.complete) {
        break;
      }
    }
    assert.equal(maintenance?.complete, true);
    assert.deepEqual(
      expiredBodyKeys.sort(),
      parts
        .map((part) => `deliveries/${deliveryId}/chunks/${hex(part.id)}.age`)
        .sort(),
    );
    assert.equal(await fixture.repository.findDelivery(deliveryId), null);
  });
}

test('a chunk upload rejects bytes that differ from its manifest', async (t) => {
  const repository = await V2_REPOSITORY_BACKENDS[0][1](t);
  await registerCapability(
    repository,
    {
      id: 'chunk-integrity',
      scope: 'write',
      direction: 'inviter->invitee',
      tokenSecret: V2_TOKENS.write,
      relationshipId: 'chunk-integrity',
      expiresAt: V2_NOW + 7_200,
    },
    EPOCH,
  );
  const fixture = attachHandler(repository, new MemoryV2BodyStore());
  const parts = [
    { id: fill(61), body: Uint8Array.of(1, 2, 3) },
    { id: fill(62), body: Uint8Array.of(4, 5, 6) },
  ];
  const uploadId = hex(
    (await decodeBody(await createUpload(fixture, parts))).get(1),
  );
  const changed = await partRequest({
    uploadId,
    part: parts[0],
    method: 'PUT',
    nonce: fill(63),
    body: Uint8Array.of(1, 2, 4),
  });
  assert.equal(
    (await fixture.route(changed.request, changed.path)).status,
    400,
  );
});

for (const [name, createRepository] of V2_REPOSITORY_BACKENDS) {
  test(`${name} rejects replayed and rate-limited part writes before body storage`, async (t) => {
    const runRejectedWrite = async ({ rateLimited }) => {
      const repository = await createRepository(t);
      await registerCapability(
        repository,
        {
          id: `chunk-admission-${name}-${rateLimited}`,
          scope: 'write',
          direction: 'inviter->invitee',
          tokenSecret: V2_TOKENS.write,
          relationshipId: `chunk-admission-${name}-${rateLimited}`,
          expiresAt: V2_NOW + 7_200,
        },
        EPOCH,
      );
      const bodyStore = new MemoryV2BodyStore();
      let stageCalls = 0;
      const stagePart = bodyStore.stagePart.bind(bodyStore);
      bodyStore.stagePart = async (...args) => {
        stageCalls++;
        return stagePart(...args);
      };
      const fixture = attachHandler(repository, bodyStore, {
        handler: rateLimited ? { maximumRequestsPerMinute: 1 } : {},
      });
      const part = { id: fill(91), body: Uint8Array.of(7, 8, 9) };
      const otherPart = { id: fill(90), body: Uint8Array.of(10) };
      const creationNonce = fill(rateLimited ? 92 : 93);
      const created = await createUpload(
        fixture,
        [part, otherPart],
        creationNonce,
      );
      assert.equal(created.status, 201);
      const uploadId = hex((await decodeBody(created)).get(1));
      const put = await partRequest({
        uploadId,
        part,
        method: 'PUT',
        nonce: rateLimited ? fill(94) : creationNonce,
      });
      assert.ok((await fixture.route(put.request, put.path)).status >= 400);
      assert.equal(stageCalls, 0);
      assert.equal(
        await bodyStore.head(`staging/uploads/${uploadId}/${hex(part.id)}.age`),
        false,
      );
    };

    await runRejectedWrite({ rateLimited: false });
    await runRejectedWrite({ rateLimited: true });
  });
}

for (const [name, createBodyStore] of productionBodyStores) {
  test(`${name} compensates a part body when metadata completion fails`, async (t) => {
    const repository = new MemoryV2Repository();
    await registerCapability(
      repository,
      {
        id: `chunk-compensation-${name}`,
        scope: 'write',
        direction: 'inviter->invitee',
        tokenSecret: V2_TOKENS.write,
        relationshipId: `chunk-compensation-${name}`,
        expiresAt: V2_NOW + 7_200,
      },
      EPOCH,
    );
    const bodyStore = await createBodyStore(t);
    const failingRepository = new Proxy(repository, {
      get(target, property) {
        if (property === 'completeChunkUploadPart') {
          return async () => {
            throw new Error('injected metadata completion failure');
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const fixture = attachHandler(failingRepository, bodyStore);
    const part = { id: fill(95), body: Uint8Array.of(1, 3, 5, 7) };
    const otherPart = { id: fill(94), body: Uint8Array.of(9) };
    const created = await createUpload(fixture, [part, otherPart], fill(96));
    assert.equal(created.status, 201);
    const uploadId = hex((await decodeBody(created)).get(1));
    const put = await partRequest({
      uploadId,
      part,
      method: 'PUT',
      nonce: fill(97),
    });
    assert.ok((await fixture.route(put.request, put.path)).status >= 400);
    assert.equal(
      await bodyStore.head(`staging/uploads/${uploadId}/${hex(part.id)}.age`),
      false,
    );
    const replay = await partRequest({
      uploadId,
      part,
      method: 'PUT',
      nonce: fill(97),
    });
    assert.ok((await fixture.route(replay.request, replay.path)).status >= 400);
  });
}

test('an ambiguous completed part write preserves the accepted body', async () => {
  const repository = new MemoryV2Repository();
  await registerCapability(
    repository,
    {
      id: 'chunk-ambiguous-completion',
      scope: 'write',
      direction: 'inviter->invitee',
      tokenSecret: V2_TOKENS.write,
      relationshipId: 'chunk-ambiguous-completion',
      expiresAt: V2_NOW + 7_200,
    },
    EPOCH,
  );
  const bodyStore = new MemoryV2BodyStore();
  let stageCalls = 0;
  const stagePart = bodyStore.stagePart.bind(bodyStore);
  bodyStore.stagePart = async (...args) => {
    stageCalls++;
    return stagePart(...args);
  };
  const ambiguousRepository = new Proxy(repository, {
    get(target, property) {
      if (property === 'completeChunkUploadPart') {
        return async (input) => {
          await target.completeChunkUploadPart(input);
          throw new Error('injected lost metadata response');
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const fixture = attachHandler(ambiguousRepository, bodyStore);
  const part = { id: fill(98), body: Uint8Array.of(2, 4, 6, 8) };
  const otherPart = { id: fill(99), body: Uint8Array.of(10) };
  const created = await createUpload(fixture, [part, otherPart], fill(100));
  assert.equal(created.status, 201);
  const uploadId = hex((await decodeBody(created)).get(1));
  const first = await partRequest({
    uploadId,
    part,
    method: 'PUT',
    nonce: fill(101),
  });
  assert.ok((await fixture.route(first.request, first.path)).status >= 400);
  const stagedKey = `staging/uploads/${uploadId}/${hex(part.id)}.age`;
  assert.equal(await bodyStore.head(stagedKey), true);

  const retry = await partRequest({
    uploadId,
    part,
    method: 'PUT',
    nonce: fill(102),
  });
  assert.equal((await fixture.route(retry.request, retry.path)).status, 204);
  assert.equal(stageCalls, 2);
  assert.equal(await bodyStore.head(stagedKey), true);
});

test('maintenance racing a slow part write leaves no staged body', async () => {
  const repository = new MemoryV2Repository();
  await registerCapability(
    repository,
    {
      id: 'chunk-maintenance-race',
      scope: 'write',
      direction: 'inviter->invitee',
      tokenSecret: V2_TOKENS.write,
      relationshipId: 'chunk-maintenance-race',
      expiresAt: V2_NOW + 7_200,
    },
    EPOCH,
  );
  const bodyStore = new MemoryV2BodyStore();
  const stagePart = bodyStore.stagePart.bind(bodyStore);
  let signalStarted;
  const started = new Promise((resolve) => {
    signalStarted = resolve;
  });
  let releaseStage;
  const stageReleased = new Promise((resolve) => {
    releaseStage = resolve;
  });
  bodyStore.stagePart = async (...args) => {
    signalStarted();
    await stageReleased;
    return stagePart(...args);
  };
  const fixture = attachHandler(repository, bodyStore);
  const part = { id: fill(103), body: Uint8Array.of(11, 12, 13) };
  const otherPart = { id: fill(104), body: Uint8Array.of(14) };
  const created = await createUpload(fixture, [part, otherPart], fill(105));
  assert.equal(created.status, 201);
  const createdBody = await decodeBody(created);
  const uploadId = hex(createdBody.get(1));
  const expiresAt = createdBody.get(2);
  const put = await partRequest({
    uploadId,
    part,
    method: 'PUT',
    nonce: fill(106),
  });
  const response = fixture.route(put.request, put.path);
  await started;

  fixture.setNow(expiresAt);
  let maintenance;
  do {
    maintenance = await repository.runMaintenance(expiresAt, 10);
    await Promise.all(
      maintenance.expiredBodyKeys.map((key) => bodyStore.delete(key)),
    );
  } while (!maintenance.complete);

  releaseStage();
  assert.ok((await response).status >= 400);
  assert.equal(
    await bodyStore.head(`staging/uploads/${uploadId}/${hex(part.id)}.age`),
    false,
  );
});
