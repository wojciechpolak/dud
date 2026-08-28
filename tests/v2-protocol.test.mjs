// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeCbor, encodeCbor } from '../dist/src/cbor.js';
import {
  buildV2DeliveryProof,
  deriveV2DailyCapabilityLookupId,
  hexToBytes,
  parseV2DeliveryProof,
  verifyV2DeliveryProof,
} from '../dist/src/v2-auth.js';
import { sha256 } from '../dist/src/sha256.js';
import {
  readV2FramedDeliveryRequest,
  readV2RequestBytes,
  V2_CBOR_CONTENT_TYPE,
  V2_CONTENT_SHA256_HEADER,
} from '../dist/src/v2-http.js';
import {
  decodeV2InboxRequest,
  decodeV2InboxResponseFrame,
  decodeV2DeliveryRequestFrame,
  encodeV2DeliveryFrame,
  v2DeliveryFrameAuthorizationDigest,
  v2InboxRequestAuthorizationDigest,
  V2_INBOX_REQUEST_KEYS,
  V2_INBOX_RESPONSE_KEYS,
  V2_DELIVERY_REQUEST_KEYS,
  V2_SLOT_PROOF_KEYS,
} from '../dist/src/v2-delivery-frame.js';
import {
  hasRequiredV2Features,
  V2_ENDPOINT,
  V2_ERROR,
  V2_ERROR_HTTP_STATUS,
  V2_REQUIRED_GIT_FEATURES,
  V2_REQUIRED_PEER_FEATURES,
  V2_SERVER_FEATURES,
  v2CompletionEndpoint,
} from '../dist/src/v2-contract.js';

function hex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

function slotProof(seed, epoch = 20_000, chain = 0) {
  return new Map([
    [
      V2_SLOT_PROOF_KEYS.slot,
      Uint8Array.from({ length: 16 }, (_, index) => seed + index),
    ],
    [V2_SLOT_PROOF_KEYS.epoch, epoch],
    [V2_SLOT_PROOF_KEYS.chain, chain],
    [V2_SLOT_PROOF_KEYS.proof, Uint8Array.of(seed)],
  ]);
}

test('deterministic CBOR matches the frozen capability-discovery vector', () => {
  const value = new Map([
    [1, [1, 2]],
    [2, [2, 3, 5, 6, 9, 10, 11]],
    [
      3,
      new Map([
        [1, 104857600],
        [2, 262144],
        [3, 2592000],
        [4, 64],
        [5, 256],
        [6, 4],
        [7, 60],
        [8, 209715200],
        [9, 4096],
      ]),
    ],
    [
      4,
      new Map([
        [1, 2],
        [2, 1],
      ]),
    ],
  ]);
  assert.equal(
    hex(encodeCbor(value)),
    'a401820102028702030506090a0b03a9011a06400000021a00040000031a00278d0004184005190100060407183c081a0c8000000919100004a201020201',
  );
});

test('strict CBOR rejects duplicates, indefinite lengths, and non-minimal integers', () => {
  assert.throws(
    () => decodeCbor(Uint8Array.of(0xa2, 0x01, 0x02, 0x01, 0x03)),
    /duplicate/,
  );
  assert.throws(
    () => decodeCbor(Uint8Array.of(0xbf, 0x01, 0x02, 0xff)),
    /Indefinite/,
  );
  assert.throws(() => decodeCbor(Uint8Array.of(0x18, 0x01)), /minimally/);
});

test('V2 request reader preserves bounded canonical body bytes', async () => {
  const bytes = encodeCbor(new Map([[1, 2]]));
  const request = new Request('https://dud.example.com/v2/inbox', {
    method: 'POST',
    headers: {
      'content-type': V2_CBOR_CONTENT_TYPE,
      'content-length': String(bytes.byteLength),
    },
    body: bytes,
  });
  assert.deepEqual(await readV2RequestBytes(request, 16), bytes);
});

test('framed delivery reader streams a content-addressed payload', async () => {
  const payload = Uint8Array.of(7, 8, 9);
  const slot = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
  const proof = await buildV2DeliveryProof({
    tokenSecret: new Uint8Array(32),
    capabilityLookupId: new Uint8Array(16),
    direction: 'inviter->invitee',
    scope: 'write',
    chain: 0,
    slot,
    slotEpoch: 20_000,
    method: 'POST',
    canonicalOrigin: 'https://dud.example.com',
    normalizedPath: '/v2/deliveries',
    operationIndex: 0,
    requestDigest: new Uint8Array(32),
    nonce: Uint8Array.from({ length: 16 }, (_, index) => index + 17),
    expiresAt: 1_800_000_000,
  });
  const header = new Map([
    [V2_DELIVERY_REQUEST_KEYS.operationId, new Uint8Array(16)],
    [V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor, Uint8Array.of(1)],
    [V2_DELIVERY_REQUEST_KEYS.requestedPolicy, new Map([[1, 1]])],
    [V2_DELIVERY_REQUEST_KEYS.payloadLength, payload.byteLength],
    [V2_DELIVERY_REQUEST_KEYS.payloadDigest, sha256(payload)],
    [
      V2_DELIVERY_REQUEST_KEYS.dataSlotProof,
      new Map([
        [V2_SLOT_PROOF_KEYS.slot, slot],
        [V2_SLOT_PROOF_KEYS.epoch, 20_000],
        [V2_SLOT_PROOF_KEYS.chain, 0],
        [V2_SLOT_PROOF_KEYS.proof, proof],
      ]),
    ],
  ]);
  const frame = encodeV2DeliveryFrame(
    header,
    payload,
    V2_DELIVERY_REQUEST_KEYS.payloadLength,
    V2_DELIVERY_REQUEST_KEYS.payloadDigest,
  );
  const request = new Request('https://dud.example.com/v2/deliveries', {
    method: 'POST',
    headers: {
      'content-type': V2_CBOR_CONTENT_TYPE,
      'content-length': String(frame.byteLength),
      [V2_CONTENT_SHA256_HEADER]: hex(sha256(frame)),
    },
    body: frame,
  });
  const delivery = await readV2FramedDeliveryRequest(request);
  assert.deepEqual(
    new Uint8Array(await new Response(delivery.payload).arrayBuffer()),
    payload,
  );
  await delivery.verified;
  assert.deepEqual(
    await delivery.authorizationDigest,
    v2DeliveryFrameAuthorizationDigest(frame),
  );

  const emptyPayload = new Uint8Array();
  const emptyHeader = new Map(header);
  emptyHeader.set(V2_DELIVERY_REQUEST_KEYS.payloadLength, 0);
  emptyHeader.set(V2_DELIVERY_REQUEST_KEYS.payloadDigest, sha256(emptyPayload));
  const emptyFrame = encodeV2DeliveryFrame(
    emptyHeader,
    emptyPayload,
    V2_DELIVERY_REQUEST_KEYS.payloadLength,
    V2_DELIVERY_REQUEST_KEYS.payloadDigest,
  );
  const emptyDelivery = await readV2FramedDeliveryRequest(
    new Request('https://dud.example.com/v2/deliveries', {
      method: 'POST',
      headers: {
        'content-type': V2_CBOR_CONTENT_TYPE,
        'content-length': String(emptyFrame.byteLength),
        [V2_CONTENT_SHA256_HEADER]: hex(sha256(emptyFrame)),
      },
      body: emptyFrame,
    }),
  );
  assert.equal(
    (await new Response(emptyDelivery.payload).arrayBuffer()).byteLength,
    0,
  );
  await emptyDelivery.verified;
  assert.deepEqual(
    await emptyDelivery.authorizationDigest,
    v2DeliveryFrameAuthorizationDigest(emptyFrame),
  );

  const wrongLength = new Request('https://dud.example.com/v2/deliveries', {
    method: 'POST',
    headers: {
      'content-type': V2_CBOR_CONTENT_TYPE,
      'content-length': String(frame.byteLength - 1),
      [V2_CONTENT_SHA256_HEADER]: hex(sha256(frame)),
    },
    body: frame,
  });
  await assert.rejects(
    () => readV2FramedDeliveryRequest(wrongLength),
    /Content-Length/,
  );

  const wrongDigest = new Request('https://dud.example.com/v2/deliveries', {
    method: 'POST',
    headers: {
      'content-type': V2_CBOR_CONTENT_TYPE,
      'content-length': String(frame.byteLength),
      [V2_CONTENT_SHA256_HEADER]: '00'.repeat(32),
    },
    body: frame,
  });
  const invalidDelivery = await readV2FramedDeliveryRequest(wrongDigest);
  const verification = assert.rejects(
    invalidDelivery.verified,
    /DUD-Content-SHA256/,
  );
  const authorization = assert.rejects(
    invalidDelivery.authorizationDigest,
    /DUD-Content-SHA256/,
  );
  await assert.rejects(
    () => new Response(invalidDelivery.payload).arrayBuffer(),
    /DUD-Content-SHA256/,
  );
  await verification;
  await authorization;

  // A lowered descriptor limit has to lower what the server will read, not
  // only what it rejects once read: otherwise an operator who tightens the
  // limit still lets a hostile caller stream a protocol-maximum header before
  // the descriptor itself is refused.
  const wideHeader = new Map(header);
  wideHeader.set(
    V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor,
    new Uint8Array(32 * 1024).fill(7),
  );
  const wideFrame = encodeV2DeliveryFrame(
    wideHeader,
    payload,
    V2_DELIVERY_REQUEST_KEYS.payloadLength,
    V2_DELIVERY_REQUEST_KEYS.payloadDigest,
  );
  const wideRequest = () =>
    new Request('https://dud.example.com/v2/deliveries', {
      method: 'POST',
      headers: {
        'content-type': V2_CBOR_CONTENT_TYPE,
        'content-length': String(wideFrame.byteLength),
        [V2_CONTENT_SHA256_HEADER]: hex(sha256(wideFrame)),
      },
      body: wideFrame,
    });
  await assert.rejects(
    () => readV2FramedDeliveryRequest(wideRequest(), 1024),
    /header length is invalid/,
  );
  // The same frame still reads under a limit with room for its descriptor, so
  // the ceiling tracks the configured value rather than refusing everything.
  const wideDelivery = await readV2FramedDeliveryRequest(
    wideRequest(),
    32 * 1024,
  );
  await wideDelivery.verified;
});

test('v2 capability and error registries are frozen', () => {
  assert.deepEqual(V2_SERVER_FEATURES, [2, 3, 5, 6, 9, 10, 11]);
  assert.deepEqual(V2_REQUIRED_PEER_FEATURES, [2, 3, 9, 10, 11]);
  assert.deepEqual(V2_REQUIRED_GIT_FEATURES, [2, 3, 9, 10, 11, 5]);
  assert.equal(V2_SERVER_FEATURES.includes(6), true);
  assert.equal(hasRequiredV2Features(V2_SERVER_FEATURES), true);
  assert.equal(hasRequiredV2Features([2, 3, 5, 9, 10]), false);
  assert.equal(V2_ERROR_HTTP_STATUS[V2_ERROR.unsupportedContract], 409);
  assert.equal(V2_ENDPOINT.inbox, '/v2/inbox');
  assert.equal(
    v2CompletionEndpoint('0123456789abcdef0123456789abcdef'),
    '/v2/deliveries/0123456789abcdef0123456789abcdef/complete',
  );
  assert.throws(() => v2CompletionEndpoint('invalid'), /invalid/);
});

test('streaming SHA-256 matches a known digest', () => {
  assert.equal(
    hex(sha256(new TextEncoder().encode('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});

test('daily capability lookup and compound delivery proof match frozen vector', async () => {
  const tokenSecret = hexToBytes(
    'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
  );
  const lookupId = await deriveV2DailyCapabilityLookupId(tokenSecret, 20340);
  assert.equal(hex(lookupId), '6622cf3ddfd3fce5a08e765e19a64b8f');
  const proof = await buildV2DeliveryProof({
    tokenSecret,
    capabilityLookupId: lookupId,
    direction: 'inviter->invitee',
    scope: 'write',
    chain: 1,
    slot: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
    slotEpoch: 20340,
    method: 'POST',
    canonicalOrigin: 'https://dud.example.com',
    normalizedPath: '/v2/deliveries',
    operationIndex: 0,
    requestDigest: sha256(new TextEncoder().encode('complete framed request')),
    nonce: hexToBytes('b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'),
    expiresAt: 1757379600,
  });
  assert.equal(
    hex(proof),
    'a501506622cf3ddfd3fce5a08e765e19a64b8f0250b0b1b2b3b4b5b6b7b8b9babbbcbdbebf031a68bf7c100400055820cfcbb0ce9daa0a2031c169c82066773bc8d8b41815e43ef1e5203b7dfbac4fb2',
  );
  assert.deepEqual(parseV2DeliveryProof(proof).capabilityLookupId, lookupId);
  assert.equal(
    (
      await verifyV2DeliveryProof({
        tokenSecret,
        capabilityLookupId: lookupId,
        direction: 'inviter->invitee',
        scope: 'write',
        chain: 1,
        slot: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
        slotEpoch: 20340,
        method: 'POST',
        canonicalOrigin: 'https://dud.example.com',
        normalizedPath: '/v2/deliveries',
        requestDigest: sha256(
          new TextEncoder().encode('complete framed request'),
        ),
        proof,
      })
    )?.operationIndex,
    0,
  );
  assert.equal(
    await verifyV2DeliveryProof({
      tokenSecret,
      capabilityLookupId: lookupId,
      direction: 'inviter->invitee',
      scope: 'write',
      chain: 1,
      slot: hexToBytes('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
      slotEpoch: 20340,
      method: 'POST',
      canonicalOrigin: 'https://dud.example.com',
      normalizedPath: '/v2/inbox',
      requestDigest: sha256(
        new TextEncoder().encode('complete framed request'),
      ),
      proof,
    }),
    null,
  );
  assert.throws(
    () => parseV2DeliveryProof(proof.subarray(0, proof.length - 1)),
    /truncated/,
  );
});

test('delivery frame matches the frozen request vector and validates its body', () => {
  const payload = new TextEncoder().encode('opaque payload');
  const header = new Map([
    [
      V2_DELIVERY_REQUEST_KEYS.operationId,
      Uint8Array.from({ length: 16 }, (_, index) => 0x10 + index),
    ],
    [
      V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor,
      Uint8Array.of(0xa1, 0x01, 0x02),
    ],
    [
      V2_DELIVERY_REQUEST_KEYS.requestedPolicy,
      new Map([
        [1, 1800003600],
        [2, 1],
        [3, 0],
        [4, 1],
      ]),
    ],
    [V2_DELIVERY_REQUEST_KEYS.payloadLength, payload.byteLength],
    [V2_DELIVERY_REQUEST_KEYS.payloadDigest, sha256(payload)],
    [V2_DELIVERY_REQUEST_KEYS.dataSlotProof, slotProof(1, 20833, 1)],
    [V2_DELIVERY_REQUEST_KEYS.controlQueries, [slotProof(4, 20832, 2)]],
    [
      V2_DELIVERY_REQUEST_KEYS.processedControlEventIds,
      [Uint8Array.from({ length: 16 }, (_, index) => 0x80 + index)],
    ],
  ]);
  const frame = encodeV2DeliveryFrame(
    header,
    payload,
    V2_DELIVERY_REQUEST_KEYS.payloadLength,
    V2_DELIVERY_REQUEST_KEYS.payloadDigest,
  );
  assert.equal(
    hex(frame),
    '4455443200000099a80150101112131415161718191a1b1c1d1e1f0243a1010203a4011a6b49e010020103000401040e055820e9ee93bb8b1d9525b1a67ba844b50e8300dcf9f139810b1cc2bc0349211813be06a401500102030405060708090a0b0c0d0e0f100219516103010441010781a401500405060708090a0b0c0d0e0f10111213021951600302044104088150808182838485868788898a8b8c8d8e8f6f7061717565207061796c6f6164',
  );
  const decoded = decodeV2DeliveryRequestFrame(frame);
  assert.deepEqual(decoded.payload, payload);
  assert.deepEqual(decoded.header, header);
});

test('delivery frame rejects malformed framing before publication', () => {
  const payload = Uint8Array.of(1, 2, 3);
  const header = new Map([
    [V2_DELIVERY_REQUEST_KEYS.operationId, new Uint8Array(16)],
    [V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor, Uint8Array.of(1)],
    [V2_DELIVERY_REQUEST_KEYS.requestedPolicy, new Map([[1, 1]])],
    [V2_DELIVERY_REQUEST_KEYS.payloadLength, payload.byteLength],
    [V2_DELIVERY_REQUEST_KEYS.payloadDigest, sha256(payload)],
    [V2_DELIVERY_REQUEST_KEYS.dataSlotProof, slotProof(1)],
  ]);
  const frame = encodeV2DeliveryFrame(
    header,
    payload,
    V2_DELIVERY_REQUEST_KEYS.payloadLength,
    V2_DELIVERY_REQUEST_KEYS.payloadDigest,
  );
  const badMagic = Uint8Array.from(frame);
  badMagic[0] = 0;
  assert.throws(() => decodeV2DeliveryRequestFrame(badMagic), /magic/);
  assert.throws(
    () => decodeV2DeliveryRequestFrame(frame.subarray(0, 7)),
    /prefix/,
  );
  const badLength = Uint8Array.from(frame);
  new DataView(badLength.buffer).setUint32(4, 0, false);
  assert.throws(() => decodeV2DeliveryRequestFrame(badLength), /length/);
  const badPayload = Uint8Array.from(frame);
  badPayload[badPayload.length - 1] ^= 1;
  assert.throws(() => decodeV2DeliveryRequestFrame(badPayload), /digest/);
  const nonDeterministic = Uint8Array.from(frame);
  nonDeterministic[8] = 0xb8;
  assert.throws(
    () => decodeV2DeliveryRequestFrame(nonDeterministic),
    /minimally|truncated|deterministic/,
  );
  const unknownRequiredField = new Map(header);
  unknownRequiredField.set(99, 1);
  assert.throws(
    () =>
      decodeV2DeliveryRequestFrame(
        encodeV2DeliveryFrame(
          unknownRequiredField,
          payload,
          V2_DELIVERY_REQUEST_KEYS.payloadLength,
          V2_DELIVERY_REQUEST_KEYS.payloadDigest,
        ),
      ),
    /unknown/,
  );
  assert.throws(
    () => decodeV2DeliveryRequestFrame(frame.subarray(0, -1)),
    /length/,
  );
});

test('inbox response frame validates batches and an optional encrypted delivery', () => {
  const payload = Uint8Array.of(1, 2, 3);
  const header = new Map([
    [
      V2_INBOX_RESPONSE_KEYS.slotResults,
      [
        new Map([
          [1, 20_000],
          [2, true],
        ]),
      ],
    ],
    [V2_INBOX_RESPONSE_KEYS.controlEvents, [new Map([[1, Uint8Array.of(4)]])]],
    [V2_INBOX_RESPONSE_KEYS.deliveryId, new Uint8Array(16)],
    [
      V2_INBOX_RESPONSE_KEYS.slot,
      Uint8Array.from({ length: 16 }, (_, index) => index),
    ],
    [V2_INBOX_RESPONSE_KEYS.encryptedDescriptor, Uint8Array.of(5)],
    [V2_INBOX_RESPONSE_KEYS.effectivePolicy, new Map([[1, 1]])],
    [V2_INBOX_RESPONSE_KEYS.payloadLength, payload.byteLength],
    [V2_INBOX_RESPONSE_KEYS.payloadDigest, sha256(payload)],
  ]);
  assert.deepEqual(
    decodeV2InboxResponseFrame(
      encodeV2DeliveryFrame(
        header,
        payload,
        V2_INBOX_RESPONSE_KEYS.payloadLength,
        V2_INBOX_RESPONSE_KEYS.payloadDigest,
      ),
    ).header,
    header,
  );

  const noDelivery = new Map([
    [V2_INBOX_RESPONSE_KEYS.slotResults, []],
    [V2_INBOX_RESPONSE_KEYS.controlEvents, []],
    [V2_INBOX_RESPONSE_KEYS.payloadLength, 0],
    [V2_INBOX_RESPONSE_KEYS.payloadDigest, sha256(new Uint8Array())],
  ]);
  assert.doesNotThrow(() =>
    decodeV2InboxResponseFrame(
      encodeV2DeliveryFrame(
        noDelivery,
        new Uint8Array(),
        V2_INBOX_RESPONSE_KEYS.payloadLength,
        V2_INBOX_RESPONSE_KEYS.payloadDigest,
      ),
    ),
  );
  const invalid = new Map(noDelivery);
  invalid.set(V2_INBOX_RESPONSE_KEYS.slot, new Uint8Array(16));
  assert.throws(
    () =>
      decodeV2InboxResponseFrame(
        encodeV2DeliveryFrame(
          invalid,
          new Uint8Array(),
          V2_INBOX_RESPONSE_KEYS.payloadLength,
          V2_INBOX_RESPONSE_KEYS.payloadDigest,
        ),
      ),
    /without a delivery ID/,
  );
});

test('inbox request body requires a bounded deterministic proof batch', () => {
  const request = new Map([
    [V2_INBOX_REQUEST_KEYS.dataSlotProofs, [slotProof(1)]],
    [V2_INBOX_REQUEST_KEYS.controlSlotProofs, [slotProof(2)]],
    [
      V2_INBOX_REQUEST_KEYS.processedControlEventIds,
      [Uint8Array.from({ length: 16 }, (_, index) => index)],
    ],
  ]);
  assert.deepEqual(decodeV2InboxRequest(encodeCbor(request)).header, request);
  assert.throws(
    () => decodeV2InboxRequest(encodeCbor(new Map())),
    /missing required key/,
  );
  assert.throws(
    () =>
      decodeV2InboxRequest(
        encodeCbor(
          new Map([
            [
              V2_INBOX_REQUEST_KEYS.dataSlotProofs,
              Array.from({ length: 32 }, () => slotProof(1)),
            ],
          ]),
        ),
      ),
    /configured limit|invalid/,
  );
});

test('authorization digests redact proof MACs without changing the signed request', async () => {
  const tokenSecret = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const lookupId = Uint8Array.from({ length: 16 }, (_, index) => index + 33);
  const slot = Uint8Array.from({ length: 16 }, (_, index) => index + 49);
  const base = {
    tokenSecret,
    capabilityLookupId: lookupId,
    direction: 'inviter->invitee',
    scope: 'read',
    chain: 3,
    slot,
    slotEpoch: 20_000,
    method: 'POST',
    canonicalOrigin: 'https://dud.example.com',
    normalizedPath: '/v2/inbox',
    operationIndex: 0,
    nonce: Uint8Array.from({ length: 16 }, (_, index) => index + 65),
    expiresAt: 1_728_000_000,
  };
  const templateProof = await buildV2DeliveryProof({
    ...base,
    requestDigest: new Uint8Array(32),
  });
  const query = new Map([
    [
      V2_INBOX_REQUEST_KEYS.dataSlotProofs,
      [
        new Map([
          [V2_SLOT_PROOF_KEYS.slot, slot],
          [V2_SLOT_PROOF_KEYS.epoch, 20_000],
          [V2_SLOT_PROOF_KEYS.chain, 3],
          [V2_SLOT_PROOF_KEYS.proof, templateProof],
        ]),
      ],
    ],
  ]);
  const digest = v2InboxRequestAuthorizationDigest(encodeCbor(query));
  const signedProof = await buildV2DeliveryProof({
    ...base,
    requestDigest: digest,
  });
  query.set(V2_INBOX_REQUEST_KEYS.dataSlotProofs, [
    new Map([
      [V2_SLOT_PROOF_KEYS.slot, slot],
      [V2_SLOT_PROOF_KEYS.epoch, 20_000],
      [V2_SLOT_PROOF_KEYS.chain, 3],
      [V2_SLOT_PROOF_KEYS.proof, signedProof],
    ]),
  ]);
  assert.deepEqual(
    v2InboxRequestAuthorizationDigest(encodeCbor(query)),
    digest,
  );

  const payload = Uint8Array.of(1);
  const deliveryTemplate = new Map([
    [V2_DELIVERY_REQUEST_KEYS.operationId, new Uint8Array(16)],
    [V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor, Uint8Array.of(2)],
    [V2_DELIVERY_REQUEST_KEYS.requestedPolicy, new Map([[1, 1]])],
    [V2_DELIVERY_REQUEST_KEYS.payloadLength, 1],
    [V2_DELIVERY_REQUEST_KEYS.payloadDigest, sha256(payload)],
    [
      V2_DELIVERY_REQUEST_KEYS.dataSlotProof,
      new Map([
        [V2_SLOT_PROOF_KEYS.slot, slot],
        [V2_SLOT_PROOF_KEYS.epoch, 20_000],
        [V2_SLOT_PROOF_KEYS.chain, 3],
        [V2_SLOT_PROOF_KEYS.proof, templateProof],
      ]),
    ],
  ]);
  const deliveryDigest = v2DeliveryFrameAuthorizationDigest(
    encodeV2DeliveryFrame(
      deliveryTemplate,
      payload,
      V2_DELIVERY_REQUEST_KEYS.payloadLength,
      V2_DELIVERY_REQUEST_KEYS.payloadDigest,
    ),
  );
  assert.equal(deliveryDigest.byteLength, 32);
});
