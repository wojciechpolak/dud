// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Shared scaffolding for the granular delivery handler: capability
// registration, the four authenticated request builders, and a repository
// fixture that runs the same scenario against Memory, SQLite and D1.

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  buildV2DeliveryProof,
  deriveV2DailyCapabilityLookupId,
  encryptV2TokenSecret,
} from '../dist/src/v2-auth.js';
import { decodeCbor, encodeCbor } from '../dist/src/cbor.js';
import {
  encodeV2DeliveryFrame,
  v2CompletionRequestAuthorizationDigest,
  v2ControlEventRequestAuthorizationDigest,
  v2DeliveryFrameAuthorizationDigest,
  v2InboxRequestAuthorizationDigest,
  V2_COMPLETION_REQUEST_KEYS,
  V2_CONTROL_EVENT_REQUEST_KEYS,
  V2_DELIVERY_REQUEST_KEYS,
  V2_INBOX_REQUEST_KEYS,
  V2_SLOT_PROOF_KEYS,
} from '../dist/src/v2-delivery-frame.js';
import { createV2DeliveryHandler } from '../dist/src/v2-delivery-service.js';
import { D1V2Repository } from '../dist/src/v2-d1-repository.js';
import {
  MemoryV2BodyStore,
  MemoryV2Repository,
} from '../dist/src/v2-memory-repository.js';
import { sha256 } from '../dist/src/sha256.js';
import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import {
  V2_CBOR_CONTENT_TYPE,
  V2_CONTENT_SHA256_HEADER,
} from '../dist/src/v2-http.js';
import { createMigratedLocalD1, LocalD1Database } from './d1-local.mjs';

// Workers expose FixedLengthStream; Node does not, and the handler only uses it
// to declare a length it already enforces.
globalThis.FixedLengthStream ??= class FixedLengthStream extends (
  TransformStream
) {
  constructor() {
    super();
  }
};

export const V2_ORIGIN = 'https://dud.example.com';
export const V2_NOW = 1_800_000_000;
export const V2_EPOCH = 20_000;
export const V2_DEPLOYMENT_KEY = Uint8Array.from(
  { length: 32 },
  (_, index) => index + 33,
);
export const V2_DATA_SLOT = Uint8Array.from(
  { length: 16 },
  (_, index) => index + 65,
);
export const V2_CONTROL_SLOT = Uint8Array.from(V2_DATA_SLOT, (b) => b + 1);
export const V2_TARGET_SLOT = Uint8Array.from(V2_DATA_SLOT, (b) => b + 2);

export const V2_TOKENS = {
  write: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
  read: Uint8Array.from({ length: 32 }, (_, index) => index + 101),
  ack: Uint8Array.from({ length: 32 }, (_, index) => index + 151),
  controlWrite: Uint8Array.from({ length: 32 }, (_, index) => index + 201),
  // The reverse-direction read the peer uses to drain its own control slot.
  peerRead: Uint8Array.from({ length: 32 }, (_, index) => index + 51),
};

export function hex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

export function fill(byte, length = 16) {
  return new Uint8Array(length).fill(byte);
}

/** The requested transport policy a well-behaved sender signs. */
export function requestedPolicy(expiresAt = V2_NOW + 60) {
  return new Map([
    [1, expiresAt],
    [2, 1],
    [3, 300],
    [4, 1],
  ]);
}

/**
 * SHA-256 of the deterministic descriptor map a real receiver decrypts, which
 * is what protocol §7.2 calls the descriptor digest. The server only ever sees
 * the ciphertext, so this value is deliberately unrelated to it.
 */
export const V2_SIGNED_DESCRIPTOR_DIGEST = sha256(
  encodeCbor(
    new Map([
      [1, fill(3)],
      [2, 1],
      [3, V2_ORIGIN],
    ]),
  ),
);

export function decodeBody(response) {
  return response
    .arrayBuffer()
    .then((buffer) => decodeCbor(new Uint8Array(buffer)));
}

function cborRequest(path, body) {
  return new Request(`${V2_ORIGIN}${path}`, {
    method: 'POST',
    headers: {
      'content-type': V2_CBOR_CONTENT_TYPE,
      'content-length': String(body.byteLength),
    },
    body,
  });
}

function slotProof(slot, epoch, chain, proof) {
  return new Map([
    [V2_SLOT_PROOF_KEYS.slot, slot],
    [V2_SLOT_PROOF_KEYS.epoch, epoch],
    [V2_SLOT_PROOF_KEYS.chain, chain],
    [V2_SLOT_PROOF_KEYS.proof, proof],
  ]);
}

/**
 * Builds the request twice: once with zeroed proof MACs to obtain the digest
 * the MACs must commit to, then again with the real proofs. This mirrors what
 * the Go client does and is the only way to sign a request that contains its
 * own signature.
 */
async function withSignedProofs(inputs, assemble, digestOf) {
  const templates = await Promise.all(
    inputs.map((input) =>
      buildV2DeliveryProof({ ...input, requestDigest: new Uint8Array(32) }),
    ),
  );
  const digest = digestOf(assemble(templates));
  const proofs = await Promise.all(
    inputs.map((input) =>
      buildV2DeliveryProof({ ...input, requestDigest: digest }),
    ),
  );
  return assemble(proofs);
}

function proofInput({
  tokenSecret,
  lookup,
  direction = 'inviter->invitee',
  scope,
  chain = 0,
  slot,
  epoch = V2_EPOCH,
  path,
  operationIndex,
  nonce,
  expiresAt = V2_NOW + 60,
}) {
  return {
    tokenSecret,
    capabilityLookupId: lookup,
    direction,
    scope,
    chain,
    slot,
    slotEpoch: epoch,
    method: 'POST',
    canonicalOrigin: V2_ORIGIN,
    normalizedPath: path,
    operationIndex,
    nonce,
    expiresAt,
  };
}

export async function buildDeliveryRequest({
  nonce = fill(1),
  operationId = fill(9),
  payload = Uint8Array.of(7, 8, 9),
  encryptedDescriptor = Uint8Array.of(1, 2, 3),
  policy = requestedPolicy(),
  tokenSecret = V2_TOKENS.write,
  lookupSecret = tokenSecret,
  scope = 'write',
  slot = V2_DATA_SLOT,
  epoch = V2_EPOCH,
  proofExpiresAt = V2_NOW + 60,
  controlQueries = [],
} = {}) {
  const inputs = [
    proofInput({
      tokenSecret,
      lookup: await deriveV2DailyCapabilityLookupId(lookupSecret, epoch),
      scope,
      slot,
      epoch,
      path: '/v2/deliveries',
      operationIndex: 0,
      nonce,
      expiresAt: proofExpiresAt,
    }),
  ];
  for (const [index, query] of controlQueries.entries()) {
    inputs.push(
      proofInput({
        tokenSecret: query.tokenSecret,
        lookup: await deriveV2DailyCapabilityLookupId(
          query.lookupSecret ?? query.tokenSecret,
          epoch,
        ),
        direction: query.direction,
        scope: query.scope ?? 'read',
        slot: query.slot,
        epoch,
        path: '/v2/deliveries',
        operationIndex: index + 1,
        nonce: query.nonce,
        expiresAt: proofExpiresAt,
      }),
    );
  }
  const assemble = (proofs) => {
    const header = new Map([
      [V2_DELIVERY_REQUEST_KEYS.operationId, operationId],
      [V2_DELIVERY_REQUEST_KEYS.encryptedDescriptor, encryptedDescriptor],
      [V2_DELIVERY_REQUEST_KEYS.requestedPolicy, policy],
      [V2_DELIVERY_REQUEST_KEYS.payloadLength, payload.byteLength],
      [V2_DELIVERY_REQUEST_KEYS.payloadDigest, sha256(payload)],
      [
        V2_DELIVERY_REQUEST_KEYS.dataSlotProof,
        slotProof(slot, epoch, 0, proofs[0]),
      ],
    ]);
    if (controlQueries.length > 0) {
      header.set(
        V2_DELIVERY_REQUEST_KEYS.controlQueries,
        controlQueries.map((query, index) =>
          slotProof(query.slot, epoch, 0, proofs[index + 1]),
        ),
      );
    }
    return encodeV2DeliveryFrame(
      header,
      payload,
      V2_DELIVERY_REQUEST_KEYS.payloadLength,
      V2_DELIVERY_REQUEST_KEYS.payloadDigest,
    );
  };
  const frame = await withSignedProofs(
    inputs,
    assemble,
    v2DeliveryFrameAuthorizationDigest,
  );
  return new Request(`${V2_ORIGIN}/v2/deliveries`, {
    method: 'POST',
    headers: {
      'content-type': V2_CBOR_CONTENT_TYPE,
      'content-length': String(frame.byteLength),
      [V2_CONTENT_SHA256_HEADER]: hex(sha256(frame)),
    },
    body: frame,
  });
}

export async function buildInboxRequest({
  nonce = fill(3),
  tokenSecret = V2_TOKENS.read,
  direction = 'inviter->invitee',
  slot = V2_DATA_SLOT,
  epoch = V2_EPOCH,
  controlSlots = [],
  processedControlEventIds = [],
  // A handler on a frozen clock takes the default; one reading the wall clock
  // needs proofs that expire relative to it.
  proofExpiresAt = V2_NOW + 60,
} = {}) {
  const lookup = await deriveV2DailyCapabilityLookupId(tokenSecret, epoch);
  const inputs = [
    proofInput({
      tokenSecret,
      lookup,
      direction,
      scope: 'read',
      slot,
      epoch,
      path: '/v2/inbox',
      operationIndex: 0,
      nonce,
      expiresAt: proofExpiresAt,
    }),
  ];
  for (const [index, control] of controlSlots.entries()) {
    inputs.push(
      proofInput({
        tokenSecret: control.tokenSecret ?? tokenSecret,
        lookup: await deriveV2DailyCapabilityLookupId(
          control.tokenSecret ?? tokenSecret,
          epoch,
        ),
        direction: control.direction ?? direction,
        scope: 'read',
        slot: control.slot,
        epoch,
        path: '/v2/inbox',
        operationIndex: index + 1,
        nonce: control.nonce,
        expiresAt: proofExpiresAt,
      }),
    );
  }
  const assemble = (proofs) => {
    const header = new Map([
      [
        V2_INBOX_REQUEST_KEYS.dataSlotProofs,
        [slotProof(slot, epoch, 0, proofs[0])],
      ],
    ]);
    if (controlSlots.length > 0) {
      header.set(
        V2_INBOX_REQUEST_KEYS.controlSlotProofs,
        controlSlots.map((control, index) =>
          slotProof(control.slot, epoch, 0, proofs[index + 1]),
        ),
      );
    }
    if (processedControlEventIds.length > 0) {
      header.set(
        V2_INBOX_REQUEST_KEYS.processedControlEventIds,
        processedControlEventIds,
      );
    }
    return encodeCbor(header);
  };
  return cborRequest(
    '/v2/inbox',
    await withSignedProofs(inputs, assemble, v2InboxRequestAuthorizationDigest),
  );
}

export async function buildCompletionRequest({
  deliveryId,
  ackNonce,
  controlNonce,
  operationId = fill(21),
  target = V2_TARGET_SLOT,
  slot = V2_DATA_SLOT,
  epoch = V2_EPOCH,
  result = 0,
  acknowledgement = Uint8Array.of(31, 32, 33),
  descriptorDigest = V2_SIGNED_DESCRIPTOR_DIGEST,
  policy = requestedPolicy(),
}) {
  const path = `/v2/deliveries/${deliveryId}/complete`;
  const inputs = [
    proofInput({
      tokenSecret: V2_TOKENS.ack,
      lookup: await deriveV2DailyCapabilityLookupId(V2_TOKENS.ack, epoch),
      scope: 'ack',
      slot,
      epoch,
      path,
      operationIndex: 0,
      nonce: ackNonce,
    }),
    proofInput({
      tokenSecret: V2_TOKENS.controlWrite,
      lookup: await deriveV2DailyCapabilityLookupId(
        V2_TOKENS.controlWrite,
        epoch,
      ),
      direction: 'invitee->inviter',
      scope: 'write',
      slot: target,
      epoch,
      path,
      operationIndex: 1,
      nonce: controlNonce,
    }),
  ];
  const assemble = ([ackProof, controlProof]) =>
    encodeCbor(
      new Map([
        [
          V2_COMPLETION_REQUEST_KEYS.deliveryId,
          Uint8Array.from(deliveryId.match(/.{2}/g), (value) =>
            Number.parseInt(value, 16),
          ),
        ],
        [
          V2_COMPLETION_REQUEST_KEYS.dataAckProof,
          slotProof(slot, epoch, 0, ackProof),
        ],
        [
          V2_COMPLETION_REQUEST_KEYS.controlWriteProof,
          slotProof(target, epoch, 0, controlProof),
        ],
        [V2_COMPLETION_REQUEST_KEYS.sourceSlot, slot],
        [V2_COMPLETION_REQUEST_KEYS.targetSlot, target],
        [V2_COMPLETION_REQUEST_KEYS.policyDigest, sha256(encodeCbor(policy))],
        [V2_COMPLETION_REQUEST_KEYS.descriptorDigest, descriptorDigest],
        [V2_COMPLETION_REQUEST_KEYS.result, result],
        [V2_COMPLETION_REQUEST_KEYS.operationId, operationId],
        [V2_COMPLETION_REQUEST_KEYS.encryptedAcknowledgement, acknowledgement],
      ]),
    );
  return cborRequest(
    path,
    await withSignedProofs(
      inputs,
      assemble,
      v2CompletionRequestAuthorizationDigest,
    ),
  );
}

export async function buildControlEventRequest({
  nonce,
  operationId = fill(44),
  envelope = Uint8Array.of(45, 46),
  tokenSecret = V2_TOKENS.controlWrite,
  slot = V2_TARGET_SLOT,
  epoch = V2_EPOCH,
  direction = 'invitee->inviter',
}) {
  const inputs = [
    proofInput({
      tokenSecret,
      lookup: await deriveV2DailyCapabilityLookupId(tokenSecret, epoch),
      direction,
      scope: 'write',
      slot,
      epoch,
      path: '/v2/control-events',
      operationIndex: 0,
      nonce,
    }),
  ];
  const assemble = ([proof]) =>
    encodeCbor(
      new Map([
        [V2_CONTROL_EVENT_REQUEST_KEYS.operationId, operationId],
        [
          V2_CONTROL_EVENT_REQUEST_KEYS.controlSlotProof,
          slotProof(slot, epoch, 0, proof),
        ],
        [V2_CONTROL_EVENT_REQUEST_KEYS.encryptedEnvelope, envelope],
      ]),
    );
  return cborRequest(
    '/v2/control-events',
    await withSignedProofs(
      inputs,
      assemble,
      v2ControlEventRequestAuthorizationDigest,
    ),
  );
}

/** The four capabilities a complete send/receive/acknowledge cycle needs. */
export const V2_RELATIONSHIP_CAPABILITIES = [
  {
    id: 'write-capability',
    scope: 'write',
    direction: 'inviter->invitee',
    tokenSecret: V2_TOKENS.write,
  },
  {
    id: 'read-capability',
    scope: 'read',
    direction: 'inviter->invitee',
    tokenSecret: V2_TOKENS.read,
  },
  {
    id: 'ack-capability',
    scope: 'ack',
    direction: 'inviter->invitee',
    tokenSecret: V2_TOKENS.ack,
  },
  {
    id: 'control-write-capability',
    scope: 'write',
    direction: 'invitee->inviter',
    tokenSecret: V2_TOKENS.controlWrite,
  },
  {
    id: 'peer-read-capability',
    scope: 'read',
    direction: 'invitee->inviter',
    tokenSecret: V2_TOKENS.peerRead,
  },
];

export async function registerCapability(
  repository,
  { id, scope, direction, tokenSecret, relationshipId, expiresAt },
  epoch = V2_EPOCH,
) {
  const capability = { id, relationshipId, direction, scope };
  await repository.registerCapability(
    {
      ...capability,
      encryptedTokenSecret: await encryptV2TokenSecret(
        V2_DEPLOYMENT_KEY,
        capability,
        tokenSecret,
        (length) => new Uint8Array(length).fill(id.length),
      ),
      createdAt: V2_NOW - 1,
      expiresAt: expiresAt ?? V2_NOW + 60,
    },
    await deriveV2DailyCapabilityLookupId(tokenSecret, epoch),
    epoch,
  );
  return capability;
}

/**
 * Backend factories. Each returns a repository and, where the backend has
 * durable storage, a `reopen` that returns a fresh instance over the same
 * files — which is how a restart is simulated.
 */
export const V2_REPOSITORY_BACKENDS = [
  ['memory', async () => new MemoryV2Repository()],
  [
    'sqlite',
    async (t) => {
      const directory = await mkdtemp(join(tmpdir(), 'dud-v2-fixture-'));
      const open = async () => {
        const instance = new SQLiteV2Repository(directory);
        await instance.initialize();
        t.after(() => instance.close());
        return instance;
      };
      const repository = await open();
      t.after(async () => {
        await rm(directory, { recursive: true, force: true });
      });
      repository.reopen = open;
      return repository;
    },
  ],
  [
    'd1',
    async (t) => {
      const database = await createMigratedLocalD1(t);
      const repository = new D1V2Repository(database);
      repository.reopen = async () =>
        new D1V2Repository(new LocalD1Database(database.path));
      return repository;
    },
  ],
];

/** True when this backend can be reopened over the same durable storage. */
export function canReopen(repository) {
  return typeof repository.reopen === 'function';
}

/**
 * A handler wired to one backend with the four relationship capabilities
 * registered, plus thin helpers that route each authenticated request.
 */
export async function createDeliveryFixture(
  t,
  createRepository,
  {
    relationshipId = 'relationship',
    capabilityExpiresAt,
    handler: handlerOptions = {},
    nowSeconds = V2_NOW,
  } = {},
) {
  const repository = await createRepository(t);
  const bodyStore = new MemoryV2BodyStore();
  for (const capability of V2_RELATIONSHIP_CAPABILITIES) {
    await registerCapability(repository, {
      ...capability,
      relationshipId,
      expiresAt: capabilityExpiresAt,
    });
  }
  const fixture = attachHandler(repository, bodyStore, {
    handler: handlerOptions,
    nowSeconds,
  });
  fixture.relationshipId = relationshipId;
  /**
   * A second handler over a fresh repository instance on the same storage,
   * sharing the body store: what a process restart looks like from outside.
   */
  fixture.restart = async () =>
    Object.assign(
      attachHandler(await repository.reopen(), bodyStore, {
        handler: handlerOptions,
        nowSeconds,
      }),
      { relationshipId },
    );
  return fixture;
}

/** Wires request helpers to one repository, body store and clock. */
export function attachHandler(
  repository,
  bodyStore,
  { handler: handlerOptions = {}, nowSeconds = V2_NOW } = {},
) {
  let current = nowSeconds;
  const handler = createV2DeliveryHandler({
    repository,
    bodyStore,
    deploymentKey: V2_DEPLOYMENT_KEY,
    now: () => current * 1000,
    ...handlerOptions,
  });
  const observers = new Set();
  const route = (request, path) => {
    for (const observe of observers) {
      observe(path);
    }
    return handler.route(request, V2_ORIGIN, path);
  };
  return {
    repository,
    bodyStore,
    handler,
    route,
    /** Reports every routed path until the returned function is called. */
    observeRoutes: (observe) => {
      observers.add(observe);
      return () => observers.delete(observe);
    },
    /** Moves the handler's clock, keeping the same repository and bodies. */
    setNow: (seconds) => {
      current = seconds;
    },
    now: () => current,
    deliver: async (options) =>
      route(await buildDeliveryRequest(options), '/v2/deliveries'),
    inbox: async (options) =>
      route(await buildInboxRequest(options), '/v2/inbox'),
    complete: async (options) =>
      route(
        await buildCompletionRequest(options),
        `/v2/deliveries/${options.deliveryId}/complete`,
      ),
    control: async (options) =>
      route(await buildControlEventRequest(options), '/v2/control-events'),
  };
}
