// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { MemoryV2Repository } from '../dist/src/v2-memory-repository.js';
import { D1V2Repository } from '../dist/src/v2-d1-repository.js';
import { D1V2PairingRepository } from '../dist/src/v2-d1-pairing-repository.js';
import { sha256 } from '../dist/src/sha256.js';
import { R2V2BodyStore } from '../dist/src/v2-r2.js';
import { SQLiteV2Repository } from '../dist/src/v2-sqlite-repository.js';
import { readD1Migrations } from './d1-local.mjs';
import { MockR2Bucket } from './v2-helpers.mjs';

globalThis.FixedLengthStream ??= class FixedLengthStream extends (
  TransformStream
) {
  constructor() {
    super();
  }
};

const bytes = (length, seed) =>
  Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff);

/** Executes the exact D1 migrations through D1's prepared/batch surface. */
class LocalD1Statement {
  constructor(database, query, values = []) {
    this.database = database;
    this.query = query;
    this.values = values;
  }

  bind(...values) {
    return new LocalD1Statement(this.database, this.query, values);
  }

  async run() {
    const result = this.database.prepare(this.query).run(...this.values);
    return { meta: { changes: Number(result.changes) } };
  }

  async first() {
    return this.database.prepare(this.query).get(...this.values) ?? null;
  }

  async all() {
    return { results: this.database.prepare(this.query).all(...this.values) };
  }
}

class LocalD1Database {
  constructor(path) {
    this.database = new DatabaseSync(path);
    // D1 enforces declared foreign keys, so the local adapter must too.
    this.database.exec('PRAGMA foreign_keys = ON;');
  }

  prepare(query) {
    return new LocalD1Statement(this.database, query);
  }

  async batch(statements) {
    this.database.exec('BEGIN IMMEDIATE');
    try {
      const results = [];
      for (const statement of statements) {
        results.push(await statement.run());
      }
      this.database.exec('COMMIT');
      return results;
    } catch (error) {
      this.database.exec('ROLLBACK');
      throw error;
    }
  }

  close() {
    this.database.close();
  }
}

async function createLocalD1Repository(t) {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-d1-conformance-'));
  const path = join(directory, 'd1.sqlite');
  const database = new LocalD1Database(path);
  for (const migration of await readD1Migrations()) {
    database.database.exec(migration);
  }
  const repository = new D1V2Repository(database);
  t.after(async () => {
    database.close();
    await rm(directory, { recursive: true, force: true });
  });
  return {
    repository,
    database,
    createIndependentRepository: () => {
      const independentDatabase = new LocalD1Database(path);
      return {
        repository: new D1V2Repository(independentDatabase),
        close: () => independentDatabase.close(),
      };
    },
  };
}

async function createSQLiteRepository(t) {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-conformance-'));
  const repository = new SQLiteV2Repository(directory);
  t.after(async () => {
    repository.close();
    await rm(directory, { recursive: true, force: true });
  });
  return { repository };
}

const factories = [
  ['memory', async () => ({ repository: new MemoryV2Repository() })],
  ['sqlite', createSQLiteRepository],
  ['d1', createLocalD1Repository],
];

/** Backends that own relationship, administrative and pairing metadata. */
const relationshipFactories = [
  [
    'sqlite',
    async (t) => {
      const { repository } = await createSQLiteRepository(t);
      return { repository, pairing: repository };
    },
  ],
  [
    'd1',
    async (t) => {
      const { repository, database } = await createLocalD1Repository(t);
      return { repository, pairing: new D1V2PairingRepository(database) };
    },
  ],
];

const RELATIONSHIP = '11'.repeat(16);

async function seedRelationship(repository, now = 1_000) {
  await repository.createRelationship({
    id: RELATIONSHIP,
    canonicalOrigin: 'https://dud.example.com',
    encryptedState: bytes(48, 200),
    createdAt: now,
  });
}

function writeRegistration(id, lookupSeed, createdAt = 1_000, epoch = 20_000) {
  return {
    capability: {
      id,
      relationshipId: RELATIONSHIP,
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: `opaque-${id}`,
      createdAt,
      expiresAt: 100_000,
    },
    lookupId: bytes(16, lookupSeed),
    epoch,
  };
}

/** One capability published across the daily lookups of its whole lifetime. */
function multiEpochRegistrations(id, lookupSeed, createdAt = 1_000) {
  return [20_000, 20_001, 20_002].map((epoch, index) =>
    writeRegistration(id, lookupSeed + index, createdAt, epoch),
  );
}

const WRITE_TUPLE = {
  relationshipId: RELATIONSHIP,
  direction: 'inviter->invitee',
  scope: 'write',
};

for (const [name, factory] of factories) {
  test(`${name} granular repository conforms for operation retries and inbox state`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    const lookup = bytes(16, 1);
    await repository.registerCapability(
      {
        id: 'capability',
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        scope: 'write',
        encryptedTokenSecret: 'opaque',
        createdAt: 1,
        expiresAt: 100,
      },
      lookup,
      20_000,
    );

    const claimedNonce = bytes(16, 90);
    const unclaimedNonce = bytes(16, 91);
    assert.equal(
      await repository.claimNonce('capability', claimedNonce, 100, 10),
      true,
    );
    assert.equal(
      await repository.claimNonces(
        [
          {
            capabilityId: 'capability',
            nonce: unclaimedNonce,
            expiresAt: 100,
          },
          {
            capabilityId: 'capability',
            nonce: claimedNonce,
            expiresAt: 100,
          },
        ],
        10,
      ),
      false,
    );
    assert.equal(
      await repository.claimNonce('capability', unclaimedNonce, 100, 10),
      true,
    );

    const operationId = bytes(16, 2);
    const operationDigest = bytes(32, 3);
    const reservation = await repository.reserveDelivery({
      capabilityId: 'capability',
      operationId,
      operationDigest,
      payloadLength: 3,
      now: 10,
      expiresAt: 100,
    });
    assert.ok('deliveryId' in reservation);
    assert.deepEqual(
      await repository.reserveDelivery({
        capabilityId: 'capability',
        operationId,
        operationDigest,
        payloadLength: 3,
        now: 11,
        expiresAt: 100,
      }),
      reservation,
    );
    const publication = await repository.publishDelivery({
      id: reservation.deliveryId,
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      slot: lookup,
      epoch: 20_000,
      encryptedDescriptor: bytes(2, 4),
      requestedPolicy: bytes(2, 5),
      effectivePolicy: bytes(2, 6),
      policyDigest: bytes(32, 7),
      payloadKey: reservation.payloadKey,
      payloadLength: 3,
      payloadDigest: bytes(32, 8),
      operationId,
      operationDigest,
      createdAt: 11,
      expiresAt: 100,
    });
    assert.equal(publication.idempotent, false);
    assert.equal(
      (
        await repository.publishDelivery({
          ...publication.delivery,
          state: undefined,
        })
      ).idempotent,
      true,
    );
    assert.equal(
      (
        await repository.queryInbox({
          relationshipId: 'relationship',
          direction: 'inviter->invitee',
          dataSlots: [{ slot: lookup, epoch: 20_000 }],
          controlSlots: [],
          now: 12,
        })
      ).delivery.id,
      reservation.deliveryId,
    );

    const completion = {
      id: reservation.deliveryId,
      operationId: bytes(16, 9),
      operationDigest: bytes(32, 10),
      completionDigest: bytes(32, 11),
      result: 0,
      now: 13,
    };
    assert.equal(
      (await repository.completeDelivery(completion)).idempotent,
      false,
    );
    assert.equal(
      (await repository.completeDelivery(completion)).idempotent,
      true,
    );
    await assert.rejects(
      repository.completeDelivery({ ...completion, result: 1 }),
      /conflicts/,
    );

    const event = {
      id: 'control-event',
      relationshipId: 'relationship',
      direction: 'invitee->inviter',
      slot: bytes(16, 12),
      epoch: 20_000,
      encryptedEnvelope: bytes(2, 13),
      operationId: bytes(16, 14),
      operationDigest: bytes(32, 15),
      sequence: 0,
      createdAt: 14,
      expiresAt: 100,
    };
    assert.equal(
      (await repository.publishControlEvent(event)).idempotent,
      false,
    );
    assert.equal(
      (await repository.publishControlEvent(event)).idempotent,
      true,
    );
    await repository.consumeControlEvents({
      ids: [event.id],
      relationshipId: 'relationship',
      direction: 'invitee->inviter',
      now: 15,
    });
    assert.deepEqual(
      (
        await repository.queryInbox({
          relationshipId: 'relationship',
          direction: 'invitee->inviter',
          dataSlots: [],
          controlSlots: [{ slot: event.slot, epoch: event.epoch }],
          now: 16,
        })
      ).controlEvents,
      [],
    );
    const maintenance = await repository.runMaintenance(101, 8);
    assert.equal(maintenance.deletedControlEvents, 1);
    assert.equal(maintenance.deletedRateWindows, 0);
    assert.equal(maintenance.deletedInvitations, 0);
    // Nothing filled its bounded batch, so the backend reports itself drained.
    assert.equal(maintenance.complete, true);
    const drained = await repository.runMaintenance(101, 8);
    assert.equal(drained.complete, true);
    assert.deepEqual(drained.expiredDeliveryIds, []);
    assert.deepEqual(drained.expiredBodyKeys, []);
    assert.equal(drained.deletedNonces, 0);
    assert.equal(drained.deletedControlEvents, 0);
  });

  // A receiver walks one descriptor chain: a delivery handed to it before an
  // earlier one reads as a gap and quarantines the chain. Publication order is
  // therefore a contract, and neither `created_at` (whole seconds) nor the
  // random `id` can carry it. Two sends inside one second, or a clock that
  // steps back between them, must still drain in publication order.
  test(`${name} drains the inbox in publication order regardless of timestamps`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    const slot = bytes(16, 150);
    await repository.registerCapability(
      {
        id: 'capability',
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        scope: 'write',
        encryptedTokenSecret: 'opaque',
        createdAt: 1,
        expiresAt: 100_000,
      },
      slot,
      20_000,
    );
    // Two publications share a second, and the third carries an earlier stamp
    // than both, so every ordering signal except publication order disagrees
    // with the order the sender committed these in.
    const stamps = [1_100, 1_100, 1_099];
    const published = [];
    for (const [index, createdAt] of stamps.entries()) {
      const reservation = await repository.reserveDelivery({
        capabilityId: 'capability',
        operationId: bytes(16, 160 + index),
        operationDigest: bytes(32, 160 + index),
        payloadLength: 3,
        now: 10,
        expiresAt: 100_000,
      });
      await repository.publishDelivery({
        id: reservation.deliveryId,
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        slot,
        epoch: 20_000,
        encryptedDescriptor: bytes(2, 170 + index),
        requestedPolicy: bytes(2, 5),
        effectivePolicy: bytes(2, 6),
        policyDigest: bytes(32, 7),
        payloadKey: reservation.payloadKey,
        payloadLength: 3,
        payloadDigest: bytes(32, 8),
        operationId: bytes(16, 160 + index),
        operationDigest: bytes(32, 160 + index),
        createdAt,
        expiresAt: 100_000,
      });
      published.push(reservation.deliveryId);
    }

    const drained = [];
    for (let index = 0; index < published.length; index++) {
      const { delivery } = await repository.queryInbox({
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        dataSlots: [{ slot, epoch: 20_000 }],
        controlSlots: [],
        now: 1_200,
      });
      assert.ok(delivery, 'every published delivery stays reachable');
      drained.push(delivery.id);
      await repository.completeDelivery({
        id: delivery.id,
        operationId: bytes(16, 180 + index),
        operationDigest: bytes(32, 180 + index),
        completionDigest: bytes(32, 190 + index),
        result: 0,
        now: 1_200,
      });
    }
    assert.deepEqual(drained, published);
  });

  test(`${name} maintenance is bounded by its batch limit and restartable`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    await repository.registerCapability(
      {
        id: 'capability',
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        scope: 'write',
        encryptedTokenSecret: 'opaque',
        createdAt: 1,
        expiresAt: 100_000,
      },
      bytes(16, 130),
      20_000,
    );
    const reserved = [];
    for (let index = 0; index < 3; index++) {
      const reservation = await repository.reserveDelivery({
        capabilityId: 'capability',
        operationId: bytes(16, 140 + index),
        operationDigest: bytes(32, 140 + index),
        payloadLength: 4,
        now: 10,
        expiresAt: 100,
      });
      reserved.push(reservation.payloadKey);
    }

    const first = await repository.runMaintenance(200, 1);
    assert.equal(first.expiredBodyKeys.length, 1);
    assert.equal(first.complete, false);
    const keys = [...first.expiredBodyKeys];
    let batches = 1;
    let result = first;
    while (!result.complete) {
      result = await repository.runMaintenance(200, 1);
      keys.push(...result.expiredBodyKeys);
      assert.ok(++batches < 10, 'a restartable drain terminates');
    }
    assert.deepEqual(keys.slice().sort(), reserved.slice().sort());
  });

  test(`${name} rechecks a live capability while reserving a delivery`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    await repository.registerCapability(
      {
        id: 'revoked-capability',
        relationshipId: 'relationship',
        direction: 'inviter->invitee',
        scope: 'write',
        encryptedTokenSecret: 'opaque',
        createdAt: 1,
        expiresAt: 100,
        revokedAt: 10,
      },
      bytes(16, 213),
      20_000,
    );
    await assert.rejects(
      repository.reserveDelivery({
        capabilityId: 'revoked-capability',
        operationId: bytes(16, 214),
        operationDigest: bytes(32, 215),
        payloadLength: 1,
        now: 11,
        expiresAt: 99,
      }),
      /(not active|unavailable)/,
    );
  });

  test(`${name} rolls back delivery authorization when admission is rejected`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    await repository.registerCapability(
      {
        id: 'atomic-capability',
        relationshipId: 'atomic-relationship',
        direction: 'inviter->invitee',
        scope: 'write',
        encryptedTokenSecret: 'opaque',
        createdAt: 1,
        expiresAt: 200,
      },
      bytes(16, 216),
      20_000,
    );
    const reserve = (operationSeed, nonce, maximumTotalBytes, maximumRate) =>
      repository.reserveDelivery({
        capabilityId: 'atomic-capability',
        operationId: bytes(16, operationSeed),
        operationDigest: bytes(32, operationSeed),
        payloadLength: 1,
        maximumTotalBytes,
        authorization: {
          claims: [
            {
              capabilityId: 'atomic-capability',
              nonce,
              expiresAt: 100,
            },
          ],
          maximumRequestsPerMinute: maximumRate,
        },
        now: 10,
        expiresAt: 100,
      });
    await assert.rejects(
      repository.reserveDelivery({
        capabilityId: 'atomic-capability',
        operationId: bytes(16, 217),
        operationDigest: bytes(32, 217),
        payloadLength: 2,
        maximumTotalBytes: 1,
        authorization: {
          claims: [
            {
              capabilityId: 'atomic-capability',
              nonce: bytes(16, 218),
              expiresAt: 100,
            },
          ],
          maximumRequestsPerMinute: 1,
        },
        now: 10,
        expiresAt: 100,
      }),
    );
    // The nonce used by the quota rejection was not consumed, nor was its
    // proof charged against the rate window.
    await assert.doesNotReject(reserve(219, bytes(16, 218), 1, 1));
    await assert.rejects(reserve(220, bytes(16, 221), 2, 1));
    // Likewise, a rate rejection leaves its fresh nonce usable.
    await assert.doesNotReject(reserve(222, bytes(16, 221), 2, 2));
  });

  test(`${name} consumes delivery control events only with an admitted reservation`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    const slot = bytes(16, 223);
    await repository.registerCapability(
      {
        id: 'control-capability',
        relationshipId: 'control-relationship',
        direction: 'inviter->invitee',
        scope: 'write',
        encryptedTokenSecret: 'opaque',
        createdAt: 1,
        expiresAt: 200,
      },
      slot,
      20_000,
    );
    const event = {
      id: 'pending-control',
      relationshipId: 'control-relationship',
      direction: 'inviter->invitee',
      slot,
      epoch: 20_000,
      encryptedEnvelope: bytes(2, 224),
      operationId: bytes(16, 225),
      operationDigest: bytes(32, 226),
      sequence: 0,
      createdAt: 1,
      expiresAt: 100,
    };
    await repository.publishControlEvent(event);
    const consumption = {
      ids: [event.id],
      relationshipId: event.relationshipId,
      direction: event.direction,
      now: 10,
    };
    const queryControls = () =>
      repository.queryInbox({
        relationshipId: event.relationshipId,
        direction: event.direction,
        dataSlots: [],
        controlSlots: [{ slot, epoch: 20_000 }],
        now: 10,
      });
    await assert.rejects(
      repository.reserveDelivery({
        capabilityId: 'control-capability',
        operationId: bytes(16, 227),
        operationDigest: bytes(32, 228),
        payloadLength: 2,
        maximumTotalBytes: 1,
        consumeControlEvents: consumption,
        now: 10,
        expiresAt: 100,
      }),
    );
    assert.equal((await queryControls()).controlEvents.length, 1);
    await repository.reserveDelivery({
      capabilityId: 'control-capability',
      operationId: bytes(16, 229),
      operationDigest: bytes(32, 230),
      payloadLength: 1,
      maximumTotalBytes: 1,
      consumeControlEvents: consumption,
      now: 10,
      expiresAt: 100,
    });
    assert.equal((await queryControls()).controlEvents.length, 0);
  });

  test(`${name} commits inbox proof claims and control consumption together`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    const slot = bytes(16, 231);
    await repository.registerCapability(
      {
        id: 'inbox-capability',
        relationshipId: 'inbox-relationship',
        direction: 'inviter->invitee',
        scope: 'read',
        encryptedTokenSecret: 'opaque',
        createdAt: 1,
        expiresAt: 200,
      },
      slot,
      20_000,
    );
    await repository.publishControlEvent({
      id: 'inbox-control',
      relationshipId: 'inbox-relationship',
      direction: 'inviter->invitee',
      slot,
      epoch: 20_000,
      encryptedEnvelope: bytes(2, 232),
      operationId: bytes(16, 233),
      operationDigest: bytes(32, 234),
      sequence: 0,
      createdAt: 1,
      expiresAt: 100,
    });
    const query = (maximumRequestsPerMinute) =>
      repository.queryInbox({
        relationshipId: 'inbox-relationship',
        direction: 'inviter->invitee',
        dataSlots: [],
        controlSlots: [{ slot, epoch: 20_000 }],
        authorization: {
          claims: [
            {
              capabilityId: 'inbox-capability',
              nonce: bytes(16, 235),
              expiresAt: 100,
            },
          ],
          maximumRequestsPerMinute,
          consumeControlEventIds: ['inbox-control'],
        },
        now: 10,
      });
    const rejected = await query(0);
    assert.equal(rejected.authorizationAccepted, false);
    assert.equal(
      (
        await repository.queryInbox({
          relationshipId: 'inbox-relationship',
          direction: 'inviter->invitee',
          dataSlots: [],
          controlSlots: [{ slot, epoch: 20_000 }],
          now: 10,
        })
      ).controlEvents.length,
      1,
    );
    const accepted = await query(1);
    assert.equal(accepted.authorizationAccepted, true);
    assert.equal(accepted.controlEvents.length, 0);
  });

  test(`${name} commits completion proof claims with its control event`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    const slot = bytes(16, 236);
    for (const [id, direction, scope, lookupSeed] of [
      ['completion-write', 'inviter->invitee', 'write', 237],
      ['completion-ack', 'invitee->inviter', 'ack', 238],
      ['completion-control', 'invitee->inviter', 'write', 239],
    ]) {
      await repository.registerCapability(
        {
          id,
          relationshipId: 'completion-relationship',
          direction,
          scope,
          encryptedTokenSecret: 'opaque',
          createdAt: 1,
          expiresAt: 200,
        },
        bytes(16, lookupSeed),
        20_000,
      );
    }
    const reservation = await repository.reserveDelivery({
      capabilityId: 'completion-write',
      operationId: bytes(16, 240),
      operationDigest: bytes(32, 241),
      payloadLength: 1,
      now: 10,
      expiresAt: 100,
    });
    assert.ok('deliveryId' in reservation);
    await repository.publishDelivery({
      id: reservation.deliveryId,
      relationshipId: 'completion-relationship',
      direction: 'inviter->invitee',
      slot,
      epoch: 20_000,
      encryptedDescriptor: bytes(2, 242),
      requestedPolicy: bytes(2, 243),
      effectivePolicy: bytes(2, 244),
      policyDigest: bytes(32, 245),
      payloadKey: reservation.payloadKey,
      payloadLength: 1,
      payloadDigest: bytes(32, 246),
      operationId: bytes(16, 240),
      operationDigest: bytes(32, 241),
      createdAt: 10,
      expiresAt: 100,
    });
    const authorization = (maximumRequestsPerMinute) => ({
      claims: [
        {
          capabilityId: 'completion-ack',
          nonce: bytes(16, 247),
          expiresAt: 100,
        },
        {
          capabilityId: 'completion-control',
          nonce: bytes(16, 248),
          expiresAt: 100,
        },
      ],
      maximumRequestsPerMinute,
    });
    const completion = {
      id: reservation.deliveryId,
      operationId: bytes(16, 249),
      operationDigest: bytes(32, 250),
      completionDigest: bytes(32, 251),
      result: 0,
      now: 10,
    };
    const event = {
      id: 'completion-event',
      relationshipId: 'completion-relationship',
      direction: 'invitee->inviter',
      slot,
      epoch: 20_000,
      encryptedEnvelope: bytes(2, 252),
      operationId: completion.operationId,
      operationDigest: completion.operationDigest,
      sequence: 0,
      createdAt: 10,
      expiresAt: 100,
    };
    const rejected = await repository.completeDeliveryWithControl({
      completion,
      event,
      authorization: authorization(0),
    });
    assert.equal(rejected.authorizationAccepted, false);
    assert.equal(
      (await repository.findDelivery(reservation.deliveryId))?.state,
      'published',
    );
    const accepted = await repository.completeDeliveryWithControl({
      completion,
      event,
      authorization: authorization(2),
    });
    assert.equal(accepted.authorizationAccepted, true);
    assert.equal(accepted.delivery.state, 'completed');
  });

  test(`${name} commits inline control proof claims with publication`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    const slot = bytes(16, 253);
    await repository.registerCapability(
      {
        id: 'inline-control-capability',
        relationshipId: 'inline-control-relationship',
        direction: 'inviter->invitee',
        scope: 'write',
        encryptedTokenSecret: 'opaque',
        createdAt: 1,
        expiresAt: 200,
      },
      slot,
      20_000,
    );
    const event = {
      id: 'inline-control-event',
      relationshipId: 'inline-control-relationship',
      direction: 'inviter->invitee',
      slot,
      epoch: 20_000,
      encryptedEnvelope: bytes(2, 254),
      operationId: bytes(16, 255),
      operationDigest: bytes(32, 1),
      sequence: 0,
      createdAt: 10,
      expiresAt: 100,
    };
    const authorization = (maximumRequestsPerMinute) => ({
      claims: [
        {
          capabilityId: 'inline-control-capability',
          nonce: bytes(16, 2),
          expiresAt: 100,
        },
      ],
      maximumRequestsPerMinute,
    });
    assert.equal(
      (await repository.publishControlEvent(event, authorization(0)))
        .authorizationAccepted,
      false,
    );
    assert.equal(
      (
        await repository.queryInbox({
          relationshipId: event.relationshipId,
          direction: event.direction,
          dataSlots: [],
          controlSlots: [{ slot, epoch: 20_000 }],
          now: 10,
        })
      ).controlEvents.length,
      0,
    );
    const accepted = await repository.publishControlEvent(
      event,
      authorization(1),
    );
    assert.equal(accepted.authorizationAccepted, true);
    assert.equal(accepted.event.id, event.id);
  });
}

test('D1/R2 maintenance removes a promoted body from an interrupted reservation', async (t) => {
  const { repository } = await createLocalD1Repository(t);
  const lookup = bytes(16, 101);
  await repository.registerCapability(
    {
      id: 'capability',
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 200,
    },
    lookup,
    20_000,
  );
  const reserved = await repository.reserveDelivery({
    capabilityId: 'capability',
    operationId: bytes(16, 102),
    operationDigest: bytes(32, 103),
    payloadLength: 3,
    now: 1,
    expiresAt: 10,
  });
  assert.ok('deliveryId' in reserved);
  const body = Uint8Array.of(1, 2, 3);
  const bucket = new MockR2Bucket();
  const bodyStore = new R2V2BodyStore(bucket);
  const staged = await bodyStore.stage(
    new ReadableStream({
      start(controller) {
        controller.enqueue(body);
        controller.close();
      },
    }),
    body.byteLength,
    sha256(body),
  );
  await bodyStore.promote(staged, reserved.payloadKey);
  assert.equal(await bodyStore.head(reserved.payloadKey), true);

  const maintenance = await repository.runMaintenance(11, 8);
  assert.deepEqual(maintenance.expiredBodyKeys, [reserved.payloadKey]);
  await Promise.all(
    maintenance.expiredBodyKeys.map((key) => bodyStore.delete(key)),
  );
  assert.equal(await bodyStore.head(reserved.payloadKey), false);
});

test('D1/R2 maintenance removes an authenticated staging crash body by metadata key', async (t) => {
  const { repository } = await createLocalD1Repository(t);
  const key = await repository.reserveStagedBody({
    id: 'e'.repeat(32),
    expiresAt: 10,
    now: 0,
    reservedBytes: 3,
    maximumConcurrentUploads: 1,
    maximumStagedBytes: 3,
  });
  const bucket = new MockR2Bucket();
  const bodyStore = new R2V2BodyStore(bucket);
  const body = Uint8Array.of(4, 5, 6);
  await bodyStore.put(
    key,
    new ReadableStream({
      start(controller) {
        controller.enqueue(body);
        controller.close();
      },
    }),
    body.byteLength,
    sha256(body),
  );
  const maintenance = await repository.runMaintenance(11, 8);
  assert.deepEqual(maintenance.expiredBodyKeys, [key]);
  await Promise.all(
    maintenance.expiredBodyKeys.map((value) => bodyStore.delete(value)),
  );
  assert.equal(bucket.objects.has(key), false);
});

test('D1/R2 maintenance tolerates a post-finalization staging record with no body', async (t) => {
  const { repository } = await createLocalD1Repository(t);
  const key = await repository.reserveStagedBody({
    id: 'f'.repeat(32),
    expiresAt: 10,
    now: 0,
    reservedBytes: 0,
    maximumConcurrentUploads: 1,
    maximumStagedBytes: 1,
  });
  const bodyStore = new R2V2BodyStore(new MockR2Bucket());
  const maintenance = await repository.runMaintenance(11, 8);
  assert.deepEqual(maintenance.expiredBodyKeys, [key]);
  await assert.doesNotReject(bodyStore.delete(key));
});

test('independent D1 repository instances preserve reservation idempotency', async (t) => {
  const { repository, createIndependentRepository } =
    await createLocalD1Repository(t);
  const lookup = bytes(16, 110);
  await repository.registerCapability(
    {
      id: 'capability',
      relationshipId: 'relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 100,
    },
    lookup,
    20_000,
  );
  const operationId = bytes(16, 111);
  const operationDigest = bytes(32, 112);
  const first = await repository.reserveDelivery({
    capabilityId: 'capability',
    operationId,
    operationDigest,
    payloadLength: 3,
    now: 1,
    expiresAt: 100,
  });
  const independent = createIndependentRepository();
  t.after(independent.close);
  assert.deepEqual(
    await independent.repository.reserveDelivery({
      capabilityId: 'capability',
      operationId,
      operationDigest,
      payloadLength: 3,
      now: 2,
      expiresAt: 100,
    }),
    first,
  );
  await assert.rejects(
    independent.repository.reserveDelivery({
      capabilityId: 'capability',
      operationId,
      operationDigest: bytes(32, 113),
      payloadLength: 3,
      now: 2,
      expiresAt: 100,
    }),
    /conflicts/,
  );
});

test('D1 delivery reservations atomically enforce relationship byte quota', async (t) => {
  const { repository } = await createLocalD1Repository(t);
  await repository.registerCapability(
    {
      id: 'quota-capability',
      relationshipId: 'quota-relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 200,
    },
    bytes(16, 114),
    20_000,
  );
  await repository.reserveDelivery({
    capabilityId: 'quota-capability',
    operationId: bytes(16, 115),
    operationDigest: bytes(32, 116),
    payloadLength: 3,
    maximumTotalBytes: 4,
    now: 1,
    expiresAt: 100,
  });
  await assert.rejects(
    repository.reserveDelivery({
      capabilityId: 'quota-capability',
      operationId: bytes(16, 117),
      operationDigest: bytes(32, 118),
      payloadLength: 2,
      maximumTotalBytes: 4,
      now: 1,
      expiresAt: 100,
    }),
    /quota is exhausted/,
  );
  await repository.runMaintenance(101, 8);
  await assert.doesNotReject(
    repository.reserveDelivery({
      capabilityId: 'quota-capability',
      operationId: bytes(16, 119),
      operationDigest: bytes(32, 120),
      payloadLength: 4,
      maximumTotalBytes: 4,
      now: 101,
      expiresAt: 200,
    }),
  );
});

for (const [name, factory] of relationshipFactories) {
  test(`${name} commits a capability reissue as one metadata transaction`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    await seedRelationship(repository);
    await repository.registerCapability(
      writeRegistration('original', 130).capability,
      bytes(16, 130),
      20_000,
    );

    const nonce = bytes(32, 140);
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: RELATIONSHIP,
        nonce,
        nonceExpiresAt: 5_000,
        now: 1_100,
        minute: 18,
        maximumRequestsPerMinute: 2,
        revocations: [WRITE_TUPLE],
        registrations: [writeRegistration('rotated', 131, 1_100)],
      }),
      'accepted',
    );
    assert.equal(
      (await repository.findCapabilityLookup(bytes(16, 130), 20_000)).revokedAt,
      1_100,
    );
    assert.equal(
      (await repository.findCapabilityLookup(bytes(16, 131), 20_000)).id,
      'rotated',
    );

    // A replayed nonce commits nothing, including its rate accounting.
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: RELATIONSHIP,
        nonce,
        nonceExpiresAt: 5_000,
        now: 1_110,
        minute: 18,
        maximumRequestsPerMinute: 2,
        revocations: [WRITE_TUPLE],
        registrations: [writeRegistration('replayed', 132, 1_110)],
      }),
      'replayed',
    );
    assert.equal(
      await repository.findCapabilityLookup(bytes(16, 132), 20_000),
      null,
    );

    // The window has one charge left, so the next request is admitted and the
    // one after it is rejected without consuming its nonce.
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: RELATIONSHIP,
        nonce: bytes(32, 141),
        nonceExpiresAt: 5_000,
        now: 1_120,
        minute: 18,
        maximumRequestsPerMinute: 2,
        revocations: [WRITE_TUPLE],
        registrations: [writeRegistration('second', 133, 1_120)],
      }),
      'accepted',
    );
    const limitedNonce = bytes(32, 142);
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: RELATIONSHIP,
        nonce: limitedNonce,
        nonceExpiresAt: 5_000,
        now: 1_130,
        minute: 18,
        maximumRequestsPerMinute: 2,
        revocations: [WRITE_TUPLE],
        registrations: [writeRegistration('limited', 134, 1_130)],
      }),
      'rate_limited',
    );
    assert.equal(
      await repository.findCapabilityLookup(bytes(16, 134), 20_000),
      null,
    );
    assert.equal(
      (await repository.findCapabilityLookup(bytes(16, 133), 20_000)).revokedAt,
      undefined,
    );
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: RELATIONSHIP,
        nonce: limitedNonce,
        nonceExpiresAt: 5_000,
        now: 1_200,
        minute: 19,
        maximumRequestsPerMinute: 2,
        revocations: [WRITE_TUPLE],
        registrations: [writeRegistration('limited', 134, 1_200)],
      }),
      'accepted',
    );
  });

  test(`${name} publishes one capability across every daily lookup`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    await seedRelationship(repository);
    await repository.registerCapability(
      writeRegistration('spanning-original', 180).capability,
      bytes(16, 180),
      20_000,
    );
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: RELATIONSHIP,
        nonce: bytes(32, 181),
        nonceExpiresAt: 5_000,
        now: 1_100,
        minute: 18,
        maximumRequestsPerMinute: 60,
        revocations: [WRITE_TUPLE],
        registrations: multiEpochRegistrations('spanning', 190, 1_100),
      }),
      'accepted',
    );
    for (const [index, epoch] of [20_000, 20_001, 20_002].entries()) {
      assert.equal(
        (await repository.findCapabilityLookup(bytes(16, 190 + index), epoch))
          .id,
        'spanning',
      );
    }
    // The retirement leaves the freshly published tuple usable.
    assert.equal(
      (await repository.findCapabilityLookup(bytes(16, 190), 20_000)).revokedAt,
      undefined,
    );
    assert.equal(
      (await repository.findCapabilityLookup(bytes(16, 180), 20_000)).revokedAt,
      1_100,
    );

    await repository.replaceCapabilities({
      revocations: [WRITE_TUPLE],
      registrations: multiEpochRegistrations('spanning-again', 200, 1_200),
      now: 1_200,
    });
    for (const [index, epoch] of [20_000, 20_001, 20_002].entries()) {
      assert.equal(
        (await repository.findCapabilityLookup(bytes(16, 200 + index), epoch))
          .id,
        'spanning-again',
      );
    }
  });

  test(`${name} reissue cannot resurrect an administratively revoked tuple`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    await seedRelationship(repository);
    await repository.registerCapability(
      writeRegistration('live', 150).capability,
      bytes(16, 150),
      20_000,
    );
    await repository.revokeRelationship({
      relationshipId: RELATIONSHIP,
      direction: 'inviter->invitee',
      scope: 'write',
      now: 1_050,
    });
    const nonce = bytes(32, 151);
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: RELATIONSHIP,
        nonce,
        nonceExpiresAt: 5_000,
        now: 1_100,
        minute: 18,
        maximumRequestsPerMinute: 60,
        revocations: [WRITE_TUPLE],
        registrations: [writeRegistration('resurrected', 152, 1_100)],
      }),
      'revoked',
    );
    assert.equal(
      await repository.findCapabilityLookup(bytes(16, 152), 20_000),
      null,
    );
    // The rejected request consumed no nonce, so the same one is still usable.
    await repository.createRelationship({
      id: 'second-relationship',
      canonicalOrigin: 'https://dud.example.com',
      encryptedState: bytes(48, 201),
      createdAt: 1_000,
    });
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: 'second-relationship',
        nonce,
        nonceExpiresAt: 5_000,
        now: 1_100,
        minute: 18,
        maximumRequestsPerMinute: 60,
        revocations: [],
        registrations: [],
      }),
      'accepted',
    );
  });

  test(`${name} fully revoking a relationship blocks every later reissue`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    await seedRelationship(repository);
    await repository.registerCapability(
      writeRegistration('doomed', 160).capability,
      bytes(16, 160),
      20_000,
    );
    await repository.revokeRelationship({
      relationshipId: RELATIONSHIP,
      now: 1_050,
    });
    const status = await repository.relationshipStatus(RELATIONSHIP);
    assert.equal(status.fullyRevoked, true);
    assert.deepEqual(
      status.tuples.map((tuple) => [tuple.scope, tuple.revoked]),
      [['write', true]],
    );
    assert.equal(
      await repository.commitCapabilityReissue({
        relationshipId: RELATIONSHIP,
        nonce: bytes(32, 161),
        nonceExpiresAt: 5_000,
        now: 1_100,
        minute: 18,
        maximumRequestsPerMinute: 60,
        revocations: [WRITE_TUPLE],
        registrations: [writeRegistration('blocked', 162, 1_100)],
      }),
      'revoked',
    );
    assert.equal(
      await repository.findCapabilityLookup(bytes(16, 162), 20_000),
      null,
    );
  });

  test(`${name} administrative request windows are bounded per key`, async (t) => {
    const { repository } = await factory(t);
    await repository.initialize();
    const window = { key: 'admin-failure', minute: 42, maximum: 2 };
    assert.deepEqual(
      [
        await repository.claimRequestWindow(window),
        await repository.claimRequestWindow(window),
        await repository.claimRequestWindow(window),
      ],
      [true, true, false],
    );
    assert.equal(
      await repository.claimRequestWindow({ ...window, key: 'failure:global' }),
      true,
    );
    assert.equal(
      await repository.claimRequestWindow({ ...window, minute: 43 }),
      true,
    );
  });

  test(`${name} pairing commits the request window with its revision swap`, async (t) => {
    const { repository, pairing } = await factory(t);
    await repository.initialize();
    const locator = 'e'.repeat(64);
    assert.equal(
      await pairing.admit({
        record: {
          locator,
          phase: 0,
          createdAt: 1,
          expiresAt: 100,
          value: bytes(48, 170),
        },
        sourceKey: 'pairing-create:test',
        minute: 5,
        globalMaximum: 10,
        sourceMaximum: 10,
        pendingMaximum: 10,
        now: 1,
      }),
      true,
    );
    const rate = { key: `pairing-mutate:${locator}`, minute: 5, maximum: 2 };
    const first = await pairing.find(locator);
    const committed = await pairing.commit({
      record: first,
      next: { phase: 1, value: bytes(48, 171) },
      rate,
    });
    assert.equal(committed.status, 'committed');
    assert.equal(committed.record.revision, first.revision + 1);
    assert.deepEqual(committed.record.value, bytes(48, 171));

    // A stale revision loses the swap and must not spend a rate charge.
    assert.deepEqual(
      await pairing.commit({
        record: first,
        next: { phase: 2, value: bytes(48, 172) },
        rate,
      }),
      { status: 'conflict' },
    );
    const second = await pairing.commit({
      record: committed.record,
      next: { phase: 2, value: bytes(48, 173) },
      rate,
    });
    assert.equal(second.status, 'committed');
    assert.deepEqual(
      await pairing.commit({
        record: second.record,
        next: { phase: 3, value: bytes(48, 174) },
        rate,
      }),
      { status: 'rate_limited' },
    );
    const unchanged = await pairing.find(locator);
    assert.equal(unchanged.revision, second.record.revision);
    assert.deepEqual(unchanged.value, bytes(48, 173));
  });
}

test('D1 replacement cannot resurrect a capability after tuple revocation', async (t) => {
  const { repository } = await createLocalD1Repository(t);
  await repository.registerCapability(
    {
      id: 'revoked-capability',
      relationshipId: 'revoked-relationship',
      direction: 'inviter->invitee',
      scope: 'write',
      encryptedTokenSecret: 'opaque',
      createdAt: 1,
      expiresAt: 100,
    },
    bytes(16, 121),
    20_000,
  );
  await repository.revokeRelationship({
    relationshipId: 'revoked-relationship',
    direction: 'inviter->invitee',
    scope: 'write',
    now: 2,
  });
  await assert.rejects(
    repository.replaceCapabilities({
      revocations: [],
      registrations: [
        {
          capability: {
            id: 'replacement-capability',
            relationshipId: 'revoked-relationship',
            direction: 'inviter->invitee',
            scope: 'write',
            encryptedTokenSecret: 'opaque',
            createdAt: 3,
            expiresAt: 100,
          },
          lookupId: bytes(16, 122),
          epoch: 20_000,
        },
      ],
      now: 3,
    }),
    /revoked during replacement/,
  );
});

test('D1 pairing admission atomically charges both windows before publishing', async (t) => {
  const { database } = await createLocalD1Repository(t);
  const pairing = new D1V2PairingRepository(database);
  const input = {
    record: {
      locator: 'c'.repeat(64),
      phase: 0,
      createdAt: 1,
      expiresAt: 100,
      value: bytes(48, 120),
    },
    sourceKey: 'pairing-create:test',
    minute: 0,
    globalMaximum: 1,
    sourceMaximum: 1,
    pendingMaximum: 1,
    now: 1,
  };
  assert.equal(await pairing.admit(input), true);
  assert.equal(
    await pairing.admit({
      ...input,
      record: { ...input.record, locator: 'd'.repeat(64) },
    }),
    false,
  );
  assert.equal(await pairing.countActive(1), 1);
});

test('D1 pairing source rejection does not consume global capacity', async (t) => {
  const { database } = await createLocalD1Repository(t);
  const pairing = new D1V2PairingRepository(database);
  const input = {
    record: {
      locator: 'e'.repeat(64),
      phase: 0,
      createdAt: 1,
      expiresAt: 100,
      value: bytes(48, 121),
    },
    sourceKey: 'pairing-create:source-a',
    minute: 0,
    globalMaximum: 2,
    sourceMaximum: 1,
    pendingMaximum: 2,
    now: 1,
  };
  assert.equal(await pairing.admit(input), true);
  assert.equal(
    await pairing.admit({
      ...input,
      record: { ...input.record, locator: 'f'.repeat(64) },
    }),
    false,
  );
  assert.equal(
    await pairing.admit({
      ...input,
      sourceKey: 'pairing-create:source-b',
      record: { ...input.record, locator: 'a'.repeat(64) },
    }),
    true,
  );
});
