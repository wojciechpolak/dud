// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type {
  V2AdministrativeRepository,
  V2Repository,
  V2CapabilityRegistration,
  V2CapabilityReissueInput,
  V2CapabilityReissueOutcome,
  V2RepositoryCapability,
  V2RepositoryControlEvent,
  V2RepositoryDelivery,
  V2RelationshipRepository,
  V2ReconciliationRepository,
} from './v2-repository.js';
import { SQLiteV2Database } from './v2-sqlite.js';
import type {
  D1PairingRecord,
  V2PairingCommit,
  V2PairingRepository,
} from './v2-d1-pairing-repository.js';

function directionNumber(direction: V2RepositoryDelivery['direction']): 0 | 1 {
  return direction === 'inviter->invitee' ? 0 : 1;
}

/** Promise-based granular repository backed by the isolated Node SQLite DB. */
export class SQLiteV2Repository
  implements
    V2Repository,
    V2AdministrativeRepository,
    V2RelationshipRepository,
    V2PairingRepository,
    V2ReconciliationRepository
{
  private readonly database: SQLiteV2Database;

  constructor(rootDir: string) {
    this.database = new SQLiteV2Database(rootDir);
  }

  async initialize(): Promise<void> {
    await this.database.initialize();
  }

  close(): void {
    this.database.close();
  }

  describeDurability() {
    return this.database.describeDurability();
  }

  addCapability(
    capability: V2RepositoryCapability,
    lookupId: Uint8Array,
    epoch: number,
  ): void {
    this.database.putCapabilityLookup(capability, lookupId, epoch);
  }

  async registerCapability(
    capability: V2RepositoryCapability,
    lookupId: Uint8Array,
    epoch: number,
  ): Promise<void> {
    this.addCapability(capability, lookupId, epoch);
  }

  async replaceCapabilities(input: {
    revocations: readonly Pick<
      V2RepositoryCapability,
      'relationshipId' | 'direction' | 'scope'
    >[];
    registrations: readonly V2CapabilityRegistration[];
    now: number;
  }): Promise<void> {
    this.database.replaceCapabilities(input);
  }

  async findCapabilityLookup(lookupId: Uint8Array, epoch: number) {
    return this.database.findCapabilityLookup(lookupId, epoch);
  }

  async findDelivery(id: string) {
    return this.database.findDeliveryById(id);
  }

  async createRelationship(input: {
    id: string;
    canonicalOrigin: string;
    encryptedState: Uint8Array;
    createdAt: number;
  }): Promise<void> {
    this.database.createRelationship(input);
  }

  async findRelationship(id: string) {
    return this.database.findRelationship(id);
  }

  async commitCapabilityReissue(
    input: V2CapabilityReissueInput,
  ): Promise<V2CapabilityReissueOutcome> {
    return this.database.commitCapabilityReissue(input);
  }

  async claimRequestWindow(input: {
    key: string;
    minute: number;
    maximum: number;
  }): Promise<boolean> {
    return this.database.claimRequestWindow(input);
  }

  async revokeRelationship(
    input: Parameters<V2AdministrativeRepository['revokeRelationship']>[0],
  ): Promise<void> {
    this.database.revokeRelationship(input);
  }

  async rotateCapability(
    input: Parameters<V2AdministrativeRepository['rotateCapability']>[0],
  ): Promise<boolean> {
    return this.database.rotateCapability(input);
  }

  async relationshipStatus(relationshipId: string) {
    return this.database.relationshipStatus(relationshipId);
  }

  async find(locator: string): Promise<D1PairingRecord | null> {
    return this.database.findPairing(locator);
  }

  async commit(
    input: Parameters<V2PairingRepository['commit']>[0],
  ): Promise<V2PairingCommit> {
    return this.database.commitPairing(input);
  }

  async compareAndSwap(
    record: D1PairingRecord,
    next: Pick<D1PairingRecord, 'phase' | 'value'>,
  ): Promise<boolean> {
    return this.database.compareAndSwapPairing(record, next);
  }

  async admit(
    input: Parameters<V2PairingRepository['admit']>[0],
  ): Promise<boolean> {
    return this.database.admitPairing(input);
  }

  async activate(
    input: Parameters<V2PairingRepository['activate']>[0],
  ): Promise<boolean> {
    return this.database.activatePairing(input);
  }

  async claimNonce(
    capabilityId: string,
    nonce: Uint8Array,
    expiresAt: number,
    now: number,
  ): Promise<boolean> {
    return this.database.claimNonce(capabilityId, nonce, expiresAt, now);
  }

  async claimNonces(
    claims: Parameters<V2Repository['claimNonces']>[0],
    now: number,
  ): Promise<boolean> {
    return this.database.claimNonces(claims, now);
  }

  async reserveStagedBody(input: {
    id: string;
    expiresAt: number;
    now: number;
    reservedBytes: number;
    maximumConcurrentUploads: number;
    maximumStagedBytes: number;
  }): Promise<string> {
    return this.database.reserveStagedBody(
      input.id,
      input.expiresAt,
      input.now,
      input.reservedBytes,
      input.maximumConcurrentUploads,
      input.maximumStagedBytes,
    );
  }

  async releaseStagedBody(id: string): Promise<void> {
    this.database.releaseStagedBody(id);
  }

  async reserveDelivery(input: Parameters<V2Repository['reserveDelivery']>[0]) {
    return this.database.reserveDelivery(
      input.capabilityId,
      input.operationId,
      input.operationDigest,
      input.payloadLength,
      input.expiresAt,
      input.maximumTotalBytes,
      input.now,
      input.authorization,
      input.consumeControlEvents,
      input.maximumPendingDeliveries,
      input.maximumObjectsPerCapability,
    );
  }

  async publishDelivery(
    input: Omit<V2RepositoryDelivery, 'state' | 'sequence'>,
  ) {
    const existing = this.database.findDeliveryById(input.id);
    if (existing) {
      if (
        !sameBytes(existing.operationId, input.operationId) ||
        !sameBytes(existing.operationDigest, input.operationDigest)
      ) {
        throw new Error('Delivery operation conflicts with existing delivery.');
      }
      return { delivery: existing, idempotent: true };
    }
    this.database.finalizeReservation(input.id, {
      relationshipId: input.relationshipId,
      direction: directionNumber(input.direction),
      slot: input.slot,
      epoch: input.epoch,
      descriptor: input.encryptedDescriptor,
      requestedPolicy: input.requestedPolicy,
      effectivePolicy: input.effectivePolicy,
      policyDigest: input.policyDigest,
      payloadLength: input.payloadLength,
      payloadDigest: input.payloadDigest,
      payloadKey: input.payloadKey,
      operationId: input.operationId,
      operationDigest: input.operationDigest,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
    });
    const delivery = this.database.findDeliveryById(input.id);
    if (!delivery) {
      throw new Error('Published delivery is unavailable.');
    }
    return { delivery, idempotent: false };
  }

  async queryInbox(input: Parameters<V2Repository['queryInbox']>[0]) {
    if (
      input.authorization &&
      !this.database.claimInboxAuthorization({
        claims: input.authorization.claims,
        maximumRequestsPerMinute: input.authorization.maximumRequestsPerMinute,
        consumeControlEventIds:
          input.authorization.consumeControlEventIds ?? [],
        relationshipId: input.relationshipId,
        direction: directionNumber(input.direction),
        now: input.now,
      })
    ) {
      return {
        delivery: null,
        controlEvents: [],
        pendingEpochs: new Set<number>(),
        authorizationAccepted: false,
      };
    }
    const direction = directionNumber(input.direction);
    const row = this.database.selectOldestDelivery(
      input.relationshipId,
      direction,
      input.dataSlots,
      input.now,
    );
    return {
      delivery: row ? this.database.findDeliveryById(String(row.id)) : null,
      controlEvents: this.database.queryPendingControlEvents(
        input.relationshipId,
        direction,
        input.controlSlots,
        input.now,
        input.maximumControlEvents,
        input.maximumControlBytes,
      ),
      pendingEpochs: this.database.pendingDeliveryEpochs(
        input.relationshipId,
        direction,
        input.dataSlots,
        input.now,
      ),
      authorizationAccepted: true,
    };
  }

  async completeDelivery(
    input: Parameters<V2Repository['completeDelivery']>[0],
  ) {
    const idempotent = this.database.completeDelivery(
      input.id,
      input.operationId,
      input.operationDigest,
      input.completionDigest,
      input.result,
      input.now,
    );
    const delivery = this.database.findDeliveryById(input.id);
    if (!delivery) {
      throw new Error('Completed delivery is unavailable.');
    }
    return { delivery, idempotent };
  }

  async publishControlEvent(
    event: V2RepositoryControlEvent,
    authorization?: Parameters<V2Repository['publishControlEvent']>[1],
  ) {
    const result = this.database.publishControlEvent(event, authorization);
    return result
      ? { ...result, authorizationAccepted: true as const }
      : { authorizationAccepted: false as const };
  }

  async completeDeliveryWithControl(
    input: Parameters<V2Repository['completeDeliveryWithControl']>[0],
  ) {
    const result = this.database.completeDeliveryWithControl(input);
    return result
      ? { ...result, authorizationAccepted: true as const }
      : { authorizationAccepted: false as const };
  }

  async consumeControlEvents(
    input: Parameters<V2Repository['consumeControlEvents']>[0],
  ): Promise<void> {
    this.database.consumeControlEvents(input);
  }

  async runMaintenance(now: number, limit: number) {
    return this.database.runMaintenance(now, limit);
  }

  async filterKnownBodyKeys(keys: readonly string[]): Promise<string[]> {
    return this.database.filterKnownBodyKeys(keys);
  }

  async listBodyKeys(input: { cursor?: string; limit: number }) {
    return this.database.listBodyKeys(input);
  }
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  return left.every((value, index) => value === right[index]);
}
