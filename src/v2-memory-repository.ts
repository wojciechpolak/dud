// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { bytesEqual } from './cbor.js';
import { runMemoryV2Maintenance } from './v2-memory-maintenance.js';
import { V2OperationConflictError } from './v2-repository.js';
import type {
  V2CapabilityRegistration,
  V2DeliveryReservation,
  V2Repository,
  V2RepositoryCapability,
  V2RepositoryControlEvent,
  V2RepositoryDelivery,
  V2ReconciliationRepository,
} from './v2-repository.js';

export { MemoryV2BodyStore } from './v2-memory-body-store.js';

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function operationKey(operationId: Uint8Array): string {
  if (operationId.byteLength !== 16) {
    throw new Error('Operation ID is invalid.');
  }
  return hex(operationId);
}

type ReserveDeliveryInput = Parameters<V2Repository['reserveDelivery']>[0];
type ReserveDeliveryResult =
  | V2DeliveryReservation
  | { existing: V2RepositoryDelivery };

interface DeliveryAuthorizationClaims {
  nonceKeys: string[];
  rateCounts: Map<string, number>;
}

/** Reference repository used by conformance tests and local handler tests. */
export class MemoryV2Repository
  implements V2Repository, V2ReconciliationRepository
{
  private readonly capabilities = new Map<string, V2RepositoryCapability>();
  private readonly lookups = new Map<string, string>();
  private readonly nonces = new Map<string, number>();
  private readonly rateWindows = new Map<
    string,
    { minute: number; count: number }
  >();
  private readonly deliveries = new Map<string, V2RepositoryDelivery>();
  private readonly reservations = new Map<string, V2DeliveryReservation>();
  private readonly stagedBodies = new Map<
    string,
    { expiresAt: number; reservedBytes: number }
  >();
  private readonly reservationBytes = new Map<string, number>();
  private readonly reservationObjects = new Set<string>();
  private readonly deliveryObjects = new Set<string>();
  private readonly reservationRelationships = new Map<string, string>();
  private readonly reservationDirections = new Map<
    string,
    V2RepositoryCapability['direction']
  >();
  private readonly quotaAccounts = new Map<
    string,
    { committedBytes: number; reservedBytes: number; objectCount: number }
  >();
  private readonly controlEvents = new Map<string, V2RepositoryControlEvent>();
  private readonly operations = new Map<
    string,
    { digest: Uint8Array; deliveryId: string }
  >();
  private readonly controlOperations = new Map<string, string>();
  private readonly controlSequences = new Map<string, number>();
  private readonly deliverySequences = new Map<string, number>();

  async initialize(): Promise<void> {}

  addCapability(
    capability: V2RepositoryCapability,
    lookupId: Uint8Array,
    epoch: number,
  ): void {
    if (lookupId.byteLength !== 16) {
      throw new Error('Capability lookup ID is invalid.');
    }
    this.capabilities.set(capability.id, clone(capability));
    this.lookups.set(`${epoch}|${hex(lookupId)}`, capability.id);
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
    for (const registration of input.registrations) {
      if (registration.lookupId.byteLength !== 16) {
        throw new Error('Capability lookup ID is invalid.');
      }
    }
    for (const revoked of input.revocations) {
      for (const capability of this.capabilities.values()) {
        if (
          capability.relationshipId === revoked.relationshipId &&
          capability.direction === revoked.direction &&
          capability.scope === revoked.scope
        ) {
          capability.revokedAt = input.now;
        }
      }
    }
    for (const registration of input.registrations) {
      this.addCapability(
        registration.capability,
        registration.lookupId,
        registration.epoch,
      );
    }
  }

  async findCapabilityLookup(
    lookupId: Uint8Array,
    epoch: number,
  ): Promise<V2RepositoryCapability | null> {
    const id = this.lookups.get(`${epoch}|${hex(lookupId)}`);
    const capability = id ? this.capabilities.get(id) : undefined;
    return capability ? clone(capability) : null;
  }

  async findDelivery(id: string): Promise<V2RepositoryDelivery | null> {
    const delivery = this.deliveries.get(id);
    return delivery ? clone(delivery) : null;
  }

  async claimNonce(
    capabilityId: string,
    nonce: Uint8Array,
    expiresAt: number,
    now: number,
  ): Promise<boolean> {
    const key = `${capabilityId}|${hex(nonce)}`;
    const previous = this.nonces.get(key);
    if (previous !== undefined && previous >= now) {
      return false;
    }
    this.nonces.set(key, expiresAt);
    return true;
  }

  async claimNonces(
    claims: readonly {
      capabilityId: string;
      nonce: Uint8Array;
      expiresAt: number;
    }[],
    now: number,
  ): Promise<boolean> {
    const keys = claims.map(
      ({ capabilityId, nonce }) => `${capabilityId}|${hex(nonce)}`,
    );
    if (new Set(keys).size !== keys.length) {
      return false;
    }
    if (
      keys.some((key) => {
        const expiresAt = this.nonces.get(key);
        return expiresAt !== undefined && expiresAt >= now;
      })
    ) {
      return false;
    }
    for (const [index, key] of keys.entries()) {
      this.nonces.set(key, claims[index]!.expiresAt);
    }
    return true;
  }

  async reserveStagedBody(input: {
    id: string;
    expiresAt: number;
    now: number;
    reservedBytes: number;
    maximumConcurrentUploads: number;
    maximumStagedBytes: number;
  }): Promise<string> {
    if (
      !/^[a-f0-9]{32}$/.test(input.id) ||
      input.expiresAt < input.now ||
      !Number.isSafeInteger(input.reservedBytes) ||
      input.reservedBytes < 0
    ) {
      throw new Error('Staged body is invalid.');
    }
    for (const [id, staged] of this.stagedBodies) {
      if (staged.expiresAt <= input.now) {
        this.stagedBodies.delete(id);
      }
    }
    const active = Array.from(this.stagedBodies.values());
    if (
      active.length >= input.maximumConcurrentUploads ||
      active.reduce((total, staged) => total + staged.reservedBytes, 0) +
        input.reservedBytes >
        input.maximumStagedBytes
    ) {
      throw new Error('Staging quota is exhausted.');
    }
    this.stagedBodies.set(input.id, {
      expiresAt: input.expiresAt,
      reservedBytes: input.reservedBytes,
    });
    return `staging/${input.id}.bin`;
  }

  async releaseStagedBody(id: string): Promise<void> {
    this.stagedBodies.delete(id);
  }

  private activeDeliveryCapability(
    capabilityId: string,
    now: number,
  ): V2RepositoryCapability {
    const capability = this.capabilities.get(capabilityId);
    if (
      !capability ||
      capability.revokedAt !== undefined ||
      capability.expiresAt <= now
    ) {
      throw new Error('Delivery capability is not active.');
    }
    return capability;
  }

  private validateDeliveryAuthorization(
    authorization: ReserveDeliveryInput['authorization'],
    now: number,
  ): DeliveryAuthorizationClaims {
    const nonceKeys =
      authorization?.claims.map(
        (claim) => `${claim.capabilityId}|${hex(claim.nonce)}`,
      ) ?? [];
    const rateCounts = new Map<string, number>();
    if (!authorization) {
      return { nonceKeys, rateCounts };
    }
    for (const claim of authorization.claims) {
      const authorized = this.capabilities.get(claim.capabilityId);
      if (
        !authorized ||
        authorized.revokedAt !== undefined ||
        authorized.expiresAt <= now
      ) {
        throw new Error('Request capability is not active.');
      }
      rateCounts.set(
        claim.capabilityId,
        (rateCounts.get(claim.capabilityId) ?? 0) + 1,
      );
    }
    const minute = Math.floor(now / 60);
    const unavailable =
      new Set(nonceKeys).size !== nonceKeys.length ||
      nonceKeys.some((key) => (this.nonces.get(key) ?? -1) >= now) ||
      Array.from(rateCounts).some(([capabilityId, count]) => {
        const window = this.rateWindows.get(capabilityId);
        return (
          (window?.minute === minute ? window.count : 0) + count >
          authorization.maximumRequestsPerMinute
        );
      });
    if (unavailable) {
      throw new Error('Request authorization is unavailable.');
    }
    return { nonceKeys, rateCounts };
  }

  private resolveExistingReservation(
    input: ReserveDeliveryInput,
    operation: string,
    claims: DeliveryAuthorizationClaims,
  ): ReserveDeliveryResult | null {
    const existing = this.operations.get(operation);
    if (!existing) {
      return null;
    }
    if (!bytesEqual(existing.digest, input.operationDigest)) {
      throw new V2OperationConflictError(
        'Operation ID conflicts with different bytes.',
      );
    }
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
    this.markControlEventsConsumed(input.consumeControlEvents);
    const delivery = this.deliveries.get(existing.deliveryId);
    if (delivery) {
      return { existing: clone(delivery) };
    }
    const reservation = this.reservations.get(existing.deliveryId);
    if (!reservation) {
      throw new Error('Operation reservation is incomplete.');
    }
    return clone(reservation);
  }

  private assertPendingDeliveryLimit(
    input: ReserveDeliveryInput,
    capability: V2RepositoryCapability,
  ): void {
    if (input.maximumPendingDeliveries === undefined) {
      return;
    }
    const pendingDeliveries = Array.from(this.deliveries.values()).filter(
      (delivery) =>
        delivery.state === 'published' &&
        delivery.expiresAt > input.now &&
        delivery.relationshipId === capability.relationshipId &&
        delivery.direction === capability.direction,
    ).length;
    const pendingReservations = Array.from(this.reservations).filter(
      ([id, reservation]) =>
        reservation.expiresAt > input.now &&
        this.reservationRelationships.get(id) === capability.relationshipId &&
        this.reservationDirections.get(id) === capability.direction,
    ).length;
    if (
      pendingDeliveries + pendingReservations >=
      input.maximumPendingDeliveries
    ) {
      throw new Error('Relationship pending delivery limit is reached.');
    }
  }

  private assertDeliveryQuota(
    input: ReserveDeliveryInput,
    relationshipId: string,
  ): void {
    const account = this.quotaAccounts.get(relationshipId) ?? {
      committedBytes: 0,
      reservedBytes: 0,
      objectCount: 0,
    };
    if (
      input.maximumTotalBytes !== undefined &&
      account.committedBytes + account.reservedBytes + input.payloadLength >
        input.maximumTotalBytes
    ) {
      throw new Error('Relationship delivery quota is exhausted.');
    }
    if (
      input.maximumObjectsPerCapability !== undefined &&
      account.objectCount >= input.maximumObjectsPerCapability
    ) {
      throw new Error('Relationship delivery object quota is exhausted.');
    }
  }

  private createDeliveryReservation(
    input: ReserveDeliveryInput,
    capability: V2RepositoryCapability,
    operation: string,
    claims: DeliveryAuthorizationClaims,
  ): V2DeliveryReservation {
    this.commitDeliveryAuthorization(
      input.authorization,
      claims.nonceKeys,
      claims.rateCounts,
      input.now,
    );
    const deliveryId = crypto.randomUUID().replaceAll('-', '');
    const reservation = {
      deliveryId,
      payloadKey: `deliveries/${deliveryId}.bin`,
      expiresAt: input.expiresAt,
    };
    this.reservations.set(deliveryId, reservation);
    this.reservationRelationships.set(deliveryId, capability.relationshipId);
    this.reservationDirections.set(deliveryId, capability.direction);
    this.reserveDeliveryQuota(input, capability.relationshipId, deliveryId);
    this.operations.set(operation, {
      digest: Uint8Array.from(input.operationDigest),
      deliveryId,
    });
    this.markControlEventsConsumed(input.consumeControlEvents);
    return clone(reservation);
  }

  private reserveDeliveryQuota(
    input: ReserveDeliveryInput,
    relationshipId: string,
    deliveryId: string,
  ): void {
    if (
      input.maximumTotalBytes === undefined &&
      input.maximumObjectsPerCapability === undefined
    ) {
      return;
    }
    const account = this.quotaAccounts.get(relationshipId) ?? {
      committedBytes: 0,
      reservedBytes: 0,
      objectCount: 0,
    };
    if (input.maximumTotalBytes !== undefined) {
      account.reservedBytes += input.payloadLength;
      this.reservationBytes.set(deliveryId, input.payloadLength);
    }
    if (input.maximumObjectsPerCapability !== undefined) {
      account.objectCount++;
      this.reservationObjects.add(deliveryId);
    }
    this.quotaAccounts.set(relationshipId, account);
  }

  async reserveDelivery(
    input: ReserveDeliveryInput,
  ): Promise<ReserveDeliveryResult> {
    const capability = this.activeDeliveryCapability(
      input.capabilityId,
      input.now,
    );
    const claims = this.validateDeliveryAuthorization(
      input.authorization,
      input.now,
    );
    const operation = operationKey(input.operationId);
    const existing = this.resolveExistingReservation(input, operation, claims);
    if (existing) {
      return existing;
    }
    this.assertPendingDeliveryLimit(input, capability);
    this.assertDeliveryQuota(input, capability.relationshipId);
    return this.createDeliveryReservation(input, capability, operation, claims);
  }

  async publishDelivery(
    input: Omit<V2RepositoryDelivery, 'state' | 'sequence'>,
  ): Promise<{ delivery: V2RepositoryDelivery; idempotent: boolean }> {
    const key = operationKey(input.operationId);
    const operation = this.operations.get(key);
    if (!operation || operation.deliveryId !== input.id) {
      throw new Error('Delivery was not reserved.');
    }
    if (!bytesEqual(operation.digest, input.operationDigest)) {
      throw new V2OperationConflictError(
        'Operation ID conflicts with different bytes.',
      );
    }
    const existing = this.deliveries.get(input.id);
    if (existing) {
      return { delivery: clone(existing), idempotent: true };
    }
    const sequenceKey = `${input.relationshipId}|${input.direction}`;
    const sequence = (this.deliverySequences.get(sequenceKey) ?? 0) + 1;
    this.deliverySequences.set(sequenceKey, sequence);
    const delivery = { ...clone(input), state: 'published' as const, sequence };
    this.deliveries.set(delivery.id, delivery);
    this.reservations.delete(delivery.id);
    this.reservationRelationships.delete(delivery.id);
    this.reservationDirections.delete(delivery.id);
    if (this.reservationObjects.delete(delivery.id)) {
      this.deliveryObjects.add(delivery.id);
    }
    const reservedBytes = this.reservationBytes.get(delivery.id);
    if (reservedBytes !== undefined) {
      const account = this.quotaAccounts.get(delivery.relationshipId);
      if (account) {
        account.reservedBytes -= reservedBytes;
        account.committedBytes += reservedBytes;
      }
      this.reservationBytes.delete(delivery.id);
    }
    return { delivery: clone(delivery), idempotent: false };
  }

  async queryInbox(input: Parameters<V2Repository['queryInbox']>[0]) {
    const authorization = input.authorization;
    if (authorization) {
      const nonceKeys = authorization.claims.map(
        ({ capabilityId, nonce }) => `${capabilityId}|${hex(nonce)}`,
      );
      const rateCounts = new Map<string, number>();
      for (const claim of authorization.claims) {
        const capability = this.capabilities.get(claim.capabilityId);
        if (
          !capability ||
          capability.revokedAt !== undefined ||
          capability.expiresAt <= input.now
        ) {
          return this.rejectedInbox();
        }
        rateCounts.set(
          claim.capabilityId,
          (rateCounts.get(claim.capabilityId) ?? 0) + 1,
        );
      }
      const minute = Math.floor(input.now / 60);
      if (
        new Set(nonceKeys).size !== nonceKeys.length ||
        nonceKeys.some((key) => (this.nonces.get(key) ?? -1) >= input.now) ||
        Array.from(rateCounts).some(([capabilityId, count]) => {
          const window = this.rateWindows.get(capabilityId);
          return (
            (window?.minute === minute ? window.count : 0) + count >
            authorization.maximumRequestsPerMinute
          );
        })
      ) {
        return this.rejectedInbox();
      }
      this.commitDeliveryAuthorization(
        authorization,
        nonceKeys,
        rateCounts,
        input.now,
      );
      this.markControlEventsConsumed({
        ids: authorization.consumeControlEventIds ?? [],
        relationshipId: input.relationshipId,
        direction: input.direction,
        now: input.now,
      });
    }
    const dataSlots = new Set(
      input.dataSlots.map(({ slot, epoch }) => `${epoch}|${hex(slot)}`),
    );
    const controlSlots = new Set(
      input.controlSlots.map(({ slot, epoch }) => `${epoch}|${hex(slot)}`),
    );
    const pending = Array.from(this.deliveries.values())
      .filter(
        (delivery) =>
          delivery.state === 'published' &&
          delivery.expiresAt > input.now &&
          delivery.relationshipId === input.relationshipId &&
          delivery.direction === input.direction &&
          dataSlots.has(`${delivery.epoch}|${hex(delivery.slot)}`),
      )
      .sort(
        (a, b) =>
          a.sequence - b.sequence ||
          a.createdAt - b.createdAt ||
          a.id.localeCompare(b.id),
      );
    const events = Array.from(this.controlEvents.values())
      .filter(
        (event) =>
          !event.consumedAt &&
          event.expiresAt > input.now &&
          event.relationshipId === input.relationshipId &&
          event.direction === input.direction &&
          controlSlots.has(`${event.epoch}|${hex(event.slot)}`),
      )
      .sort((a, b) => a.sequence - b.sequence);
    const boundedEvents: V2RepositoryControlEvent[] = [];
    let controlBytes = 0;
    for (const event of events) {
      if (
        boundedEvents.length >=
          (input.maximumControlEvents ?? Number.MAX_SAFE_INTEGER) ||
        controlBytes + event.encryptedEnvelope.byteLength >
          (input.maximumControlBytes ?? Number.MAX_SAFE_INTEGER)
      ) {
        break;
      }
      boundedEvents.push(event);
      controlBytes += event.encryptedEnvelope.byteLength;
    }
    return {
      delivery: pending[0] ? clone(pending[0]) : null,
      controlEvents: clone(boundedEvents),
      pendingEpochs: new Set(pending.map((delivery) => delivery.epoch)),
      authorizationAccepted: true,
    };
  }

  async completeDelivery(
    input: Parameters<V2Repository['completeDelivery']>[0],
  ) {
    const delivery = this.deliveries.get(input.id);
    if (!delivery) {
      throw new Error('Delivery is unavailable.');
    }
    if (delivery.state === 'completed') {
      if (
        !delivery.completionDigest ||
        !delivery.completionOperationId ||
        !delivery.completionOperationDigest ||
        delivery.completionResult !== input.result ||
        !bytesEqual(delivery.completionDigest, input.completionDigest) ||
        !bytesEqual(delivery.completionOperationId, input.operationId) ||
        !bytesEqual(delivery.completionOperationDigest, input.operationDigest)
      ) {
        throw new V2OperationConflictError(
          'Delivery completion conflicts with prior result.',
        );
      }
      return { delivery: clone(delivery), idempotent: true };
    }
    delivery.state = 'completed';
    delivery.completedAt = input.now;
    delivery.completionOperationId = Uint8Array.from(input.operationId);
    delivery.completionOperationDigest = Uint8Array.from(input.operationDigest);
    delivery.completionDigest = Uint8Array.from(input.completionDigest);
    delivery.completionResult = input.result;
    return { delivery: clone(delivery), idempotent: false };
  }

  async publishControlEvent(
    event: V2RepositoryControlEvent,
    authorization?: Parameters<V2Repository['publishControlEvent']>[1],
  ) {
    const nonceKeys = authorization
      ? authorization.claims.map(
          ({ capabilityId, nonce }) => `${capabilityId}|${hex(nonce)}`,
        )
      : [];
    const rateCounts = new Map<string, number>();
    if (authorization) {
      for (const claim of authorization.claims) {
        const capability = this.capabilities.get(claim.capabilityId);
        if (
          !capability ||
          capability.revokedAt !== undefined ||
          capability.expiresAt <= event.createdAt
        ) {
          return { authorizationAccepted: false as const };
        }
        rateCounts.set(
          claim.capabilityId,
          (rateCounts.get(claim.capabilityId) ?? 0) + 1,
        );
      }
      const minute = Math.floor(event.createdAt / 60);
      if (
        new Set(nonceKeys).size !== nonceKeys.length ||
        nonceKeys.some(
          (key) => (this.nonces.get(key) ?? -1) >= event.createdAt,
        ) ||
        Array.from(rateCounts).some(([capabilityId, count]) => {
          const window = this.rateWindows.get(capabilityId);
          return (
            (window?.minute === minute ? window.count : 0) + count >
            authorization.maximumRequestsPerMinute
          );
        })
      ) {
        return { authorizationAccepted: false as const };
      }
    }
    this.assertControlEventCompatible(event);
    const operation = operationKey(event.operationId);
    const existingId = this.controlOperations.get(operation);
    if (existingId) {
      const existing = this.controlEvents.get(existingId);
      if (
        !existing ||
        !bytesEqual(existing.operationDigest, event.operationDigest)
      ) {
        throw new V2OperationConflictError(
          'Control operation conflicts with different bytes.',
        );
      }
      return {
        event: clone(existing),
        idempotent: true,
        authorizationAccepted: true as const,
      };
    }
    if (this.controlEvents.has(event.id)) {
      throw new V2OperationConflictError(
        'Control event ID conflicts with a prior operation.',
      );
    }
    const quota = authorization?.controlQuota;
    if (quota) {
      const active = Array.from(this.controlEvents.values()).filter(
        (existing) =>
          existing.relationshipId === event.relationshipId &&
          existing.direction === event.direction &&
          existing.expiresAt > event.createdAt,
      );
      if (
        active.length >= quota.maximumEvents ||
        active.reduce(
          (total, existing) => total + existing.encryptedEnvelope.byteLength,
          0,
        ) +
          event.encryptedEnvelope.byteLength >
          quota.maximumBytes
      ) {
        throw new Error('Control event quota is exhausted.');
      }
    }
    this.commitDeliveryAuthorization(
      authorization,
      nonceKeys,
      rateCounts,
      event.createdAt,
    );
    const sequenceKey = `${event.relationshipId}|${event.direction}`;
    const sequence = (this.controlSequences.get(sequenceKey) ?? 0) + 1;
    this.controlSequences.set(sequenceKey, sequence);
    const stored = { ...clone(event), sequence };
    this.controlEvents.set(stored.id, stored);
    this.controlOperations.set(operation, stored.id);
    return {
      event: clone(stored),
      idempotent: false,
      authorizationAccepted: true as const,
    };
  }

  async completeDeliveryWithControl(input: {
    completion: Parameters<V2Repository['completeDelivery']>[0];
    event: V2RepositoryControlEvent;
    authorization?: Parameters<
      V2Repository['completeDeliveryWithControl']
    >[0]['authorization'];
  }) {
    const authorization = input.authorization;
    const nonceKeys = authorization
      ? authorization.claims.map(
          ({ capabilityId, nonce }) => `${capabilityId}|${hex(nonce)}`,
        )
      : [];
    const rateCounts = new Map<string, number>();
    if (authorization) {
      for (const claim of authorization.claims) {
        const capability = this.capabilities.get(claim.capabilityId);
        if (
          !capability ||
          capability.revokedAt !== undefined ||
          capability.expiresAt <= input.completion.now
        ) {
          return { authorizationAccepted: false as const };
        }
        rateCounts.set(
          claim.capabilityId,
          (rateCounts.get(claim.capabilityId) ?? 0) + 1,
        );
      }
      const minute = Math.floor(input.completion.now / 60);
      if (
        new Set(nonceKeys).size !== nonceKeys.length ||
        nonceKeys.some(
          (key) => (this.nonces.get(key) ?? -1) >= input.completion.now,
        ) ||
        Array.from(rateCounts).some(([capabilityId, count]) => {
          const window = this.rateWindows.get(capabilityId);
          return (
            (window?.minute === minute ? window.count : 0) + count >
            authorization.maximumRequestsPerMinute
          );
        })
      ) {
        return { authorizationAccepted: false as const };
      }
    }
    this.assertCompletionCompatible(input.completion);
    this.assertControlEventCompatible(input.event);
    this.commitDeliveryAuthorization(
      authorization,
      nonceKeys,
      rateCounts,
      input.completion.now,
    );
    const completion = await this.completeDelivery(input.completion);
    const control = await this.publishControlEvent(
      input.event,
      authorization
        ? {
            claims: [],
            maximumRequestsPerMinute: authorization.maximumRequestsPerMinute,
            controlQuota: authorization.controlQuota,
          }
        : undefined,
    );
    if (!control.authorizationAccepted) {
      throw new Error('Control event authorization is unavailable.');
    }
    return {
      delivery: completion.delivery,
      event: control.event,
      idempotent: completion.idempotent && control.idempotent,
      authorizationAccepted: true as const,
    };
  }

  async consumeControlEvents(input: {
    ids: readonly string[];
    relationshipId: string;
    direction: V2RepositoryControlEvent['direction'];
    now: number;
  }): Promise<void> {
    this.markControlEventsConsumed(input);
  }

  private markControlEventsConsumed(
    input:
      | {
          ids: readonly string[];
          relationshipId: string;
          direction: V2RepositoryControlEvent['direction'];
          now: number;
        }
      | undefined,
  ): void {
    if (!input) {
      return;
    }
    for (const id of input.ids) {
      const event = this.controlEvents.get(id);
      if (
        event &&
        event.relationshipId === input.relationshipId &&
        event.direction === input.direction
      ) {
        event.consumedAt = input.now;
      }
    }
  }

  private assertCompletionCompatible(
    input: Parameters<V2Repository['completeDelivery']>[0],
  ): void {
    const delivery = this.deliveries.get(input.id);
    if (!delivery) {
      throw new Error('Delivery is unavailable.');
    }
    if (delivery.state !== 'completed') {
      return;
    }
    if (
      !delivery.completionDigest ||
      !delivery.completionOperationId ||
      !delivery.completionOperationDigest ||
      delivery.completionResult !== input.result ||
      !bytesEqual(delivery.completionDigest, input.completionDigest) ||
      !bytesEqual(delivery.completionOperationId, input.operationId) ||
      !bytesEqual(delivery.completionOperationDigest, input.operationDigest)
    ) {
      throw new V2OperationConflictError(
        'Delivery completion conflicts with prior result.',
      );
    }
  }

  private rejectedInbox() {
    return {
      delivery: null,
      controlEvents: [],
      pendingEpochs: new Set<number>(),
      authorizationAccepted: false,
    };
  }

  private assertControlEventCompatible(event: V2RepositoryControlEvent): void {
    const existingId = this.controlOperations.get(
      operationKey(event.operationId),
    );
    if (existingId) {
      const existing = this.controlEvents.get(existingId);
      if (
        !existing ||
        !bytesEqual(existing.operationDigest, event.operationDigest)
      ) {
        throw new V2OperationConflictError(
          'Control operation conflicts with different bytes.',
        );
      }
      return;
    }
    if (this.controlEvents.has(event.id)) {
      throw new V2OperationConflictError(
        'Control event ID conflicts with a prior operation.',
      );
    }
  }
  async runMaintenance(now: number, limit: number) {
    return runMemoryV2Maintenance(
      {
        deliveries: this.deliveries,
        reservations: this.reservations,
        stagedBodies: this.stagedBodies,
        reservationBytes: this.reservationBytes,
        reservationObjects: this.reservationObjects,
        deliveryObjects: this.deliveryObjects,
        reservationRelationships: this.reservationRelationships,
        reservationDirections: this.reservationDirections,
        quotaAccounts: this.quotaAccounts,
        operations: this.operations,
        nonces: this.nonces,
        controlEvents: this.controlEvents,
        controlOperations: this.controlOperations,
        rateWindows: this.rateWindows,
      },
      now,
      limit,
    );
  }

  /** Reconciliation-only bounded lookups; no request path calls these. */
  async filterKnownBodyKeys(keys: readonly string[]): Promise<string[]> {
    const known = new Set(this.metadataBodyKeys());
    return keys.filter((key) => known.has(key));
  }

  async listBodyKeys(input: {
    cursor?: string;
    limit: number;
  }): Promise<{ keys: string[]; cursor?: string }> {
    if (!Number.isSafeInteger(input.limit) || input.limit < 1) {
      throw new Error('Body key page limit is invalid.');
    }
    const keys = this.metadataBodyKeys()
      .filter((key) => input.cursor === undefined || key > input.cursor)
      .sort()
      .slice(0, input.limit);
    return {
      keys,
      ...(keys.length === input.limit ? { cursor: keys[keys.length - 1] } : {}),
    };
  }

  private metadataBodyKeys(): string[] {
    return [
      ...Array.from(this.deliveries.values(), (value) => value.payloadKey),
      ...Array.from(this.reservations.values(), (value) => value.payloadKey),
    ];
  }

  private commitDeliveryAuthorization(
    authorization: Parameters<
      V2Repository['reserveDelivery']
    >[0]['authorization'],
    nonceKeys: readonly string[],
    rateCounts: ReadonlyMap<string, number>,
    now: number,
  ): void {
    if (!authorization) {
      return;
    }
    for (const [index, key] of nonceKeys.entries()) {
      this.nonces.set(key, authorization.claims[index]!.expiresAt);
    }
    const minute = Math.floor(now / 60);
    for (const [capabilityId, count] of rateCounts) {
      const window = this.rateWindows.get(capabilityId);
      this.rateWindows.set(capabilityId, {
        minute,
        count: (window?.minute === minute ? window.count : 0) + count,
      });
    }
  }
}
