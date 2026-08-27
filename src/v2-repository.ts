// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { BlobObject } from './types.js';
import type { V2Direction } from './v2-types.js';

export type V2DeliveryScope = 'write' | 'read' | 'ack';
export type V2DeliveryState = 'reserved' | 'published' | 'completed';

/**
 * Raised when a caller reuses one of its own operation IDs with different
 * bytes, or completes a delivery again with a different result. The conflict
 * is with the caller's own prior write, so it is reported as protocol
 * `conflict` rather than folded into the uniform rejection that hides quota,
 * rate, replay, and capability state from a proven holder.
 */
export class V2OperationConflictError extends Error {
  /**
   * Marker checked instead of `instanceof`, so a repository loaded from a
   * second copy of this module still reports a conflict as one.
   */
  readonly isV2OperationConflict = true as const;

  constructor(message: string) {
    super(message);
    this.name = 'V2OperationConflictError';
  }
}

export function isV2OperationConflict(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { isV2OperationConflict?: unknown }).isV2OperationConflict ===
      true
  );
}

export interface V2CapabilityLookup {
  lookupId: Uint8Array;
  epoch: number;
  capabilityId: string;
}

export interface V2AdministrativeRepository {
  /**
   * Charges one bounded keyed request window. Administrative and
   * authorization-failure accounting uses this rather than a whole-state
   * rewrite, so a rejected request mutates one metadata row at most.
   */
  claimRequestWindow(input: {
    key: string;
    minute: number;
    maximum: number;
  }): Promise<boolean>;
  revokeRelationship(input: {
    relationshipId: string;
    direction?: V2Direction;
    scope?: V2DeliveryScope;
    now: number;
  }): Promise<void>;
  rotateCapability(input: {
    relationshipId: string;
    direction: V2Direction;
    scope: V2DeliveryScope;
    now: number;
  }): Promise<boolean>;
  relationshipStatus(relationshipId: string): Promise<{
    fullyRevoked: boolean;
    tuples: Array<{
      direction: V2Direction;
      scope: V2DeliveryScope;
      revoked: boolean;
      rotatedAt: number;
    }>;
  }>;
}

/**
 * Opaque relationship material used by pairing and capability recovery.  The
 * handler encrypts/decrypts `encryptedState`; the repository only ever sees a
 * bounded opaque blob and the canonical origin needed for request routing.
 */
export interface V2RelationshipRepository {
  createRelationship(input: {
    id: string;
    canonicalOrigin: string;
    encryptedState: Uint8Array;
    createdAt: number;
  }): Promise<void>;
  findRelationship(id: string): Promise<{
    id: string;
    canonicalOrigin: string;
    encryptedState: Uint8Array;
    createdAt: number;
    revokedAt?: number;
  } | null>;
  /**
   * Commits an entire capability reissue request as one metadata transaction.
   * The proof nonce claim, relationship rate accounting, the live relationship
   * and tuple revocation check, and the capability replacement all apply
   * together; a rejected request leaves no nonce, rate, or capability mutation.
   */
  commitCapabilityReissue(
    input: V2CapabilityReissueInput,
  ): Promise<V2CapabilityReissueOutcome>;
}

export type V2CapabilityReissueOutcome =
  | 'accepted'
  | 'replayed'
  | 'rate_limited'
  | 'revoked';

export interface V2CapabilityReissueInput {
  relationshipId: string;
  nonce: Uint8Array;
  nonceExpiresAt: number;
  now: number;
  minute: number;
  maximumRequestsPerMinute: number;
  revocations: readonly Pick<
    V2RepositoryCapability,
    'relationshipId' | 'direction' | 'scope'
  >[];
  registrations: readonly V2CapabilityRegistration[];
}

export interface V2RepositoryCapability {
  id: string;
  relationshipId: string;
  direction: V2Direction;
  scope: V2DeliveryScope;
  encryptedTokenSecret: string;
  createdAt: number;
  expiresAt: number;
  revokedAt?: number;
}

export interface V2CapabilityRegistration {
  capability: V2RepositoryCapability;
  lookupId: Uint8Array;
  epoch: number;
}

export interface V2RepositoryDelivery {
  id: string;
  relationshipId: string;
  direction: V2Direction;
  slot: Uint8Array;
  epoch: number;
  encryptedDescriptor: Uint8Array;
  requestedPolicy: Uint8Array;
  effectivePolicy: Uint8Array;
  policyDigest: Uint8Array;
  payloadKey: string;
  payloadLength: number;
  payloadDigest: Uint8Array;
  operationId: Uint8Array;
  operationDigest: Uint8Array;
  state: V2DeliveryState;
  /**
   * Server-assigned publication order within a relationship and direction.
   * The inbox orders by it so a receiver never sees a later delivery before an
   * earlier one; `createdAt` is whole seconds and `id` is random, so neither
   * can carry that order on its own.
   */
  sequence: number;
  createdAt: number;
  expiresAt: number;
  completedAt?: number;
  completionOperationId?: Uint8Array;
  completionOperationDigest?: Uint8Array;
  completionDigest?: Uint8Array;
  completionResult?: 0 | 1;
}

export interface V2RepositoryControlEvent {
  id: string;
  relationshipId: string;
  direction: V2Direction;
  slot: Uint8Array;
  epoch: number;
  encryptedEnvelope: Uint8Array;
  operationId: Uint8Array;
  operationDigest: Uint8Array;
  sequence: number;
  createdAt: number;
  expiresAt: number;
  consumedAt?: number;
}

export interface V2DeliveryReservation {
  deliveryId: string;
  payloadKey: string;
  expiresAt: number;
}

/** Opaque encrypted payload storage; metadata never contains payload bytes. */
export interface V2BodyStore {
  stage(
    body: ReadableStream<Uint8Array>,
    expectedLength: number,
    expectedDigest: Uint8Array,
  ): Promise<string>;
  promote(stagedKey: string, key: string): Promise<void>;
  put(
    key: string,
    body: ReadableStream<Uint8Array>,
    expectedLength: number,
    expectedDigest: Uint8Array,
  ): Promise<void>;
  get(key: string): Promise<BlobObject | null>;
  head(key: string): Promise<boolean>;
  delete(key: string): Promise<void>;
}

export interface V2BodyInventoryEntry {
  key: string;
  size: number;
  /** Storage-side last modification, in seconds, or undefined when unknown. */
  modifiedAt?: number;
}

/**
 * Bounded walk over the opaque body namespace, used only by the explicit
 * administrator reconciliation command. Request handling never lists storage:
 * this method is outside {@link V2BodyStore} so no delivery,
 * inbox, control, or pairing path can reach it.
 */
export interface V2BodyInventory {
  listBodies(input: { cursor?: string; limit: number }): Promise<{
    entries: V2BodyInventoryEntry[];
    cursor?: string;
  }>;
}

/**
 * Bounded metadata lookups that pair a storage walk with the body keys
 * metadata still names. Like {@link V2BodyInventory} this is separate from
 * {@link V2Repository} so only the administrator command can reach it.
 */
export interface V2ReconciliationRepository {
  /** Returns the subset of `keys` that live metadata still names. */
  filterKnownBodyKeys(keys: readonly string[]): Promise<string[]>;
  /** One ordered, bounded page of every body key metadata names. */
  listBodyKeys(input: { cursor?: string; limit: number }): Promise<{
    keys: string[];
    cursor?: string;
  }>;
}

export interface V2MaintenanceResult {
  expiredDeliveryIds: string[];
  expiredBodyKeys: string[];
  deletedNonces: number;
  deletedControlEvents: number;
  deletedRateWindows: number;
  deletedInvitations: number;
  /**
   * False when at least one bounded category filled its batch limit, so the
   * caller should run another pass before considering the backend drained.
   */
  complete: boolean;
}

/**
 * The granular metadata contract. Every mutating operation is expected to
 * claim its nonce, apply rate accounting, re-check authorization and commit
 * only records involved in that operation in one backend transaction.
 */
export interface V2Repository {
  initialize(): Promise<void>;
  registerCapability(
    capability: V2RepositoryCapability,
    lookupId: Uint8Array,
    epoch: number,
  ): Promise<void>;
  /** Atomically retire capability tuples and publish their replacement lookups. */
  replaceCapabilities(input: {
    revocations: readonly Pick<
      V2RepositoryCapability,
      'relationshipId' | 'direction' | 'scope'
    >[];
    registrations: readonly V2CapabilityRegistration[];
    now: number;
  }): Promise<void>;
  findCapabilityLookup(
    lookupId: Uint8Array,
    epoch: number,
  ): Promise<V2RepositoryCapability | null>;
  findDelivery(id: string): Promise<V2RepositoryDelivery | null>;
  claimNonce(
    capabilityId: string,
    nonce: Uint8Array,
    expiresAt: number,
    now: number,
  ): Promise<boolean>;
  /** Claims every proof nonce in one metadata mutation, or claims none. */
  claimNonces(
    claims: readonly {
      capabilityId: string;
      nonce: Uint8Array;
      expiresAt: number;
    }[],
    now: number,
  ): Promise<boolean>;
  reserveStagedBody(input: {
    id: string;
    expiresAt: number;
    now: number;
    reservedBytes: number;
    maximumConcurrentUploads: number;
    maximumStagedBytes: number;
  }): Promise<string>;
  releaseStagedBody(id: string): Promise<void>;
  reserveDelivery(input: {
    capabilityId: string;
    operationId: Uint8Array;
    operationDigest: Uint8Array;
    payloadLength: number;
    /** Maximum aggregate published plus in-flight bytes for the relationship. */
    maximumTotalBytes?: number;
    /** Maximum published-but-uncompleted deliveries for the relationship. */
    maximumPendingDeliveries?: number;
    /** Maximum retained or in-flight delivery objects for the relationship. */
    maximumObjectsPerCapability?: number;
    /** Bound proof claims committed with the reservation, never beforehand. */
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
    };
    /** Control acknowledgements committed with the delivery reservation. */
    consumeControlEvents?: {
      ids: readonly string[];
      relationshipId: string;
      direction: V2Direction;
      now: number;
    };
    now: number;
    expiresAt: number;
  }): Promise<V2DeliveryReservation | { existing: V2RepositoryDelivery }>;
  publishDelivery(
    input: Omit<V2RepositoryDelivery, 'state' | 'sequence'>,
  ): Promise<{
    delivery: V2RepositoryDelivery;
    idempotent: boolean;
  }>;
  queryInbox(input: {
    relationshipId: string;
    direction: V2Direction;
    dataSlots: readonly { slot: Uint8Array; epoch: number }[];
    controlSlots: readonly { slot: Uint8Array; epoch: number }[];
    /** Bounds the control batch before it is materialized into an inbox reply. */
    maximumControlEvents?: number;
    maximumControlBytes?: number;
    /** Inbox proof claims and control consumption share one metadata mutation. */
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
      consumeControlEventIds?: readonly string[];
    };
    now: number;
  }): Promise<{
    delivery: V2RepositoryDelivery | null;
    controlEvents: V2RepositoryControlEvent[];
    pendingEpochs: Set<number>;
    authorizationAccepted: boolean;
  }>;
  completeDelivery(input: {
    id: string;
    operationId: Uint8Array;
    operationDigest: Uint8Array;
    completionDigest: Uint8Array;
    result: 0 | 1;
    now: number;
  }): Promise<{ delivery: V2RepositoryDelivery; idempotent: boolean }>;
  completeDeliveryWithControl(input: {
    completion: {
      id: string;
      operationId: Uint8Array;
      operationDigest: Uint8Array;
      completionDigest: Uint8Array;
      result: 0 | 1;
      now: number;
    };
    event: V2RepositoryControlEvent;
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
      controlQuota?: {
        maximumEvents: number;
        maximumBytes: number;
      };
    };
  }): Promise<
    | {
        delivery: V2RepositoryDelivery;
        event: V2RepositoryControlEvent;
        idempotent: boolean;
        authorizationAccepted: true;
      }
    | { authorizationAccepted: false }
  >;
  publishControlEvent(
    event: V2RepositoryControlEvent,
    authorization?: {
      claims: readonly {
        capabilityId: string;
        nonce: Uint8Array;
        expiresAt: number;
      }[];
      maximumRequestsPerMinute: number;
      controlQuota?: {
        maximumEvents: number;
        maximumBytes: number;
      };
    },
  ): Promise<
    | {
        event: V2RepositoryControlEvent;
        idempotent: boolean;
        authorizationAccepted: true;
      }
    | { authorizationAccepted: false }
  >;
  consumeControlEvents(input: {
    ids: readonly string[];
    relationshipId: string;
    direction: V2Direction;
    now: number;
  }): Promise<void>;
  /**
   * One bounded, restartable batch. Every category is limited to `limit`
   * records so a pass never grows with the backend, and `complete` tells the
   * caller whether another batch is needed to drain the expired records.
   */
  runMaintenance(now: number, limit: number): Promise<V2MaintenanceResult>;
}
