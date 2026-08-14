// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export type V2QuotaEnforcement = 'atomic' | 'best-effort';
export type V2Direction = 'inviter->invitee' | 'invitee->inviter';
export type V2Scope = 'write' | 'read' | 'ack';

export interface V2CapabilityRecord {
  id: string;
  relationshipId: string;
  direction: V2Direction;
  scope: V2Scope;
  encryptedTokenSecret: string;
  createdAt: number;
  expiresAt: number;
  revoked: boolean;
  rotatedAt: number;
}

/** Staged-byte reservation for an in-flight V1 upload. */
export interface V2ReservationRecord {
  id: string;
  objectId: string;
  reservedBytes: number;
  expiresAt: number;
}

export interface V2BearerVerifier {
  salt: string;
  digest: string;
}

/** Committed V1 object accounted against the shared deployment quota. */
export interface V2LegacyObjectRecord {
  objectId: string;
  ciphertextSize: number;
  expiresAt: number;
}

export interface V2RevocationRecord {
  relationshipId: string;
  direction?: V2Direction;
  scope?: V2Scope;
  revoked: boolean;
  rotatedAt: number;
}

export interface V2RateWindow {
  minute: number;
  count: number;
}

export interface V2PairingCompletionRecord {
  map: string;
  signature: string;
  digest: string;
}

export interface V2PairingInvitationRecord {
  locator: string;
  envelopeNonce: string;
  envelopeCiphertext: string;
  bootstrapVerifier: V2BearerVerifier;
  inviterStatusVerifier: V2BearerVerifier;
  createdAt: number;
  expiresAt: number;
  phase: 0 | 1 | 2 | 3 | 4;
  invitationId?: string;
  relationshipId?: string;
  inviterPairingId?: string;
  inviterAgeRecipient?: string;
  inviterSigningPublicKey?: string;
  canonicalOrigin?: string;
  inviterNonce?: string;
  invitationDigest?: string;
  acceptanceMap?: string;
  acceptanceSignature?: string;
  acceptanceDigest?: string;
  inviteePairingId?: string;
  inviteeAgeRecipient?: string;
  inviteeSigningPublicKey?: string;
  inviteeNonce?: string;
  inviteeStatusVerifier?: V2BearerVerifier;
  keyConfirmationMap?: string;
  keyConfirmationSignature?: string;
  fullTranscriptHash?: string;
  inviterCompletion?: V2PairingCompletionRecord;
  inviteeCompletion?: V2PairingCompletionRecord;
  inviterGrant?: string;
  inviteeGrant?: string;
}

export interface V2RelationshipRecord {
  relationshipId: string;
  canonicalOrigin: string;
  inviterSigningPublicKey: string;
  inviterAgeRecipient: string;
  inviteeSigningPublicKey: string;
  inviteeAgeRecipient: string;
  createdAt: number;
}

export interface V2StoredState {
  version: 2;
  capabilities: Record<string, V2CapabilityRecord>;
  reservations: Record<string, V2ReservationRecord>;
  revocations: Record<string, V2RevocationRecord>;
  rateWindows: Record<string, V2RateWindow>;
  invitations: Record<string, V2PairingInvitationRecord>;
  relationships: Record<string, V2RelationshipRecord>;
  legacyObjects: Record<string, V2LegacyObjectRecord>;
  legacyCommittedBytes: number;
}

export function emptyV2State(): V2StoredState {
  return {
    version: 2,
    capabilities: {},
    reservations: {},
    revocations: {},
    rateWindows: {},
    invitations: {},
    relationships: {},
    legacyObjects: {},
    legacyCommittedBytes: 0,
  };
}

export interface V2Store {
  readonly quotaEnforcement: V2QuotaEnforcement;
  /**
   * Whether this store holds the whole-state document. Dead drop rate metering
   * and the quota dead drops share with peer transfers are whole-state records,
   * so they exist only where this is true. A deployment that keeps every peer
   * record in granular repositories has no such document, and its dead drop
   * routes behave exactly as they do with peer mode disabled.
   */
  readonly wholeState: boolean;
  initialize(): Promise<void>;
  readState(): Promise<V2StoredState>;
  transaction<T>(
    operation: (state: V2StoredState) => T | Promise<T>,
  ): Promise<T>;
  claimNonce(key: string, expiresAt: number, now: number): Promise<boolean>;
  deleteExpiredNonces(now: number, limit: number): Promise<number>;
}

export interface V2Limits {
  maxObjectBytes: number;
  maxDescriptorBytes: number;
  maxTtlSeconds: number;
  maxPendingDeliveries: number;
  maxObjectsPerCapability: number;
  maxConcurrentUploads: number;
  maxRequestsPerMinute: number;
  maxStagedBytes: number;
  maxPairingEnvelopeBytes: number;
  maxPairingTtlSeconds: number;
  maxPairingCreatesPerMinute: number;
  maxPendingPairings: number;
  maxTotalBytes: number;
}
