// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

/** Immutable V2 wire-contract constants. */
export const V2_WIRE_PROTOCOL = 2;

export const V2_FEATURE = {
  scopedAuth: 2,
  pairing: 3,
  gitFull: 5,
  gitIncremental: 6,
  atomicDelivery: 9,
  batchedInbox: 10,
  inlineControl: 11,
} as const;

/**
 * Features this server advertises. IDs 1 (objects) and 4 (delivery-slots) name
 * endpoints the protocol does not serve, so they never belong in this list.
 */
export const V2_SERVER_FEATURES = [
  V2_FEATURE.scopedAuth,
  V2_FEATURE.pairing,
  V2_FEATURE.gitFull,
  V2_FEATURE.gitIncremental,
  V2_FEATURE.atomicDelivery,
  V2_FEATURE.batchedInbox,
  V2_FEATURE.inlineControl,
] as const;

export const V2_REQUIRED_PEER_FEATURES = [
  V2_FEATURE.scopedAuth,
  V2_FEATURE.pairing,
  V2_FEATURE.atomicDelivery,
  V2_FEATURE.batchedInbox,
  V2_FEATURE.inlineControl,
] as const;

export const V2_REQUIRED_GIT_FEATURES = [
  ...V2_REQUIRED_PEER_FEATURES,
  V2_FEATURE.gitFull,
] as const;

export const V2_ENDPOINT = {
  capabilities: '/v2/capabilities',
  deliveries: '/v2/deliveries',
  inbox: '/v2/inbox',
  controlEvents: '/v2/control-events',
  pairing: '/v2/pairing',
  capabilityReissue: '/v2/capabilities/reissue',
} as const;

export function v2CompletionEndpoint(deliveryId: string): string {
  if (!/^[a-f0-9]{32}$/.test(deliveryId)) {
    throw new Error('V2 delivery ID is invalid.');
  }
  return `${V2_ENDPOINT.deliveries}/${deliveryId}/complete`;
}

/** Numeric fields in the capability document's limits map. */
export const V2_LIMIT = {
  maxPayloadBytes: 1,
  maxDescriptorBytes: 2,
  maxTtlSeconds: 3,
  maxPendingDeliveries: 4,
  maxDeliveriesPerCapability: 5,
  maxConcurrentDeliveries: 6,
  maxProofsPerMinute: 7,
  maxStagedBytes: 8,
  maxPairingEnvelopeBytes: 9,
} as const;

/** Stable, redaction-safe error codes shared by every V2 endpoint. */
export const V2_ERROR = {
  malformedRequest: 1,
  authenticationFailed: 2,
  authorizationFailed: 3,
  unavailable: 4,
  operationConflict: 5,
  nonceReplay: 6,
  expired: 7,
  invalidState: 8,
  tooLarge: 9,
  rateLimited: 10,
  quotaExceeded: 11,
  unsupportedContract: 12,
  integrityFailure: 13,
  internal: 14,
} as const;

export type V2ErrorCode = (typeof V2_ERROR)[keyof typeof V2_ERROR];

export const V2_ERROR_HTTP_STATUS: Readonly<Record<V2ErrorCode, number>> = {
  [V2_ERROR.malformedRequest]: 400,
  [V2_ERROR.authenticationFailed]: 401,
  [V2_ERROR.authorizationFailed]: 403,
  [V2_ERROR.unavailable]: 404,
  [V2_ERROR.operationConflict]: 409,
  [V2_ERROR.nonceReplay]: 409,
  [V2_ERROR.expired]: 410,
  [V2_ERROR.invalidState]: 422,
  [V2_ERROR.tooLarge]: 413,
  [V2_ERROR.rateLimited]: 429,
  [V2_ERROR.quotaExceeded]: 429,
  [V2_ERROR.unsupportedContract]: 409,
  [V2_ERROR.integrityFailure]: 409,
  [V2_ERROR.internal]: 500,
};

export function hasRequiredV2Features(
  advertised: readonly number[],
  required: readonly number[] = V2_REQUIRED_PEER_FEATURES,
): boolean {
  const present = new Set(advertised);
  return required.every((feature) => present.has(feature));
}
