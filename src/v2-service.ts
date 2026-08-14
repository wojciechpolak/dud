// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { bytesEqual, requireCborMap, type CborValue } from './cbor.js';
import {
  bytesToHex,
  isV2Scope,
  parseV2BearerHeader,
  V2_AUTH_CLOCK_SKEW_SECONDS,
} from './v2-auth.js';
import {
  readV2CborRequest,
  v2CborResponse,
  v2EmptyResponse,
  v2ErrorResponse,
  type V2ErrorCode,
} from './v2-http.js';
import { createV2PairingHandlers } from './v2-pairing.js';
import type { V2PairingRepository } from './v2-d1-pairing-repository.js';
import { createV2ReissueHandler } from './v2-reissue.js';
import { V2_SERVER_FEATURES } from './v2-contract.js';
import {
  createV2DeliveryHandler,
  type V2RejectionObserver,
} from './v2-delivery-service.js';
import {
  classifyV2Operation,
  startV2Timing,
  type V2TimingObserver,
  type V2TimingRecorder,
} from './v2-timing.js';
import type {
  V2AdministrativeRepository,
  V2BodyStore,
  V2Repository,
} from './v2-repository.js';
import type {
  V2CapabilityRecord,
  V2Direction,
  V2Limits,
  V2RevocationRecord,
  V2Scope,
  V2Store,
} from './v2-types.js';

function administrativeRepository(
  repository: V2Repository | undefined,
): V2AdministrativeRepository | undefined {
  return repository &&
    'revokeRelationship' in repository &&
    'rotateCapability' in repository &&
    'relationshipStatus' in repository &&
    'claimRequestWindow' in repository
    ? (repository as unknown as V2AdministrativeRepository)
    : undefined;
}

class V2RequestError extends Error {
  constructor(
    readonly code: V2ErrorCode,
    message: string,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

export interface V2ServiceDependencies {
  store: V2Store;
  repository?: V2Repository;
  pairingRepository?: V2PairingRepository;
  bodyStore?: V2BodyStore;
  deploymentKey: Uint8Array;
  adminSecret?: Uint8Array;
  /**
   * The operator's enrollment passphrase. Absent only on a deployment that
   * opted into open enrollment.
   */
  enrollmentSecret?: string;
  limits: V2Limits;
  now?: () => number;
  randomBytes?: (length: number) => Uint8Array;
  observeTiming?: V2TimingObserver;
  observeRejection?: V2RejectionObserver;
  monotonicMs?: () => number;
}

function defaultRandomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function seconds(milliseconds: number): number {
  return Math.floor(milliseconds / 1000);
}

function directionNumber(direction: V2Direction): number {
  return direction === 'inviter->invitee' ? 0 : 1;
}

function parseDirection(value: CborValue | undefined): V2Direction {
  if (value === 0) {
    return 'inviter->invitee';
  }
  if (value === 1) {
    return 'invitee->inviter';
  }
  throw new V2RequestError(1, 'Direction is invalid.');
}

function revocationKey(
  relationshipId: string,
  direction?: V2Direction,
  scope?: V2Scope,
): string {
  return `${relationshipId}|${direction ?? '*'}|${scope ?? '*'}`;
}

function capabilityIsRevoked(
  capability: V2CapabilityRecord,
  revocations: Record<string, V2RevocationRecord>,
): boolean {
  return (
    capability.revoked ||
    revocations[revocationKey(capability.relationshipId)]?.revoked === true ||
    revocations[revocationKey(capability.relationshipId, capability.direction)]
      ?.revoked === true ||
    revocations[
      revocationKey(capability.relationshipId, undefined, capability.scope)
    ]?.revoked === true ||
    revocations[
      revocationKey(
        capability.relationshipId,
        capability.direction,
        capability.scope,
      )
    ]?.revoked === true
  );
}

function canonicalRequestOrigin(request: Request): string {
  const url = new URL(request.url);
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new V2RequestError(
      1,
      'V2 requests require a canonical HTTPS origin.',
    );
  }
  return url.origin;
}

/**
 * Bounded prune of the whole-state store: expired V1 staged-byte reservations,
 * stale rate windows, and the expired pairing invitations a deployment without
 * a granular pairing repository keeps there.
 */
function pruneLegacyState(
  state: Awaited<ReturnType<V2Store['readState']>>,
  now: number,
): void {
  for (const [id, reservation] of Object.entries(state.reservations)) {
    if (reservation.expiresAt <= now) {
      delete state.reservations[id];
    }
  }
  for (const [id, object] of Object.entries(state.legacyObjects)) {
    if (object.expiresAt <= now) {
      delete state.legacyObjects[id];
      state.legacyCommittedBytes = Math.max(
        0,
        state.legacyCommittedBytes - object.ciphertextSize,
      );
    }
  }
  const currentMinute = Math.floor(now / 60);
  for (const [key, window] of Object.entries(state.rateWindows)) {
    if (window.minute + 2 < currentMinute) {
      delete state.rateWindows[key];
    }
  }
  for (const [id, invitation] of Object.entries(state.invitations)) {
    if (invitation.expiresAt + V2_AUTH_CLOCK_SKEW_SECONDS < now) {
      delete state.invitations[id];
    }
  }
}

function applyRateLimit(
  state: Awaited<ReturnType<V2Store['readState']>>,
  key: string,
  now: number,
  limit: number,
): boolean {
  const minute = Math.floor(now / 60);
  const window = state.rateWindows[key];
  if (!window || window.minute !== minute) {
    state.rateWindows[key] = { minute, count: 1 };
    return true;
  }
  window.count += 1;
  return window.count <= limit;
}

/**
 * `enrollmentGated` reports whether rendezvous creation requires the deployment
 * enrollment secret. A gated deployment still advertises feature 3, because
 * pairing works — it just needs a credential — so enforcement ID 3 carries the
 * gate instead, and a client that does not know that entry ignores it.
 */
function v2Capabilities(
  store: V2Store,
  limits: V2Limits,
  v1Enabled: boolean,
  pairingEnabled: boolean,
  enrollmentGated: boolean,
): Response {
  const limitMap = new Map<number, CborValue>([
    [1, limits.maxObjectBytes],
    [2, limits.maxDescriptorBytes],
    [3, limits.maxTtlSeconds],
    [4, limits.maxPendingDeliveries],
    [5, limits.maxObjectsPerCapability],
    [6, limits.maxConcurrentUploads],
    [7, limits.maxRequestsPerMinute],
    [8, limits.maxStagedBytes],
    [9, limits.maxPairingEnvelopeBytes],
  ]);
  return v2CborResponse(
    new Map<number, CborValue>([
      [1, v1Enabled ? [1, 2] : [2]],
      [
        2,
        pairingEnabled
          ? [...V2_SERVER_FEATURES]
          : V2_SERVER_FEATURES.filter((feature) => feature !== 3),
      ],
      [3, limitMap],
      [
        4,
        new Map<number, CborValue>([
          [1, store.quotaEnforcement === 'atomic' ? 2 : 1],
          [2, 0],
          [3, enrollmentGated ? 1 : 0],
        ]),
      ],
    ]),
  );
}

export function createV2Service(dependencies: V2ServiceDependencies) {
  const now = dependencies.now ?? (() => Date.now());
  const randomBytes = dependencies.randomBytes ?? defaultRandomBytes;
  const initialized: Promise<void> = Promise.all([
    dependencies.store.initialize(),
    dependencies.repository?.initialize(),
  ]).then(() => undefined);
  // Initialization starts here so the first request does not pay for it, but
  // nothing awaits it until a request needs the store. Keep a handler attached
  // so a failure before then is reported to whichever request awaits it rather
  // than escaping as a process-level unhandled rejection, which would take a
  // self-hosted deployment down instead of failing that one request.
  initialized.catch(() => undefined);

  /**
   * Bounded maintenance for the whole-state store. A granular deployment keeps
   * every V2 record in the repository, so this prunes only V1 shared-quota
   * accounting and whatever a non-granular deployment writes there. Request
   * handling never calls it; the V1 cleanup schedule does.
   *
   * A store that holds no whole-state document has nothing here to prune: its
   * records expire through the repository maintenance pass instead, and reading
   * or rewriting whole state on it fails closed by design.
   */
  async function cleanup(): Promise<void> {
    await initialized;
    if (!dependencies.store.wholeState) {
      return;
    }
    const current = seconds(now());
    await dependencies.store.transaction((state) =>
      pruneLegacyState(state, current),
    );
    await dependencies.store.deleteExpiredNonces(current, 128);
  }

  /**
   * Charges bounded request windows for a rejected request. A granular
   * deployment accounts through the repository, so a failure never rewrites
   * whole-state metadata.
   */
  async function claimFailureWindows(
    keys: readonly string[],
    current: number,
  ): Promise<boolean> {
    const administrator = administrativeRepository(dependencies.repository);
    if (administrator) {
      const minute = Math.floor(current / 60);
      let allowed = true;
      for (const key of keys) {
        allowed =
          (await administrator.claimRequestWindow({
            key,
            minute,
            maximum: dependencies.limits.maxRequestsPerMinute,
          })) && allowed;
      }
      return allowed;
    }
    return dependencies.store.transaction((state) =>
      keys.reduce(
        (allowed, key) =>
          applyRateLimit(
            state,
            key,
            current,
            dependencies.limits.maxRequestsPerMinute,
          ) && allowed,
        true,
      ),
    );
  }

  async function requireAdminAuthorization(
    request: Request,
  ): Promise<Response | null> {
    let authorized = false;
    if (
      dependencies.adminSecret &&
      dependencies.adminSecret.byteLength === 32
    ) {
      try {
        authorized = bytesEqual(
          parseV2BearerHeader(request.headers.get('authorization')),
          dependencies.adminSecret,
        );
      } catch {
        authorized = false;
      }
    }
    if (authorized) {
      return null;
    }

    const allowed = await claimFailureWindows(
      ['admin-failure'],
      seconds(now()),
    );
    return allowed
      ? v2ErrorResponse(3, 'Administrative authorization failed.')
      : v2ErrorResponse(10, 'Too many authorization failures.', 60);
  }

  async function adminBody(request: Request): Promise<Map<number, CborValue>> {
    try {
      const value = await readV2CborRequest(
        request,
        dependencies.limits.maxDescriptorBytes,
      );
      if (!(value instanceof Map)) {
        throw new Error('Administrative body must be a CBOR map.');
      }
      return value;
    } catch (error) {
      throw new V2RequestError(
        1,
        error instanceof Error ? error.message : 'Invalid administrative body.',
      );
    }
  }

  async function revokeRelationship(request: Request): Promise<Response> {
    const authorizationFailure = await requireAdminAuthorization(request);
    if (authorizationFailure) {
      return authorizationFailure;
    }
    let map: Map<number, CborValue>;
    try {
      map = requireCborMap(await adminBody(request), [1, 2, 3], [1]);
    } catch (error) {
      return v2ErrorResponse(
        error instanceof V2RequestError ? error.code : 1,
        error instanceof Error ? error.message : 'Invalid revocation request.',
      );
    }
    const relationship = map.get(1);
    if (
      !(relationship instanceof Uint8Array) ||
      relationship.byteLength !== 16
    ) {
      return v2ErrorResponse(1, 'Relationship ID is invalid.');
    }
    let direction: V2Direction | undefined;
    let scope: V2Scope | undefined;
    try {
      if (map.has(2)) {
        direction = parseDirection(map.get(2));
      }
      if (map.has(3)) {
        const rawScope = map.get(3);
        if (!isV2Scope(rawScope)) {
          throw new V2RequestError(1, 'Capability scope is invalid.');
        }
        scope = rawScope;
      }
    } catch (error) {
      return v2ErrorResponse(
        error instanceof V2RequestError ? error.code : 1,
        error instanceof Error ? error.message : 'Invalid revocation request.',
      );
    }
    const relationshipId = bytesToHex(relationship);
    const current = seconds(now());
    const administrator = administrativeRepository(dependencies.repository);
    if (administrator) {
      await administrator.revokeRelationship({
        relationshipId,
        ...(direction ? { direction } : {}),
        ...(scope ? { scope } : {}),
        now: current,
      });
      return v2EmptyResponse();
    }
    try {
      await dependencies.store.transaction((state) => {
        state.revocations[revocationKey(relationshipId, direction, scope)] = {
          relationshipId,
          ...(direction ? { direction } : {}),
          ...(scope ? { scope } : {}),
          revoked: true,
          rotatedAt: current,
        };
        for (const capability of Object.values(state.capabilities)) {
          if (
            capability.relationshipId === relationshipId &&
            (!direction || capability.direction === direction) &&
            (!scope || capability.scope === scope)
          ) {
            capability.revoked = true;
            capability.rotatedAt = current;
          }
        }
      });
    } catch {
      return v2ErrorResponse(4, 'Capability scope is not available.');
    }
    return v2EmptyResponse();
  }

  async function rotateCapability(request: Request): Promise<Response> {
    const authorizationFailure = await requireAdminAuthorization(request);
    if (authorizationFailure) {
      return authorizationFailure;
    }
    let map: Map<number, CborValue>;
    try {
      map = requireCborMap(await adminBody(request), [1, 2, 3], [1, 2, 3]);
    } catch (error) {
      return v2ErrorResponse(
        error instanceof V2RequestError ? error.code : 1,
        error instanceof Error ? error.message : 'Invalid rotation request.',
      );
    }
    const relationship = map.get(1);
    const rawScope = map.get(3);
    if (
      !(relationship instanceof Uint8Array) ||
      relationship.byteLength !== 16 ||
      !isV2Scope(rawScope)
    ) {
      return v2ErrorResponse(1, 'Rotation target is invalid.');
    }
    let direction: V2Direction;
    try {
      direction = parseDirection(map.get(2));
    } catch (error) {
      return v2ErrorResponse(
        1,
        error instanceof Error ? error.message : 'Direction is invalid.',
      );
    }
    const relationshipId = bytesToHex(relationship);
    const current = seconds(now());
    const administrator = administrativeRepository(dependencies.repository);
    if (administrator) {
      return (await administrator.rotateCapability({
        relationshipId,
        direction,
        scope: rawScope,
        now: current,
      }))
        ? v2EmptyResponse()
        : v2ErrorResponse(4, 'Capability tuple is not available.');
    }
    let found = false;
    try {
      await dependencies.store.transaction((state) => {
        for (const capability of Object.values(state.capabilities)) {
          if (
            capability.relationshipId === relationshipId &&
            capability.direction === direction &&
            capability.scope === rawScope
          ) {
            capability.revoked = true;
            capability.rotatedAt = current;
            found = true;
          }
        }
        state.revocations[revocationKey(relationshipId, direction, rawScope)] =
          {
            relationshipId,
            direction,
            scope: rawScope,
            revoked: false,
            rotatedAt: current,
          };
      });
    } catch {
      return v2ErrorResponse(4, 'Capability scope is not available.');
    }
    return found
      ? v2EmptyResponse()
      : v2ErrorResponse(4, 'Capability tuple is not available.');
  }

  async function relationshipStatus(request: Request): Promise<Response> {
    const authorizationFailure = await requireAdminAuthorization(request);
    if (authorizationFailure) {
      return authorizationFailure;
    }
    let map: Map<number, CborValue>;
    try {
      map = requireCborMap(await adminBody(request), [1], [1]);
    } catch (error) {
      return v2ErrorResponse(
        error instanceof V2RequestError ? error.code : 1,
        error instanceof Error ? error.message : 'Invalid status request.',
      );
    }
    const relationship = map.get(1);
    if (
      !(relationship instanceof Uint8Array) ||
      relationship.byteLength !== 16
    ) {
      return v2ErrorResponse(1, 'Relationship ID is invalid.');
    }
    const relationshipId = bytesToHex(relationship);
    const administrator = administrativeRepository(dependencies.repository);
    if (administrator) {
      const status = await administrator.relationshipStatus(relationshipId);
      return v2CborResponse(
        new Map<number, CborValue>([
          [1, status.fullyRevoked],
          [
            2,
            status.tuples.map(
              (tuple) =>
                new Map<number, CborValue>([
                  [1, directionNumber(tuple.direction)],
                  [2, tuple.scope],
                  [3, tuple.revoked],
                  [4, tuple.rotatedAt],
                ]),
            ),
          ],
        ]),
      );
    }
    const state = await dependencies.store.readState();
    const fullyRevoked =
      state.revocations[revocationKey(relationshipId)]?.revoked === true;
    const tuples = new Map<string, V2RevocationRecord>();
    for (const capability of Object.values(state.capabilities)) {
      if (capability.relationshipId !== relationshipId) {
        continue;
      }
      tuples.set(`${capability.direction}|${capability.scope}`, {
        relationshipId,
        direction: capability.direction,
        scope: capability.scope,
        revoked:
          fullyRevoked || capabilityIsRevoked(capability, state.revocations),
        rotatedAt: capability.rotatedAt,
      });
    }
    for (const revocation of Object.values(state.revocations)) {
      if (
        revocation.relationshipId === relationshipId &&
        revocation.direction &&
        revocation.scope
      ) {
        tuples.set(`${revocation.direction}|${revocation.scope}`, revocation);
      }
    }
    const rendered: CborValue[] = Array.from(tuples.values())
      .sort((a, b) =>
        `${a.direction}|${a.scope}`.localeCompare(`${b.direction}|${b.scope}`),
      )
      .map(
        (tuple) =>
          new Map<number, CborValue>([
            [1, directionNumber(tuple.direction!)],
            [2, tuple.scope!],
            [3, tuple.revoked],
            [4, tuple.rotatedAt],
          ]),
      );
    return v2CborResponse(
      new Map<number, CborValue>([
        [1, fullyRevoked],
        [2, rendered],
      ]),
    );
  }

  const pairing = createV2PairingHandlers({
    store: dependencies.store,
    repository: dependencies.repository,
    pairingRepository: dependencies.pairingRepository,
    deploymentKey: dependencies.deploymentKey,
    enrollmentSecret: dependencies.enrollmentSecret,
    limits: dependencies.limits,
    now: dependencies.now ?? (() => Date.now()),
    randomBytes,
  });
  const delivery =
    dependencies.repository && dependencies.bodyStore
      ? createV2DeliveryHandler({
          repository: dependencies.repository,
          bodyStore: dependencies.bodyStore,
          deploymentKey: dependencies.deploymentKey,
          now: dependencies.now,
          maximumTotalBytes: dependencies.limits.maxTotalBytes,
          maximumDescriptorBytes: dependencies.limits.maxDescriptorBytes,
          maximumObjectBytes: dependencies.limits.maxObjectBytes,
          maximumTtlSeconds: dependencies.limits.maxTtlSeconds,
          maximumRequestsPerMinute: dependencies.limits.maxRequestsPerMinute,
          maximumPendingDeliveries: dependencies.limits.maxPendingDeliveries,
          maximumObjectsPerCapability:
            dependencies.limits.maxObjectsPerCapability,
          maximumConcurrentUploads: dependencies.limits.maxConcurrentUploads,
          maximumStagedBytes: dependencies.limits.maxStagedBytes,
          observeTiming: dependencies.observeTiming,
          observeRejection: dependencies.observeRejection,
          monotonicMs: dependencies.monotonicMs,
        })
      : undefined;
  const reissue = createV2ReissueHandler({
    store: dependencies.store,
    repository: dependencies.repository,
    deploymentKey: dependencies.deploymentKey,
    limits: dependencies.limits,
    now: dependencies.now ?? (() => Date.now()),
    randomBytes,
  });

  /**
   * Times one request end to end. Every route reports a total; the delivery
   * routes also report the authorization, metadata, and body phases inside it.
   */
  async function fetch(
    request: Request,
    v1Enabled: boolean,
    sourceKey = 'unknown',
    observeTiming?: V2TimingObserver,
  ): Promise<Response> {
    const timing = startV2Timing(
      classifyV2Operation(request.method, new URL(request.url).pathname),
      observeTiming ?? dependencies.observeTiming,
      dependencies.monotonicMs,
    );
    const response = await route(request, v1Enabled, sourceKey, timing);
    timing.finish(response.status);
    return response;
  }

  async function route(
    request: Request,
    v1Enabled: boolean,
    sourceKey: string,
    timing: V2TimingRecorder,
  ): Promise<Response> {
    await initialized;
    const url = new URL(request.url);
    if (url.search || url.hash) {
      return v2ErrorResponse(
        1,
        'V2 requests must not contain a query or fragment.',
      );
    }
    let origin: string;
    try {
      origin = canonicalRequestOrigin(request);
    } catch (error) {
      return v2ErrorResponse(
        error instanceof V2RequestError ? error.code : 1,
        error instanceof Error ? error.message : 'Invalid v2 request origin.',
      );
    }

    if (request.method === 'GET' && url.pathname === '/v2/capabilities') {
      return v2Capabilities(
        dependencies.store,
        dependencies.limits,
        v1Enabled,
        true,
        dependencies.enrollmentSecret !== undefined,
      );
    }
    const deliveryResponse = delivery
      ? await delivery.route(request, origin, url.pathname, timing)
      : null;
    if (deliveryResponse) {
      return deliveryResponse;
    }
    const pairingResponse = await pairing.route(
      request,
      origin,
      url.pathname,
      sourceKey,
    );
    if (pairingResponse) {
      return pairingResponse;
    }
    if (
      request.method === 'POST' &&
      url.pathname === '/v2/admin/relationships/revoke'
    ) {
      return revokeRelationship(request);
    }
    if (
      request.method === 'POST' &&
      url.pathname === '/v2/admin/relationships/rotate-capabilities'
    ) {
      return rotateCapability(request);
    }
    if (
      request.method === 'POST' &&
      url.pathname === '/v2/admin/relationships/status'
    ) {
      return relationshipStatus(request);
    }
    if (
      request.method === 'POST' &&
      url.pathname === '/v2/capabilities/reissue'
    ) {
      return reissue(request, origin, sourceKey);
    }
    return v2ErrorResponse(4, 'V2 endpoint is not available.');
  }

  // `initialized` is exposed so the v1 surface can await the same readiness
  // instead of starting a second, concurrent initialization of the same store.
  return { fetch, cleanup, initialized };
}
