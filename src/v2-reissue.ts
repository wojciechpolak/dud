// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { CborValue } from './cbor.js';
import { bytesToHex, decodeBase64Url } from './v2-auth.js';
import { v2CborResponse, v2ErrorResponse } from './v2-http.js';
import {
  buildCapabilityReplacement,
  commitStoredCapabilities,
  isReissueTupleRevoked,
  prepareReissueCapabilities,
  type PreparedReissueCapabilities,
} from './v2-reissue-capabilities.js';
import {
  directionForReissue,
  encryptV2ReissueGrant,
  parseV2ReissueRequest,
  REISSUE_CLOCK_SKEW_SECONDS,
  ReissueError,
  verifyV2ReissueSignature,
  type ParsedV2ReissueRequest,
} from './v2-reissue-protocol.js';
import { sha256 } from './sha256.js';
import { decryptV2RelationshipState } from './v2-relationship-state.js';
import type {
  V2Limits,
  V2RelationshipRecord,
  V2StoredState,
  V2Store,
} from './v2-types.js';
import type {
  V2AdministrativeRepository,
  V2RelationshipRepository,
  V2Repository,
} from './v2-repository.js';

const textEncoder = new TextEncoder();

interface V2ReissueDependencies {
  store: V2Store;
  repository?: V2Repository;
  deploymentKey: Uint8Array;
  limits: V2Limits;
  now: () => number;
  randomBytes: (length: number) => Uint8Array;
}

/** The two relationship operations a granular reissue request performs. */
type GranularRecoveryRepository = Pick<
  V2RelationshipRepository,
  'findRelationship' | 'commitCapabilityReissue'
>;

interface ReissueRelationshipContext {
  recovery?: GranularRecoveryRepository;
  state?: V2StoredState;
  relationship: V2RelationshipRecord;
}

function granularRecoveryRepository(
  repository: V2Repository | undefined,
): GranularRecoveryRepository | undefined {
  return repository &&
    'findRelationship' in repository &&
    'commitCapabilityReissue' in repository
    ? (repository as unknown as GranularRecoveryRepository)
    : undefined;
}

function seconds(milliseconds: number): number {
  return Math.floor(milliseconds / 1000);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    parts.reduce((length, part) => length + part.byteLength, 0),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

async function claimReissueSourceWindow(
  dependencies: V2ReissueDependencies,
  sourceKey: string,
  now: number,
): Promise<boolean> {
  const sourceDigest = bytesToHex(sha256(textEncoder.encode(sourceKey)));
  const minute = Math.floor(now / 60);
  const windowed = dependencies.repository as
    | {
        claimRequestWindow?: V2AdministrativeRepository['claimRequestWindow'];
      }
    | undefined;
  if (windowed?.claimRequestWindow) {
    return windowed.claimRequestWindow({
      key: `reissue-source:${sourceDigest}`,
      minute,
      maximum: dependencies.limits.maxRequestsPerMinute,
    });
  }
  let allowed = false;
  await dependencies.store.transaction((state) => {
    const key = `reissue-source:${sourceDigest}`;
    const window = state.rateWindows[key];
    if (!window || window.minute !== minute) {
      state.rateWindows[key] = { minute, count: 1 };
      allowed = true;
      return;
    }
    window.count++;
    allowed = window.count <= dependencies.limits.maxRequestsPerMinute;
  });
  return allowed;
}

async function loadRelationship(
  dependencies: V2ReissueDependencies,
  relationshipId: string,
): Promise<ReissueRelationshipContext> {
  const recovery = granularRecoveryRepository(dependencies.repository);
  const state = recovery ? undefined : await dependencies.store.readState();
  const storedRelationship = recovery
    ? await recovery.findRelationship(relationshipId)
    : undefined;
  const relationship = storedRelationship
    ? await decryptV2RelationshipState(
        dependencies.deploymentKey,
        relationshipId,
        storedRelationship.encryptedState,
      )
    : state?.relationships[relationshipId];
  if (!relationship) {
    throw new ReissueError(4, 'Relationship is not available.');
  }
  return {
    ...(recovery === undefined ? {} : { recovery }),
    ...(state === undefined ? {} : { state }),
    relationship,
  };
}

async function verifyRelationshipProof(
  context: ReissueRelationshipContext,
  request: ParsedV2ReissueRequest,
  origin: string,
): Promise<void> {
  if (context.relationship.canonicalOrigin !== origin) {
    throw new ReissueError(3, 'Relationship origin does not match.');
  }
  const publicKey = decodeBase64Url(
    request.role === 0
      ? context.relationship.inviterSigningPublicKey
      : context.relationship.inviteeSigningPublicKey,
    32,
  );
  if (
    !(await verifyV2ReissueSignature(
      publicKey,
      request.signedMap,
      request.signature,
    ))
  ) {
    throw new ReissueError(3, 'Reissue signature is invalid.');
  }
}

function assertStoredTuplesActive(
  state: V2StoredState,
  request: ParsedV2ReissueRequest,
): void {
  for (const scope of request.scopes) {
    if (
      isReissueTupleRevoked(
        state,
        request.relationshipId,
        directionForReissue(request.role, scope),
        scope,
      )
    ) {
      throw new ReissueError(
        3,
        'A requested relationship capability is revoked.',
      );
    }
  }
}

async function claimStoredReissue(
  dependencies: V2ReissueDependencies,
  request: ParsedV2ReissueRequest,
  state: V2StoredState,
  now: number,
): Promise<void> {
  assertStoredTuplesActive(state, request);
  const nonceKey = bytesToHex(
    sha256(
      concat(
        textEncoder.encode('dud/v2/reissue-nonce|'),
        request.relationship,
        Uint8Array.of(request.role),
        request.nonce,
      ),
    ),
  );
  const nonceClaimed = await dependencies.store.claimNonce(
    nonceKey,
    request.expiresAt + REISSUE_CLOCK_SKEW_SECONDS + 1,
    now,
  );
  if (!nonceClaimed) {
    throw new ReissueError(13, 'Reissue nonce was already used.');
  }
  const rateAllowed = await dependencies.store.transaction(
    (current): boolean => {
      const key = `reissue:${request.relationshipId}`;
      const minute = Math.floor(now / 60);
      const window = current.rateWindows[key];
      if (!window || window.minute !== minute) {
        current.rateWindows[key] = { minute, count: 1 };
        return true;
      }
      window.count++;
      return window.count <= dependencies.limits.maxRequestsPerMinute;
    },
  );
  if (!rateAllowed) {
    throw new ReissueError(10, 'Relationship reissue rate exceeded.');
  }
}

async function commitGranularReissue(
  recovery: GranularRecoveryRepository,
  request: ParsedV2ReissueRequest,
  prepared: PreparedReissueCapabilities,
  now: number,
  maximumRequestsPerMinute: number,
): Promise<void> {
  const { revocations, registrations } = await buildCapabilityReplacement(
    prepared.items,
  );
  // Nonce, rate accounting, the live revocation check and the tuple
  // replacement commit together; a rejection mutates nothing.
  const committed = await recovery.commitCapabilityReissue({
    relationshipId: request.relationshipId,
    nonce: request.nonce,
    nonceExpiresAt: request.expiresAt + REISSUE_CLOCK_SKEW_SECONDS + 1,
    now,
    minute: Math.floor(now / 60),
    maximumRequestsPerMinute,
    revocations,
    registrations,
  });
  if (committed === 'replayed') {
    throw new ReissueError(13, 'Reissue nonce was already used.');
  }
  if (committed === 'rate_limited') {
    throw new ReissueError(10, 'Relationship reissue rate exceeded.');
  }
  if (committed === 'revoked') {
    throw new ReissueError(
      3,
      'A requested relationship capability is revoked.',
    );
  }
}

async function processReissue(
  dependencies: V2ReissueDependencies,
  request: Request,
  origin: string,
  sourceKey: string,
): Promise<Response> {
  const now = seconds(dependencies.now());
  if (!(await claimReissueSourceWindow(dependencies, sourceKey, now))) {
    throw new ReissueError(10, 'Reissue source rate exceeded.');
  }
  const parsed = await parseV2ReissueRequest(
    request,
    dependencies.limits.maxDescriptorBytes,
    now,
    origin,
  );
  const context = await loadRelationship(dependencies, parsed.relationshipId);
  await verifyRelationshipProof(context, parsed, origin);
  if (context.state) {
    await claimStoredReissue(dependencies, parsed, context.state, now);
  }

  const prepared = await prepareReissueCapabilities({
    deploymentKey: dependencies.deploymentKey,
    relationship: parsed.relationship,
    relationshipId: parsed.relationshipId,
    role: parsed.role,
    scopes: parsed.scopes,
    now,
    limits: dependencies.limits,
    randomBytes: dependencies.randomBytes,
    ...(context.state === undefined ? {} : { state: context.state }),
  });
  const recipient = decodeBase64Url(
    parsed.role === 0
      ? context.relationship.inviterAgeRecipient
      : context.relationship.inviteeAgeRecipient,
    1216,
  );
  const encrypted = await encryptV2ReissueGrant(
    parsed.relationship,
    parsed.role,
    origin,
    prepared.items,
    recipient,
    dependencies.randomBytes,
  );

  if (context.recovery) {
    await commitGranularReissue(
      context.recovery,
      parsed,
      prepared,
      now,
      dependencies.limits.maxRequestsPerMinute,
    );
  } else {
    await commitStoredCapabilities({
      store: dependencies.store,
      ...(dependencies.repository === undefined
        ? {}
        : { repository: dependencies.repository }),
      relationshipId: parsed.relationshipId,
      prepared,
      now,
    });
  }
  return v2CborResponse(new Map<number, CborValue>([[1, encrypted]]));
}

export function createV2ReissueHandler(dependencies: V2ReissueDependencies) {
  return async function reissue(
    request: Request,
    origin: string,
    sourceKey: string,
  ): Promise<Response> {
    try {
      return await processReissue(dependencies, request, origin, sourceKey);
    } catch (error) {
      if (error instanceof ReissueError) {
        return v2ErrorResponse(error.code, error.message);
      }
      return v2ErrorResponse(14, 'Capability re-issuance failed.');
    }
  };
}
