// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { encodeCbor, requireCborMap, type CborValue } from './cbor.js';
import {
  bytesToHex,
  createV2CapabilityRecord,
  decodeBase64Url,
  deriveV2DailyCapabilityLookupId,
} from './v2-auth.js';
import { encryptV2AgeGrant } from './v2-age.js';
import {
  readV2CborRequest,
  v2CborResponse,
  v2ErrorResponse,
} from './v2-http.js';
import { sha256 } from './sha256.js';
import { decryptV2RelationshipState } from './v2-relationship-state.js';
import type {
  V2CapabilityRecord,
  V2Direction,
  V2Limits,
  V2Scope,
  V2Store,
} from './v2-types.js';
import type {
  V2CapabilityRegistration,
  V2AdministrativeRepository,
  V2RelationshipRepository,
  V2Repository,
} from './v2-repository.js';

const textEncoder = new TextEncoder();
const CLOCK_SKEW_SECONDS = 300;
const ASSIGNED_SCOPES = ['ack', 'read', 'write'] as const;

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

function granularRecoveryRepository(
  repository: V2Repository | undefined,
): GranularRecoveryRepository | undefined {
  return repository &&
    'findRelationship' in repository &&
    'commitCapabilityReissue' in repository
    ? (repository as unknown as GranularRecoveryRepository)
    : undefined;
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

interface PreparedCapability {
  record: V2CapabilityRecord;
  direction: V2Direction;
  scope: V2Scope;
  tokenSecret: Uint8Array;
}

/** Derives the tuple retirements and daily lookups a reissue must commit. */
async function capabilityReplacement(
  prepared: readonly PreparedCapability[],
): Promise<{
  revocations: Array<{
    relationshipId: string;
    direction: V2Direction;
    scope: V2Scope;
  }>;
  registrations: V2CapabilityRegistration[];
}> {
  const registrations: V2CapabilityRegistration[] = [];
  const revocations: Array<{
    relationshipId: string;
    direction: V2Direction;
    scope: V2Scope;
  }> = [];
  for (const item of prepared) {
    revocations.push({
      relationshipId: item.record.relationshipId,
      direction: item.direction,
      scope: item.scope,
    });
    const firstEpoch = Math.floor(item.record.createdAt / 86_400);
    const lastEpoch = Math.floor((item.record.expiresAt - 1) / 86_400);
    for (let epoch = firstEpoch; epoch <= lastEpoch; epoch++) {
      registrations.push({
        capability: {
          id: item.record.id,
          relationshipId: item.record.relationshipId,
          direction: item.direction,
          scope: item.scope,
          encryptedTokenSecret: item.record.encryptedTokenSecret,
          createdAt: item.record.createdAt,
          expiresAt: item.record.expiresAt,
        },
        lookupId: await deriveV2DailyCapabilityLookupId(
          item.tokenSecret,
          epoch,
        ),
        epoch,
      });
    }
  }
  return { revocations, registrations };
}

async function replaceGranularCapabilities(
  dependencies: V2ReissueDependencies,
  prepared: readonly PreparedCapability[],
  now: number,
): Promise<void> {
  if (!dependencies.repository) {
    return;
  }
  const { revocations, registrations } = await capabilityReplacement(prepared);
  if (registrations.length > 0) {
    await dependencies.repository.replaceCapabilities({
      revocations,
      registrations,
      now,
    });
  }
}

class ReissueError extends Error {
  constructor(
    readonly code: 1 | 3 | 4 | 5 | 7 | 10 | 13 | 14,
    message: string,
  ) {
    super(message);
  }
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

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function requiredBytes(
  map: Map<number, CborValue>,
  key: number,
  length: number,
  name: string,
): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new ReissueError(1, `${name} is invalid.`);
  }
  return value;
}

function revocationKey(
  relationshipId: string,
  direction?: V2Direction,
  scope?: V2Scope,
): string {
  return `${relationshipId}|${direction ?? '*'}|${scope ?? '*'}`;
}

function tupleRevoked(
  state: Awaited<ReturnType<V2Store['readState']>>,
  relationshipId: string,
  direction: V2Direction,
  scope: V2Scope,
): boolean {
  return (
    state.revocations[revocationKey(relationshipId)]?.revoked === true ||
    state.revocations[revocationKey(relationshipId, direction)]?.revoked ===
      true ||
    state.revocations[revocationKey(relationshipId, undefined, scope)]
      ?.revoked === true ||
    state.revocations[revocationKey(relationshipId, direction, scope)]
      ?.revoked === true
  );
}

function directionFor(role: 0 | 1, scope: V2Scope): V2Direction {
  const outbound: V2Direction =
    role === 0 ? 'inviter->invitee' : 'invitee->inviter';
  const inbound: V2Direction =
    role === 0 ? 'invitee->inviter' : 'inviter->invitee';
  return scope === 'write' ? outbound : inbound;
}

function parseScopes(value: CborValue | undefined): V2Scope[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > ASSIGNED_SCOPES.length
  ) {
    throw new ReissueError(1, 'Reissue scopes are invalid.');
  }
  const scopes = value.map((scope) => {
    if (
      typeof scope !== 'string' ||
      !ASSIGNED_SCOPES.includes(scope as (typeof ASSIGNED_SCOPES)[number])
    ) {
      throw new ReissueError(1, 'Reissue scope is invalid.');
    }
    return scope as V2Scope;
  });
  const sorted = [...scopes].sort();
  if (
    scopes.some((scope, index) => scope !== sorted[index]) ||
    new Set(scopes).size !== scopes.length
  ) {
    throw new ReissueError(1, 'Reissue scopes must be unique and sorted.');
  }
  return scopes;
}

async function verifySignature(
  publicKey: Uint8Array,
  map: Map<number, CborValue>,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      arrayBuffer(publicKey),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const input = concat(
      textEncoder.encode('dud/v2/capability-reissue\0'),
      sha256(encodeCbor(map)),
    );
    return crypto.subtle.verify(
      'Ed25519',
      key,
      arrayBuffer(signature),
      arrayBuffer(input),
    );
  } catch {
    return false;
  }
}

function grant(
  relationshipId: Uint8Array,
  role: 0 | 1,
  origin: string,
  capabilities: Array<{
    direction: V2Direction;
    scope: V2Scope;
    tokenSecret: Uint8Array;
  }>,
): Uint8Array {
  return encodeCbor(
    new Map<number, CborValue>([
      [1, 2],
      [2, relationshipId],
      [3, role],
      [4, 0],
      [5, origin],
      [
        6,
        capabilities.map(
          (capability) =>
            new Map<number, CborValue>([
              [1, capability.direction === 'inviter->invitee' ? 0 : 1],
              [2, capability.scope],
              [3, capability.tokenSecret],
            ]),
        ),
      ],
    ]),
  );
}

export function createV2ReissueHandler(dependencies: V2ReissueDependencies) {
  return async function reissue(
    request: Request,
    origin: string,
    sourceKey: string,
  ): Promise<Response> {
    try {
      const now = seconds(dependencies.now());
      if (!(await claimReissueSourceWindow(dependencies, sourceKey, now))) {
        throw new ReissueError(10, 'Reissue source rate exceeded.');
      }
      const wrapper = requireCborMap(
        await readV2CborRequest(
          request,
          dependencies.limits.maxDescriptorBytes,
        ),
        [1, 2],
        [1, 2],
      );
      const map = requireCborMap(
        wrapper.get(1)!,
        [1, 2, 3, 4, 5, 6, 7],
        [1, 2, 3, 4, 5, 6, 7],
      );
      if (map.get(1) !== 2) {
        throw new ReissueError(1, 'Reissue version is unsupported.');
      }
      const relationship = requiredBytes(map, 2, 16, 'Relationship ID');
      const relationshipId = bytesToHex(relationship);
      const roleValue = map.get(3);
      if (roleValue !== 0 && roleValue !== 1) {
        throw new ReissueError(1, 'Reissue role is invalid.');
      }
      const role = roleValue as 0 | 1;
      const nonce = requiredBytes(map, 4, 32, 'Reissue nonce');
      const expiresAt = map.get(5);
      const scopes = parseScopes(map.get(6));
      const mapOrigin = map.get(7);
      if (
        typeof expiresAt !== 'number' ||
        !Number.isSafeInteger(expiresAt) ||
        expiresAt < now - CLOCK_SKEW_SECONDS ||
        expiresAt > now + CLOCK_SKEW_SECONDS ||
        mapOrigin !== origin
      ) {
        throw new ReissueError(1, 'Reissue expiry or origin is invalid.');
      }
      const signature = requiredBytes(wrapper, 2, 64, 'Reissue signature');
      const recovery = granularRecoveryRepository(dependencies.repository);
      const state = recovery ? undefined : await dependencies.store.readState();
      const storedRelationship = recovery
        ? await recovery.findRelationship(relationshipId)
        : undefined;
      const relationshipRecord = storedRelationship
        ? await decryptV2RelationshipState(
            dependencies.deploymentKey,
            relationshipId,
            storedRelationship.encryptedState,
          )
        : state?.relationships[relationshipId];
      if (!relationshipRecord) {
        throw new ReissueError(4, 'Relationship is not available.');
      }
      if (relationshipRecord.canonicalOrigin !== origin) {
        throw new ReissueError(3, 'Relationship origin does not match.');
      }
      const publicKey = decodeBase64Url(
        role === 0
          ? relationshipRecord.inviterSigningPublicKey
          : relationshipRecord.inviteeSigningPublicKey,
        32,
      );
      if (!(await verifySignature(publicKey, map, signature))) {
        throw new ReissueError(3, 'Reissue signature is invalid.');
      }
      if (!recovery) {
        for (const scope of scopes) {
          if (
            tupleRevoked(
              state!,
              relationshipId,
              directionFor(role, scope),
              scope,
            )
          ) {
            throw new ReissueError(
              3,
              'A requested relationship capability is revoked.',
            );
          }
        }
        const nonceKey = bytesToHex(
          sha256(
            concat(
              textEncoder.encode('dud/v2/reissue-nonce|'),
              relationship,
              Uint8Array.of(role),
              nonce,
            ),
          ),
        );
        const nonceClaimed = await dependencies.store.claimNonce(
          nonceKey,
          expiresAt + CLOCK_SKEW_SECONDS + 1,
          now,
        );
        if (!nonceClaimed) {
          throw new ReissueError(13, 'Reissue nonce was already used.');
        }
        const rateAllowed = await dependencies.store.transaction(
          (current): boolean => {
            const key = `reissue:${relationshipId}`;
            const window = current.rateWindows[key];
            if (!window || window.minute !== Math.floor(now / 60)) {
              current.rateWindows[key] = {
                minute: Math.floor(now / 60),
                count: 1,
              };
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
      const prepared: PreparedCapability[] = [];
      const expectedActive = new Map<string, string[]>();
      for (const scope of scopes) {
        const direction = directionFor(role, scope);
        if (state) {
          expectedActive.set(
            `${direction}|${scope}`,
            Object.values(state.capabilities)
              .filter(
                (capability) =>
                  capability.relationshipId === relationshipId &&
                  capability.direction === direction &&
                  capability.scope === scope &&
                  !capability.revoked,
              )
              .map((capability) => capability.id)
              .sort(),
          );
        }
        const tokenSecret = dependencies.randomBytes(32);
        if (tokenSecret.byteLength !== 32) {
          throw new Error('V2 random source returned an invalid byte count.');
        }
        prepared.push({
          direction,
          scope,
          tokenSecret,
          record: await createV2CapabilityRecord(dependencies.deploymentKey, {
            relationshipId: relationship,
            direction,
            scope,
            tokenSecret,
            createdAt: now,
            expiresAt: now + dependencies.limits.maxTtlSeconds,
            randomBytes: dependencies.randomBytes,
          }),
        });
      }
      const recipient = decodeBase64Url(
        role === 0
          ? relationshipRecord.inviterAgeRecipient
          : relationshipRecord.inviteeAgeRecipient,
        1216,
      );
      const encrypted = await encryptV2AgeGrant(
        grant(
          relationship,
          role,
          origin,
          prepared.map(({ direction, scope, tokenSecret }) => ({
            direction,
            scope,
            tokenSecret,
          })),
        ),
        recipient,
        dependencies.randomBytes,
      );
      if (recovery) {
        const { revocations, registrations } =
          await capabilityReplacement(prepared);
        // Nonce, rate accounting, the live revocation check and the tuple
        // replacement commit together; a rejection mutates nothing.
        const committed = await recovery.commitCapabilityReissue({
          relationshipId,
          nonce,
          nonceExpiresAt: expiresAt + CLOCK_SKEW_SECONDS + 1,
          now,
          minute: Math.floor(now / 60),
          maximumRequestsPerMinute: dependencies.limits.maxRequestsPerMinute,
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
      } else {
        await dependencies.store.transaction((current) => {
          if (!current.relationships[relationshipId]) {
            throw new ReissueError(4, 'Relationship is not available.');
          }
          for (const item of prepared) {
            if (
              tupleRevoked(current, relationshipId, item.direction, item.scope)
            ) {
              throw new ReissueError(
                3,
                'A requested relationship capability is revoked.',
              );
            }
            const active = Object.values(current.capabilities)
              .filter(
                (capability) =>
                  capability.relationshipId === relationshipId &&
                  capability.direction === item.direction &&
                  capability.scope === item.scope &&
                  !capability.revoked,
              )
              .map((capability) => capability.id)
              .sort();
            const expected =
              expectedActive.get(`${item.direction}|${item.scope}`) ?? [];
            if (
              active.length !== expected.length ||
              active.some((id, index) => id !== expected[index])
            ) {
              throw new ReissueError(
                5,
                'Capability tuple changed during re-issuance.',
              );
            }
            for (const capability of Object.values(current.capabilities)) {
              if (
                capability.relationshipId === relationshipId &&
                capability.direction === item.direction &&
                capability.scope === item.scope
              ) {
                capability.revoked = true;
                capability.rotatedAt = now;
              }
            }
            if (current.capabilities[item.record.id]) {
              throw new Error('V2 random capability identifier collision.');
            }
            current.capabilities[item.record.id] = item.record;
          }
        });
        await replaceGranularCapabilities(dependencies, prepared, now);
      }
      return v2CborResponse(new Map<number, CborValue>([[1, encrypted]]));
    } catch (error) {
      if (error instanceof ReissueError) {
        return v2ErrorResponse(error.code, error.message);
      }
      return v2ErrorResponse(14, 'Capability re-issuance failed.');
    }
  };
}
