// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  bytesEqual,
  decodeCbor,
  encodeCbor,
  requireCborMap,
  type CborValue,
} from './cbor.js';
import {
  bytesToHex,
  createV2CapabilityRecord,
  decryptV2TokenSecret,
  decodeBase64Url,
  deriveV2DailyCapabilityLookupId,
  deriveV2EnrollmentKey,
  deriveV2EnrollmentProof,
  encodeBase64Url,
  hexToBytes,
  parseV2BearerHeader,
  parseV2EnrollmentHeader,
  verifyV2Bearer,
} from './v2-auth.js';
import { encryptV2AgeGrant } from './v2-age.js';
import {
  readV2CborRequest,
  v2CborResponse,
  v2EmptyResponse,
  v2ErrorResponse,
} from './v2-http.js';
import { sha256 } from './sha256.js';
import { encryptV2RelationshipState } from './v2-relationship-state.js';
import type {
  D1PairingRecord,
  V2PairingRepository,
} from './v2-d1-pairing-repository.js';
import type {
  V2BearerVerifier,
  V2CapabilityRecord,
  V2Direction,
  V2Limits,
  V2PairingInvitationRecord,
  V2Scope,
  V2Store,
} from './v2-types.js';
import type {
  V2AdministrativeRepository,
  V2CapabilityRegistration,
  V2RelationshipRepository,
  V2Repository,
} from './v2-repository.js';

const textEncoder = new TextEncoder();
const RENDEZVOUS_PATH =
  /^\/v2\/pairing\/rendezvous\/([a-f0-9]{64})(?:\/(accept|key-confirm|complete|status))?$/;
const PAIRING_CLOCK_SKEW = 300;
/**
 * Enrollment attempts allowed per source per minute. Deliberately not one of
 * the configurable limits: it bounds online guessing at a typeable passphrase,
 * so an operator raising a throughput limit must not widen it by accident.
 */
const ENROLLMENT_ATTEMPTS_PER_MINUTE = 10;

type PairingRole = 0 | 1;

interface V2PairingDependencies {
  store: V2Store;
  repository?: V2Repository;
  pairingRepository?: V2PairingRepository;
  deploymentKey: Uint8Array;
  /**
   * The operator's enrollment passphrase, absent only on a deployment that
   * opted into open enrollment. Anyone who learns the hostname of such a
   * deployment can pair two of their own devices and relay through it, so
   * `createDudService` refuses to start without either this secret or the
   * explicit opt-in.
   */
  enrollmentSecret?: string;
  limits: V2Limits;
  now: () => number;
  randomBytes: (length: number) => Uint8Array;
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

async function encryptInvitationRecord(
  deploymentKey: Uint8Array,
  locator: string,
  invitation: V2PairingInvitationRecord,
  randomBytes: (length: number) => Uint8Array,
): Promise<Uint8Array> {
  const nonce = randomBytes(12);
  if (deploymentKey.byteLength !== 32 || nonce.byteLength !== 12) {
    throw new Error('Pairing record encryption input is invalid.');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(deploymentKey),
    'AES-GCM',
    false,
    ['encrypt'],
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: arrayBuffer(nonce),
        additionalData: arrayBuffer(
          textEncoder.encode(`dud/v2/pairing|${locator}`),
        ),
      },
      key,
      arrayBuffer(textEncoder.encode(JSON.stringify(invitation))),
    ),
  );
  return concat(nonce, ciphertext);
}

async function decryptInvitationRecord(
  deploymentKey: Uint8Array,
  locator: string,
  value: Uint8Array,
): Promise<V2PairingInvitationRecord> {
  if (deploymentKey.byteLength !== 32 || value.byteLength < 29) {
    throw new Error('Pairing record is invalid.');
  }
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      arrayBuffer(deploymentKey),
      'AES-GCM',
      false,
      ['decrypt'],
    );
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: arrayBuffer(value.subarray(0, 12)),
        additionalData: arrayBuffer(
          textEncoder.encode(`dud/v2/pairing|${locator}`),
        ),
      },
      key,
      arrayBuffer(value.subarray(12)),
    );
    const invitation = JSON.parse(
      new TextDecoder().decode(plaintext),
    ) as V2PairingInvitationRecord;
    if (
      invitation.locator !== locator ||
      invitation.phase < 0 ||
      invitation.phase > 4
    ) {
      throw new Error('Pairing record is invalid.');
    }
    return invitation;
  } catch {
    throw new Error('Pairing record failed authentication.');
  }
}

/** Pairing activation only ever publishes the encrypted relationship. */
function relationshipRepository(
  repository: V2Repository | undefined,
): Pick<V2RelationshipRepository, 'createRelationship'> | undefined {
  return repository && 'createRelationship' in repository
    ? (repository as unknown as Pick<
        V2RelationshipRepository,
        'createRelationship'
      >)
    : undefined;
}

interface PairingMutation {
  invitation: V2PairingInvitationRecord;
  record?: D1PairingRecord;
}

class PairingError extends Error {
  constructor(
    readonly code: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 10 | 11 | 13 | 14,
    message: string,
  ) {
    super(message);
  }
}

function seconds(milliseconds: number): number {
  return Math.floor(milliseconds / 1000);
}

export async function registerActivationCapabilities(
  dependencies: V2PairingDependencies,
  capabilities: readonly V2CapabilityRecord[],
): Promise<void> {
  if (!dependencies.repository) {
    return;
  }
  const registrations = await activationCapabilityRegistrations(
    dependencies,
    capabilities,
  );
  for (const registration of registrations) {
    await dependencies.repository.registerCapability(
      registration.capability,
      registration.lookupId,
      registration.epoch,
    );
  }
}

async function activationCapabilityRegistrations(
  dependencies: V2PairingDependencies,
  capabilities: readonly V2CapabilityRecord[],
): Promise<V2CapabilityRegistration[]> {
  const registrations: V2CapabilityRegistration[] = [];
  for (const capability of capabilities) {
    const tokenSecret = await decryptV2TokenSecret(
      dependencies.deploymentKey,
      capability,
    );
    const firstEpoch = Math.floor(capability.createdAt / 86_400);
    const lastEpoch = Math.floor((capability.expiresAt - 1) / 86_400);
    for (let epoch = firstEpoch; epoch <= lastEpoch; epoch++) {
      registrations.push({
        capability: {
          id: capability.id,
          relationshipId: capability.relationshipId,
          direction: capability.direction,
          scope: capability.scope,
          encryptedTokenSecret: capability.encryptedTokenSecret,
          createdAt: capability.createdAt,
          expiresAt: capability.expiresAt,
        },
        lookupId: await deriveV2DailyCapabilityLookupId(tokenSecret, epoch),
        epoch,
      });
    }
  }
  return registrations;
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

function requireBytes(
  map: Map<number, CborValue>,
  key: number,
  length: number,
  name: string,
): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    throw new PairingError(1, `${name} is invalid.`);
  }
  return value;
}

function requireBoundedBytes(
  map: Map<number, CborValue>,
  key: number,
  maximum: number,
  name: string,
): Uint8Array {
  const value = map.get(key);
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength === 0 ||
    value.byteLength > maximum
  ) {
    throw new PairingError(1, `${name} is invalid.`);
  }
  return value;
}

function requireUint(
  map: Map<number, CborValue>,
  key: number,
  name: string,
): number {
  const value = map.get(key);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new PairingError(1, `${name} is invalid.`);
  }
  return value;
}

function requireText(
  map: Map<number, CborValue>,
  key: number,
  name: string,
): string {
  const value = map.get(key);
  if (typeof value !== 'string') {
    throw new PairingError(1, `${name} is invalid.`);
  }
  return value;
}

function parseVerifier(value: CborValue, name: string): V2BearerVerifier {
  const map = requireCborMap(value, [1, 2], [1, 2]);
  return {
    salt: encodeBase64Url(requireBytes(map, 1, 16, `${name} salt`)),
    digest: encodeBase64Url(requireBytes(map, 2, 32, `${name} digest`)),
  };
}

function decodeStoredMap(value: string): Map<number, CborValue> {
  return requireCborMap(
    decodeCbor(decodeBase64Url(value), {
      maxArrayElements: 64,
      maxBytes: 8192,
      maxDepth: 8,
      maxMapPairs: 32,
      requireDeterministic: true,
    }),
    Array.from({ length: 32 }, (_, index) => index),
    [],
  );
}

async function verifyPairingSignature(
  publicKey: Uint8Array,
  messageName: string,
  map: Map<number, CborValue>,
  signature: Uint8Array,
): Promise<boolean> {
  if (publicKey.byteLength !== 32 || signature.byteLength !== 64) {
    return false;
  }
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      Uint8Array.from(publicKey).buffer,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const input = concat(
      textEncoder.encode(`dud/v2/pairing/${messageName}\0`),
      sha256(encodeCbor(map)),
    );
    return crypto.subtle.verify(
      'Ed25519',
      key,
      Uint8Array.from(signature).buffer,
      Uint8Array.from(input).buffer,
    );
  } catch {
    return false;
  }
}

function applyRateLimit(
  state: Awaited<ReturnType<V2Store['readState']>>,
  key: string,
  now: number,
  maximum: number,
): boolean {
  const minute = Math.floor(now / 60);
  const existing = state.rateWindows[key];
  if (!existing || existing.minute !== minute) {
    state.rateWindows[key] = { minute, count: 1 };
    return true;
  }
  if (existing.count >= maximum) {
    return false;
  }
  existing.count += 1;
  return true;
}

function invitationPhase(
  invitation: V2PairingInvitationRecord,
  now: number,
): number {
  return invitation.expiresAt <= now ? 5 : invitation.phase;
}

async function roleForStatusBearer(
  request: Request,
  invitation: V2PairingInvitationRecord,
): Promise<PairingRole> {
  let bearer: Uint8Array;
  try {
    bearer = parseV2BearerHeader(request.headers.get('authorization'));
  } catch {
    throw new PairingError(2, 'Pairing status authorization failed.');
  }
  const [inviter, invitee] = await Promise.all([
    verifyV2Bearer(bearer, invitation.inviterStatusVerifier),
    invitation.inviteeStatusVerifier
      ? verifyV2Bearer(bearer, invitation.inviteeStatusVerifier)
      : false,
  ]);
  if (inviter === invitee) {
    throw new PairingError(2, 'Pairing status authorization failed.');
  }
  return inviter ? 0 : 1;
}

function assertInvitationMap(
  value: CborValue,
  origin: string,
  now: number,
  expectedExpiry: number,
): { map: Map<number, CborValue>; bootstrap: Uint8Array; id: string } {
  const map = requireCborMap(
    value,
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
  );
  if (
    requireUint(map, 1, 'Invitation version') !== 2 ||
    requireUint(map, 2, 'Invitation KEM algorithm') !== 1 ||
    requireUint(map, 3, 'Invitation signature algorithm') !== 1
  ) {
    throw new PairingError(1, 'Invitation algorithms are unsupported.');
  }
  const invitationId = requireBytes(map, 4, 32, 'Invitation ID');
  requireBytes(map, 5, 16, 'Relationship ID');
  requireBytes(map, 6, 16, 'Inviter pairing ID');
  requireBytes(map, 7, 1216, 'Inviter age recipient');
  requireBytes(map, 8, 32, 'Inviter signing key');
  if (requireText(map, 9, 'Invitation origin') !== origin) {
    throw new PairingError(
      1,
      'Invitation origin does not match the request origin.',
    );
  }
  const bootstrap = requireBytes(
    map,
    10,
    32,
    'Invitation bootstrap capability',
  );
  requireBytes(map, 11, 32, 'Inviter nonce');
  const expiresAt = requireUint(map, 12, 'Invitation expiry');
  if (expiresAt !== expectedExpiry || expiresAt <= now) {
    throw new PairingError(7, 'Pairing code is invalid or expired.');
  }
  return { map, bootstrap, id: bytesToHex(invitationId) };
}

function preTranscript(
  invitation: V2PairingInvitationRecord,
  acceptance: Map<number, CborValue>,
): Map<number, CborValue> {
  return new Map<number, CborValue>([
    [1, 2],
    [2, 1],
    [3, 1],
    [4, hexToBytes(invitation.invitationId!, 32)],
    [5, hexToBytes(invitation.relationshipId!, 16)],
    [6, invitation.canonicalOrigin!],
    [7, decodeBase64Url(invitation.inviterPairingId!, 16)],
    [8, requireBytes(acceptance, 6, 16, 'Invitee pairing ID')],
    [9, decodeBase64Url(invitation.inviterAgeRecipient!, 1216)],
    [10, requireBytes(acceptance, 7, 1216, 'Invitee age recipient')],
    [11, decodeBase64Url(invitation.inviterSigningPublicKey!, 32)],
    [12, requireBytes(acceptance, 8, 32, 'Invitee signing key')],
    [13, decodeBase64Url(invitation.inviterNonce!, 32)],
    [14, requireBytes(acceptance, 9, 32, 'Invitee nonce')],
    [15, invitation.expiresAt],
    [16, 0],
    [17, 'bootstrap'],
    [18, hexToBytes(invitation.locator, 32)],
    [19, requireBytes(acceptance, 13, 32, 'Invitee pairing binder')],
  ]);
}

function fullTranscriptHash(
  invitation: V2PairingInvitationRecord,
  acceptance: Map<number, CborValue>,
  encA: Uint8Array,
): Uint8Array {
  const full = preTranscript(invitation, acceptance);
  full.set(20, encA);
  full.set(21, requireBytes(acceptance, 11, 1120, 'enc_B'));
  return sha256(encodeCbor(full));
}

function capabilityGrant(
  invitation: V2PairingInvitationRecord,
  role: PairingRole,
  grants: Array<{
    direction: V2Direction;
    scope: V2Scope;
    tokenSecret: Uint8Array;
  }>,
): Uint8Array {
  return encodeCbor(
    new Map<number, CborValue>([
      [1, 2],
      [2, hexToBytes(invitation.relationshipId!, 16)],
      [3, role],
      [4, 0],
      [5, invitation.canonicalOrigin!],
      [
        6,
        grants.map(
          (grant) =>
            new Map<number, CborValue>([
              [1, grant.direction === 'inviter->invitee' ? 0 : 1],
              [2, grant.scope],
              [3, grant.tokenSecret],
            ]),
        ),
      ],
    ]),
  );
}

function grantsForRole(
  role: PairingRole,
  all: Array<{
    direction: V2Direction;
    scope: V2Scope;
    tokenSecret: Uint8Array;
  }>,
) {
  const outbound: V2Direction =
    role === 0 ? 'inviter->invitee' : 'invitee->inviter';
  const inbound: V2Direction =
    role === 0 ? 'invitee->inviter' : 'inviter->invitee';
  return all.filter(
    (grant) =>
      (grant.direction === outbound && grant.scope === 'write') ||
      (grant.direction === inbound &&
        (grant.scope === 'read' || grant.scope === 'ack')),
  );
}

async function prepareActivation(
  dependencies: V2PairingDependencies,
  invitation: V2PairingInvitationRecord,
): Promise<{
  capabilities: V2CapabilityRecord[];
  inviterGrant: string;
  inviteeGrant: string;
}> {
  if (
    !invitation.relationshipId ||
    !invitation.canonicalOrigin ||
    !invitation.inviterAgeRecipient ||
    !invitation.inviteeAgeRecipient
  ) {
    throw new Error('Pairing activation is missing relationship identity.');
  }
  const createdAt = seconds(dependencies.now());
  const expiresAt = createdAt + dependencies.limits.maxTtlSeconds;
  const relationshipId = hexToBytes(invitation.relationshipId, 16);
  const grants: Array<{
    direction: V2Direction;
    scope: V2Scope;
    tokenSecret: Uint8Array;
  }> = [];
  const capabilities: V2CapabilityRecord[] = [];
  for (const direction of ['inviter->invitee', 'invitee->inviter'] as const) {
    for (const scope of ['write', 'read', 'ack'] as const) {
      const tokenSecret = dependencies.randomBytes(32);
      if (tokenSecret.byteLength !== 32) {
        throw new Error('V2 random source returned an invalid byte count.');
      }
      grants.push({ direction, scope, tokenSecret });
      capabilities.push(
        await createV2CapabilityRecord(dependencies.deploymentKey, {
          relationshipId,
          direction,
          scope,
          tokenSecret,
          createdAt,
          expiresAt,
          randomBytes: dependencies.randomBytes,
        }),
      );
    }
  }
  const inviterGrant = await encryptV2AgeGrant(
    capabilityGrant(invitation, 0, grantsForRole(0, grants)),
    decodeBase64Url(invitation.inviterAgeRecipient, 1216),
    dependencies.randomBytes,
  );
  const inviteeGrant = await encryptV2AgeGrant(
    capabilityGrant(invitation, 1, grantsForRole(1, grants)),
    decodeBase64Url(invitation.inviteeAgeRecipient, 1216),
    dependencies.randomBytes,
  );
  return {
    capabilities,
    inviterGrant: encodeBase64Url(inviterGrant),
    inviteeGrant: encodeBase64Url(inviteeGrant),
  };
}

export function createV2PairingHandlers(dependencies: V2PairingDependencies) {
  async function readInvitation(
    locator: string,
  ): Promise<V2PairingInvitationRecord | undefined> {
    if (!dependencies.pairingRepository) {
      return (await dependencies.store.readState()).invitations[locator];
    }
    const record = await dependencies.pairingRepository.find(locator);
    return record
      ? decryptInvitationRecord(
          dependencies.deploymentKey,
          locator,
          record.value,
        )
      : undefined;
  }

  /**
   * Applies one bounded rendezvous mutation.  The granular path charges the
   * request window and swaps the record under its exact revision in a single
   * repository transaction, and returns the committed record so no caller has
   * to read the rendezvous back.
   */
  async function updateInvitation(
    locator: string,
    operation: (invitation: V2PairingInvitationRecord) => void | Promise<void>,
  ): Promise<PairingMutation> {
    if (!dependencies.pairingRepository) {
      return dependencies.store.transaction(async (state) => {
        const invitation = state.invitations[locator];
        if (!invitation) {
          throw new PairingError(7, 'Pairing code is invalid or expired.');
        }
        await operation(invitation);
        return { invitation };
      });
    }
    const rate = {
      key: `pairing-mutate:${locator}`,
      minute: Math.floor(seconds(dependencies.now()) / 60),
      maximum: dependencies.limits.maxRequestsPerMinute,
    };
    for (let attempt = 0; attempt < 8; attempt++) {
      const record = await dependencies.pairingRepository.find(locator);
      if (!record) {
        throw new PairingError(7, 'Pairing code is invalid or expired.');
      }
      const invitation = await decryptInvitationRecord(
        dependencies.deploymentKey,
        locator,
        record.value,
      );
      await operation(invitation);
      const value = await encryptInvitationRecord(
        dependencies.deploymentKey,
        locator,
        invitation,
        dependencies.randomBytes,
      );
      const committed = await dependencies.pairingRepository.commit({
        record,
        next: { phase: invitation.phase, value },
        rate,
      });
      if (committed.status === 'committed') {
        return { invitation, record: committed.record };
      }
      if (committed.status === 'rate_limited') {
        throw new PairingError(10, 'Pairing request rate exceeded.');
      }
    }
    throw new PairingError(5, 'Pairing state changed too frequently.');
  }

  /**
   * The enrollment secret is a passphrase, so the HMAC key is stretched rather
   * than configured. Derive it once. The result is reused for the life of the
   * isolate, so the expensive KDF runs for the first gated invitation after a
   * cold start and never for a request that will be refused.
   */
  let enrollmentKey: Promise<Uint8Array> | undefined;
  function enrollmentKeyOnce(secret: string): Promise<Uint8Array> {
    enrollmentKey ??= deriveV2EnrollmentKey(secret);
    return enrollmentKey;
  }

  /**
   * Charges one enrollment attempt against this source's per-minute window,
   * answering whether it stays within it. A granular deployment charges the one
   * metadata row `claimRequestWindow` owns; a deployment backed only by the
   * whole-state store rewrites that state, which is acceptable on this path
   * alone.
   */
  async function claimEnrollmentWindow(sourceDigest: string): Promise<boolean> {
    const minute = Math.floor(seconds(dependencies.now()) / 60);
    const windowed = dependencies.repository as
      | {
          claimRequestWindow?: V2AdministrativeRepository['claimRequestWindow'];
        }
      | undefined;
    if (windowed?.claimRequestWindow) {
      return windowed.claimRequestWindow({
        key: `enrollment:${sourceDigest}`,
        minute,
        maximum: ENROLLMENT_ATTEMPTS_PER_MINUTE,
      });
    }
    let within = true;
    await dependencies.store.transaction((state) => {
      within = applyRateLimit(
        state,
        `enrollment:${sourceDigest}`,
        seconds(dependencies.now()),
        ENROLLMENT_ATTEMPTS_PER_MINUTE,
      );
    });
    return within;
  }

  /**
   * Checks the `DUD2-Enroll` proof that gates rendezvous creation. Every
   * failure is the same refusal, so a caller learns only that it does not hold
   * the enrollment secret.
   *
   * A wrong proof is throttled per source. Rejections do not
   * consume the deployment-wide creation window, so that an unauthenticated
   * caller cannot deny pairing to everyone else; without this second counter
   * that same property would leave a typeable passphrase open to online
   * guessing at network speed. Offline guessing against a captured proof is
   * bounded by the KDF work factor instead. See `deriveV2EnrollmentKey`.
   */
  async function requireEnrollment(
    request: Request,
    sourceKey: string,
    locator: Uint8Array,
    expiresAt: number,
  ): Promise<void> {
    const secret = dependencies.enrollmentSecret;
    if (!secret) {
      return;
    }
    // Counted before the proof is checked, so exhausting the budget actually
    // stops the next guess instead of only relabelling its refusal. A correct
    // inviter spends one unit per invitation it creates, which the deployment
    // already caps at the same order through `maxPairingCreatesPerMinute`.
    const sourceDigest = bytesToHex(sha256(textEncoder.encode(sourceKey)));
    if (!(await claimEnrollmentWindow(sourceDigest))) {
      throw new PairingError(10, 'Pairing enrollment rate exceeded.');
    }
    let proof: Uint8Array;
    try {
      proof = parseV2EnrollmentHeader(request.headers.get('authorization'));
    } catch {
      throw new PairingError(2, 'Pairing enrollment is not authorized.');
    }
    const expected = await deriveV2EnrollmentProof(
      await enrollmentKeyOnce(secret),
      locator,
      expiresAt,
    );
    if (!bytesEqual(proof, expected)) {
      throw new PairingError(2, 'Pairing enrollment is not authorized.');
    }
  }

  async function createRendezvous(
    request: Request,
    sourceKey: string,
  ): Promise<Response> {
    try {
      const body = requireCborMap(
        await readV2CborRequest(
          request,
          dependencies.limits.maxPairingEnvelopeBytes + 512,
        ),
        [1, 2, 3, 4, 5, 6, 7],
        [1, 2, 3, 4, 5, 6, 7],
      );
      if (requireUint(body, 1, 'Rendezvous version') !== 2) {
        throw new PairingError(1, 'Rendezvous version is unsupported.');
      }
      const locatorBytes = requireBytes(body, 2, 32, 'Rendezvous locator');
      const locator = bytesToHex(locatorBytes);
      const nonce = requireBytes(body, 3, 24, 'Invitation envelope nonce');
      const ciphertext = requireBoundedBytes(
        body,
        4,
        dependencies.limits.maxPairingEnvelopeBytes,
        'Invitation envelope',
      );
      const expiresAt = requireUint(body, 5, 'Rendezvous expiry');
      const bootstrapVerifier = parseVerifier(
        body.get(6)!,
        'Bootstrap verifier',
      );
      const inviterStatusVerifier = parseVerifier(
        body.get(7)!,
        'Inviter status verifier',
      );
      const now = seconds(dependencies.now());
      if (
        expiresAt <= now ||
        expiresAt > now + dependencies.limits.maxPairingTtlSeconds
      ) {
        throw new PairingError(
          1,
          'Rendezvous expiry is outside the allowed lifetime.',
        );
      }
      // Enrollment is the only route that creates state for a caller holding
      // neither a capability nor a relationship, so it is authorized before
      // anything else: ahead of the admission call, so a rejected request
      // cannot consume the deployment-wide creation window, and ahead of the
      // existence check, so a refusal never discloses that the locator is
      // already taken.
      await requireEnrollment(request, sourceKey, locatorBytes, expiresAt);
      if (dependencies.pairingRepository) {
        const existing = await readInvitation(locator);
        if (existing) {
          if (
            existing.envelopeNonce === encodeBase64Url(nonce) &&
            existing.envelopeCiphertext === encodeBase64Url(ciphertext) &&
            existing.expiresAt === expiresAt &&
            existing.bootstrapVerifier.salt === bootstrapVerifier.salt &&
            existing.bootstrapVerifier.digest === bootstrapVerifier.digest &&
            existing.inviterStatusVerifier.salt ===
              inviterStatusVerifier.salt &&
            existing.inviterStatusVerifier.digest ===
              inviterStatusVerifier.digest
          ) {
            return v2CborResponse(
              new Map<number, CborValue>([
                [1, now],
                [2, expiresAt],
              ]),
              201,
            );
          }
          throw new PairingError(5, 'Pairing rendezvous already exists.');
        }
        const sourceDigest = bytesToHex(sha256(textEncoder.encode(sourceKey)));
        const invitation: V2PairingInvitationRecord = {
          locator,
          envelopeNonce: encodeBase64Url(nonce),
          envelopeCiphertext: encodeBase64Url(ciphertext),
          bootstrapVerifier,
          inviterStatusVerifier,
          createdAt: now,
          expiresAt,
          phase: 0,
        };
        if (
          !(await dependencies.pairingRepository.admit({
            record: {
              locator,
              phase: 0,
              createdAt: now,
              expiresAt,
              value: await encryptInvitationRecord(
                dependencies.deploymentKey,
                locator,
                invitation,
                dependencies.randomBytes,
              ),
            },
            sourceKey: `pairing-create:${sourceDigest}`,
            minute: Math.floor(now / 60),
            globalMaximum: dependencies.limits.maxRequestsPerMinute,
            sourceMaximum: dependencies.limits.maxPairingCreatesPerMinute,
            pendingMaximum: dependencies.limits.maxPendingPairings,
            now,
          }))
        ) {
          throw new PairingError(10, 'Pairing rendezvous admission failed.');
        }
      } else {
        await dependencies.store.transaction((state) => {
          for (const [key, invitation] of Object.entries(state.invitations)) {
            if (invitation.expiresAt + PAIRING_CLOCK_SKEW < now) {
              delete state.invitations[key];
            }
          }
          const existing = state.invitations[locator];
          if (existing) {
            if (
              existing.envelopeNonce === encodeBase64Url(nonce) &&
              existing.envelopeCiphertext === encodeBase64Url(ciphertext) &&
              existing.expiresAt === expiresAt &&
              existing.bootstrapVerifier.salt === bootstrapVerifier.salt &&
              existing.bootstrapVerifier.digest === bootstrapVerifier.digest &&
              existing.inviterStatusVerifier.salt ===
                inviterStatusVerifier.salt &&
              existing.inviterStatusVerifier.digest ===
                inviterStatusVerifier.digest
            ) {
              return;
            }
            throw new PairingError(5, 'Pairing rendezvous already exists.');
          }
          const sourceDigest = bytesToHex(
            sha256(textEncoder.encode(sourceKey)),
          );
          if (
            !applyRateLimit(
              state,
              'pairing-create:global',
              now,
              dependencies.limits.maxRequestsPerMinute,
            ) ||
            !applyRateLimit(
              state,
              `pairing-create:${sourceDigest}`,
              now,
              dependencies.limits.maxPairingCreatesPerMinute,
            )
          ) {
            throw new PairingError(10, 'Pairing creation rate exceeded.');
          }
          if (
            Object.values(state.invitations).filter(
              (invitation) => invitation.expiresAt > now,
            ).length >= dependencies.limits.maxPendingPairings
          ) {
            throw new PairingError(11, 'Pairing rendezvous capacity exceeded.');
          }
          state.invitations[locator] = {
            locator,
            envelopeNonce: encodeBase64Url(nonce),
            envelopeCiphertext: encodeBase64Url(ciphertext),
            bootstrapVerifier,
            inviterStatusVerifier,
            createdAt: now,
            expiresAt,
            phase: 0,
          };
        });
      }
      return v2CborResponse(
        new Map<number, CborValue>([
          [1, now],
          [2, expiresAt],
        ]),
        201,
      );
    } catch (error) {
      return pairingErrorResponse(
        error,
        'Pairing rendezvous could not be created.',
      );
    }
  }

  async function retrieveRendezvous(locator: string): Promise<Response> {
    const record = await readInvitation(locator);
    if (!record || record.expiresAt <= seconds(dependencies.now())) {
      return v2ErrorResponse(4, 'Pairing code is invalid or expired.');
    }
    return v2CborResponse(
      new Map<number, CborValue>([
        [1, 2],
        [2, decodeBase64Url(record.envelopeNonce, 24)],
        [3, decodeBase64Url(record.envelopeCiphertext)],
        [4, record.expiresAt],
      ]),
    );
  }

  async function acceptInvitation(
    request: Request,
    locator: string,
    origin: string,
  ): Promise<Response> {
    try {
      const record = await readInvitation(locator);
      const now = seconds(dependencies.now());
      if (!record || record.expiresAt <= now) {
        throw new PairingError(4, 'Pairing code is invalid or expired.');
      }
      const bearer = parseV2BearerHeader(request.headers.get('authorization'));
      if (!(await verifyV2Bearer(bearer, record.bootstrapVerifier))) {
        throw new PairingError(4, 'Pairing code is invalid or expired.');
      }
      const wrapper = requireCborMap(
        await readV2CborRequest(
          request,
          dependencies.limits.maxDescriptorBytes,
        ),
        [1, 2, 3, 4],
        [1, 2, 3, 4],
      );
      const parsed = assertInvitationMap(
        wrapper.get(1)!,
        origin,
        now,
        record.expiresAt,
      );
      if (!bytesEqual(parsed.bootstrap, bearer)) {
        throw new PairingError(4, 'Pairing code is invalid or expired.');
      }
      const acceptance = requireCborMap(
        wrapper.get(2)!,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
      );
      const signature = requireBytes(wrapper, 3, 64, 'Acceptance signature');
      const inviteeStatus = requireBytes(
        wrapper,
        4,
        32,
        'Invitee status capability',
      );
      const invitationDigest = sha256(encodeCbor(parsed.map));
      if (
        requireUint(acceptance, 1, 'Acceptance version') !== 2 ||
        requireUint(acceptance, 2, 'Acceptance KEM') !== 1 ||
        requireUint(acceptance, 3, 'Acceptance signature algorithm') !== 1 ||
        bytesToHex(requireBytes(acceptance, 4, 32, 'Invitation ID')) !==
          parsed.id ||
        !bytesEqual(
          requireBytes(acceptance, 5, 16, 'Relationship ID'),
          requireBytes(parsed.map, 5, 16, 'Relationship ID'),
        ) ||
        !bytesEqual(
          requireBytes(acceptance, 10, 32, 'Invitation digest'),
          invitationDigest,
        ) ||
        !bytesEqual(
          sha256(inviteeStatus),
          requireBytes(acceptance, 12, 32, 'Status capability hash'),
        ) ||
        bytesToHex(requireBytes(acceptance, 14, 32, 'Rendezvous locator')) !==
          locator
      ) {
        throw new PairingError(1, 'Acceptance does not match the invitation.');
      }
      requireBytes(acceptance, 6, 16, 'Invitee pairing ID');
      requireBytes(acceptance, 7, 1216, 'Invitee age recipient');
      const inviteeSigningKey = requireBytes(
        acceptance,
        8,
        32,
        'Invitee signing key',
      );
      requireBytes(acceptance, 9, 32, 'Invitee nonce');
      requireBytes(acceptance, 11, 1120, 'enc_B');
      requireBytes(acceptance, 13, 32, 'Invitee pairing binder');
      if (
        !(await verifyPairingSignature(
          inviteeSigningKey,
          'acceptance',
          acceptance,
          signature,
        ))
      ) {
        throw new PairingError(3, 'Acceptance signature is invalid.');
      }
      const acceptanceBytes = encodeCbor(acceptance);
      const acceptanceDigest = bytesToHex(sha256(acceptanceBytes));
      const inviteeStatusVerifier = {
        salt: encodeBase64Url(dependencies.randomBytes(16)),
        digest: '',
      };
      inviteeStatusVerifier.digest = encodeBase64Url(
        sha256(
          concat(
            textEncoder.encode('dud/v2/bearer\0'),
            decodeBase64Url(inviteeStatusVerifier.salt, 16),
            inviteeStatus,
          ),
        ),
      );
      await updateInvitation(locator, (pending) => {
        if (pending.expiresAt <= now || pending.phase === 4) {
          throw new PairingError(7, 'Pairing code is invalid or expired.');
        }
        if (pending.acceptanceDigest) {
          if (
            pending.acceptanceDigest !== acceptanceDigest ||
            pending.acceptanceSignature !== encodeBase64Url(signature)
          ) {
            throw new PairingError(
              6,
              'Pairing invitation was already claimed.',
            );
          }
          return;
        }
        pending.invitationId = parsed.id;
        pending.relationshipId = bytesToHex(
          requireBytes(parsed.map, 5, 16, 'Relationship ID'),
        );
        pending.inviterPairingId = encodeBase64Url(
          requireBytes(parsed.map, 6, 16, 'Inviter pairing ID'),
        );
        pending.inviterAgeRecipient = encodeBase64Url(
          requireBytes(parsed.map, 7, 1216, 'Inviter age recipient'),
        );
        pending.inviterSigningPublicKey = encodeBase64Url(
          requireBytes(parsed.map, 8, 32, 'Inviter signing key'),
        );
        pending.canonicalOrigin = origin;
        pending.inviterNonce = encodeBase64Url(
          requireBytes(parsed.map, 11, 32, 'Inviter nonce'),
        );
        pending.invitationDigest = bytesToHex(invitationDigest);
        pending.acceptanceMap = encodeBase64Url(acceptanceBytes);
        pending.acceptanceSignature = encodeBase64Url(signature);
        pending.acceptanceDigest = acceptanceDigest;
        pending.inviteePairingId = encodeBase64Url(
          requireBytes(acceptance, 6, 16, 'Invitee pairing ID'),
        );
        pending.inviteeAgeRecipient = encodeBase64Url(
          requireBytes(acceptance, 7, 1216, 'Invitee age recipient'),
        );
        pending.inviteeSigningPublicKey = encodeBase64Url(inviteeSigningKey);
        pending.inviteeNonce = encodeBase64Url(
          requireBytes(acceptance, 9, 32, 'Invitee nonce'),
        );
        pending.inviteeStatusVerifier = inviteeStatusVerifier;
        pending.phase = 1;
      });
      return v2EmptyResponse(202);
    } catch (error) {
      return pairingErrorResponse(
        error,
        'Pairing invitation acceptance failed.',
      );
    }
  }

  async function keyConfirm(
    request: Request,
    locator: string,
  ): Promise<Response> {
    try {
      const invitation = await readInvitation(locator);
      if (!invitation || invitation.expiresAt <= seconds(dependencies.now())) {
        throw new PairingError(4, 'Pairing code is invalid or expired.');
      }
      if ((await roleForStatusBearer(request, invitation)) !== 0) {
        throw new PairingError(3, 'Only the inviter may confirm keys.');
      }
      if (!invitation.acceptanceMap || !invitation.acceptanceDigest) {
        throw new PairingError(5, 'Pairing invitation has not been accepted.');
      }
      const wrapper = requireCborMap(
        await readV2CborRequest(
          request,
          dependencies.limits.maxDescriptorBytes,
        ),
        [1, 2],
        [1, 2],
      );
      const confirmation = requireCborMap(
        wrapper.get(1)!,
        [1, 2, 3, 4, 5, 6, 7],
        [1, 2, 3, 4, 5, 6, 7],
      );
      const signature = requireBytes(
        wrapper,
        2,
        64,
        'Key-confirmation signature',
      );
      const encA = requireBytes(confirmation, 5, 1120, 'enc_A');
      requireBytes(confirmation, 7, 32, 'Inviter pairing binder');
      const acceptance = decodeStoredMap(invitation.acceptanceMap);
      const expectedTranscript = fullTranscriptHash(
        invitation,
        acceptance,
        encA,
      );
      if (
        requireUint(confirmation, 1, 'Key-confirmation version') !== 2 ||
        bytesToHex(requireBytes(confirmation, 2, 32, 'Invitation ID')) !==
          invitation.invitationId ||
        bytesToHex(requireBytes(confirmation, 3, 16, 'Relationship ID')) !==
          invitation.relationshipId ||
        bytesToHex(requireBytes(confirmation, 4, 32, 'Acceptance digest')) !==
          invitation.acceptanceDigest ||
        !bytesEqual(
          requireBytes(confirmation, 6, 32, 'Full transcript hash'),
          expectedTranscript,
        )
      ) {
        throw new PairingError(
          1,
          'Key confirmation does not match the transcript.',
        );
      }
      if (
        !(await verifyPairingSignature(
          decodeBase64Url(invitation.inviterSigningPublicKey!, 32),
          'key-confirmation',
          confirmation,
          signature,
        ))
      ) {
        throw new PairingError(3, 'Key-confirmation signature is invalid.');
      }
      const encoded = encodeBase64Url(encodeCbor(confirmation));
      const encodedSignature = encodeBase64Url(signature);
      await updateInvitation(locator, (record) => {
        if (record.expiresAt <= seconds(dependencies.now())) {
          throw new PairingError(7, 'Pairing code is invalid or expired.');
        }
        if (
          record.keyConfirmationMap &&
          (record.keyConfirmationMap !== encoded ||
            record.keyConfirmationSignature !== encodedSignature)
        ) {
          throw new PairingError(5, 'Key confirmation already differs.');
        }
        record.keyConfirmationMap = encoded;
        record.keyConfirmationSignature = encodedSignature;
        record.fullTranscriptHash = bytesToHex(expectedTranscript);
        record.phase = 2;
      });
      return v2EmptyResponse(202);
    } catch (error) {
      return pairingErrorResponse(error, 'Key confirmation failed.');
    }
  }

  async function complete(
    request: Request,
    locator: string,
  ): Promise<Response> {
    try {
      const invitation = await readInvitation(locator);
      if (!invitation || invitation.expiresAt <= seconds(dependencies.now())) {
        throw new PairingError(4, 'Pairing code is invalid or expired.');
      }
      const now = seconds(dependencies.now());
      const role = await roleForStatusBearer(request, invitation);
      if (!invitation.fullTranscriptHash || invitation.phase < 2) {
        throw new PairingError(5, 'Pairing key confirmation is incomplete.');
      }
      const wrapper = requireCborMap(
        await readV2CborRequest(
          request,
          dependencies.limits.maxDescriptorBytes,
        ),
        [1, 2],
        [1, 2],
      );
      const completion = requireCborMap(
        wrapper.get(1)!,
        [1, 2, 3, 4, 5, 6],
        [1, 2, 3, 4, 5, 6],
      );
      const signature = requireBytes(wrapper, 2, 64, 'Completion signature');
      const completedAt = requireUint(completion, 6, 'Completion timestamp');
      if (
        requireUint(completion, 1, 'Completion version') !== 2 ||
        bytesToHex(requireBytes(completion, 2, 32, 'Invitation ID')) !==
          invitation.invitationId ||
        bytesToHex(requireBytes(completion, 3, 16, 'Relationship ID')) !==
          invitation.relationshipId ||
        bytesToHex(requireBytes(completion, 4, 32, 'Full transcript hash')) !==
          invitation.fullTranscriptHash ||
        requireUint(completion, 5, 'Completion role') !== role ||
        completedAt < invitation.createdAt - PAIRING_CLOCK_SKEW ||
        completedAt > invitation.expiresAt + PAIRING_CLOCK_SKEW ||
        Math.abs(completedAt - now) > PAIRING_CLOCK_SKEW
      ) {
        throw new PairingError(1, 'Pairing completion is invalid.');
      }
      const publicKey =
        role === 0
          ? decodeBase64Url(invitation.inviterSigningPublicKey!, 32)
          : decodeBase64Url(invitation.inviteeSigningPublicKey!, 32);
      if (
        !(await verifyPairingSignature(
          publicKey,
          'pairing-complete',
          completion,
          signature,
        ))
      ) {
        throw new PairingError(3, 'Pairing completion signature is invalid.');
      }
      const encodedMap = encodeBase64Url(encodeCbor(completion));
      const encodedSignature = encodeBase64Url(signature);
      const digest = bytesToHex(sha256(encodeCbor(completion)));
      const mutated = await updateInvitation(locator, (record) => {
        if (record.expiresAt <= now || record.phase === 4) {
          throw new PairingError(7, 'Pairing code is invalid or expired.');
        }
        const field = role === 0 ? 'inviterCompletion' : 'inviteeCompletion';
        const existing = record[field];
        if (
          existing &&
          (existing.map !== encodedMap ||
            existing.signature !== encodedSignature)
        ) {
          throw new PairingError(5, 'Pairing completion already differs.');
        }
        record[field] = {
          map: encodedMap,
          signature: encodedSignature,
          digest,
        };
      });

      const pending = mutated.invitation;
      if (
        pending.phase !== 3 &&
        pending.inviterCompletion &&
        pending.inviteeCompletion
      ) {
        const activation = await prepareActivation(dependencies, pending);
        let activated = false;
        if (dependencies.pairingRepository) {
          // Activation is conditional on the revision this request committed,
          // so a concurrent activation loses the compare-and-swap instead of
          // publishing a second relationship.
          const record = mutated.record!;
          if (pending.expiresAt <= seconds(dependencies.now())) {
            return v2EmptyResponse(202);
          }
          const relationship = {
            relationshipId: pending.relationshipId!,
            canonicalOrigin: pending.canonicalOrigin!,
            inviterSigningPublicKey: pending.inviterSigningPublicKey!,
            inviterAgeRecipient: pending.inviterAgeRecipient!,
            inviteeSigningPublicKey: pending.inviteeSigningPublicKey!,
            inviteeAgeRecipient: pending.inviteeAgeRecipient!,
            createdAt: seconds(dependencies.now()),
          };
          const published: V2PairingInvitationRecord = {
            ...pending,
            inviterGrant: activation.inviterGrant,
            inviteeGrant: activation.inviteeGrant,
            phase: 3,
          };
          activated = await dependencies.pairingRepository.activate({
            record,
            invitationValue: await encryptInvitationRecord(
              dependencies.deploymentKey,
              locator,
              published,
              dependencies.randomBytes,
            ),
            relationship: {
              id: relationship.relationshipId,
              canonicalOrigin: relationship.canonicalOrigin,
              encryptedState: await encryptV2RelationshipState(
                dependencies.deploymentKey,
                relationship,
                dependencies.randomBytes,
              ),
              createdAt: relationship.createdAt,
            },
            registrations: await activationCapabilityRegistrations(
              dependencies,
              activation.capabilities,
            ),
          });
        } else {
          await dependencies.store.transaction((current) => {
            const record = current.invitations[locator];
            if (
              !record ||
              record.phase === 3 ||
              !record.inviterCompletion ||
              !record.inviteeCompletion ||
              record.expiresAt <= seconds(dependencies.now())
            ) {
              return;
            }
            const ids = new Set<string>();
            for (const capability of activation.capabilities) {
              if (
                ids.has(capability.id) ||
                current.capabilities[capability.id]
              ) {
                throw new Error('V2 random capability identifier collision.');
              }
              ids.add(capability.id);
            }
            for (const capability of activation.capabilities) {
              current.capabilities[capability.id] = capability;
            }
            current.relationships[record.relationshipId!] = {
              relationshipId: record.relationshipId!,
              canonicalOrigin: record.canonicalOrigin!,
              inviterSigningPublicKey: record.inviterSigningPublicKey!,
              inviterAgeRecipient: record.inviterAgeRecipient!,
              inviteeSigningPublicKey: record.inviteeSigningPublicKey!,
              inviteeAgeRecipient: record.inviteeAgeRecipient!,
              createdAt: seconds(dependencies.now()),
            };
            record.inviterGrant = activation.inviterGrant;
            record.inviteeGrant = activation.inviteeGrant;
            record.phase = 3;
            activated = true;
          });
        }
        if (activated && !dependencies.pairingRepository) {
          await registerActivationCapabilities(
            dependencies,
            activation.capabilities,
          );
          const relationship = (await dependencies.store.readState())
            .relationships[pending.relationshipId!];
          const repository = relationshipRepository(dependencies.repository);
          if (relationship && repository) {
            await repository.createRelationship({
              id: relationship.relationshipId,
              canonicalOrigin: relationship.canonicalOrigin,
              encryptedState: await encryptV2RelationshipState(
                dependencies.deploymentKey,
                relationship,
                dependencies.randomBytes,
              ),
              createdAt: relationship.createdAt,
            });
          }
        }
      }
      return v2EmptyResponse(202);
    } catch (error) {
      return pairingErrorResponse(error, 'Pairing completion failed.');
    }
  }

  async function status(request: Request, locator: string): Promise<Response> {
    try {
      const invitation = await readInvitation(locator);
      if (!invitation) {
        throw new PairingError(4, 'Pairing code is invalid or expired.');
      }
      const role = await roleForStatusBearer(request, invitation);
      const result = new Map<number, CborValue>([
        [1, invitationPhase(invitation, seconds(dependencies.now()))],
        [4, invitation.inviterCompletion !== undefined],
        [5, invitation.inviteeCompletion !== undefined],
      ]);
      if (
        role === 0 &&
        invitation.acceptanceMap &&
        invitation.acceptanceSignature
      ) {
        result.set(
          2,
          new Map<number, CborValue>([
            [1, decodeStoredMap(invitation.acceptanceMap)],
            [2, decodeBase64Url(invitation.acceptanceSignature, 64)],
          ]),
        );
      }
      if (
        role === 1 &&
        invitation.keyConfirmationMap &&
        invitation.keyConfirmationSignature
      ) {
        result.set(
          3,
          new Map<number, CborValue>([
            [1, decodeStoredMap(invitation.keyConfirmationMap)],
            [2, decodeBase64Url(invitation.keyConfirmationSignature, 64)],
          ]),
        );
      }
      if (invitation.phase === 3) {
        result.set(
          6,
          decodeBase64Url(
            role === 0 ? invitation.inviterGrant! : invitation.inviteeGrant!,
          ),
        );
      }
      return v2CborResponse(result);
    } catch (error) {
      return pairingErrorResponse(error, 'Pairing status failed.');
    }
  }

  async function cancel(request: Request, locator: string): Promise<Response> {
    try {
      const invitation = await readInvitation(locator);
      if (!invitation) {
        throw new PairingError(4, 'Pairing code is invalid or expired.');
      }
      await roleForStatusBearer(request, invitation);
      await updateInvitation(locator, (record) => {
        if (record.phase === 3) {
          throw new PairingError(5, 'Active pairing cannot be cancelled.');
        }
        record.phase = 4;
        delete record.acceptanceMap;
        delete record.acceptanceSignature;
        delete record.keyConfirmationMap;
        delete record.keyConfirmationSignature;
        delete record.inviterCompletion;
        delete record.inviteeCompletion;
      });
      return v2EmptyResponse();
    } catch (error) {
      return pairingErrorResponse(error, 'Pairing cancellation failed.');
    }
  }

  async function route(
    request: Request,
    origin: string,
    pathname: string,
    sourceKey: string,
  ): Promise<Response | null> {
    if (request.method === 'POST' && pathname === '/v2/pairing/rendezvous') {
      return createRendezvous(request, sourceKey);
    }
    const match = RENDEZVOUS_PATH.exec(pathname);
    if (!match) {
      return null;
    }
    const [, locator, operation] = match;
    if (!operation && request.method === 'GET') {
      return retrieveRendezvous(locator);
    }
    if (!operation && request.method === 'DELETE') {
      return cancel(request, locator);
    }
    if (operation === 'accept' && request.method === 'POST') {
      return acceptInvitation(request, locator, origin);
    }
    if (operation === 'key-confirm' && request.method === 'POST') {
      return keyConfirm(request, locator);
    }
    if (operation === 'complete' && request.method === 'POST') {
      return complete(request, locator);
    }
    if (operation === 'status' && request.method === 'GET') {
      return status(request, locator);
    }
    return v2ErrorResponse(4, 'V2 endpoint is not available.');
  }

  return { route };
}

function pairingErrorResponse(error: unknown, fallback: string): Response {
  if (error instanceof PairingError) {
    return v2ErrorResponse(error.code, error.message);
  }
  if (error instanceof Error) {
    if (
      error.message.includes('CBOR') ||
      error.message.includes('body') ||
      error.message.includes('map') ||
      error.message.includes('authorization')
    ) {
      return v2ErrorResponse(1, error.message);
    }
  }
  return v2ErrorResponse(14, fallback);
}
