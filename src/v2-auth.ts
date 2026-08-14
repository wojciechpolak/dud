// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { bytesEqual, decodeCbor, encodeCbor, requireCborMap } from './cbor.js';
import { sha256 } from './sha256.js';
import { V2_WIRE_PROTOCOL } from './v2-contract.js';
import type {
  V2BearerVerifier,
  V2CapabilityRecord,
  V2Direction,
  V2Scope,
  V2Store,
} from './v2-types.js';

const textEncoder = new TextEncoder();
export const V2_AUTH_CLOCK_SKEW_SECONDS = 300;

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

export function hexToBytes(value: string, expectedLength?: number): Uint8Array {
  if (
    !/^(?:[a-f0-9]{2})+$/.test(value) ||
    (expectedLength !== undefined && value.length !== expectedLength * 2)
  ) {
    throw new Error('Invalid lowercase hexadecimal value.');
  }
  return Uint8Array.from(
    value.match(/../g)!.map((pair) => Number.parseInt(pair, 16)),
  );
}

export function encodeBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

export function decodeBase64Url(
  value: string,
  expectedLength?: number,
): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.includes('=')) {
    throw new Error('Invalid base64url value.');
  }
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  let decoded: string;
  try {
    decoded = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  } catch {
    throw new Error('Invalid base64url value.');
  }
  const result = Uint8Array.from(decoded, (character) =>
    character.charCodeAt(0),
  );
  if (expectedLength !== undefined && result.byteLength !== expectedLength) {
    throw new Error(`Expected ${expectedLength} decoded bytes.`);
  }
  if (encodeBase64Url(result) !== value) {
    throw new Error('Non-canonical base64url value.');
  }
  return result;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const result = new Uint8Array(length);
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

function uint64(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('Value is outside the supported uint64 range.');
  }
  const result = new Uint8Array(8);
  const view = new DataView(result.buffer);
  view.setUint32(0, Math.floor(value / 0x100000000), false);
  view.setUint32(4, value >>> 0, false);
  return result;
}

async function hmacSha256(
  secret: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(
    await crypto.subtle.sign('HMAC', key, arrayBuffer(message)),
  );
}

async function hkdfSha256(
  secret: Uint8Array,
  info: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(secret),
    'HKDF',
    false,
    ['deriveBits'],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new ArrayBuffer(0),
        info: arrayBuffer(info),
      },
      key,
      256,
    ),
  );
}

/** Scope values permitted on the V2 delivery endpoints. */
export type V2DeliveryScope = 'write' | 'read' | 'ack';

export interface V2DeliveryAuthorizationInput {
  tokenSecret: Uint8Array;
  capabilityLookupId: Uint8Array;
  direction: V2Direction;
  scope: V2DeliveryScope;
  chain: number;
  slot: Uint8Array;
  slotEpoch: number;
  method: string;
  canonicalOrigin: string;
  normalizedPath: string;
  operationIndex: number;
  requestDigest: Uint8Array;
  nonce: Uint8Array;
  expiresAt: number;
}

export interface V2DeliveryProof {
  capabilityLookupId: Uint8Array;
  nonce: Uint8Array;
  expiresAt: number;
  operationIndex: number;
  mac: Uint8Array;
}

const V2_DELIVERY_PROOF_KEYS = [1, 2, 3, 4, 5] as const;

/**
 * Produces the daily, indexed capability identifier the V2 endpoints look up
 * by. The long-lived secret never appears in the database index.
 */
export async function deriveV2DailyCapabilityLookupId(
  tokenSecret: Uint8Array,
  epoch: number,
): Promise<Uint8Array> {
  return (
    await hmacSha256(
      tokenSecret,
      concat(textEncoder.encode('dud/v2/capability-lookup|'), uint64(epoch)),
    )
  ).subarray(0, 16);
}

function deliveryCapabilityContext(
  input: Pick<
    V2DeliveryAuthorizationInput,
    'direction' | 'scope' | 'chain' | 'slot' | 'slotEpoch'
  >,
): Uint8Array {
  if (
    input.slot.byteLength !== 16 ||
    !Number.isSafeInteger(input.chain) ||
    input.chain < 0
  ) {
    throw new Error('Delivery authorization context is invalid.');
  }
  return concat(
    textEncoder.encode(input.direction),
    Uint8Array.of(0x7c),
    textEncoder.encode(input.scope),
    Uint8Array.of(0x7c),
    uint64(input.chain),
    Uint8Array.of(0x7c),
    input.slot,
    Uint8Array.of(0x7c),
    uint64(input.slotEpoch),
  );
}

/**
 * Derives the proof MAC for framed delivery endpoints. It deliberately binds
 * a complete request digest and its index so batch entries cannot be spliced,
 * reordered, or replayed as a differently scoped operation.
 */
export async function deriveV2DeliveryAuthorizationMac(
  input: V2DeliveryAuthorizationInput,
): Promise<Uint8Array> {
  if (
    input.tokenSecret.byteLength !== 32 ||
    input.capabilityLookupId.byteLength !== 16 ||
    input.requestDigest.byteLength !== 32 ||
    input.nonce.byteLength !== 16 ||
    !Number.isSafeInteger(input.operationIndex) ||
    input.operationIndex < 0
  ) {
    throw new Error('Delivery authorization proof is invalid.');
  }
  const context = deliveryCapabilityContext(input);
  const authKey = await hkdfSha256(
    input.tokenSecret,
    concat(textEncoder.encode('dud/v2/delivery-authkey|'), context),
  );
  return hmacSha256(
    authKey,
    concat(
      textEncoder.encode('dud/v2/delivery-auth'),
      Uint8Array.of(0),
      uint64(V2_WIRE_PROTOCOL),
      Uint8Array.of(0),
      input.capabilityLookupId,
      Uint8Array.of(0),
      textEncoder.encode(input.direction),
      Uint8Array.of(0),
      textEncoder.encode(input.scope),
      Uint8Array.of(0),
      uint64(input.chain),
      Uint8Array.of(0),
      input.slot,
      Uint8Array.of(0),
      uint64(input.slotEpoch),
      Uint8Array.of(0),
      textEncoder.encode(input.method),
      Uint8Array.of(0),
      textEncoder.encode(input.canonicalOrigin),
      Uint8Array.of(0),
      textEncoder.encode(input.normalizedPath),
      Uint8Array.of(0),
      uint64(input.operationIndex),
      Uint8Array.of(0),
      input.requestDigest,
      Uint8Array.of(0),
      input.nonce,
      Uint8Array.of(0),
      uint64(input.expiresAt),
    ),
  );
}

export async function buildV2DeliveryProof(
  input: V2DeliveryAuthorizationInput,
): Promise<Uint8Array> {
  const mac = await deriveV2DeliveryAuthorizationMac(input);
  return encodeCbor(
    new Map<number, import('./cbor.js').CborValue>([
      [1, input.capabilityLookupId],
      [2, input.nonce],
      [3, input.expiresAt],
      [4, input.operationIndex],
      [5, mac],
    ]),
  );
}

export function parseV2DeliveryProof(value: Uint8Array): V2DeliveryProof {
  const map = requireCborMap(
    decodeCbor(value, {
      maxBytes: 160,
      maxMapPairs: V2_DELIVERY_PROOF_KEYS.length,
      maxDepth: 2,
      requireDeterministic: true,
    }),
    V2_DELIVERY_PROOF_KEYS,
    V2_DELIVERY_PROOF_KEYS,
  );
  const capabilityLookupId = map.get(1);
  const nonce = map.get(2);
  const expiresAt = map.get(3);
  const operationIndex = map.get(4);
  const mac = map.get(5);
  if (
    !(capabilityLookupId instanceof Uint8Array) ||
    capabilityLookupId.byteLength !== 16 ||
    !(nonce instanceof Uint8Array) ||
    nonce.byteLength !== 16 ||
    typeof expiresAt !== 'number' ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt < 0 ||
    typeof operationIndex !== 'number' ||
    !Number.isSafeInteger(operationIndex) ||
    operationIndex < 0 ||
    !(mac instanceof Uint8Array) ||
    mac.byteLength !== 32
  ) {
    throw new Error('Delivery authorization proof fields are invalid.');
  }
  return { capabilityLookupId, nonce, expiresAt, operationIndex, mac };
}

/**
 * Parses and authenticates a delivery proof against its complete request
 * context. Callers still enforce expiry, scope, relationship and replay rules.
 */
export async function verifyV2DeliveryProof(
  input: Omit<
    V2DeliveryAuthorizationInput,
    'capabilityLookupId' | 'nonce' | 'expiresAt' | 'operationIndex'
  > & {
    capabilityLookupId: Uint8Array;
    proof: Uint8Array;
  },
): Promise<V2DeliveryProof | null> {
  let parsed: V2DeliveryProof;
  try {
    parsed = parseV2DeliveryProof(input.proof);
  } catch {
    return null;
  }
  if (!bytesEqual(parsed.capabilityLookupId, input.capabilityLookupId)) {
    return null;
  }
  const mac = await deriveV2DeliveryAuthorizationMac({
    ...input,
    nonce: parsed.nonce,
    expiresAt: parsed.expiresAt,
    operationIndex: parsed.operationIndex,
  });
  return bytesEqual(mac, parsed.mac) ? parsed : null;
}

function capabilityAad(record: {
  id: string;
  relationshipId: string;
  direction: V2Direction;
  scope: V2Scope;
}): Uint8Array {
  return textEncoder.encode(
    `dud/v2/verifier|${record.id}|${record.relationshipId}|${record.direction}|${record.scope}`,
  );
}

export async function encryptV2TokenSecret(
  deploymentKey: Uint8Array,
  record: {
    id: string;
    relationshipId: string;
    direction: V2Direction;
    scope: V2Scope;
  },
  tokenSecret: Uint8Array,
  randomBytes: (length: number) => Uint8Array,
): Promise<string> {
  if (deploymentKey.byteLength !== 32 || tokenSecret.byteLength !== 32) {
    throw new Error('V2 deployment and token keys must be 32 bytes.');
  }
  const nonce = randomBytes(12);
  if (nonce.byteLength !== 12) {
    throw new Error('V2 random source returned an invalid nonce.');
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
        additionalData: arrayBuffer(capabilityAad(record)),
      },
      key,
      arrayBuffer(tokenSecret),
    ),
  );
  return encodeBase64Url(concat(nonce, ciphertext));
}

export async function decryptV2TokenSecret(
  deploymentKey: Uint8Array,
  record: Pick<
    V2CapabilityRecord,
    'id' | 'relationshipId' | 'direction' | 'scope' | 'encryptedTokenSecret'
  >,
): Promise<Uint8Array> {
  const encoded = decodeBase64Url(record.encryptedTokenSecret);
  if (encoded.byteLength !== 60 || deploymentKey.byteLength !== 32) {
    throw new Error('Encrypted v2 verifier is invalid.');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(deploymentKey),
    'AES-GCM',
    false,
    ['decrypt'],
  );
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: arrayBuffer(encoded.subarray(0, 12)),
          additionalData: arrayBuffer(capabilityAad(record)),
        },
        key,
        arrayBuffer(encoded.subarray(12)),
      ),
    );
  } catch {
    throw new Error('Encrypted v2 verifier failed authentication.');
  }
}

export interface ProvisionV2CapabilityInput {
  relationshipId: Uint8Array;
  direction: V2Direction;
  scope: V2Scope;
  tokenSecret: Uint8Array;
  createdAt: number;
  expiresAt: number;
  randomBytes?: (length: number) => Uint8Array;
}

function defaultRandomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export async function createV2CapabilityRecord(
  deploymentKey: Uint8Array,
  input: ProvisionV2CapabilityInput,
): Promise<V2CapabilityRecord> {
  if (
    input.relationshipId.byteLength !== 16 ||
    input.tokenSecret.byteLength !== 32 ||
    !isV2Scope(input.scope) ||
    !Number.isSafeInteger(input.createdAt) ||
    !Number.isSafeInteger(input.expiresAt) ||
    input.expiresAt <= input.createdAt
  ) {
    throw new Error('Invalid capability provisioning input.');
  }
  const randomBytes = input.randomBytes ?? defaultRandomBytes;
  const id = bytesToHex(randomBytes(16));
  const relationshipId = bytesToHex(input.relationshipId);
  const base = {
    id,
    relationshipId,
    direction: input.direction,
    scope: input.scope,
  };
  return {
    ...base,
    encryptedTokenSecret: await encryptV2TokenSecret(
      deploymentKey,
      base,
      input.tokenSecret,
      randomBytes,
    ),
    createdAt: input.createdAt,
    expiresAt: input.expiresAt,
    revoked: false,
    rotatedAt: input.createdAt,
  };
}

export async function rewrapV2VerifierKeys(
  store: V2Store,
  oldDeploymentKey: Uint8Array,
  newDeploymentKey: Uint8Array,
  randomBytes: (length: number) => Uint8Array = defaultRandomBytes,
): Promise<number> {
  if (
    oldDeploymentKey.byteLength !== 32 ||
    newDeploymentKey.byteLength !== 32
  ) {
    throw new Error('V2 deployment keys must be 32 bytes.');
  }
  return store.transaction(async (state) => {
    const replacements = new Map<string, string>();
    for (const capability of Object.values(state.capabilities)) {
      const tokenSecret = await decryptV2TokenSecret(
        oldDeploymentKey,
        capability,
      );
      replacements.set(
        capability.id,
        await encryptV2TokenSecret(
          newDeploymentKey,
          capability,
          tokenSecret,
          randomBytes,
        ),
      );
    }
    for (const [id, encrypted] of replacements) {
      state.capabilities[id].encryptedTokenSecret = encrypted;
    }
    return replacements.size;
  });
}

export async function verifyV2Bearer(
  bearer: Uint8Array,
  verifier: V2BearerVerifier,
): Promise<boolean> {
  let salt: Uint8Array;
  let expected: Uint8Array;
  try {
    salt = decodeBase64Url(verifier.salt, 16);
    expected = decodeBase64Url(verifier.digest, 32);
  } catch {
    return false;
  }
  const actual = sha256(
    concat(textEncoder.encode('dud/v2/bearer\0'), salt, bearer),
  );
  return bytesEqual(actual, expected);
}

export function parseV2BearerHeader(value: string | null): Uint8Array {
  const prefix = 'DUD2-Bearer ';
  if (!value?.startsWith(prefix) || value.length > prefix.length + 43) {
    throw new Error('Missing or invalid v2 bearer authorization.');
  }
  return decodeBase64Url(value.slice(prefix.length), 32);
}

/**
 * Decodes one 32-byte deployment credential, naming the variable and the form
 * it wants. `decodeBase64Url` alone reports neither, so an operator holding
 * three interchangeable-looking values learns only that one of them is wrong —
 * and a hex value is the common case, because it passes the character check and
 * fails only on length.
 */
export function parseV2Credential(name: string, value: string): Uint8Array {
  try {
    return decodeBase64Url(value, 32);
  } catch {
    throw new Error(
      `${name} must be 32 bytes encoded as base64url: 43 characters, no padding, no hex. ` +
        `Generate one with: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`,
    );
  }
}

export function parseV2DeploymentKey(value: string | undefined): Uint8Array {
  if (!value) {
    throw new Error('DUD_PEER_DEPLOYMENT_KEY is required when v2 is enabled.');
  }
  return parseV2Credential('DUD_PEER_DEPLOYMENT_KEY', value);
}

/**
 * Shortest accepted enrollment passphrase. Unlike the two server-only
 * credentials, this one is carried by hand to every device that may invite, so
 * it is a passphrase rather than 32 encoded bytes. The floor bounds the worst
 * case an operator can choose; the work factor below is what makes even a
 * modest choice expensive to attack. See `threat-model-v2.md` §3.20.
 */
export const V2_ENROLLMENT_SECRET_MIN_LENGTH = 24;

/**
 * Work factor for the enrollment passphrase, following the current OWASP
 * figure for PBKDF2-HMAC-SHA256.
 *
 * A proof is a deterministic MAC over public values, so anyone who captures one
 * can test passphrase guesses against it offline, without the server and
 * without spending the per-source throttle. Nothing about the protocol can
 * prevent that; what bounds it is the cost of each guess. This figure puts a
 * single guess in the hundreds of milliseconds.
 */
export const V2_ENROLLMENT_KDF_ITERATIONS = 600_000;

/**
 * Bounds on an explicitly stated work factor. The floor keeps a reduced setting
 * from becoming decorative, and the ceiling is a typo guard: a stray zero would
 * otherwise hang startup rather than report a bad value.
 */
export const V2_ENROLLMENT_KDF_MIN_ITERATIONS = 10_000;
export const V2_ENROLLMENT_KDF_MAX_ITERATIONS = 10_000_000;

/** Domain separation for the enrollment key, used as the PBKDF2 salt. */
const V2_ENROLLMENT_KDF_SALT = 'dud/v2/enrollment-key';

/** Marks a `DUD_PEER_SECRET` that carries the derived key rather than a passphrase. */
export const V2_ENROLLMENT_KEY_PREFIX = 'dud2-enroll-key:';

/** Marks a `DUD_PEER_SECRET` that states its own work factor before the passphrase. */
export const V2_ENROLLMENT_KDF_PREFIX = 'dud2-enroll-kdf:';

/**
 * What an operator put in `DUD_PEER_SECRET`. Either the derived key itself, or a
 * passphrase together with the work factor to stretch it by.
 */
export type V2EnrollmentCredential =
  | { kind: 'key'; key: Uint8Array }
  | { kind: 'passphrase'; passphrase: string; iterations: number };

function parseV2EnrollmentPassphrase(
  passphrase: string,
  iterations: number,
): V2EnrollmentCredential {
  if (passphrase.length < V2_ENROLLMENT_SECRET_MIN_LENGTH) {
    throw new Error(
      `DUD_PEER_SECRET must be at least ${V2_ENROLLMENT_SECRET_MIN_LENGTH} characters. ` +
        'It is a passphrase carried to every device that may invite, so choose one you can type ' +
        'and that is long enough not to be guessed, such as four or five random words.',
    );
  }
  if (passphrase.trim() !== passphrase) {
    throw new Error(
      'DUD_PEER_SECRET must not begin or end with whitespace, which does not survive being ' +
        'retyped on another device.',
    );
  }
  return { kind: 'passphrase', passphrase, iterations };
}

/**
 * Reads the three accepted forms of `DUD_PEER_SECRET` into one key derivation.
 *
 * A bare passphrase is stretched at the default work factor, and is what most
 * deployments configure. `dud2-enroll-key:` carries the derived key directly, so
 * a server verifying proofs does no key-derivation work at all — the cost the
 * KDF exists to impose falls on whoever guesses the passphrase, not on whoever
 * checks the result, so moving the derivation off the server costs an attacker
 * nothing they were not already paying. `dud2-enroll-kdf:` states a work factor
 * ahead of the passphrase.
 *
 * The parameters live inside the value rather than beside it so that they travel
 * with the secret to every device that holds it. A work factor configured
 * separately on each side could disagree, and that disagreement would surface
 * only as the deliberately indistinguishable enrollment refusal.
 */
export function parseV2EnrollmentCredential(
  value: string,
): V2EnrollmentCredential {
  if (value.startsWith(V2_ENROLLMENT_KEY_PREFIX)) {
    const encoded = value.slice(V2_ENROLLMENT_KEY_PREFIX.length);
    let key: Uint8Array;
    try {
      key = decodeBase64Url(encoded, 32);
    } catch {
      throw new Error(
        `DUD_PEER_SECRET starts with ${V2_ENROLLMENT_KEY_PREFIX}, so the rest must be a derived ` +
          'enrollment key: 32 bytes as 43 base64url characters, no padding. Produce one from a ' +
          'passphrase with: node dist/src/v2-admin.js enrollment-key',
      );
    }
    return { kind: 'key', key };
  }
  if (value.startsWith(V2_ENROLLMENT_KDF_PREFIX)) {
    const rest = value.slice(V2_ENROLLMENT_KDF_PREFIX.length);
    const separator = rest.indexOf(':');
    const digits = separator === -1 ? '' : rest.slice(0, separator);
    const iterations = /^[0-9]+$/.test(digits) ? Number(digits) : Number.NaN;
    if (
      !Number.isSafeInteger(iterations) ||
      iterations < V2_ENROLLMENT_KDF_MIN_ITERATIONS ||
      iterations > V2_ENROLLMENT_KDF_MAX_ITERATIONS
    ) {
      throw new Error(
        `DUD_PEER_SECRET starts with ${V2_ENROLLMENT_KDF_PREFIX}, so the rest must be an iteration ` +
          `count between ${V2_ENROLLMENT_KDF_MIN_ITERATIONS} and ${V2_ENROLLMENT_KDF_MAX_ITERATIONS}, ` +
          'a colon, and the passphrase.',
      );
    }
    return parseV2EnrollmentPassphrase(rest.slice(separator + 1), iterations);
  }
  return parseV2EnrollmentPassphrase(value, V2_ENROLLMENT_KDF_ITERATIONS);
}

/**
 * Produces the 32-byte HMAC key a proof is computed under. The wire contract is
 * unchanged by any of this: a proof is still an HMAC-SHA256 tag under a 32-byte
 * key, and only the way that key is obtained differs.
 */
export async function deriveV2EnrollmentKey(
  secret: string,
): Promise<Uint8Array> {
  const credential = parseV2EnrollmentCredential(secret);
  if (credential.kind === 'key') {
    return credential.key;
  }
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(textEncoder.encode(credential.passphrase)),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: arrayBuffer(textEncoder.encode(V2_ENROLLMENT_KDF_SALT)),
        iterations: credential.iterations,
      },
      key,
      256,
    ),
  );
}

/** Formats a derived key as the `DUD_PEER_SECRET` value that carries it. */
export function formatV2EnrollmentKey(key: Uint8Array): string {
  if (key.byteLength !== 32) {
    throw new Error('An enrollment key is 32 bytes.');
  }
  return `${V2_ENROLLMENT_KEY_PREFIX}${encodeBase64Url(key)}`;
}

/**
 * Proof that the caller holds the enrollment secret of this deployment. It is
 * bound to the rendezvous it authorizes, so the secret itself never reaches the
 * wire or a request log, and a captured proof opens nothing beyond the one
 * rendezvous whose locator and lifetime it already names.
 */
export async function deriveV2EnrollmentProof(
  secret: Uint8Array,
  locator: Uint8Array,
  expiresAt: number,
): Promise<Uint8Array> {
  return hmacSha256(
    secret,
    concat(
      textEncoder.encode('dud/v2/enrollment|'),
      locator,
      uint64(expiresAt),
    ),
  );
}

export function parseV2EnrollmentHeader(value: string | null): Uint8Array {
  const prefix = 'DUD2-Enroll ';
  if (!value?.startsWith(prefix) || value.length > prefix.length + 43) {
    throw new Error('Missing or invalid v2 enrollment authorization.');
  }
  return decodeBase64Url(value.slice(prefix.length), 32);
}

/**
 * Validates the configured enrollment credential at startup, so a mistyped key
 * or an unacceptable work factor names the variable now rather than surfacing on
 * the first invitation as the refusal that means "wrong secret". It returns the
 * string rather than a key, because stretching one is asynchronous and service
 * construction is not; the pairing handler derives once, lazily.
 */
export function parseV2EnrollmentSecret(
  value: string | undefined,
  acceptWeakKdf = false,
): string | undefined {
  if (!value) {
    return undefined;
  }
  const credential = parseV2EnrollmentCredential(value);
  if (
    credential.kind === 'passphrase' &&
    credential.iterations < V2_ENROLLMENT_KDF_ITERATIONS &&
    !acceptWeakKdf
  ) {
    throw new Error(
      `DUD_PEER_SECRET states a work factor of ${credential.iterations} iterations, below the ` +
        `default ${V2_ENROLLMENT_KDF_ITERATIONS}. That makes offline guessing against a captured ` +
        `enrollment proof ${Math.round(V2_ENROLLMENT_KDF_ITERATIONS / credential.iterations)}x ` +
        'cheaper. Set DUD_PEER_ACCEPT_WEAK_ENROLLMENT_KDF=true to accept that, or configure the ' +
        `derived key with ${V2_ENROLLMENT_KEY_PREFIX} instead, which keeps the full work factor ` +
        'and costs the server no derivation at all.',
    );
  }
  return value;
}

export function isV2Direction(value: unknown): value is V2Direction {
  return value === 'inviter->invitee' || value === 'invitee->inviter';
}

export function isV2Scope(value: unknown): value is V2Scope {
  return value === 'write' || value === 'read' || value === 'ack';
}
