// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  createV2CapabilityRecord,
  decryptV2TokenSecret,
  encodeBase64Url,
  hexToBytes,
} from '../dist/src/v2-auth.js';
import { FilesystemV2Store } from '../dist/src/v2-filesystem.js';

const execute = promisify(execFile);

async function seedCapability(store, deploymentKey, relationship, tokenSecret) {
  const createdAt = Math.floor(Date.now() / 1000);
  const record = await createV2CapabilityRecord(deploymentKey, {
    relationshipId: hexToBytes(relationship, 16),
    direction: 'inviter->invitee',
    scope: 'write',
    tokenSecret,
    createdAt,
    expiresAt: createdAt + 3600,
  });
  await store.transaction((state) => {
    state.capabilities[record.id] = record;
  });
  return record;
}

test('offline admin rewraps and revokes without exposing secrets', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'dud-v2-admin-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const relationship = '12'.repeat(16);
  const oldKey = Uint8Array.from({ length: 32 }, (_, index) => 0x30 + index);
  const newKey = Uint8Array.from({ length: 32 }, (_, index) => 0x70 + index);
  const tokenSecret = Uint8Array.from(
    { length: 32 },
    (_, index) => 0x10 + index,
  );

  const store = new FilesystemV2Store(directory);
  await store.initialize();
  await seedCapability(store, oldKey, relationship, tokenSecret);
  assert.equal(
    (await readFile(path.join(directory, 'v2', 'state.json'), 'utf8')).includes(
      encodeBase64Url(tokenSecret),
    ),
    false,
  );

  await execute(
    process.execPath,
    ['dist/src/v2-admin.js', 'rewrap-key', '--data-dir', directory],
    {
      env: {
        ...process.env,
        DUD_PEER_DEPLOYMENT_KEY: encodeBase64Url(oldKey),
        DUD_PEER_NEW_DEPLOYMENT_KEY: encodeBase64Url(newKey),
      },
    },
  );
  const rewrapped = Object.values((await store.readState()).capabilities)[0];
  await assert.rejects(
    decryptV2TokenSecret(oldKey, rewrapped),
    /failed authentication/,
  );
  assert.deepEqual(await decryptV2TokenSecret(newKey, rewrapped), tokenSecret);

  await execute(process.execPath, [
    'dist/src/v2-admin.js',
    'revoke',
    '--data-dir',
    directory,
    '--relationship',
    relationship,
  ]);
  assert.equal(
    Object.values((await store.readState()).capabilities)[0].revoked,
    true,
  );
});

test('offline derivation prints an enrollment key a deployment can hold', async () => {
  // The command moves derivation off the server. Its output must be accepted as
  // DUD_PEER_SECRET and derive the same key as the passphrase. Otherwise, a
  // deployment configured from it would refuse its own clients.
  const { deriveV2EnrollmentKey, formatV2EnrollmentKey } =
    await import('../dist/src/v2-auth.js');
  const secret = 'squid-lantern-rotate-9-mango';
  const { stdout } = await execute(
    process.execPath,
    ['dist/src/v2-admin.js', 'enrollment-key'],
    { env: { ...process.env, DUD_PEER_SECRET: secret } },
  );
  const printed = stdout.trim();
  assert.equal(
    printed,
    formatV2EnrollmentKey(await deriveV2EnrollmentKey(secret)),
  );
  assert.deepEqual(
    await deriveV2EnrollmentKey(printed),
    await deriveV2EnrollmentKey(secret),
  );
  assert.ok(!printed.includes(secret), 'the passphrase must not be printed');

  // The passphrase is never an argument, so it cannot reach a shell history or
  // the process table.
  await assert.rejects(
    execute(process.execPath, ['dist/src/v2-admin.js', 'enrollment-key'], {
      env: { ...process.env, DUD_PEER_SECRET: '' },
    }),
    /DUD_PEER_SECRET/,
  );
  await assert.rejects(
    execute(process.execPath, [
      'dist/src/v2-admin.js',
      'enrollment-key',
      '--secret',
      secret,
    ]),
    /--secret/,
  );
});

test('the retired upload provisioning command is rejected', async (t) => {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), 'dud-v2-admin-retired-'),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  await assert.rejects(
    execute(process.execPath, [
      'dist/src/v2-admin.js',
      'provision-upload',
      '--data-dir',
      directory,
      '--relationship',
      '34'.repeat(16),
    ]),
    /Unknown v2 admin command provision-upload/,
  );
});

test('offline revocation rejects an unknown capability scope', async (t) => {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), 'dud-v2-admin-scope-'),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  await assert.rejects(
    execute(process.execPath, [
      'dist/src/v2-admin.js',
      'revoke',
      '--data-dir',
      directory,
      '--relationship',
      '34'.repeat(16),
      '--scope',
      'upload',
    ]),
    /--scope is invalid/,
  );
});
