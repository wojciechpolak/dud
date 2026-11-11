// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const directory = mkdtempSync(path.join(tmpdir(), 'dud-optical-recovery-'));
const binary = path.join(directory, 'dud');
const age = path.join(directory, 'age');
const saved = path.join(directory, 'saved.age');
const active = path.join(directory, 'active');
const plaintext = path.join(directory, 'container');
const env = {
  ...process.env,
  TMPDIR: directory,
  DUD_AGE_BIN: age,
  DUD_DROP_SECRET: '',
  DUD_DROP_BASE_URL: 'invalid origin',
  DUD_DOH_URL: 'invalid resolver',
  DUD_ECH_MODE: 'invalid mode',
  DUD_CONNECT_TO: 'invalid mapping',
  DUD_CA_BUNDLE: '/missing',
  OPTICAL_CONTAINER: plaintext,
  OPTICAL_ACTIVE: active,
};

function capsule(payload) {
  const name = Buffer.from('private display name');
  const header = Buffer.alloc(64);
  header.write('DUDCAP1\0');
  header[8] = 1;
  header[9] = 3;
  header.writeUInt16BE(64, 12);
  header.writeUInt16BE(name.length, 14);
  header.writeBigUInt64BE(BigInt(payload.length), 16);
  header.writeBigUInt64BE(BigInt(payload.length), 24);
  createHash('sha256').update(payload).digest().copy(header, 32);
  return Buffer.concat([header, name, payload]);
}
function assertRemoved() {
  assert.deepEqual(
    readdirSync(directory).filter((name) => name.startsWith('dud-optical-')),
    [],
  );
}

test.before(() => {
  execFileSync('go', ['build', '-o', binary, './cmd/dud'], {
    cwd: path.join(root, 'client'),
    env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
    timeout: 90000,
  });
  writeFileSync(saved, 'opaque local ciphertext');
  writeFileSync(age, '#!/bin/sh\ncat "$OPTICAL_CONTAINER"\n', { mode: 0o700 });
});
test.after(() => rmSync(directory, { recursive: true, force: true }));

test('installed optical recovery validates bytes and reports only the chosen absolute path', () => {
  const payload = Buffer.from('private recovered payload\x00');
  writeFileSync(plaintext, capsule(payload));
  const destination = path.join(directory, 'output');
  const report = JSON.parse(
    execFileSync(
      binary,
      ['optical', 'decrypt', '--file', saved, '--out', destination, '--json'],
      { env, timeout: 15000 },
    ),
  );
  assert.deepEqual(report, {
    mode: 'optical',
    format: 'dud/optical/1',
    operation: 'decrypt',
    status: 'recovered',
    output: destination,
  });
  assert.deepEqual(readFileSync(destination), payload);
  assert.equal(statSync(destination).mode & 0o777, 0o600);
  assert.deepEqual(
    execFileSync(binary, ['optical', 'decrypt', '--file', saved, '--stdout'], {
      env,
      timeout: 15000,
    }),
    payload,
  );
  assertRemoved();
});

test('installed optical recovery emits no stdout or final file on digest failure', () => {
  const broken = capsule(Buffer.from('private invalid bytes'));
  broken[broken.length - 1] ^= 1;
  writeFileSync(plaintext, broken);
  const destination = path.join(directory, 'absent');
  for (const output of [['--stdout'], ['--out', destination, '--json']]) {
    let failure;
    try {
      execFileSync(binary, ['optical', 'decrypt', '--file', saved, ...output], {
        env,
        timeout: 15000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (error) {
      failure = error;
    }
    assert.equal(failure?.status, 1);
    assert.equal(existsSync(destination), false);
    if (output[0] === '--stdout') {
      assert.equal(failure.stdout.length, 0);
    } else {
      assert.equal(JSON.parse(failure.stdout).error.code, 'capsule');
    }
    assert.doesNotMatch(
      failure.stderr.toString(),
      /private display name|private invalid bytes/,
    );
    assertRemoved();
  }
});

test('optical recovery signals terminate age and remove staged plaintext and identities', async () => {
  for (const signal of ['SIGINT', 'SIGTERM']) {
    rmSync(active, { force: true });
    writeFileSync(
      age,
      '#!/bin/sh\nprintf "%s\\n" "$$" > "$OPTICAL_ACTIVE.tmp"\nmv "$OPTICAL_ACTIVE.tmp" "$OPTICAL_ACTIVE"\ncat "$OPTICAL_CONTAINER"\nexec sleep 30\n',
      { mode: 0o700 },
    );
    const child = spawn(
      binary,
      [
        'optical',
        'decrypt',
        '--file',
        saved,
        '--out',
        path.join(directory, 'signal-output'),
        '--json',
      ],
      { env, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (data) => {
      stdout += data;
    });
    child.stderr.on('data', (data) => {
      stderr += data;
    });
    const exited = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code, exitedSignal) =>
        resolve({ code, signal: exitedSignal }),
      );
    });
    const deadline = Date.now() + 10000;
    while (
      !existsSync(active) &&
      Date.now() < deadline &&
      child.exitCode === null
    ) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.ok(existsSync(active), `decryption did not start: ${stderr}`);
    const agePID = Number(readFileSync(active, 'utf8').trim());
    assert.ok(
      Number.isSafeInteger(agePID) && agePID > 0,
      'age must publish its process ID',
    );
    child.kill(signal);
    assert.deepEqual(await exited, {
      code: signal === 'SIGINT' ? 130 : 143,
      signal: null,
    });
    assert.throws(() => process.kill(agePID, 0), { code: 'ESRCH' });
    assert.doesNotMatch(stdout + stderr, /private|display name/);
    assert.equal(existsSync(path.join(directory, 'signal-output')), false);
    assertRemoved();
  }
});
