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
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const directory = mkdtempSync(path.join(tmpdir(), 'dud-optical-command-'));
const binary = path.join(directory, 'dud');
const helper = path.join(directory, 'dud-optical-window');
const age = path.join(directory, 'age');
const received = path.join(directory, 'received');
const active = path.join(directory, 'active');
const recipientArgs = path.join(directory, 'age-arguments');
const env = {
  ...process.env,
  TMPDIR: directory,
  DISPLAY: ':0',
  DUD_AGE_BIN: age,
  DUD_DROP_SECRET: '',
  DUD_DROP_BASE_URL: 'invalid origin',
  DUD_DOH_URL: 'invalid resolver',
  DUD_ECH_MODE: 'invalid mode',
  DUD_CONNECT_TO: 'invalid mapping',
  DUD_CA_BUNDLE: '/missing',
  OPTICAL_CAPTURE: received,
  OPTICAL_ACTIVE: active,
  OPTICAL_AGE_ARGUMENTS: recipientArgs,
};

test.before(() => {
  execFileSync(
    'go',
    ['build', '-tags', 'nativewindow', '-o', binary, './cmd/dud'],
    {
      cwd: path.join(root, 'client'),
      env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
      timeout: 90000,
    },
  );
  writeFileSync(
    age,
    `#!/bin/sh
printf '%s\\n' "$@" > "$OPTICAL_AGE_ARGUMENTS"
out=""
input=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2; continue ;;
    -R) shift 2; continue ;;
    -*) shift; continue ;;
  esac
  input="$1"
  shift
done
cp "$input" "$out"
`,
    { mode: 0o700 },
  );
});
test.after(() => rmSync(directory, { recursive: true, force: true }));

function writeHelper(wait) {
  writeFileSync(
    helper,
    `#!/bin/sh
printf 'DUD-OPTICAL-WINDOW-READY-1\\n'
read ciphertext || exit 1
cp "$ciphertext" "$OPTICAL_CAPTURE"
printf '%s\\n' "$ciphertext" > "$OPTICAL_ACTIVE.tmp"
mv "$OPTICAL_ACTIVE.tmp" "$OPTICAL_ACTIVE"
${wait ? 'while read unused; do :; done' : ''}
`,
    { mode: 0o700 },
  );
}
function assertRemoved() {
  assert.deepEqual(
    readdirSync(directory).filter(
      (name) =>
        /^dud-(?:optical-|upload-recipients-)/.test(name) &&
        name !== 'dud-optical-window',
    ),
    [],
  );
}

test('installed optical upload reaches only its local renderer and keeps stdout for JSON', () => {
  writeHelper(false);
  const output = execFileSync(
    binary,
    ['send', '--optical', '--json', '-m', 'private command payload'],
    { env, encoding: 'utf8', timeout: 15000 },
  );
  const report = JSON.parse(output);
  assert.deepEqual(Object.keys(report).sort(), [
    'ciphertextBytes',
    'format',
    'mode',
    'operation',
    'profile',
    'renderer',
    'status',
  ]);
  assert.equal(report.status, 'display-ended');
  assert.equal(report.mode, 'optical');
  assert.equal(report.format, 'dud/optical/1');
  assert.equal(report.ciphertextBytes, readFileSync(received).length);
  assert.equal(readFileSync(received).subarray(0, 8).toString(), 'DUDCAP1\0');
  assert.match(readFileSync(recipientArgs, 'utf8'), /--passphrase/);
  assert.doesNotMatch(output, /private|payload|expiresAt|"id"/);
  assertRemoved();
});

test('optical SIGINT exits 130 and removes owned ciphertext and renderer state', async () => {
  writeHelper(true);
  rmSync(active, { force: true });
  const child = spawn(
    binary,
    ['upload', '--optical', '--json', '-m', 'private interrupted payload'],
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
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  const deadline = Date.now() + 10000;
  while (
    !existsSync(active) &&
    Date.now() < deadline &&
    child.exitCode === null
  ) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.ok(existsSync(active), `renderer did not receive data: ${stderr}`);
  const ciphertext = readFileSync(active, 'utf8').trim();
  assert.ok(existsSync(ciphertext));
  child.kill('SIGINT');
  const outcome = await exited;
  assert.equal(outcome.code, 130);
  assert.equal(outcome.signal, null);
  assert.equal(existsSync(ciphertext), false);
  assert.doesNotMatch(stdout + stderr, /private interrupted payload/);
  assertRemoved();
});

test('optical SIGTERM during encryption stops age and removes plaintext staging', async () => {
  writeHelper(true);
  rmSync(active, { force: true });
  writeFileSync(
    age,
    `#!/bin/sh
printf '%s\\n' "$$" > "$OPTICAL_ACTIVE.tmp"
mv "$OPTICAL_ACTIVE.tmp" "$OPTICAL_ACTIVE"
exec sleep 30
`,
    { mode: 0o700 },
  );
  const child = spawn(
    binary,
    ['upload', '--optical', '--json', '-m', 'private encryption payload'],
    { env, stdio: ['pipe', 'pipe', 'pipe'] },
  );
  let stderr = '';
  child.stdout.resume();
  child.stderr.on('data', (data) => {
    stderr += data;
  });
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  const deadline = Date.now() + 10000;
  while (
    !existsSync(active) &&
    Date.now() < deadline &&
    child.exitCode === null
  ) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.ok(existsSync(active), `encryption did not start: ${stderr}`);
  const agePID = Number(readFileSync(active, 'utf8').trim());
  assert.ok(
    Number.isSafeInteger(agePID) && agePID > 0,
    'age must publish its process ID',
  );
  child.kill('SIGTERM');
  const outcome = await exited;
  assert.equal(outcome.code, 143);
  assert.equal(outcome.signal, null);
  assert.throws(() => process.kill(agePID, 0), { code: 'ESRCH' });
  assertRemoved();
});
