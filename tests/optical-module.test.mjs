// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const client = path.resolve(import.meta.dirname, '../client');
const preparationEnv = {
  ...process.env,
  GOCACHE: '/tmp/dud-go-build-cache',
  GOWORK: 'off',
};
const env = {
  ...preparationEnv,
  GOPROXY: 'off',
};

test(
  'optical packages and unit fixtures compile and pass in an isolated client module',
  { timeout: 120000 },
  (t) => {
    const isolated = mkdtempSync(path.join(tmpdir(), 'dud-optical-client-'));
    t.after(() => rmSync(isolated, { recursive: true, force: true }));
    for (const entry of ['go.mod', 'go.sum', 'drop', 'optical-sender']) {
      cpSync(path.join(client, entry), path.join(isolated, entry), {
        recursive: true,
      });
    }
    const run = (args, commandEnv = env) =>
      execFileSync('go', args, {
        cwd: isolated,
        env: commandEnv,
        encoding: 'utf8',
        timeout: 90000,
      });
    // The complete module graph includes pruned dependency metadata that
    // package builds do not fetch. Stage it before the offline checks.
    run(['mod', 'download', 'all'], preparationEnv);
    const dependencies = run(['list', '-deps', './optical-sender/...']);
    assert.doesNotMatch(dependencies, /client\/cmd/);
    const modules = run(['list', '-m', 'all']);
    assert.doesNotMatch(
      modules,
      /github\.com\/yeqown\/(?:go-qrcode|reedsolomon)/,
    );
    assert.match(
      run(['test', './optical-sender/...']),
      /client\/optical-sender\/display/,
    );
  },
);

test('optical compatibility and QR oracle fixtures preserve their pinned bytes', () => {
  const digests = {
    'client/optical-sender/testdata/format0/go-vectors.json':
      'eb55a27f293bf6e96f99c2bbeed16cbc6c7c1d30f2774b36d394f77489272310',
    'client/optical-sender/testdata/format0/typescript-vectors.json':
      '347d4f99ff088e2a3135c136f448a03a5bf870095f9572e6da53a96e5ec203e1',
    'client/optical-sender/testdata/qr/oracle-v30-capacity.json':
      'b287beee174d5052c3f902a917ee45f05f4b09a9cda01166f9baf82b0c0571dd',
    'client/optical-sender/testdata/qr/oracle-v30-cycle.json':
      'c017c8f1ef5c97d5de3c57f90ef829b43e3f1d7924c7208a0c4948f5ddd6207a',
    'client/optical-sender/testdata/qr/oracle-v30-random.json':
      '8b8d14958f263fc23f4f835f835f0bb3e4c08b40b4f6b6a138d280ee91d5257b',
    'client/optical-sender/testdata/qr/oracle-v30-zero.json':
      '6795447dd01febaa25a8047c2522fde3ba5b5801d6951771794fdfb41cf2d07a',
    'client/optical-sender/testdata/qr/oracle-v40-capacity.json':
      '4fe3c708e12ed81f779fc0bd24fe8932784e7a2eb96829680c5f6de1e8294185',
    'client/optical-sender/testdata/qr/oracle-v40-cycle.json':
      '56be04edd80ae6c262e45d8e9047ed9ebbbf6460e9649ac706bad5174e04e91f',
    'client/optical-sender/testdata/qr/oracle-v40-random.json':
      '64f517c8ba77db99b263ea3a129463dcd775579f144c93ad739417bf944363d8',
    'client/optical-sender/testdata/qr/oracle-v40-zero.json':
      '8f25849adc807c23f1ff2ccf480718498bee23eeae49d69e5a168c7bdb69fb84',
  };
  for (const [file, expected] of Object.entries(digests)) {
    const actual = createHash('sha256')
      .update(readFileSync(path.resolve(import.meta.dirname, '..', file)))
      .digest('hex');
    assert.equal(actual, expected, file);
  }
});

test(
  'server and receiver builds use their isolated source packages',
  { timeout: 90000 },
  (t) => {
    const repository = path.resolve(client, '..');
    const isolated = mkdtempSync(path.join(tmpdir(), 'dud-optical-server-'));
    t.after(() => rmSync(isolated, { recursive: true, force: true }));
    for (const entry of [
      'package.json',
      'package-lock.json',
      'tsconfig.json',
      'server',
    ]) {
      cpSync(path.join(repository, entry), path.join(isolated, entry), {
        recursive: true,
        filter: (source) => !source.split(path.sep).includes('.work'),
      });
    }
    rmSync(path.join(isolated, 'server/src/optical-pwa-assets.generated.ts'));
    symlinkSync(
      path.join(repository, 'node_modules'),
      path.join(isolated, 'node_modules'),
      'dir',
    );
    const output = execFileSync('npm', ['run', 'build:server'], {
      cwd: isolated,
      env: process.env,
      encoding: 'utf8',
      timeout: 60000,
    });
    assert.match(output, /server\/optical-receiver\/build\.mjs/);
    const generated = readFileSync(
      path.join(isolated, 'server/src/optical-pwa-assets.generated.ts'),
    );
    assert.deepEqual(
      generated,
      readFileSync(
        path.join(repository, 'server/src/optical-pwa-assets.generated.ts'),
      ),
    );
    assert.ok(
      existsSync(path.join(isolated, 'dist/server/src/node-server.js')),
    );
    const nestedEnvironment = { ...process.env };
    delete nestedEnvironment.NODE_TEST_CONTEXT;
    execFileSync(
      process.execPath,
      ['--test', 'server/optical-receiver/test/pwa.test.mjs'],
      {
        cwd: isolated,
        env: nestedEnvironment,
        encoding: 'utf8',
        timeout: 30000,
      },
    );
  },
);

test('camera fixtures preserve their pinned bytes', () => {
  const digests = {
    'server/optical-receiver/testdata/qr/camera-v40-format0.gray.gz':
      '66812612bd000d1d1430028f2fe9c66c0bf10f94cfa79906b6998610de85dd1c',
    'server/optical-receiver/testdata/qr/camera-v40-format0.frame.bin':
      '7e3563e9d8406e917d3907ed038422d243dc55912666269a88225a55474b5e2e',
  };
  for (const [file, expected] of Object.entries(digests)) {
    const actual = createHash('sha256')
      .update(readFileSync(path.resolve(import.meta.dirname, '..', file)))
      .digest('hex');
    assert.equal(actual, expected, file);
  }
});
