// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const repository = path.resolve(import.meta.dirname, '..');
const corpus = path.join(repository, 'server/optical-receiver/corpus');
const manifestPath = path.join(corpus, 'manifest.json');
const env = {
  ...process.env,
  GOCACHE: '/tmp/dud-go-build-cache',
  GOWORK: 'off',
  GOPROXY: 'off',
};

test(
  'all deterministic corpus fixtures recover exactly and invalid fixture bytes fail',
  { timeout: 120000 },
  (t) => {
    const directory = mkdtempSync(path.join(tmpdir(), 'dud-optical-corpus-'));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    const manifestBytes = readFileSync(manifestPath);
    assert.equal(
      createHash('sha256').update(manifestBytes).digest('hex'),
      '3cb6e8e2ccff10ed0b15c30158bbe4b8e0ffede756edd0c0880f8b2ff8e40f45',
    );
    const manifest = JSON.parse(manifestBytes);
    assert.equal(manifest.files.length, 12);
    execFileSync(
      process.execPath,
      [path.join(corpus, 'generate.mjs'), directory],
      {
        env,
        timeout: 60000,
      },
    );
    const checker = path.join(
      directory,
      process.platform === 'win32' ? 'corpus-check.exe' : 'corpus-check',
    );
    execFileSync(
      'go',
      ['build', '-o', checker, './optical-sender/testtools/corpus-check'],
      {
        cwd: path.join(repository, 'client'),
        env,
        timeout: 60000,
      },
    );
    const output = execFileSync(checker, [manifestPath, directory], {
      env,
      encoding: 'utf8',
      timeout: 60000,
    });
    assert.deepEqual(
      output.trim().split('\n'),
      manifest.files.map(({ name }) => name),
    );

    const first = path.join(directory, manifest.files[0].name);
    const original = readFileSync(first);
    for (const scenario of ['missing', 'truncated', 'corrupt']) {
      if (scenario === 'missing') {
        rmSync(first);
      } else if (scenario === 'truncated') {
        writeFileSync(first, original.subarray(1));
      } else {
        const corrupt = Buffer.from(original);
        corrupt[0] ^= 1;
        writeFileSync(first, corrupt);
      }
      const result = spawnSync(checker, [manifestPath, directory], {
        env,
        encoding: 'utf8',
      });
      assert.ifError(result.error);
      assert.equal(result.status, 1, scenario);
      assert.match(result.stderr, /collection-hostile\.tar/);
      assert.match(
        result.stderr,
        scenario === 'missing'
          ? /no such file|cannot find/i
          : scenario === 'truncated'
            ? /size=/
            : /digest does not match/,
      );
    }
  },
);
