#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = path.dirname(fileURLToPath(import.meta.url));
const client = path.resolve(root, '../../client');
const temporary = mkdtempSync(path.join(tmpdir(), 'dud-optical-vectors-'));
const generated = [
  {
    name: 'go-vectors.json',
    run: () =>
      execFileSync(
        'go',
        [
          'run',
          './optical-sender/cmd/vector-gen',
          path.join(temporary, 'go-vectors.json'),
        ],
        {
          cwd: client,
          env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
          stdio: 'inherit',
        },
      ),
  },
  {
    name: 'typescript-vectors.json',
    run: () =>
      execFileSync(
        process.execPath,
        [
          path.join(root, '.work/receiver/vector-gen.js'),
          path.join(temporary, 'typescript-vectors.json'),
        ],
        { cwd: root, stdio: 'inherit' },
      ),
  },
];

try {
  for (const vector of generated) {
    vector.run();
    const expected = readFileSync(
      path.join(
        root,
        '../../client/optical-sender/testdata/format1',
        vector.name,
      ),
    );
    const actual = readFileSync(path.join(temporary, vector.name));
    if (!expected.equals(actual)) {
      throw new Error(
        `${vector.name} is stale; regenerate the optical vectors`,
      );
    }
  }
  const goVectors = JSON.parse(
    readFileSync(path.join(temporary, 'go-vectors.json'), 'utf8'),
  );
  const typeScriptVectors = JSON.parse(
    readFileSync(path.join(temporary, 'typescript-vectors.json'), 'utf8'),
  );
  delete goVectors.generatedBy;
  delete typeScriptVectors.generatedBy;
  assert.deepEqual(
    typeScriptVectors,
    goVectors,
    'Go and TypeScript generated different vectors',
  );
  console.log('optical vectors: Go and TypeScript fixtures are reproducible');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
