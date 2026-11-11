// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const require = createRequire(import.meta.url);
const coverageRequire = createRequire(require.resolve('c8'));
const TestExclude = coverageRequire('test-exclude');

test('coverage discovery includes unexecuted source files and respects path exclusions', async (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-coverage-discovery-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const name of [
    'server/src/main.ts',
    'server/src/nested/unused.ts',
    'server/src/.hidden.ts',
    'server/src/nested/schema.d.ts',
    'server/src/types.ts',
    'server/src/main.js',
    'tests/outside.ts',
  ]) {
    const file = path.join(root, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, '');
  }
  const discovery = new TestExclude({
    cwd: root,
    include: ['server/src/**/*.ts'],
    exclude: ['**/*.d.ts', 'server/src/types.ts'],
    extension: ['.ts'],
  });
  const expected = [
    'server/src/.hidden.ts',
    'server/src/main.ts',
    'server/src/nested/unused.ts',
  ];
  assert.deepEqual(discovery.globSync().sort(), expected);
  assert.deepEqual((await discovery.glob()).sort(), expected);
});
