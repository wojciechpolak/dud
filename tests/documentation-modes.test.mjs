// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const repository = path.resolve(import.meta.dirname, '..');

test('documentation names three transfer modes and preserves dead drop and ECH rules', (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), 'dud-mode-docs-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const entry of readdirSync(repository, { withFileTypes: true })) {
    if (
      (entry.name.startsWith('.') && entry.name !== '.github') ||
      ['README.md', 'node_modules', 'dist', 'bin', 'tmp'].includes(entry.name)
    ) {
      continue;
    }
    symlinkSync(
      path.join(repository, entry.name),
      path.join(directory, entry.name),
      entry.isDirectory() ? 'dir' : 'file',
    );
  }
  const cases = [
    ['DUD has three transfer modes: dead drop, peer and optical.', true],
    [
      '# Optical transfers\n\nOptical uses a local screen-to-camera carrier.',
      true,
    ],
    ['A dead drop uses an opaque ID. The drop expires at its TTL.', true],
    ['ECH has two modes: hard and off.', true],
    ['Optical dead drops use a local display.', false],
    ['DUD has two transfer modes.', false],
    ['DUD offers two permanent transfer modes.', false],
    ['# Two ways to transfer: dead drops and peers', false],
    ['Both transfer modes use the client.', false],
    ['The drop expires at its TTL.', false],
    ['ECH mode strict is enabled.', false],
  ];
  for (const [text, accepted] of cases) {
    writeFileSync(path.join(directory, 'README.md'), `${text}\n`);
    const result = spawnSync(
      process.execPath,
      [path.join(repository, 'scripts/check-docs.mjs')],
      {
        cwd: directory,
        encoding: 'utf8',
        timeout: 10000,
      },
    );
    assert.equal(result.status, accepted ? 0 : 1, `${text}\n${result.stderr}`);
    if (!accepted) {
      assert.match(result.stderr, /README\.md:/);
    }
  }
});
