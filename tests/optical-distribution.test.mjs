// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  goToolchainNoticeRecords,
  noticeInventory,
  noticeBundle,
  parseGoObjects,
  sha256,
} from '../scripts/distribution-notices.mjs';

test('Go toolchain notices preserve official and Homebrew license layouts', (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-go-notices-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const license = 'Exact Go license\n';
  const patents = 'Exact Go patent grant\n';
  const official = path.join(root, 'go');
  mkdirSync(official);
  writeFileSync(path.join(official, 'LICENSE'), license);
  writeFileSync(path.join(official, 'PATENTS'), patents);
  const expected = (licensePath) => [
    {
      path: licensePath,
      kind: 'license-file',
      sha256: sha256(license),
      text: license,
    },
    {
      path: 'PATENTS',
      kind: 'license-file',
      sha256: sha256(patents),
      text: patents,
    },
  ];
  assert.deepEqual(goToolchainNoticeRecords(official), expected('LICENSE'));

  const prefix = path.join(root, 'Cellar/go/1.27.3');
  const homebrew = path.join(prefix, 'libexec');
  mkdirSync(homebrew, { recursive: true });
  writeFileSync(path.join(prefix, 'LICENSE'), license);
  writeFileSync(path.join(homebrew, 'PATENTS'), patents);
  const alias = path.join(root, 'opt-go');
  symlinkSync(prefix, alias, 'dir');
  assert.deepEqual(
    goToolchainNoticeRecords(path.join(alias, 'libexec')),
    expected('../LICENSE'),
  );

  writeFileSync(path.join(homebrew, 'LICENSE'), license);
  writeFileSync(path.join(prefix, 'LICENSE'), 'Different prefix license\n');
  assert.deepEqual(goToolchainNoticeRecords(homebrew), expected('LICENSE'));
});

test('Go toolchain notices require both files within the Go installation', (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-go-notices-missing-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const official = path.join(root, 'go');
  mkdirSync(official);
  writeFileSync(path.join(root, 'LICENSE'), 'Unrelated parent license\n');
  writeFileSync(path.join(official, 'PATENTS'), 'Go patent grant\n');
  assert.throws(() => goToolchainNoticeRecords(official), { code: 'ENOENT' });

  const homebrew = path.join(root, 'libexec');
  mkdirSync(homebrew);
  assert.throws(() => goToolchainNoticeRecords(homebrew), { code: 'ENOENT' });
  mkdirSync(path.join(homebrew, 'LICENSE'));
  assert.throws(() => goToolchainNoticeRecords(homebrew), { code: 'EISDIR' });
});

test('dependency notices retain nested licenses and selected header terms without licensing an unlicensed archive', (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-optical-notices-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, 'vendor'));
  const text = 'Exact license text\n';
  writeFileSync(path.join(root, 'vendor', 'LICENSE.txt'), text);
  writeFileSync(
    path.join(root, 'selected.c'),
    '/* Copyright Holder\n * Permission is granted with restrictions.\n */\nint value;',
  );
  writeFileSync(
    path.join(root, 'unselected.go'),
    '// Copyright Excluded\npackage ignored',
  );
  const inventory = noticeInventory(root, ['selected.c']);
  assert.equal(inventory.rootLicensePresent, false);
  assert.equal(inventory.scannedFiles, 3);
  assert.deepEqual(
    inventory.records.map(({ path }) => path),
    ['vendor/LICENSE.txt', 'selected.c'],
  );
  assert.equal(inventory.records[0].sha256, sha256(text));
  assert.equal(inventory.records[0].text, text);
  const bundle = noticeBundle([{ name: 'module@version', ...inventory }]);
  assert.match(bundle, /MISSING ROOT LICENSE/);
  assert.ok(bundle.includes(text));
  assert.match(bundle, /Permission is granted with restrictions/);
  assert.doesNotMatch(bundle, /int value|Excluded/);
  writeFileSync(path.join(root, 'LICENSE'), text);
  assert.equal(noticeInventory(root, []).rootLicensePresent, true);
  writeFileSync(
    path.join(root, 'ordinary.go'),
    '// Ordinary comment\npackage main',
  );
  assert.equal(
    noticeInventory(root, ['ordinary.go']).records.some(
      ({ path }) => path === 'ordinary.go',
    ),
    false,
  );
});

test('Go JSON object streams preserve nested objects and braces inside strings', () => {
  const objects = [
    { Module: { Path: 'example/{name}' }, Name: 'one' },
    { Name: 'two' },
  ];
  assert.deepEqual(
    parseGoObjects(
      objects.map((value) => JSON.stringify(value, null, 2)).join('\n'),
    ),
    objects,
  );
  assert.deepEqual(parseGoObjects(''), []);
  assert.throws(() => parseGoObjects('{ invalid }'));
});
