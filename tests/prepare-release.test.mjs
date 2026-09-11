// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  addChangelogRelease,
  planRelease,
  releaseDate,
  stableVersion,
} from '../scripts/prepare-release.mjs';

function scratchRelease(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-release-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const files = {
    'CHANGELOG.md': '# Changelog\n\n## [Unreleased]\n\n### Added\n\n- Work.\n',
    'docs/dead-drops-v1.md': '  "version": "2.2.0"\n',
    'src/config.ts': "  version: '2.2.0',\n",
    'tests/v2-workerd.test.mjs': "      APP_VERSION: '2.2.0',\n",
    'tests/worker.test.mjs': "    config: { version: '2.2.0' },\n",
    'wrangler.example.toml': 'APP_VERSION = "2.2.0"\n',
  };
  for (const [file, contents] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    writeFileSync(path.join(root, file), contents);
  }
  return root;
}

test('release date uses the local calendar date', () => {
  assert.equal(releaseDate(new Date(2026, 8, 11, 23, 59)), '2026-09-11');
});

test('only stable semantic versions are accepted', () => {
  assert.equal(stableVersion('3.0.0'), '3.0.0');
  for (const version of ['v3.0.0', '3.0', '3.0.0-rc.1', '03.0.0', 'latest']) {
    assert.throws(() => stableVersion(version), /must be MAJOR\.MINOR\.PATCH/);
  }
});

test('a release heading moves Unreleased entries under the new version', () => {
  const changelog = '# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- A fix.\n';
  assert.equal(
    addChangelogRelease(changelog, '2.3.0', '2026-09-11'),
    '# Changelog\n\n## [Unreleased]\n\n## [2.3.0] - 2026-09-11\n\n### Fixed\n\n- A fix.\n',
  );
});

test('the release plan updates every version shared by prior release commits', (t) => {
  const changes = planRelease(
    scratchRelease(t),
    '2.2.0',
    '2.3.0',
    '2026-09-11',
  );

  assert.equal(changes.length, 6);
  for (const change of changes) {
    assert.doesNotMatch(change.contents, /2\.2\.0/);
    assert.match(change.contents, /2\.3\.0/);
  }
});

test('the release plan rejects a missing or duplicated version marker', (t) => {
  const root = scratchRelease(t);
  writeFileSync(
    path.join(root, 'src/config.ts'),
    "  version: '2.2.0',\n  version: '2.2.0',\n",
  );
  assert.throws(
    () => planRelease(root, '2.2.0', '2.3.0', '2026-09-11'),
    /src\/config\.ts contains .* more than once/,
  );
});
