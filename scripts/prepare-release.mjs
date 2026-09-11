#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//
// Keeps every checked-in release version in step with `npm version`. The
// preversion pass checks all inputs before npm edits package.json. The version
// pass writes and stages the remaining files for npm's release commit.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHANGELOG = 'CHANGELOG.md';
const VERSION_TARGETS = [
  {
    file: 'docs/dead-drops-v1.md',
    text: (version) => `  "version": "${version}"`,
  },
  {
    file: 'src/config.ts',
    text: (version) => `  version: '${version}',`,
  },
  {
    file: 'tests/v2-workerd.test.mjs',
    text: (version) => `      APP_VERSION: '${version}',`,
  },
  {
    file: 'tests/worker.test.mjs',
    text: (version) => `    config: { version: '${version}' },`,
  },
  {
    file: 'wrangler.example.toml',
    text: (version) => `APP_VERSION = "${version}"`,
  },
];
const RELEASE_FILES = [CHANGELOG, ...VERSION_TARGETS.map(({ file }) => file)];
const STABLE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

function replaceOnce(contents, before, after, file) {
  const first = contents.indexOf(before);
  const last = contents.lastIndexOf(before);
  if (first === -1) {
    throw new Error(`${file} does not contain ${JSON.stringify(before)}`);
  }
  if (first !== last) {
    throw new Error(
      `${file} contains ${JSON.stringify(before)} more than once`,
    );
  }
  return `${contents.slice(0, first)}${after}${contents.slice(first + before.length)}`;
}

export function releaseDate(now = new Date()) {
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export function stableVersion(value, name = 'version') {
  if (!STABLE_VERSION.test(value ?? '')) {
    throw new Error(
      `${name} must be MAJOR.MINOR.PATCH, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

export function addChangelogRelease(contents, version, date) {
  const heading = `## [${version}]`;
  if (contents.includes(heading)) {
    throw new Error(`${CHANGELOG} already contains ${heading}`);
  }
  return replaceOnce(
    contents,
    '## [Unreleased]\n',
    `## [Unreleased]\n\n## [${version}] - ${date}\n`,
    CHANGELOG,
  );
}

function readJson(root, file) {
  return JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
}

function checkManifestVersions(root, expected) {
  const manifest = readJson(root, 'package.json');
  const lock = readJson(root, 'package-lock.json');
  if (manifest.version !== expected) {
    throw new Error(
      `package.json has version ${manifest.version}, expected ${expected}`,
    );
  }
  if (lock.version !== expected || lock.packages?.['']?.version !== expected) {
    throw new Error(
      `package-lock.json does not consistently use version ${expected}`,
    );
  }
}

export function planRelease(
  root,
  oldVersion,
  newVersion,
  date = releaseDate(),
) {
  stableVersion(oldVersion, 'npm_old_version');
  stableVersion(newVersion, 'npm_new_version');
  if (oldVersion === newVersion) {
    throw new Error('npm_new_version must differ from npm_old_version');
  }

  const changes = [];
  const changelog = fs.readFileSync(path.join(root, CHANGELOG), 'utf8');
  changes.push({
    file: CHANGELOG,
    contents: addChangelogRelease(changelog, newVersion, date),
  });

  for (const target of VERSION_TARGETS) {
    const contents = fs.readFileSync(path.join(root, target.file), 'utf8');
    changes.push({
      file: target.file,
      contents: replaceOnce(
        contents,
        target.text(oldVersion),
        target.text(newVersion),
        target.file,
      ),
    });
  }
  return changes;
}

function run(mode, env = process.env) {
  if (mode !== 'check' && mode !== 'update') {
    throw new Error('usage: prepare-release.mjs check|update');
  }
  const oldVersion = stableVersion(env.npm_old_version, 'npm_old_version');
  const newVersion = stableVersion(env.npm_new_version, 'npm_new_version');
  checkManifestVersions(ROOT, mode === 'check' ? oldVersion : newVersion);
  const changes = planRelease(ROOT, oldVersion, newVersion);

  if (mode === 'check') {
    console.log(`release: ${oldVersion} -> ${newVersion} is ready`);
    return;
  }

  for (const change of changes) {
    fs.writeFileSync(path.join(ROOT, change.file), change.contents);
  }
  if (env.npm_config_git_tag_version !== 'false') {
    execFileSync('git', ['add', '--', ...RELEASE_FILES], {
      cwd: ROOT,
      stdio: 'inherit',
    });
  }
  console.log(`release: prepared ${newVersion}`);
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    run(process.argv[2]);
  } catch (error) {
    console.error(`release preparation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
