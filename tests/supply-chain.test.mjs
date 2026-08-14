// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const CHECK_PINS = path.resolve('scripts/check-pins.mjs');
const CHECK_DOCS = path.resolve('scripts/check-docs.mjs');

const DIGEST = `sha256:${'a'.repeat(64)}`;
const COMMIT = 'b'.repeat(40);
const ACTION_SHA = 'c'.repeat(40);

/**
 * Writes the smallest tree the pin checker accepts, so each test can break
 * exactly one thing and see only that failure.
 */
function pinFixture(t, overrides = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-pins-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const files = {
    'client/Dockerfile': [
      '# pin: debian stable-slim',
      `ARG DEBIAN_DIGEST=${DIGEST}`,
      'FROM debian:stable-slim@${DEBIAN_DIGEST} AS build-base',
      '# pin: openssl openssl-4.0.0',
      `RUN git init openssl && git -C openssl fetch --depth 1 origin ${COMMIT}`,
      'FROM build-base',
      '',
    ].join('\n'),
    'server/Dockerfile': [
      '# pin: node 24-alpine',
      `ARG NODE_DIGEST=${DIGEST}`,
      'FROM node:24-alpine@${NODE_DIGEST}',
      '',
    ].join('\n'),
    '.github/workflows/ci.yml': [
      'jobs:',
      '  build:',
      '    steps:',
      `      - uses: actions/checkout@${ACTION_SHA} # v6.0.3`,
      '',
    ].join('\n'),
    '.github/supported-versions.json': JSON.stringify({
      node: { minimum: '24.0.0' },
      go: { minimum: '1.24.0' },
      pinnedSources: { openssl: 'openssl-4.0.0' },
      updatePolicy: 'reviewed like code',
    }),
    '.node-version': '24.15.0\n',
    'client/go.mod': 'module example.test/client\n\ngo 1.24.0\n',
    ...overrides,
  };
  for (const [relative, contents] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, contents);
  }
  return root;
}

function run(script, cwd) {
  try {
    return {
      ok: true,
      output: execFileSync(process.execPath, [script], {
        cwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    };
  } catch (error) {
    return { ok: false, output: `${error.stdout ?? ''}${error.stderr ?? ''}` };
  }
}

test('the pin gate accepts a fully pinned tree', (t) => {
  const result = run(CHECK_PINS, pinFixture(t));
  assert.equal(result.ok, true, result.output);
  assert.match(result.output, /every base image, source checkout, and action/);
});

test('the pin gate rejects a base image selected by tag', (t) => {
  const root = pinFixture(t, {
    'server/Dockerfile': '# pin: node 24-alpine\nFROM node:24-alpine\n',
  });
  const result = run(CHECK_PINS, root);
  assert.equal(result.ok, false);
  assert.match(result.output, /FROM node:24-alpine is not pinned to a digest/);
});

test('the pin gate rejects a tagged base image behind a FROM flag', (t) => {
  const root = pinFixture(t, {
    'server/Dockerfile':
      '# pin: node 24-alpine\nFROM --platform=linux/amd64 node:24-alpine\n',
  });
  const result = run(CHECK_PINS, root);
  assert.equal(result.ok, false);
  assert.match(result.output, /FROM node:24-alpine is not pinned to a digest/);
});

test('the pin gate rejects a source checkout at a moving reference', (t) => {
  const root = pinFixture(t, {
    'client/Dockerfile': [
      '# pin: debian stable-slim',
      `ARG DEBIAN_DIGEST=${DIGEST}`,
      'FROM debian:stable-slim@${DEBIAN_DIGEST}',
      '# pin: openssl openssl-4.0.0',
      'RUN git -C openssl fetch --depth 1 origin master',
      '',
    ].join('\n'),
  });
  const result = run(CHECK_PINS, root);
  assert.equal(result.ok, false);
  assert.match(
    result.output,
    /openssl is fetched at master, not a full commit/,
  );
});

test('the pin gate rejects an action pinned to a tag', (t) => {
  const root = pinFixture(t, {
    '.github/workflows/ci.yml':
      'jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v6\n',
  });
  const result = run(CHECK_PINS, root);
  assert.equal(result.ok, false);
  assert.match(result.output, /is not pinned to a commit SHA/);
});

test('the pin gate rejects a docker workflow action selected by tag', (t) => {
  const root = pinFixture(t, {
    '.github/workflows/ci.yml':
      'jobs:\n  build:\n    steps:\n      - uses: docker://alpine:3.22\n',
  });
  const result = run(CHECK_PINS, root);
  assert.equal(result.ok, false);
  assert.match(result.output, /is not pinned to an image digest/);
});

test('the pin gate rejects a manifest that disagrees with the build', (t) => {
  const root = pinFixture(t, {
    '.github/supported-versions.json': JSON.stringify({
      node: { minimum: '22.0.0' },
      go: { minimum: '1.21.0' },
      pinnedSources: { openssl: 'openssl-3.0.0' },
      updatePolicy: 'reviewed like code',
    }),
  });
  const result = run(CHECK_PINS, root);
  assert.equal(result.ok, false);
  for (const pattern of [
    /node minimum 22\.0\.0 disagrees/,
    /go minimum 1\.21\.0 disagrees/,
    /pinned source 'openssl' is openssl-3\.0\.0 here and openssl-4\.0\.0/,
  ]) {
    assert.match(result.output, pattern);
  }
});

test('the pin gate rejects a :latest reference', (t) => {
  const root = pinFixture(t, {
    'server/Dockerfile': [
      '# pin: node 24-alpine',
      `ARG NODE_DIGEST=${DIGEST}`,
      'FROM node:24-alpine@${NODE_DIGEST}',
      'RUN echo docker.io/library/busybox:latest',
      '',
    ].join('\n'),
  });
  const result = run(CHECK_PINS, root);
  assert.equal(result.ok, false);
  assert.match(result.output, /references a :latest tag/);
});

test('the documentation gate passes on this repository', () => {
  const result = run(CHECK_DOCS, process.cwd());
  assert.equal(result.ok, true, result.output);
  assert.match(result.output, /required document\(s\) present/);
});

test('the documentation gate rejects a missing document and a broken link', (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-docs-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, 'docs'), { recursive: true });
  writeFileSync(
    path.join(root, 'README.md'),
    'See [the protocol](docs/protocol-v2.md).\n',
  );
  const result = run(CHECK_DOCS, root);
  assert.equal(result.ok, false);
  assert.match(result.output, /required document SECURITY\.md is missing/);
  assert.match(result.output, /link to docs\/protocol-v2\.md does not resolve/);
});

test('the documentation gate rejects invented transport-mode names', (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-docs-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, 'docs'), { recursive: true });
  writeFileSync(
    path.join(root, 'README.md'),
    'Run the client in ECH mode strict for production.\n',
  );
  const result = run(CHECK_DOCS, root);
  assert.equal(result.ok, false);
  assert.match(result.output, /the modes are hard and off/);
});
