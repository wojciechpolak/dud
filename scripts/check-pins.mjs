#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//
// Offline verification that every external input this repository builds from is
// pinned to an exact revision, and that the declared minimum tool versions match
// what the repository actually requires.
//
// It reads files only. Nothing here resolves a tag, contacts a registry, or
// touches the network, so it runs identically on a developer laptop, in CI, and
// in an air-gapped audit.

import fs from 'node:fs';
import path from 'node:path';

const MANIFEST = '.github/supported-versions.json';
const DOCKERFILES = ['client/Dockerfile', 'server/Dockerfile'];
const WORKFLOW_DIR = '.github/workflows';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;

const failures = [];

function fail(file, message) {
  failures.push(`${file}: ${message}`);
}

function read(file) {
  return fs.readFileSync(file, 'utf8');
}

/**
 * Every base image must be selected by digest. A tag is a moving target, so a
 * `FROM` that names one is unpinned even when the tag looks specific.
 */
function checkDockerfile(file) {
  const text = read(file);
  const lines = text.split('\n');
  const digestArgs = new Map();
  const stages = new Set();

  for (const [index, line] of lines.entries()) {
    const at = `${file}:${index + 1}`;
    const arg = /^ARG\s+([A-Z0-9_]+)=(\S+)\s*$/.exec(line.trim());
    if (arg && arg[1].endsWith('_DIGEST')) {
      if (!DIGEST.test(arg[2])) {
        fail(at, `ARG ${arg[1]} is not a sha256 digest`);
      }
      digestArgs.set(arg[1], arg[2]);
      continue;
    }

    const from = /^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$/i.exec(
      line.trim(),
    );
    if (!from) {
      continue;
    }
    const [, reference, stage] = from;
    if (stage) {
      stages.add(stage);
    }
    if (stages.has(reference)) {
      continue;
    }
    const digested = /@\$\{([A-Z0-9_]+)\}$/.exec(reference);
    if (digested) {
      if (!digestArgs.has(digested[1])) {
        fail(at, `FROM uses undefined digest ARG ${digested[1]}`);
      }
      continue;
    }
    if (/@sha256:[a-f0-9]{64}$/.test(reference)) {
      continue;
    }
    fail(at, `FROM ${reference} is not pinned to a digest`);
  }

  // Each `# pin: <name> <tag>` records what a source checkout is meant to be,
  // and the checkout below it must name an exact commit.
  const annotations = [...text.matchAll(/^# pin: (\S+) (\S+)$/gm)].map(
    (match) => match[1],
  );
  const duplicates = annotations.filter(
    (name, index) => annotations.indexOf(name) !== index,
  );
  if (duplicates.length !== 0) {
    fail(
      file,
      `duplicate pin annotations: ${[...new Set(duplicates)].join(', ')}`,
    );
  }

  for (const match of text.matchAll(
    /git -C (\S+) fetch --depth 1 origin (\S+)/g,
  )) {
    const [, checkout, reference] = match;
    if (!COMMIT.test(reference)) {
      fail(
        file,
        `${checkout} is fetched at ${reference}, not a full commit SHA`,
      );
    }
    if (!annotations.includes(checkout)) {
      fail(
        file,
        `${checkout} is fetched without a '# pin: ${checkout} <tag>' annotation`,
      );
    }
  }

  for (const name of annotations) {
    const pinnedImage = new RegExp(`^ARG ${name.toUpperCase()}_DIGEST=`, 'm');
    const pinnedSource = new RegExp(`git -C ${name} fetch --depth 1 origin`);
    if (!pinnedImage.test(text) && !pinnedSource.test(text)) {
      fail(file, `pin annotation '${name}' has no pinned consumer`);
    }
  }

  if (/:latest\b/.test(text)) {
    fail(file, 'references a :latest tag');
  }
}

/** A workflow action is only pinned when it names a full commit SHA. */
function checkWorkflow(file) {
  for (const [index, line] of read(file).split('\n').entries()) {
    const at = `${file}:${index + 1}`;
    const uses = /^\s*(?:-\s*)?uses:\s*(\S+)/.exec(line);
    if (!uses) {
      continue;
    }
    const reference = uses[1];
    if (reference.startsWith('./')) {
      continue;
    }
    if (reference.startsWith('docker://')) {
      if (!/@sha256:[a-f0-9]{64}$/.test(reference)) {
        fail(at, `uses: ${reference} is not pinned to an image digest`);
      }
      continue;
    }
    const at_ = reference.lastIndexOf('@');
    if (at_ < 0) {
      fail(at, `uses: ${reference} has no revision`);
      continue;
    }
    const revision = reference.slice(at_ + 1);
    if (!COMMIT.test(revision)) {
      fail(at, `uses: ${reference} is not pinned to a commit SHA`);
    }
    if (!/#\s*v?\d/.test(line)) {
      fail(at, `uses: ${reference} has no human-readable version comment`);
    }
  }
}

/**
 * The manifest is the single place that states what DUD supports. Everything it
 * claims has to match the file that actually enforces it.
 */
function checkManifest() {
  const manifest = JSON.parse(read(MANIFEST));

  const nodeVersion = read('.node-version').trim();
  if (!nodeVersion.startsWith(`${manifest.node.minimum.split('.')[0]}.`)) {
    fail(
      MANIFEST,
      `node minimum ${manifest.node.minimum} disagrees with .node-version ${nodeVersion}`,
    );
  }

  const goDirective = /^go\s+(\S+)$/m.exec(read('client/go.mod'));
  if (!goDirective) {
    fail('client/go.mod', 'has no go directive');
  } else if (goDirective[1] !== manifest.go.minimum) {
    fail(
      MANIFEST,
      `go minimum ${manifest.go.minimum} disagrees with client/go.mod ${goDirective[1]}`,
    );
  }

  for (const [name, expected] of Object.entries(manifest.pinnedSources)) {
    const found = [
      ...read('client/Dockerfile').matchAll(/^# pin: (\S+) (\S+)$/gm),
    ].find((match) => match[1] === name);
    if (!found) {
      fail(
        MANIFEST,
        `pinned source '${name}' is absent from client/Dockerfile`,
      );
      continue;
    }
    if (found[2] !== expected) {
      fail(
        MANIFEST,
        `pinned source '${name}' is ${expected} here and ${found[2]} in client/Dockerfile`,
      );
    }
  }

  if (!manifest.updatePolicy?.trim()) {
    fail(MANIFEST, 'has no update policy');
  }
}

for (const file of DOCKERFILES) {
  checkDockerfile(file);
}
for (const entry of fs.readdirSync(WORKFLOW_DIR).sort()) {
  if (entry.endsWith('.yml') || entry.endsWith('.yaml')) {
    checkWorkflow(path.join(WORKFLOW_DIR, entry));
  }
}
checkManifest();

if (failures.length !== 0) {
  console.error(`unpinned or inconsistent inputs:\n${failures.join('\n')}`);
  process.exit(1);
}
console.log('pins: every base image, source checkout, and action is pinned');
