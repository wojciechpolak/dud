#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//
// Verification that the protocol test vectors quoted by docs/protocol-v2.md are
// the vectors the generator actually produces.
//
// The generator in tests/vectors/protocol-v2 recomputes the section 7
// construction against upstream filippo.io/hpke and filippo.io/age, asserting
// its own invariants as it goes. Its output is committed as a golden file
// because the specification cites it and other implementations read it without
// a Go toolchain. A golden file only means anything while something compares it
// to a fresh run, which is what this does: regenerate, diff, and fail on any
// difference. A change to the vectors is then always a reviewed change, never a
// forgotten regeneration.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const MODULE_DIR = 'tests/vectors/protocol-v2';
const GOLDEN = path.join(MODULE_DIR, 'vectors.txt');
const TERMINATOR = 'ALL CHECKS PASSED';

function die(message, detail) {
  console.error(`check-vectors: ${message}`);
  if (detail) {
    console.error(detail.trimEnd());
  }
  process.exit(1);
}

/**
 * The first difference locates the change far better than a whole-file dump, so
 * report that line rather than every line downstream of it.
 */
function firstDifference(expected, actual) {
  const want = expected.split('\n');
  const got = actual.split('\n');
  for (let i = 0; i < Math.max(want.length, got.length); i += 1) {
    if (want[i] !== got[i]) {
      return [
        `first difference at line ${i + 1}`,
        `  committed: ${want[i] ?? '<end of file>'}`,
        `  generated: ${got[i] ?? '<end of file>'}`,
      ].join('\n');
    }
  }
  return 'files differ only in trailing content';
}

if (!fs.existsSync(GOLDEN)) {
  die(`${GOLDEN} is missing`);
}

const run = spawnSync('go', ['run', '.'], {
  cwd: MODULE_DIR,
  encoding: 'utf8',
  env: {
    ...process.env,
    GOCACHE: process.env.GOCACHE ?? '/tmp/dud-go-build-cache',
  },
  maxBuffer: 32 * 1024 * 1024,
});

if (run.error) {
  die(`could not run the generator in ${MODULE_DIR}`, String(run.error));
}
if (run.status !== 0) {
  die(
    `the generator failed with exit code ${run.status}; the specification and the code disagree`,
    run.stderr,
  );
}

const generated = run.stdout;
const committed = fs.readFileSync(GOLDEN, 'utf8');

// The generator prints this only after every assertion has held. Its absence
// means a check was silently dropped from the generator.
if (!generated.includes(TERMINATOR)) {
  die(`the generator did not print "${TERMINATOR}"`, generated.slice(-2000));
}

if (generated !== committed) {
  die(
    `${GOLDEN} is stale — regenerate it with:\n` +
      `  cd ${MODULE_DIR} && go run . > vectors.txt`,
    firstDifference(committed, generated),
  );
}

console.log(
  `check-vectors: ${GOLDEN} matches the generator (${committed.split('\n').length} lines)`,
);
