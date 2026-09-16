// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { firstDifference } from '../scripts/check-vectors.mjs';
import {
  parseGoProfile,
  run,
  summarizeGoTestFailure,
} from '../scripts/test-coverage.mjs';

test('a stale vector file is reported at its first differing line', () => {
  assert.equal(
    firstDifference('a\nb\nc', 'a\nx\nc'),
    'first difference at line 2\n  committed: b\n  generated: x',
  );
  assert.equal(
    firstDifference('a', 'a\nextra'),
    'first difference at line 2\n  committed: <end of file>\n  generated: extra',
  );
  assert.equal(
    firstDifference('a\nb', 'a'),
    'first difference at line 2\n  committed: b\n  generated: <end of file>',
  );
});

test('a Go coverage profile is summarized per file, least covered first', () => {
  const profile = [
    'mode: atomic',
    'example.com/dud/client/cmd/dud/main.go:10.2,12.3 2 1',
    'example.com/dud/client/cmd/dud/main.go:14.2,15.3 1 0',
    'example.com/dud/client/cmd/dud/erase.go:3.1,4.2 3 5',
    '',
  ].join('\n');
  const summary = parseGoProfile(profile);
  assert.deepEqual(summary.total.statements, {
    covered: 5,
    total: 6,
    percent: 83.3,
  });
  assert.deepEqual(
    summary.files.map(({ file, statements }) => [file, statements.percent]),
    [
      ['client/cmd/dud/main.go', 66.7],
      ['client/cmd/dud/erase.go', 100],
    ],
  );
  assert.deepEqual(summary.files[0].uncoveredBlocks, [
    {
      start: { line: 14, column: 2 },
      end: { line: 15, column: 3 },
      statements: 1,
    },
  ]);
  assert.throws(
    () => parseGoProfile('mode: atomic\nnot a profile line'),
    /cannot parse Go coverage profile line/,
  );
});

test('a failed Go test run is summarized by failing test and panic output', () => {
  const events = [
    JSON.stringify({ Action: 'run', Test: 'TestPass' }),
    JSON.stringify({ Action: 'fail', Test: 'TestErase' }),
    JSON.stringify({
      Action: 'output',
      Output: '--- FAIL: TestErase (0.01s)\n',
    }),
    JSON.stringify({ Action: 'output', Output: 'ok\n' }),
    'build output that is not JSON',
    '',
  ].join('\n');
  assert.equal(
    summarizeGoTestFailure(events, 'vet failed\n', 'report.jsonl'),
    [
      'Failed tests: TestErase',
      '--- FAIL: TestErase (0.01s)',
      'vet failed',
      'Full Go test report: report.jsonl',
    ].join('\n'),
  );
  assert.equal(
    summarizeGoTestFailure('', '', 'report.jsonl'),
    'Full Go test report: report.jsonl',
  );
});

test('a coverage subprocess saves its output and names the failure', async (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-coverage-run-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const stdoutFile = path.join(root, 'stdout.txt');

  const passed = await run(
    process.execPath,
    ['-e', 'process.stdout.write("done")'],
    { stdoutFile },
  );
  assert.equal(passed.stdout, 'done');
  assert.equal(readFileSync(stdoutFile, 'utf8'), 'done');

  await assert.rejects(
    run(process.execPath, ['-e', 'console.error("broken"); process.exit(3)']),
    /failed with exit code 3\nbroken/,
  );
  await assert.rejects(
    run(process.execPath, ['-e', 'process.exit(4)'], {
      stdoutFile,
      failureSummary: (stdout, stderr, file) => `see ${path.basename(file)}`,
    }),
    /failed with exit code 4\nsee stdout\.txt/,
  );
  await assert.rejects(
    run(process.execPath, [
      '-e',
      'process.stdout.write("x".repeat(13000)); process.exit(1)',
    ]),
    /\[diagnostics truncated; full stdout is in the coverage test report\]/,
  );
});
