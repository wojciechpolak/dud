// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const MODULES = ['client', 'tests/vectors/protocol-v2', 'tools'];

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-go-quality-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const dir of ['scripts', 'bin', '.github', ...MODULES]) {
    mkdirSync(path.join(root, dir), { recursive: true });
  }
  return root;
}

function run(root, script, args = []) {
  const result = spawnSync(
    'bash',
    [path.join(root, 'scripts', script), ...args],
    {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, GOPROXY: 'off', GOSUMDB: 'off', GOWORK: 'off' },
    },
  );
  assert.ifError(result.error);
  return { status: result.status, output: result.stdout + result.stderr };
}

test('the vulnerability gate honors waivers and rejects incomplete scans', (t) => {
  const root = fixture(t);
  for (const script of ['go-analyze.sh', 'check-security-waivers.mjs']) {
    copyFileSync(`scripts/${script}`, path.join(root, 'scripts', script));
  }
  writeFileSync(path.join(root, 'scripts/go-tools.sh'), '#!/bin/sh\nexit 0\n', {
    mode: 0o755,
  });
  const finding = { finding: { osv: 'GO-2099-0001' } };
  const report = [{ config: { protocol_version: 'v1' } }, finding]
    .map((entry) => JSON.stringify(entry))
    .join('\n');
  const waiver = {
    scanner: 'govulncheck',
    id: `govulncheck:${finding.finding.osv}`,
    reason: 'The affected operation is excluded by application validation.',
    expires: '2100-01-01T00:00:00Z',
  };
  for (const scenario of [
    {
      name: 'clean',
      waivers: [],
      report: '{"config":{}}',
      exit: 0,
      accepted: true,
    },
    { name: 'waived', waivers: [waiver], report, exit: 0, accepted: true },
    { name: 'unwaived', waivers: [], report, exit: 0, accepted: false },
    {
      name: 'expired',
      waivers: [{ ...waiver, expires: '2000-01-01T00:00:00Z' }],
      report,
      exit: 0,
      accepted: false,
    },
    {
      name: 'failed scan',
      waivers: [waiver],
      report,
      exit: 1,
      accepted: false,
    },
    { name: 'empty report', waivers: [], report: '', exit: 0, accepted: false },
  ]) {
    writeFileSync(
      path.join(root, '.github/security-waivers.json'),
      JSON.stringify({ waivers: scenario.waivers }),
    );
    writeFileSync(
      path.join(root, 'bin/govulncheck'),
      `#!/usr/bin/env node
if (!process.argv.includes('-json')) process.exit(3);
process.stdout.write(${JSON.stringify(scenario.report)});
process.exitCode = ${scenario.exit};
`,
      { mode: 0o755 },
    );
    const result = run(root, 'go-analyze.sh', ['--gate', 'govulncheck']);
    assert.equal(
      result.status,
      scenario.accepted ? 0 : 1,
      `${scenario.name}: ${result.output}`,
    );
  }
});

// The dependency is also imported by the client, so building the repository
// populates the Go module cache needed by these offline fixtures.
test('the tidy check reports changes without writing module files', (t) => {
  for (const withSums of [false, true]) {
    const root = fixture(t);
    copyFileSync(
      'scripts/check-tidy.sh',
      path.join(root, 'scripts/check-tidy.sh'),
    );
    const mod = readFileSync('client/go.mod', 'utf8');
    const sum = readFileSync('client/go.sum', 'utf8');
    for (const dir of MODULES) {
      writeFileSync(path.join(root, dir, 'go.mod'), mod);
      if (withSums) {
        writeFileSync(path.join(root, dir, 'go.sum'), sum);
      }
      writeFileSync(
        path.join(root, dir, 'main.go'),
        'package main\nimport "golang.org/x/crypto/chacha20poly1305"\nfunc main() { _, _ = chacha20poly1305.New(make([]byte, 32)) }\n',
      );
    }
    const result = run(root, 'check-tidy.sh');
    assert.equal(result.status, 1, result.output);
    for (const dir of MODULES) {
      assert.equal(readFileSync(path.join(root, dir, 'go.mod'), 'utf8'), mod);
      assert.equal(existsSync(path.join(root, dir, 'go.sum')), withSums);
      if (withSums) {
        assert.equal(readFileSync(path.join(root, dir, 'go.sum'), 'utf8'), sum);
      }
    }
    assert.match(result.output, /diff .*go.sum/, result.output);
  }
});

test('the tidy check accepts tidy modules and reports dependency failures', (t) => {
  const root = fixture(t);
  copyFileSync(
    'scripts/check-tidy.sh',
    path.join(root, 'scripts/check-tidy.sh'),
  );
  const version = JSON.parse(readFileSync('.github/supported-versions.json')).go
    .minimum;
  const mod = `module example.test/fixture\n\ngo ${version}\n`;
  for (const dir of MODULES) {
    writeFileSync(path.join(root, dir, 'go.mod'), mod);
    writeFileSync(
      path.join(root, dir, 'main.go'),
      'package main\nfunc main() {}\n',
    );
  }
  const clean = run(root, 'check-tidy.sh');
  assert.equal(clean.status, 0, clean.output);
  writeFileSync(
    path.join(root, 'client/main.go'),
    'package main\nimport _ "example.invalid/missing"\nfunc main() {}\n',
  );
  const failed = run(root, 'check-tidy.sh');
  assert.equal(failed.status, 1, failed.output);
  assert.match(failed.output, /module lookup disabled by GOPROXY=off/);
  for (const dir of MODULES) {
    assert.equal(readFileSync(path.join(root, dir, 'go.mod'), 'utf8'), mod);
    assert.equal(existsSync(path.join(root, dir, 'go.sum')), false);
  }
});
