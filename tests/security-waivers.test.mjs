// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const CHECK_WAIVERS = path.resolve('scripts/check-security-waivers.mjs');
const npmReport = {
  vulnerabilities: {
    glob: {
      via: [
        {
          source: 12345,
          range: '<10.5.0',
        },
      ],
    },
  },
};

function runNpmWaiver(t, waivers) {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-security-waivers-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const report = path.join(root, 'npm-audit.json');
  const waiver = path.join(root, 'waivers.json');
  writeFileSync(report, JSON.stringify(npmReport));
  writeFileSync(waiver, JSON.stringify({ waivers }));
  try {
    return {
      ok: true,
      output: execFileSync(
        process.execPath,
        [CHECK_WAIVERS, 'npm', report, waiver],
        {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      ),
    };
  } catch (error) {
    return { ok: false, output: `${error.stdout ?? ''}${error.stderr ?? ''}` };
  }
}

function runWaiver(t, scanner, reportContent) {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-security-waivers-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const report = path.join(root, 'report');
  const waiver = path.join(root, 'waivers.json');
  writeFileSync(report, reportContent);
  writeFileSync(waiver, JSON.stringify({ waivers: [] }));
  try {
    return {
      ok: true,
      output: execFileSync(
        process.execPath,
        [CHECK_WAIVERS, scanner, report, waiver],
        {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      ),
    };
  } catch (error) {
    return { ok: false, output: `${error.stdout ?? ''}${error.stderr ?? ''}` };
  }
}

function npmWaiver(overrides = {}) {
  return {
    scanner: 'npm',
    id: 'npm:glob:12345',
    package: 'glob',
    range: '<10.5.0',
    reason: 'Tracked upstream remediation.',
    expires: '2100-01-01T00:00:00Z',
    ...overrides,
  };
}

test('an npm waiver must identify the exact advisory and affected range', (t) => {
  const accepted = runNpmWaiver(t, [npmWaiver()]);
  assert.equal(accepted.ok, true, accepted.output);

  const wrongAdvisory = runNpmWaiver(t, [npmWaiver({ id: 'npm:glob:67890' })]);
  assert.equal(wrongAdvisory.ok, false);
  assert.match(wrongAdvisory.output, /npm:glob:12345/);

  const wrongRange = runNpmWaiver(t, [npmWaiver({ range: '<10.4.0' })]);
  assert.equal(wrongRange.ok, false);
  assert.match(wrongRange.output, /npm:glob:12345/);
});

test('scanner failures and incomplete reports fail closed', (t) => {
  const npmFailure = runWaiver(
    t,
    'npm',
    JSON.stringify({ error: { code: 'EAUDIT' } }),
  );
  assert.equal(npmFailure.ok, false);
  assert.match(npmFailure.output, /npm audit failed/);

  const govulncheckFailure = runWaiver(
    t,
    'govulncheck',
    '{"error":"database unavailable"}\n',
  );
  assert.equal(govulncheckFailure.ok, false);
  assert.match(govulncheckFailure.output, /govulncheck failed/);

  const trivyFailure = runWaiver(
    t,
    'trivy',
    JSON.stringify({ Error: 'database unavailable' }),
  );
  assert.equal(trivyFailure.ok, false);
  assert.match(trivyFailure.output, /trivy failed/);

  const incompleteTrivy = runWaiver(t, 'trivy', JSON.stringify({}));
  assert.equal(incompleteTrivy.ok, false);
  assert.match(incompleteTrivy.output, /Results array/);
});

test('govulncheck accepts formatted JSON stream records', (t) => {
  const report = `
{
  "config": {
    "protocol_version": "v1"
  }
}
{
  "progress": {
    "message": "Scanning"
  }
}
`;
  const result = runWaiver(t, 'govulncheck', report);
  assert.equal(result.ok, true, result.output);
});
