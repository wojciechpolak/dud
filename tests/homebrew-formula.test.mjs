// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  releaseChecksum,
  releaseVersion,
  renderFormula,
} from '../scripts/render-homebrew-formula.mjs';

const RENDERER = path.resolve('scripts/render-homebrew-formula.mjs');
const SHA256 = 'a'.repeat(64);
const RELEASE = { version: '2.0.2', sha256: SHA256 };

function scratch(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'dud-homebrew-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function run(t, args) {
  try {
    return {
      ok: true,
      output: execFileSync(process.execPath, [RENDERER, ...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    };
  } catch (error) {
    return { ok: false, output: `${error.stdout ?? ''}${error.stderr ?? ''}` };
  }
}

test('a stable release version is accepted with or without the tag prefix', () => {
  assert.equal(releaseVersion('2.0.2'), '2.0.2');
  assert.equal(releaseVersion('v2.0.2'), '2.0.2');
  assert.equal(releaseVersion('v10.20.30'), '10.20.30');
  assert.equal(releaseVersion('v0.0.0'), '0.0.0');
});

test('a pre-release version never reaches the tap', () => {
  // The tap is what `brew install` resolves, so a candidate for a version must
  // not be published under the name of the version it is a candidate for.
  for (const version of [
    '2.0.0-rc.1',
    'v2.0.0-rc.1',
    '2.0.0-beta',
    '2.0.0+1',
  ]) {
    assert.throws(
      () => releaseVersion(version),
      /not a stable release version/,
      version,
    );
  }
});

test('a version that is not three numbers is rejected', () => {
  for (const version of [
    '2.0',
    '2.0.2.1',
    'v',
    'latest',
    '',
    undefined,
    '2.0.x',
    '02.0.2',
  ]) {
    assert.throws(
      () => releaseVersion(version),
      /not a stable release version/,
    );
  }
});

test('only a 64-character lowercase hex digest is a checksum', () => {
  assert.equal(releaseChecksum(SHA256), SHA256);
  for (const value of [
    'a'.repeat(63),
    'a'.repeat(65),
    'A'.repeat(64),
    `sha256:${'a'.repeat(64)}`,
    'g'.repeat(64),
    '',
    undefined,
  ]) {
    assert.throws(() => releaseChecksum(value), /not a 64-character/);
  }
});

test('the rendered formula pins the release it was given', () => {
  const formula = renderFormula(RELEASE);

  assert.match(formula, /^class Dud < Formula$/m);
  assert.match(
    formula,
    /^ {2}url "https:\/\/github\.com\/wojciechpolak\/dud\/archive\/refs\/tags\/v2\.0\.2\.tar\.gz"$/m,
  );
  assert.match(formula, new RegExp(`^ {2}sha256 "${SHA256}"$`, 'm'));
  assert.match(formula, /^ {2}license "MIT"$/m);
});

test('the description says what the name stands for', () => {
  // `brew search` shows this line alone, and Homebrew's own index holds the
  // name `dud` for an unrelated tool, so the line has to answer "which dud".
  assert.match(
    renderFormula(RELEASE),
    /^ {2}desc "Discreet upload \/ download over dead drops and paired peers"$/m,
  );
});

test('the description obeys the rules Homebrew audits it against', () => {
  const [, desc] = /^ {2}desc "([^"]+)"$/m.exec(renderFormula(RELEASE));

  assert.ok(desc.length <= 80, `desc is ${desc.length} characters`);
  assert.doesNotMatch(desc, /^\s|\s$/);
  assert.doesNotMatch(desc, /^(?:an?|the)\s/i);
  assert.doesNotMatch(desc, /^dud\b/i);
  assert.doesNotMatch(desc, /\.$/);
  assert.doesNotMatch(desc, /command[- ]line/i);
  assert.match(desc, /^[A-Z]/);
});

test('the formula declares the toolchain and the helpers the binary calls', () => {
  const formula = renderFormula(RELEASE);

  assert.match(formula, /^ {2}depends_on "go" => :build$/m);
  for (const helper of ['age', 'git', 'qrencode']) {
    assert.match(formula, new RegExp(`^ {2}depends_on "${helper}"$`, 'm'));
  }
});

test('the build matches the flags release binaries are built with', () => {
  // A Homebrew source build and a published release binary of the same version
  // have to be the same program: no cgo, no build ID, and the version compiled
  // in rather than defaulted to "dev".
  const formula = renderFormula(RELEASE);

  assert.match(formula, /ENV\["CGO_ENABLED"\] = "0"/);
  assert.match(formula, /-buildid= -X main\.version=#\{version\}/);
  assert.match(formula, /std_go_args\(output: bin\/"dud", ldflags: ldflags\)/);
  // The CLI is a package under the module root, so the build needs to name it.
  // Without it `go build` builds `client` itself, which holds no Go files.
  assert.match(formula, /std_go_args\([^)]*\), "\.\/cmd\/dud"/);
});

test('the formula parses on an interpreter older than the shorthand syntax', (t) => {
  // The release workflow syntax-checks the rendered formula with the runner's
  // own `ruby`, so the formula must not depend on a 3.1 interpreter to parse.
  const file = path.join(scratch(t), 'dud.rb');
  writeFileSync(file, renderFormula(RELEASE));

  assert.doesNotMatch(readFileSync(file, 'utf8'), /\bldflags:\s*\)/);
  execFileSync('ruby', ['-c', file], { stdio: ['ignore', 'pipe', 'pipe'] });
});

test('the formula tests the version it claims to install', () => {
  assert.match(
    renderFormula(RELEASE),
    /assert_equal version\.to_s, shell_output\("#\{bin\}\/dud --version"\)\.strip/,
  );
});

test('the formula says it is generated so a hand edit is not silently lost', () => {
  assert.match(
    renderFormula(RELEASE),
    /Generated by scripts\/render-homebrew-formula\.mjs/,
  );
});

test('rendering is deterministic and independent of the tag prefix', () => {
  const bare = renderFormula(RELEASE);
  assert.equal(renderFormula(RELEASE), bare);
  assert.equal(renderFormula({ version: 'v2.0.2', sha256: SHA256 }), bare);
});

test('two different releases render two different formulae', () => {
  const before = renderFormula(RELEASE);
  const after = renderFormula({ version: '2.1.0', sha256: 'b'.repeat(64) });

  assert.notEqual(before, after);
  assert.match(after, /tags\/v2\.1\.0\.tar\.gz/);
  assert.doesNotMatch(after, /v2\.0\.2/);
});

test('rewriting a formula for the same release changes no bytes', (t) => {
  const out = path.join(scratch(t), 'dud.rb');

  assert.ok(run(t, ['v2.0.2', SHA256, '--out', out]).ok);
  const first = readFileSync(out, 'utf8');
  assert.ok(run(t, ['v2.0.2', SHA256, '--out', out]).ok);

  assert.equal(readFileSync(out, 'utf8'), first);
  assert.equal(first, renderFormula(RELEASE));
});

test('--check accepts a file the renderer would have written', (t) => {
  const out = path.join(scratch(t), 'dud.rb');
  writeFileSync(out, renderFormula(RELEASE));

  assert.ok(run(t, ['v2.0.2', SHA256, '--check', out]).ok);
});

test('--check rejects a hand-edited formula and a stale one', (t) => {
  const root = scratch(t);
  const edited = path.join(root, 'edited.rb');
  const stale = path.join(root, 'stale.rb');
  writeFileSync(
    edited,
    renderFormula(RELEASE).replace(
      'depends_on "age"',
      'depends_on "age" # local',
    ),
  );
  writeFileSync(stale, renderFormula({ version: '2.0.1', sha256: SHA256 }));

  assert.equal(run(t, ['v2.0.2', SHA256, '--check', edited]).ok, false);
  assert.equal(run(t, ['v2.0.2', SHA256, '--check', stale]).ok, false);
});

test('--check reports a missing formula rather than creating one', (t) => {
  const missing = path.join(scratch(t), 'absent.rb');

  const result = run(t, ['v2.0.2', SHA256, '--check', missing]);

  assert.equal(result.ok, false);
  assert.match(result.output, /does not match the formula/);
});

test('the command line refuses inputs it cannot render a release from', (t) => {
  const out = path.join(scratch(t), 'dud.rb');

  assert.equal(run(t, ['v2.0.0-rc.1', SHA256, '--out', out]).ok, false);
  assert.equal(run(t, ['v2.0.2', 'not-a-digest', '--out', out]).ok, false);
  assert.equal(run(t, ['v2.0.2']).ok, false);
  assert.equal(run(t, ['v2.0.2', SHA256, '--out']).ok, false);
  assert.equal(
    run(t, ['v2.0.2', SHA256, '--out', out, '--check', out]).ok,
    false,
  );
  assert.equal(run(t, ['v2.0.2', SHA256, '--publish']).ok, false);
});

test('a rejected release leaves the formula on disk untouched', (t) => {
  const out = path.join(scratch(t), 'dud.rb');
  writeFileSync(out, renderFormula(RELEASE));

  assert.equal(run(t, ['v2.0.0-rc.1', 'z'.repeat(64), '--out', out]).ok, false);

  assert.equal(readFileSync(out, 'utf8'), renderFormula(RELEASE));
});

test('with no destination the formula goes to stdout', (t) => {
  const result = run(t, ['v2.0.2', SHA256]);

  assert.ok(result.ok);
  assert.equal(result.output, renderFormula(RELEASE));
});
