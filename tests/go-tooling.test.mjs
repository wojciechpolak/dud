// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//
// The Go static analyzers live in a module of their own so that nothing they
// depend on can reach the client binary. These tests check that the two stay
// separate and that the declared set matches what the scripts build. They read
// files only. `npm run analyze:go` builds and runs the analyzers themselves.

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const TOOLS_GO_MOD = readFileSync('tools/go.mod', 'utf8');
const MANIFEST = JSON.parse(
  readFileSync('.github/supported-versions.json', 'utf8'),
);

// The packages named by the tool directives. Each is a command the analysis
// scripts build into bin/.
const TOOL_PACKAGES = [
  'github.com/fzipp/gocyclo/cmd/gocyclo',
  'github.com/kisielk/errcheck',
  'golang.org/x/tools/cmd/deadcode',
  'golang.org/x/tools/cmd/goimports',
  'golang.org/x/vuln/cmd/govulncheck',
  'honnef.co/go/tools/cmd/staticcheck',
];

test('the tools module declares every analyzer', () => {
  for (const pkg of TOOL_PACKAGES) {
    assert.match(
      TOOLS_GO_MOD,
      new RegExp(`^\\t${pkg.replaceAll('.', '\\.')}$`, 'm'),
      `tools/go.mod has no tool directive for ${pkg}`,
    );
  }
});

test('the tools module states the supported Go version', () => {
  const directive = /^go\s+(\S+)$/m.exec(TOOLS_GO_MOD);
  assert.ok(directive, 'tools/go.mod has no go directive');
  assert.equal(directive[1], MANIFEST.go.minimum);
});

test('the tools module pins every analyzer by checksum', () => {
  const sums = readFileSync('tools/go.sum', 'utf8').trim().split('\n');
  assert.ok(sums.length > 0, 'tools/go.sum is empty');
  for (const line of sums) {
    assert.match(
      line,
      /^\S+ \S+ h1:\S+=$/,
      `tools/go.sum line is not a module checksum: ${line}`,
    );
  }
});

// An analyzer can reach the shipped binary only if a module the client
// requires pulls it in, so these assertions check that nothing does.
test('no shipping module requires an analyzer', () => {
  for (const module of ['client/go.mod', 'tests/vectors/protocol-v2/go.mod']) {
    const text = readFileSync(module, 'utf8');
    assert.doesNotMatch(
      text,
      /^tool\b|^\t*tool \(/m,
      `${module} declares a tool directive`,
    );
    for (const pkg of TOOL_PACKAGES) {
      const owner = pkg.split('/cmd/')[0];
      assert.ok(
        !text.includes(`${owner} v`),
        `${module} requires the analyzer module ${owner}`,
      );
    }
  }
});

// This repository builds govulncheck from the pinned tools module. An ad-hoc
// `go install` fetches whatever the proxy resolves at job time, which the pin
// gate exists to prevent, and it sits in a `run:` body that the gate does not
// read.
test('no workflow installs an analyzer at job time', () => {
  const dir = '.github/workflows';
  for (const name of readdirSync(dir)) {
    if (!/\.ya?ml$/.test(name)) {
      continue;
    }
    const text = readFileSync(path.join(dir, name), 'utf8');
    assert.doesNotMatch(
      text,
      /go install\s+(golang\.org\/x\/(vuln|tools)|honnef\.co|github\.com\/(kisielk|fzipp))/,
      `${name} installs an analyzer with 'go install'`,
    );
  }
});
