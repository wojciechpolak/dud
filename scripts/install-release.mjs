// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
import assert from 'node:assert/strict';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  chmodSync,
} from 'node:fs';
import { arch, platform } from 'node:os';
import path from 'node:path';
import { sha256 } from './distribution-notices.mjs';

// The caller verifies the release attestation and obtains this directory locally.
const options = {};
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i += 2) {
  assert.ok(
    ['--from', '--variant', '--prefix'].includes(args[i]) &&
      args[i + 1] &&
      !options[args[i]],
    'usage: install-release.mjs --from DIR --variant headless|desktop --prefix DIR',
  );
  options[args[i]] = args[i + 1];
}
assert.ok(
  options['--from'] &&
    options['--prefix'] &&
    ['headless', 'desktop'].includes(options['--variant']),
);
const directory = path.resolve(options['--from']);
const prefix = path.resolve(options['--prefix']);
const os = platform() === 'win32' ? 'windows' : platform();
const architecture = arch() === 'x64' ? 'amd64' : arch();
const stem = `dud-${os}-${architecture}`;
const desktop = options['--variant'] === 'desktop';
const provenancePath = desktop ? 'provenance.json' : `${stem}-provenance.json`;
assert.ok(lstatSync(path.join(directory, provenancePath)).isFile());
const provenanceBytes = readFileSync(path.join(directory, provenancePath));
const metadata = JSON.parse(provenanceBytes);
assert.equal(metadata.platform, os, 'package must match the installation host');
assert.equal(metadata.architecture, architecture);
assert.equal(metadata.variant, options['--variant']);
const suffix = os === 'windows' ? '.exe' : '';
const expected = [
  `dud${suffix}`,
  ...(desktop ? [`dud-optical-window${suffix}`] : []),
];
assert.deepEqual(
  metadata.binaries.map(({ name }) => name),
  expected,
);
const files = metadata.binaries.map((entry) => {
  const source = desktop ? entry.name : stem + suffix;
  const file = path.join(directory, source);
  assert.ok(lstatSync(file).isFile(), 'release input must be regular');
  const bytes = readFileSync(file);
  assert.equal(bytes.length, entry.bytes);
  assert.equal(
    sha256(bytes),
    entry.sha256,
    'binary differs from recorded release',
  );
  return { name: entry.name, bytes };
});
const notices = desktop ? 'NOTICES.txt' : `${stem}-NOTICES.txt`;
assert.ok(lstatSync(path.join(directory, notices)).isFile());
const noticeBytes = readFileSync(path.join(directory, notices));
assert.equal(noticeBytes.length, metadata.noticeBytes);
assert.equal(sha256(noticeBytes), metadata.noticeSHA256);
// Validate all inputs and refuse overwrites before creating installation files.
const destinations = files.map(({ name }) => path.join(prefix, 'bin', name));
const share = path.join(prefix, 'share/dud');
for (const destination of [
  ...destinations,
  path.join(share, 'NOTICES.txt'),
  path.join(share, 'provenance.json'),
]) {
  assert.ok(!existsSync(destination), `destination exists: ${destination}`);
}
for (const directory of [
  prefix,
  path.join(prefix, 'bin'),
  path.join(prefix, 'share'),
  share,
]) {
  assert.ok(
    !existsSync(directory) || lstatSync(directory).isDirectory(),
    'installation directories must not be symlinks',
  );
  mkdirSync(directory, { recursive: true });
}
const { writeFileSync } = await import('node:fs');
for (const [index, entry] of files.entries()) {
  writeFileSync(destinations[index], entry.bytes, { flag: 'wx', mode: 0o755 });
  chmodSync(destinations[index], 0o755);
}
writeFileSync(path.join(share, 'NOTICES.txt'), noticeBytes, { flag: 'wx' });
writeFileSync(path.join(share, 'provenance.json'), provenanceBytes, {
  flag: 'wx',
});
console.log(`Installed ${metadata.variant} ${os}/${architecture} in ${prefix}`);
