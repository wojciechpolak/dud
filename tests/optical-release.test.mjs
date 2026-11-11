// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir, platform, arch } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { archive } from '../scripts/release-archive.mjs';
import { sha256 } from '../scripts/distribution-notices.mjs';

const root = path.resolve(import.meta.dirname, '..');
const scratch = mkdtempSync(path.join(tmpdir(), 'dud-release-tests-'));
const binary = path.join(scratch, 'dud');
test.before(() =>
  execFileSync('go', ['build', '-o', binary, './cmd/dud'], {
    cwd: path.join(root, 'client'),
    env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
  }),
);
test.after(() => rmSync(scratch, { recursive: true, force: true }));

test('release archives preserve exact bytes, executable modes and fixed timestamps', () => {
  const file = path.join(scratch, 'archive.tar.gz');
  const payload = Buffer.from('exact bytes\0');
  const files = {
    dud: { bytes: payload, mode: 0o755 },
    'NOTICES.txt': { bytes: 'license\n' },
  };
  assert.deepEqual(archive(files), archive(files));
  assert.throws(() => archive({ '../dud': { bytes: '' } }));
  writeFileSync(file, archive(files));
  const out = path.join(scratch, 'unpacked');
  cpSync(path.join(root, 'scripts/optical-notices'), out, { recursive: true });
  execFileSync('tar', ['-xzf', file, '-C', out]);
  assert.deepEqual(readFileSync(path.join(out, 'dud')), payload);
  assert.equal(statSync(path.join(out, 'dud')).mode & 0o777, 0o755);
  assert.equal(statSync(path.join(out, 'dud')).mtimeMs, 0);
});

test('Docker wrappers delegate optical window errors without forwarding or staging stdin', () => {
  const invoked = path.join(scratch, 'docker-args');
  const stdin = path.join(scratch, 'docker-stdin');
  const docker = path.join(scratch, 'docker');
  const quote = (value) => `'${value.replaceAll("'", "'\"'\"'")}'`;
  writeFileSync(
    docker,
    `#!/bin/sh
printf '%s\\n' "$@" > ${quote(invoked)}
cat > ${quote(stdin)}
while [ "$#" -gt 0 ] && [ "$1" != dud-wrapper-test ]; do shift; done
[ "$#" -gt 0 ] || exit 99
shift
exec ${quote(binary)} "$@"
`,
    { mode: 0o755 },
  );
  for (const mode of ['install', 'shell-init']) {
    const wrapper = execFileSync(binary, [mode], { encoding: 'utf8' });
    const file = path.join(scratch, `${mode}.sh`);
    writeFileSync(
      file,
      mode === 'install' ? wrapper : wrapper + '\ndud "$@"\n',
    );
    const result = spawnSync('sh', [file, 'upload', '--optical'], {
      input: 'private payload',
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${scratch}:${process.env.PATH}`,
        DUD_HOME: path.join(scratch, 'unused-state'),
        DUD_IMAGE: 'dud-wrapper-test',
        DUD_PROFILE: '',
        DUD_TEST_HOST_TTY: '1',
        DUD_TEST_STDOUT_TTY: '1',
      },
    });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Optical window renderer unavailable/);
    assert.equal(readFileSync(stdin, 'utf8'), '');
    const args = readFileSync(invoked, 'utf8').split('\n');
    assert.equal(args.includes('-i') || args.includes('-it'), false);
    assert.equal(
      args.some((arg) => arg.includes('/tmp/dud-stdin')),
      false,
    );
    const ordinary = spawnSync('sh', [file, 'upload', '-m', '--optical'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${scratch}:${process.env.PATH}`,
        DUD_HOME: path.join(scratch, `state-${mode}`),
        DUD_IMAGE: 'dud-wrapper-test',
        DUD_PROFILE: '',
        DUD_DROP_SECRET: '',
      },
    });
    assert.equal(ordinary.status, 1, ordinary.stderr);
    assert.match(ordinary.stderr, /requires DUD_DROP_SECRET/);
    assert.equal(
      readFileSync(invoked, 'utf8').includes('-m\n--optical\n'),
      true,
    );
  }
});

test('local installation checks the selected host, binaries and notices before writing', () => {
  const os = platform() === 'win32' ? 'windows' : platform();
  const architecture = arch() === 'x64' ? 'amd64' : arch();
  const stem = `dud-${os}-${architecture}`;
  const suffix = os === 'windows' ? '.exe' : '';
  const directory = path.join(scratch, 'install-input');
  cpSync(path.join(root, 'scripts/optical-notices'), directory, {
    recursive: true,
  });
  const bytes = readFileSync(binary);
  const notices = Buffer.from('verbatim terms\n');
  const metadata = {
    platform: os,
    architecture,
    variant: 'headless',
    binaries: [
      { name: `dud${suffix}`, bytes: bytes.length, sha256: sha256(bytes) },
    ],
    noticeBytes: notices.length,
    noticeSHA256: sha256(notices),
  };
  const provenance = path.join(directory, `${stem}-provenance.json`);
  writeFileSync(path.join(directory, stem + suffix), bytes);
  writeFileSync(path.join(directory, `${stem}-NOTICES.txt`), notices);
  writeFileSync(provenance, JSON.stringify(metadata));
  const prefix = path.join(scratch, 'installed');
  const run = () =>
    spawnSync(
      process.execPath,
      [
        path.join(root, 'scripts/install-release.mjs'),
        '--from',
        directory,
        '--variant',
        'headless',
        '--prefix',
        prefix,
      ],
      { encoding: 'utf8' },
    );
  writeFileSync(provenance, JSON.stringify({ ...metadata, platform: 'wrong' }));
  assert.notEqual(run().status, 0);
  assert.equal(existsSync(prefix), false);
  writeFileSync(provenance, JSON.stringify(metadata));
  writeFileSync(path.join(directory, `${stem}-NOTICES.txt`), 'damaged notice');
  assert.notEqual(run().status, 0);
  assert.equal(existsSync(prefix), false);
  writeFileSync(path.join(directory, `${stem}-NOTICES.txt`), notices);
  assert.equal(run().status, 0);
  assert.deepEqual(
    readFileSync(path.join(prefix, 'bin', `dud${suffix}`)),
    bytes,
  );
  assert.deepEqual(
    readFileSync(path.join(prefix, 'share/dud/NOTICES.txt')),
    notices,
  );
  assert.notEqual(run().status, 0);
});
