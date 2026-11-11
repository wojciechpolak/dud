// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { archive } from './release-archive.mjs';
import {
  goToolchainNoticeRecords,
  noticeBundle,
  noticeInventory,
  parseGoObjects,
  sha256,
} from './distribution-notices.mjs';

const root = path.resolve(import.meta.dirname, '..');
const matrix = JSON.parse(
  readFileSync(path.join(root, 'scripts/release-targets.json')),
);
const positional = process.argv.slice(2);
const version =
  positional.shift() ??
  JSON.parse(readFileSync(path.join(root, 'package.json'))).version;
assert.match(version, /^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/);
let output = path.join(root, 'dist/release');
let desktop = false;
for (let index = 0; index < positional.length; index++) {
  if (positional[index] === '--desktop-host') {
    desktop = true;
  } else if (positional[index] === '--out' && positional[index + 1]) {
    output = path.resolve(positional[++index]);
  } else {
    throw new Error(
      'usage: build-release-binaries.sh [version] [--desktop-host] [--out DIR]',
    );
  }
}
assert.ok(
  !existsSync(output) || !readdirSync(output).length,
  'use an empty output directory; build records are preserved',
);
mkdirSync(output, { recursive: true });
const work = mkdtempSync(path.join(tmpdir(), 'dud-release-'));
const run = (command, args, options = {}) =>
  execFileSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
// Resolve the exact module-pinned toolchain once, then prohibit toolchain downloads.
const pinEnv = { ...process.env, GOTOOLCHAIN: matrix.goVersion, GOWORK: 'off' };
const host = JSON.parse(
  run(
    'go',
    ['env', '-json', 'GOROOT', 'GOMODCACHE', 'GOVERSION', 'GOOS', 'GOARCH'],
    { cwd: path.join(root, 'client'), env: pinEnv },
  ),
);
assert.equal(host.GOVERSION, matrix.goVersion);
const goNotices = goToolchainNoticeRecords(host.GOROOT);
const go = path.join(host.GOROOT, 'bin/go');
const env = {
  PATH: process.env.PATH,
  GOENV: 'off',
  GOWORK: 'off',
  GOTOOLCHAIN: 'local',
  GOPROXY: 'off',
  GOSUMDB: 'off',
  GOMODCACHE: host.GOMODCACHE,
  GOROOT: host.GOROOT,
  SOURCE_DATE_EPOCH: '0',
};
let nativeInputs = null;
if (desktop) {
  assert.equal(
    host.GOOS,
    matrix.desktopToolchain.os,
    'desktop build requires its native host',
  );
  assert.equal(host.GOARCH, matrix.desktopToolchain.arch);
  assert.equal(
    run('xcodebuild', ['-version']).trim(),
    matrix.desktopToolchain.xcode,
  );
  assert.equal(
    run('xcrun', ['--show-sdk-version']).trim(),
    matrix.desktopToolchain.sdkVersion,
  );
  const compiler = run('xcrun', ['-find', 'clang']).trim();
  const compilerVersion = run(compiler, ['--version']).trim();
  assert.equal(
    compilerVersion.split('\n')[0],
    matrix.desktopToolchain.compilerVersion,
  );
  const sdk = run('xcrun', ['--show-sdk-path']).trim();
  nativeInputs = {
    compilerVersion,
    compilerSHA256: sha256(readFileSync(compiler)),
    sdk,
    sdkVersion: matrix.desktopToolchain.sdkVersion,
    xcode: matrix.desktopToolchain.xcode,
  };
  Object.assign(env, {
    CC: compiler,
    SDKROOT: sdk,
    CGO_CFLAGS: `-O2 -g0 -isysroot ${sdk}`,
    CGO_CPPFLAGS: '',
    CGO_CXXFLAGS: `-O2 -g0 -isysroot ${sdk}`,
    CGO_FFLAGS: '-O2 -g0',
    CGO_LDFLAGS: `-O2 -g0 -isysroot ${sdk}`,
  });
}
function sourcePaths(directory) {
  return readdirSync(path.join(root, directory), {
    withFileTypes: true,
  }).flatMap((entry) => {
    const name = `${directory}/${entry.name}`;
    return entry.isDirectory()
      ? sourcePaths(name)
      : /\.go$|\/go\.(mod|sum)$/.test(name)
        ? [name]
        : [];
  });
}
const paths = [
  'LICENSE',
  '.node-version',
  ...sourcePaths('client'),
  ...[
    'build-release-binaries.sh',
    'build-release-binaries.mjs',
    'distribution-notices.mjs',
    'release-archive.mjs',
    'release-targets.json',
    'optical-notices/provenance.json',
    'optical-notices/embedded-assets.txt',
  ].map((name) => `scripts/${name}`),
];
const sources = paths.sort().map((name) => ({
  path: name,
  sha256: sha256(readFileSync(path.join(root, name))),
}));
const sourceDigest = sha256(JSON.stringify(sources));
const snapshots = [1, 2].map((attempt) => {
  const directory = path.join(work, String(attempt));
  for (const name of paths) {
    mkdirSync(path.dirname(path.join(directory, name)), { recursive: true });
    copyFileSync(path.join(root, name), path.join(directory, name));
    assert.equal(
      sha256(readFileSync(path.join(directory, name))),
      sources.find((item) => item.path === name).sha256,
      'source snapshot changed during capture',
    );
  }
  const cache = path.join(directory, 'cache');
  const temporary = path.join(directory, 'tmp');
  mkdirSync(cache);
  mkdirSync(temporary);
  return {
    directory,
    cwd: path.join(directory, 'client'),
    env: { ...env, GOCACHE: cache, GOTMPDIR: temporary },
  };
});
const records = [];
const checksums = [];
const save = (name, bytes, mode = 0o644) => {
  writeFileSync(path.join(output, name), bytes, { mode });
  checksums.push(`${sha256(bytes)}  ${name}`);
};
async function compile(args, options) {
  const child = spawn(go, args, {
    ...options,
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (part) => {
    stderr += part;
  });
  const code = await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  });
  assert.equal(code, 0, stderr);
}
async function probeWindow(binary, snapshot) {
  const child = spawn(binary, ['30', '4', '1', '30'], {
    env: snapshot.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let output = '';
  let errors = '';
  child.stderr.on('data', (part) => {
    errors += part;
  });
  const closed = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  });
  const ready = new Promise((resolve) => {
    child.stdout.on('data', (part) => {
      output += part;
      if (output.includes('\n')) {
        resolve(output.split('\n')[0] === 'DUD-OPTICAL-WINDOW-READY-1');
      }
    });
    child.on('close', () => resolve(false));
  });
  const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
  try {
    assert.ok(await ready, `native helper startup failed: ${errors}`);
    child.stdin.end();
    assert.equal(await closed, 1, 'helper must reject absent ciphertext');
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null) {
      child.kill('SIGKILL');
      await closed;
    }
  }
}

const provenance = JSON.parse(
  readFileSync(path.join(root, 'scripts/optical-notices/provenance.json')),
);
function selectPackageFiles(pkg, selected) {
  for (const field of [
    'GoFiles',
    'CgoFiles',
    'CFiles',
    'CXXFiles',
    'MFiles',
    'HFiles',
    'SFiles',
    'SysoFiles',
  ]) {
    for (const name of pkg[field] ?? []) {
      selected.add(path.relative(pkg.Module.Dir, path.join(pkg.Dir, name)));
    }
  }
}

function verifyEmbeddedAsset(module, known, digest, relative) {
  assert.ok(
    module.Path === 'github.com/hajimehoshi/ebiten/v2' &&
      module.Version === provenance.ebiten.version &&
      known?.sha256 === digest,
    `embedded asset requires pinned provenance: ${relative}`,
  );
}

function collectEmbeddedAssets(pkg, embeds) {
  for (const name of pkg.EmbedFiles ?? []) {
    const relative = path.relative(pkg.Module.Dir, path.join(pkg.Dir, name));
    const digest = sha256(readFileSync(path.join(pkg.Dir, name)));
    const known = [provenance.font, ...provenance.controllers.databases].find(
      (item) => item.asset === relative,
    );
    verifyEmbeddedAsset(pkg.Module, known, digest, relative);
    embeds.set(relative, {
      module: pkg.Module.Path,
      path: relative,
      sha256: digest,
    });
  }
}

function addDependencyPackage(pkg, modules, embeds) {
  if (!pkg.Module || pkg.Module.Main) {
    return;
  }
  assert.ok(
    !pkg.Module.Replace,
    'release dependencies must have pinned module sources',
  );
  const entry = modules.get(pkg.Module.Path) ?? {
    module: pkg.Module,
    selected: new Set(),
  };
  selectPackageFiles(pkg, entry.selected);
  collectEmbeddedAssets(pkg, embeds);
  modules.set(pkg.Module.Path, entry);
}

function dependencyRecords(packages) {
  const modules = new Map();
  const embeds = new Map();
  for (const pkg of packages) {
    assert.ok(!pkg.Error && !pkg.DepsErrors?.length);
    addDependencyPackage(pkg, modules, embeds);
  }
  return { modules, embeds };
}

function inventory(snapshot, commands) {
  const packages = commands.flatMap(({ target, native, cgo }) =>
    parseGoObjects(
      run(
        go,
        [
          'list',
          '-mod=readonly',
          '-deps',
          '-json',
          ...(native ? ['-tags=nativewindow'] : []),
          target,
        ],
        { cwd: snapshot.cwd, env: { ...snapshot.env, CGO_ENABLED: cgo } },
      ),
    ),
  );
  const { modules, embeds } = dependencyRecords(packages);
  const entities = [...modules].sort().map(([name, { module, selected }]) => ({
    name: `${name}@${module.Version}`,
    ...noticeInventory(module.Dir, [...selected]),
  }));
  assert.ok(
    entities.every((item) => item.rootLicensePresent),
    'dependency root license required',
  );
  entities.unshift({
    name: 'DUD',
    rootLicensePresent: true,
    records: [
      {
        path: 'LICENSE',
        kind: 'license-file',
        sha256: sha256(readFileSync(path.join(root, 'LICENSE'))),
        text: readFileSync(path.join(root, 'LICENSE'), 'utf8'),
      },
    ],
  });
  entities.push({
    name: `Go ${host.GOVERSION}`,
    rootLicensePresent: true,
    records: goNotices,
  });
  const supplemental = embeds.size
    ? '\n' +
      readFileSync(
        path.join(root, 'scripts/optical-notices/embedded-assets.txt'),
        'utf8',
      )
    : '';
  return {
    notices: noticeBundle(entities) + supplemental,
    modules: [...modules.values()].map(({ module }) => ({
      path: module.Path,
      version: module.Version,
      sum: module.Sum,
      goModSum: module.GoModSum,
    })),
    embeddedAssets: [...embeds.values()],
  };
}
try {
  for (const snapshot of snapshots) {
    run(go, ['mod', 'verify'], { cwd: snapshot.cwd, env: snapshot.env });
  }
  const targets = desktop
    ? matrix.targets.filter((item) => item.desktop)
    : matrix.targets.filter((item) => item.headless);
  for (const target of targets) {
    const stem = `dud-${target.os}-${target.arch}`;
    const suffix = target.os === 'windows' ? '.exe' : '';
    const artifact = desktop ? `${stem}-desktop.tar.gz` : `${stem}${suffix}`;
    const commands = [
      { name: `dud${suffix}`, target: './cmd/dud', native: desktop, cgo: '0' },
      ...(desktop
        ? [
            {
              name: `dud-optical-window${suffix}`,
              target: './cmd/dud-optical-window',
              native: true,
              cgo: '1',
            },
          ]
        : []),
    ];
    const builds = [];
    let metadata;
    let files;
    let firstRecords;
    for (const [index, snapshot] of snapshots.entries()) {
      console.log(`${artifact}: clean build ${index + 1}/2`);
      Object.assign(snapshot.env, { GOOS: target.os, GOARCH: target.arch });
      const binaries = {};
      const info = [];
      for (const command of commands) {
        const binary = path.join(snapshot.directory, command.name);
        const flags = [
          '-trimpath',
          '-buildvcs=false',
          '-mod=readonly',
          `-ldflags=-s -w -buildid= -X main.version=${version}${command.cgo === '1' ? ` -B 0x${sha256(`${sourceDigest}|${version}|${command.target}`).slice(0, 32)}` : ''}`,
          ...(command.native ? ['-tags=nativewindow'] : []),
        ];
        await compile(['build', ...flags, '-o', binary, command.target], {
          cwd: snapshot.cwd,
          env: { ...snapshot.env, CGO_ENABLED: command.cgo },
        });
        if (command.cgo === '1') {
          await probeWindow(binary, snapshot);
        }
        const bytes = readFileSync(binary);
        const buildInfo = run(go, ['version', '-m', binary], {
          env: snapshot.env,
        }).replace(binary, command.name);
        assert.doesNotMatch(buildInfo, /yeqown\/(go-qrcode|reedsolomon)/);
        binaries[command.name] = { bytes, mode: 0o755 };
        info.push({
          name: command.name,
          bytes: bytes.length,
          sha256: sha256(bytes),
          flags,
          buildInfo,
          ...(command.cgo === '1'
            ? {
                linkedLibraries: run('otool', ['-L', binary]).replace(
                  binary,
                  command.name,
                ),
              }
            : {}),
        });
      }
      const selected = inventory(snapshot, commands);
      metadata = {
        schemaVersion: 1,
        version,
        platform: target.os,
        architecture: target.arch,
        variant: desktop ? 'desktop' : 'headless',
        sourceDigest,
        sources,
        goVersion: host.GOVERSION,
        goBinarySHA256: sha256(readFileSync(go)),
        generatorInputs: {
          nodeVersion: process.version,
          zlibVersion: process.versions.zlib,
          nodeSHA256: sha256(readFileSync(process.execPath)),
        },
        nativeInputs,
        nativeHelperStartupVerified: desktop,
        noticeSHA256: sha256(selected.notices),
        noticeBytes: Buffer.byteLength(selected.notices),
        modules: selected.modules,
        embeddedAssets: selected.embeddedAssets,
        binaries: info,
      };
      files = {
        ...binaries,
        'NOTICES.txt': { bytes: selected.notices },
        'provenance.json': { bytes: JSON.stringify(metadata, null, 2) + '\n' },
      };
      const bytes = desktop ? archive(files) : binaries[`dud${suffix}`].bytes;
      const recordBytes = ['NOTICES.txt', 'provenance.json'].map((name) =>
        Buffer.from(files[name].bytes),
      );
      if (index === 0) {
        firstRecords = recordBytes;
      } else {
        assert.deepEqual(
          firstRecords,
          recordBytes,
          `${artifact}: notices or provenance differ`,
        );
      }
      builds.push(bytes);
      if (index === 1) {
        assert.deepEqual(
          builds[0],
          builds[1],
          `${artifact}: reproducibility failed`,
        );
      }
    }
    save(artifact, builds[0], desktop ? 0o644 : 0o755);
    if (!desktop) {
      save(`${stem}-NOTICES.txt`, files['NOTICES.txt'].bytes);
      save(`${stem}-provenance.json`, files['provenance.json'].bytes);
    }
    records.push({
      artifact,
      sha256: sha256(builds[0]),
      bytes: builds[0].length,
      capability: metadata.variant,
      reproducible: true,
    });
  }
  save(
    'capability-matrix.json',
    JSON.stringify({ ...matrix, artifacts: records }, null, 2) + '\n',
  );
  writeFileSync(
    path.join(output, 'SHA256SUMS'),
    checksums.sort().join('\n') + '\n',
  );
  console.log(`Reproducible artifacts and exact notices: ${output}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
