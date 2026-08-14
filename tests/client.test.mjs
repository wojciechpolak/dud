// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import {
  mkdtemp,
  readdir,
  readFile,
  writeFile,
  chmod,
  mkdir,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn, spawnSync } from 'node:child_process';

const CLIENT_BIN = path.resolve('client/bin/dud');

function runCommand(command, args, env = {}, options = {}) {
  return new Promise((resolve, reject) => {
    const stdinMode = options.input === undefined ? 'ignore' : 'pipe';
    const child = spawn(command, args, {
      env: {
        ...process.env,
        ...env,
      },
      cwd: options.cwd,
      stdio: [stdinMode, 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    if (options.input !== undefined) {
      child.stdin.end(options.input);
    }

    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

function commandExists(command) {
  const result = spawnSync(
    'sh',
    ['-c', 'command -v -- "$1" >/dev/null 2>&1', 'sh', command],
    { stdio: 'ignore' },
  );

  return result.status === 0;
}

async function makeExecutable(filePath, content) {
  await writeFile(filePath, content, 'utf8');
  await chmod(filePath, 0o755);
}

test('version flag prints the package.json version', async () => {
  const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
  const result = await runCommand(CLIENT_BIN, ['--version']);

  assert.equal(result.code, 0);
  // Guards the full injection chain: package.json -> npm_package_version
  // -> ldflags -X main.version. A broken link reports "dev" instead.
  assert.equal(result.stdout, `${packageJson.version}\n`);
  assert.equal(result.stderr, '');
});

test('version flag honors the DUD_VERSION runtime override', async () => {
  const result = await runCommand(CLIENT_BIN, ['--version'], {
    DUD_VERSION: '9.9.9-test',
  });

  assert.equal(result.code, 0);
  assert.equal(result.stdout, '9.9.9-test\n');
});

// age, git, tar, and qrencode run as subprocesses, and their exit status has
// to survive the trip.
test('exit codes from failing subprocesses are propagated', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-exit-code-'));
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' 'age: no identity matched any of the recipients' >&2
exit 22
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['upload', '--passphrase', '-m', 'hello', '--json'],
    {
      DUD_AGE_BIN: ageMock,
      DUD_DROP_SECRET: 'top-secret',
    },
  );

  assert.equal(result.code, 22);
  assert.match(result.stderr, /no identity matched/);
  assert.doesNotMatch(result.stderr, /exit status/);
});

test('upload removes sensitive temp files when interrupted by SIGINT', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-sigint-'));
  const scratchDir = path.join(tmpDir, 'scratch');
  await mkdir(scratchDir);
  const filePath = path.join(tmpDir, 'input.txt');
  await writeFile(filePath, 'sensitive plaintext', 'utf8');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  await makeExecutable(ageMock, '#!/bin/sh\nsleep 30\n');

  const child = spawn(CLIENT_BIN, ['upload', '--file', filePath], {
    env: {
      ...process.env,
      TMPDIR: scratchDir,
      DUD_AGE_BIN: ageMock,
      DUD_DROP_SECRET: 'top-secret',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Wait for the upload to stage its plaintext temp file, then interrupt
  // it while the (stalled) age subprocess still holds everything open.
  const deadline = Date.now() + 5000;
  let staged = [];
  while (Date.now() < deadline) {
    staged = (await readdir(scratchDir)).filter((name) =>
      name.startsWith('dud-upload-plain-'),
    );
    if (staged.length > 0) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.ok(staged.length > 0, 'expected a staged plaintext temp file');

  // 'exit' instead of 'close': the orphaned age mock keeps the stdio
  // pipes open after the client itself has terminated.
  const exited = new Promise((resolve) => {
    child.on('exit', (code) => resolve(code));
  });
  child.kill('SIGINT');
  const code = await exited;

  assert.equal(code, 130);
  const leftover = (await readdir(scratchDir)).filter((name) =>
    name.startsWith('dud-'),
  );
  assert.deepEqual(leftover, []);
});

test('upload command rejects the removed --recipients-file alias', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-recipient-file-removed-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');
  const recipientsPath = path.join(tmpDir, 'recipients.txt');

  await writeFile(filePath, 'plaintext', 'utf8');
  await writeFile(recipientsPath, 'age1examplepublickey\n', 'utf8');

  const result = await runCommand(
    CLIENT_BIN,
    ['upload', '--file', filePath, '--recipients-file', recipientsPath],
    {
      DUD_DROP_SECRET: 'top-secret',
    },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /Unknown upload option: --recipients-file/);
});

test('upload command rejects passphrase and recipient options together', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-mode-conflict-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');

  await writeFile(filePath, 'plaintext', 'utf8');

  const result = await runCommand(
    CLIENT_BIN,
    [
      'upload',
      '--file',
      filePath,
      '--passphrase',
      '--recipient',
      'age1examplepublickey0000000000000000000000000000000000000000000000',
    ],
    {
      DUD_DROP_SECRET: 'top-secret',
    },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /either --passphrase or recipient options/);
});

test('upload command rejects conflicting source options', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-conflict-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');

  await writeFile(filePath, 'plaintext', 'utf8');

  const result = await runCommand(
    CLIENT_BIN,
    ['upload', '--file', filePath, '-m', 'hello'],
    {
      DUD_DROP_SECRET: 'top-secret',
    },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /upload accepts only one source/);
});

test('git command validates required arguments and subcommands', async () => {
  const missingId = await runCommand(CLIENT_BIN, ['git', 'fetch']);

  assert.notEqual(missingId.code, 0);
  assert.match(missingId.stderr, /git fetch requires --id/);

  const unknown = await runCommand(CLIENT_BIN, ['git', 'dance']);

  assert.notEqual(unknown.code, 0);
  assert.match(unknown.stderr, /Unknown git subcommand: dance/);
});

test('download command validates stdout and file output options', async () => {
  const bothResult = await runCommand(CLIENT_BIN, [
    'download',
    '--id',
    '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
    '--out',
    '/tmp/out.bin',
    '--stdout',
  ]);

  assert.notEqual(bothResult.code, 0);
  assert.match(bothResult.stderr, /only one output target/);

  const missingResult = await runCommand(CLIENT_BIN, [
    'download',
    '--id',
    '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
  ]);

  assert.notEqual(missingResult.code, 0);
  assert.match(missingResult.stderr, /requires either --out or --stdout/);

  const extractStdoutResult = await runCommand(CLIENT_BIN, [
    'download',
    '--id',
    '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
    '--extract',
    '--stdout',
  ]);

  assert.notEqual(extractStdoutResult.code, 0);
  assert.match(
    extractStdoutResult.stderr,
    /does not support --stdout with --extract/,
  );
});

test('interactive keygen can convert an identity to recipients', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-keygen-'),
  );
  const interactiveScript = CLIENT_BIN;
  const keyPath = path.join(tmpDir, 'identity.txt');
  const recipientPath = path.join(tmpDir, 'recipient.txt');
  const ageKeygenMock = path.join(tmpDir, 'age-keygen-mock.sh');

  await writeFile(keyPath, 'AGE-SECRET-KEY-1EXAMPLE\n', 'utf8');

  await makeExecutable(
    ageKeygenMock,
    `#!/bin/sh
if [ "$1" = "-y" ] && [ "$2" = "-o" ]; then
  printf '%s\n' 'age1interactiveconverted' > "$3"
  exit 0
fi
exit 1
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_AGE_KEYGEN_BIN: ageKeygenMock,
    },
    { input: `7\n2\n2\n${keyPath}\n${recipientPath}\n` },
  );

  assert.equal(result.code, 0);
  assert.equal(
    await readFile(recipientPath, 'utf8'),
    'age1interactiveconverted\n',
  );
  assert.match(result.stdout, /Keygen mode:/);
});

// The peer transfer paths of the menu are observed through the option parsers
// and the local peer state, which both run before any network operation.
async function createInteractiveV2Home(tmpDir, peers = []) {
  const dudHome = path.join(tmpDir, 'dud');
  const env = { DUD_HOME: dudHome };
  if (peers.length === 0) {
    return env;
  }
  const init = await runCommand(
    CLIENT_BIN,
    ['init', '--device', 'desktop'],
    env,
  );
  assert.equal(init.code, 0, init.stderr);
  const configFile = path.join(dudHome, 'default', 'config', 'config.toml');
  const sections = peers
    .map((alias) => `\n[peer."${alias}"]\nstatus = "active"\nkey_epoch = 0\n`)
    .join('');
  await writeFile(
    configFile,
    (await readFile(configFile, 'utf8')) + sections,
    'utf8',
  );
  return env;
}

test('interactive send picks a peer target and passes peer send options', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-peer-send-'),
  );
  const env = await createInteractiveV2Home(tmpDir, ['laptop', 'phone']);

  const result = await runCommand(
    CLIENT_BIN,
    [],
    { ...env, DUD_TEST_STDIN_TTY: '1' },
    { input: '1\n1\n1\nhello\n\n999h\n' },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stdout, /Send to:/);
  assert.match(result.stdout, /1\) laptop/);
  assert.match(result.stdout, /2\) phone/);
  assert.match(result.stdout, /3\) dead drop — share by ID/);
  // A dead drop upload would have rejected the missing secret token instead;
  // this is the peer option parser refusing the TTL.
  assert.match(result.stderr, /--ttl must be between 1 second and 720 hours/);
});

test('interactive send to a peer collects repeated file arguments', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-peer-send-files-'),
  );
  const env = await createInteractiveV2Home(tmpDir, ['laptop']);
  const presentFile = path.join(tmpDir, 'present.bin');
  const missingFile = path.join(tmpDir, 'missing.bin');
  await writeFile(presentFile, 'payload', 'utf8');

  const result = await runCommand(
    CLIENT_BIN,
    [],
    { ...env, DUD_TEST_STDIN_TTY: '1' },
    {
      input: `1\n1\n3\n${presentFile}\n${missingFile}\n\nbundle\n\ny\n`,
    },
  );

  assert.notEqual(result.code, 0);
  // The second path is only read once the first one was collected, so naming
  // it proves both --file arguments reached the command.
  assert.match(
    result.stderr,
    new RegExp(missingFile.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
  assert.match(result.stderr, /no such file or directory/);
});

test('interactive receive from a peer passes wait and extraction options', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-peer-receive-'),
  );
  const env = await createInteractiveV2Home(tmpDir, ['laptop', 'phone']);

  const result = await runCommand(
    CLIENT_BIN,
    [],
    { ...env, DUD_TEST_STDIN_TTY: '1' },
    { input: '2\n2\n1\nn\nnope\n' },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stdout, /Receive from:/);
  assert.match(result.stdout, /2\) phone/);
  assert.match(result.stdout, /Extract received collections\?/);
  // --wait exists only on the peer path, so refusing it proves the menu did
  // not fall back to a dead drop download.
  assert.match(result.stderr, /--wait must be a non-negative duration/);
});

test('interactive git push reaches the peer Git path', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-peer-git-push-'),
  );
  const env = await createInteractiveV2Home(tmpDir, ['laptop']);
  const gitLog = path.join(tmpDir, 'git.log');
  const gitMock = path.join(tmpDir, 'git-mock.sh');
  await makeExecutable(
    gitMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${gitLog}"
exit 0
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    [],
    { ...env, DUD_TEST_STDIN_TTY: '1', DUD_GIT_BIN: gitMock },
    { input: '3\n1\n1\n2\n999h\n' },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stdout, /Push to:/);
  assert.match(result.stdout, /Push scope:/);
  assert.match(result.stderr, /--ttl must be between 1 second and 720 hours/);
  assert.equal(
    existsSync(gitLog),
    false,
    'peer git push fell back to a dead drop bundle',
  );
});

test('interactive transfer degrades to the dead drop entry without a device', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-no-device-'),
  );
  const env = await createInteractiveV2Home(tmpDir);

  const typedAlias = await runCommand(
    CLIENT_BIN,
    [],
    { ...env, DUD_TEST_STDIN_TTY: '1' },
    { input: '1\nlaptop\n1\nhello\n\n\n\n' },
  );

  assert.notEqual(typedAlias.code, 0);
  assert.match(typedAlias.stdout, /1\) dead drop — share by ID/);
  assert.match(
    typedAlias.stdout,
    /No peers available \(this device is not initialized for peer transfers.*use setup to initialize this device and peers to pair one\./,
  );
  assert.match(
    typedAlias.stderr,
    /this device is not initialized for peer transfers/,
  );
});

test('install command prints a TTY-aware wrapper', async () => {
  const result = await runCommand(CLIENT_BIN, ['install']);

  assert.equal(result.code, 0);
  assert.match(result.stdout, /dud_docker_env_args\(\)/);
  assert.match(result.stdout, /if \[ -r \.env \]; then/);
  assert.match(result.stdout, /--env-file/);
  assert.match(
    result.stdout,
    /DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_DROP_SECRET DUD_PEER_SECRET DUD_CA_BUNDLE DUD_CONNECT_TO/,
  );
  assert.match(result.stdout, /dud_world_dir_name\(\)/);
  assert.match(result.stdout, /dud_docker_run_args\(\)/);
  assert.match(result.stdout, /DUD_DOCKER_NETWORK/);
  assert.match(result.stdout, /dud_shell_quote -e/);
  assert.match(result.stdout, /if \[ -t 0 \] && \[ -t 1 \]; then/);
  assert.match(result.stdout, /docker run --rm -it/);
  assert.match(result.stdout, /docker run --rm -i/);
});

test('shell-init command prints a TTY-aware shell function', async () => {
  const result = await runCommand(CLIENT_BIN, ['shell-init']);

  assert.equal(result.code, 0);
  assert.match(result.stdout, /^_dud_shell_quote\(\) \{/m);
  assert.match(result.stdout, /^_dud_world_dir_name\(\) \{/m);
  assert.match(result.stdout, /^_dud_host_has_tty\(\) \{/m);
  assert.match(result.stdout, /^_dud_stdout_is_tty\(\) \{/m);
  assert.match(result.stdout, /^_dud_tty_input_path\(\) \{/m);
  assert.match(result.stdout, /^_dud_upload_uses_stdin\(\) \{/m);
  assert.match(result.stdout, /^_dud_docker_cli_args\(\) \{/m);
  assert.match(result.stdout, /^_dud_complete_wordlist\(\) \{/m);
  assert.match(result.stdout, /^_dud_complete_filter_prefix\(\) \{/m);
  assert.match(result.stdout, /^_dud_complete_parse\(\) \{/m);
  assert.match(result.stdout, /^_dud_complete_candidates\(\) \{/m);
  assert.match(result.stdout, /^dud\(\) \{/m);
  assert.doesNotMatch(result.stdout, /^dud_host_has_tty\(\) \{/m);
  assert.doesNotMatch(result.stdout, /^dud_stdout_is_tty\(\) \{/m);
  assert.doesNotMatch(result.stdout, /^dud_tty_input_path\(\) \{/m);
  assert.doesNotMatch(result.stdout, /^dud_upload_uses_stdin\(\) \{/m);
  assert.doesNotMatch(result.stdout, /^dud_docker_cli_args\(\) \{/m);
  assert.match(result.stdout, /complete -o default -F _dud_complete_bash dud/);
  assert.match(result.stdout, /compdef _dud_complete_zsh dud/);
  assert.match(result.stdout, /if \[ -r \.env \]; then/);
  assert.match(result.stdout, /--env-file/);
  assert.match(
    result.stdout,
    /DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_DROP_SECRET DUD_PEER_SECRET DUD_CA_BUNDLE DUD_CONNECT_TO/,
  );
  assert.match(result.stdout, /DUD_DOCKER_NETWORK/);
  assert.match(result.stdout, /_dud_shell_quote -e/);
  assert.match(result.stdout, /docker run --rm -it/);
  assert.match(result.stdout, /docker run --rm -i/);
});

test('shell-init output can be evaled and used in the current shell', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-'),
  );
  const logFile = path.join(tmpDir, 'docker.log');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );

  const result = await runCommand(
    'bash',
    ['-c', `eval "$(${CLIENT_BIN} shell-init)"; dud test`],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
      DUD_DROP_SECRET: 'top-secret',
      DUD_DOCKER_NETWORK: 'dud_dev',
      DUD_CA_BUNDLE: '/work/.dud-dev/caddy-data/pki/authorities/local/root.crt',
      DUD_CONNECT_TO: 'dud.local.test:443:caddy:443',
    },
  );

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /run/);
  assert.match(args, /--rm/);
  assert.match(args, /ghcr\.io\/wojciechpolak\/dud\/dud-client:latest/);
  assert.match(args, /test/);
  assert.match(args, /--network\ndud_dev/);
  assert.match(args, /-e\nDUD_DROP_SECRET=top-secret/);
  assert.match(
    args,
    /-e\nDUD_CA_BUNDLE=\/work\/\.dud-dev\/caddy-data\/pki\/authorities\/local\/root\.crt/,
  );
  assert.match(args, /-e\nDUD_CONNECT_TO=dud\.local\.test:443:caddy:443/);
});

// A repository .env is imported for network settings, and the worktree it comes
// from is bind-mounted at /work alongside the read-write config and state roots
// that hold the master seed and the peer graph. A .env that chooses which
// executable the client runs would therefore run repository code with the seed
// in reach, so every selector is pinned after --env-file, where it wins.
for (const wrapper of ['install', 'shell-init']) {
  test(`${wrapper} wrapper refuses executable selectors from a repository .env`, async () => {
    const tmpDir = await mkdtemp(
      path.join(os.tmpdir(), `dud-client-${wrapper}-env-`),
    );
    const logFile = path.join(tmpDir, 'docker.log');
    await makeExecutable(
      path.join(tmpDir, 'docker'),
      `#!/bin/sh\nprintf '%s\\n' "$@" > "${logFile}"\n`,
    );
    await makeExecutable(path.join(tmpDir, 'evil'), '#!/bin/sh\nexit 0\n');
    await writeFile(
      path.join(tmpDir, '.env'),
      [
        'DUD_GIT_BIN=/work/evil',
        'DUD_AGE_BIN=/work/evil',
        'DUD_AGE_KEYGEN_BIN=/work/evil',
        'DUD_QRENCODE_BIN=/work/evil',
        'PATH=/work',
        'LD_PRELOAD=/work/evil.so',
        'LD_LIBRARY_PATH=/work',
        'LD_AUDIT=/work/evil.so',
        '',
      ].join('\n'),
      'utf8',
    );

    const script =
      wrapper === 'install'
        ? `"${CLIENT_BIN}" install > ./dud-wrapper; sh ./dud-wrapper test`
        : `eval "$(${CLIENT_BIN} shell-init)"; dud test`;
    const result = await runCommand(
      'bash',
      ['-c', script],
      { PATH: `${tmpDir}:${process.env.PATH ?? ''}`, HOME: tmpDir },
      { cwd: tmpDir },
    );

    assert.equal(result.code, 0);
    const args = await readFile(logFile, 'utf8');
    assert.match(args, /--env-file\n\.env/);
    assert.doesNotMatch(args, /\/work\/evil/);

    // Docker applies duplicates in order, so a pinned -e only wins where it
    // follows the imported file. Asserting the order keeps the control from
    // being silently undone by a later reshuffle of the argument list.
    const argv = args.split('\n');
    const envFileAt = argv.indexOf('--env-file');
    assert.notEqual(envFileAt, -1);
    for (const pinned of [
      'DUD_GIT_BIN=git',
      'DUD_AGE_BIN=age',
      'DUD_AGE_KEYGEN_BIN=age-keygen',
      'DUD_QRENCODE_BIN=qrencode',
      'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      'LD_PRELOAD=',
      'LD_LIBRARY_PATH=',
      'LD_AUDIT=',
    ]) {
      const at = argv.indexOf(pinned);
      assert.notEqual(at, -1, `${pinned} is not pinned`);
      assert.equal(argv[at - 1], '-e', `${pinned} is not passed with -e`);
      assert.ok(at > envFileAt, `${pinned} is pinned before --env-file`);
    }
  });
}

test('shell-init registers bash completion for dud', async () => {
  const result = await runCommand(
    'bash',
    ['-c', `eval "$(${CLIENT_BIN} shell-init)"; complete -p dud`],
    {},
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /complete .*_dud_complete_bash dud/);
});

test('shell-init bash completion suggests subcommands and file arguments', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-complete-'),
  );
  const identityFile = path.join(tmpDir, 'identity.txt');
  await writeFile(identityFile, 'secret', 'utf8');
  const result = await runCommand(
    'bash',
    [
      '-c',
      `eval "$(${CLIENT_BIN} shell-init)"; COMP_WORDS=(dud gi); COMP_CWORD=1; _dud_complete_bash; printf 'TOP:%s\n' "\${COMPREPLY[*]}"; COMP_WORDS=(dud git ''); COMP_CWORD=2; _dud_complete_bash; printf 'GIT:%s\n' "\${COMPREPLY[*]}"; COMP_WORDS=(dud peer ''); COMP_CWORD=2; _dud_complete_bash; printf 'PEER:%s\n' "\${COMPREPLY[*]}"; COMP_WORDS=(dud download --identity ${path.basename(identityFile).slice(0, 2)}); COMP_CWORD=3; _dud_complete_bash; printf 'FILE:%s\n' "\${COMPREPLY[*]}"`,
    ],
    {},
    { cwd: tmpDir },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /TOP:.*git/);
  assert.doesNotMatch(result.stdout, /GIT:.*--version/);
  assert.doesNotMatch(result.stdout, /GIT:.*version/);
  assert.doesNotMatch(result.stdout, /GIT:.*--help/);
  assert.doesNotMatch(result.stdout, /GIT:.*-h/);
  assert.match(result.stdout, /GIT:.*push/);
  assert.match(result.stdout, /GIT:.*fetch/);
  assert.match(result.stdout, /PEER:.*invite/);
  assert.match(result.stdout, /PEER:.*accept/);
  assert.doesNotMatch(result.stdout, /PEER:.*add/);
  assert.match(result.stdout, /FILE:.*identity\.txt/);
});

test(
  'shell-init zsh completion filters partial top-level commands',
  { skip: commandExists('zsh') ? false : 'zsh is not installed' },
  async () => {
    const result = await runCommand(
      'zsh',
      [
        '-fc',
        `autoload -Uz compinit; compinit; eval "$(${CLIENT_BIN} shell-init)"; compadd() { printf 'ADD:%s\\n' "$@"; }; words=(dud gi); CURRENT=2; _dud_complete_zsh`,
      ],
      {},
    );

    assert.equal(result.code, 0);
    assert.match(result.stdout, /ADD:--/);
    assert.match(result.stdout, /ADD:git/);
    assert.doesNotMatch(result.stdout, /ADD:version/);
    assert.doesNotMatch(result.stdout, /ADD:--version/);
    assert.doesNotMatch(result.stdout, /ADD:--help/);
  },
);

test('shell-init output honors runtime DUD_IMAGE overrides', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-image-'),
  );
  const logFile = path.join(tmpDir, 'docker.log');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );

  const result = await runCommand(
    'bash',
    [
      '-c',
      `eval "$(${CLIENT_BIN} shell-init)"; DUD_IMAGE=dud-client-local dud test`,
    ],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    },
  );

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /dud-client-local/);
  assert.doesNotMatch(args, /ghcr\.io\/wojciechpolak\/dud\/dud-client:latest/);
});

test('shell-init output preserves the generated DUD_IMAGE fallback', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-baked-image-'),
  );
  const logFile = path.join(tmpDir, 'docker.log');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );

  const result = await runCommand(
    'bash',
    [
      '-c',
      `eval "$(DUD_IMAGE=dud-client-baked ${CLIENT_BIN} shell-init)"; dud test`,
    ],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    },
  );

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /dud-client-baked/);
  assert.doesNotMatch(args, /ghcr\.io\/wojciechpolak\/dud\/dud-client:latest/);
});

test('shell-init output does not pass an empty command argument', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-empty-'),
  );
  const logFile = path.join(tmpDir, 'docker.log');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );

  const result = await runCommand(
    'bash',
    ['-c', `eval "$(${CLIENT_BIN} shell-init)"; dud`],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    },
  );

  assert.equal(result.code, 0);
  const args = (await readFile(logFile, 'utf8')).trimEnd().split('\n');
  assert.equal(args.at(-1), 'ghcr.io/wojciechpolak/dud/dud-client:latest');
  assert.notEqual(args.at(-1), '');
});

test('shell-init stages piped upload stdin so age can still use a tty', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-pipe-'),
  );
  const logFile = path.join(tmpDir, 'docker.log');
  const payloadFile = path.join(tmpDir, 'payload.bin');
  const hostPathFile = path.join(tmpDir, 'host-path.txt');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
stdin_mount=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-v" ]; then
    case "$2" in
      *:/tmp/dud-stdin:ro) stdin_mount="$2" ;;
    esac
    shift 2
    continue
  fi
  shift
done
host_path="\${stdin_mount%%:/tmp/dud-stdin:ro}"
printf '%s' "$host_path" > "${hostPathFile}"
cat "$host_path" > "${payloadFile}"
`,
  );

  const result = await runCommand(
    'bash',
    [
      '-c',
      `eval "$(${CLIENT_BIN} shell-init)"; printf streamed-payload | dud upload`,
    ],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
      DUD_DROP_SECRET: 'top-secret',
      DUD_TEST_HOST_TTY: '1',
      DUD_TEST_STDOUT_TTY: '1',
      DUD_TEST_TTY_INPUT_PATH: '/dev/null',
    },
  );

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /run/);
  assert.match(args, /-it/);
  assert.match(args, /\/tmp\/dud-stdin:ro/);
  assert.match(args, /--file\n\/tmp\/dud-stdin/);
  assert.equal(await readFile(payloadFile, 'utf8'), 'streamed-payload');

  const hostPath = await readFile(hostPathFile, 'utf8');
  assert.match(hostPath, /dud-wrapper-stdin-/);
  assert.equal(
    existsSync(hostPath),
    false,
    `shell-init left staged plaintext at ${hostPath}`,
  );
});

test('install wrapper stages piped upload stdin and removes it afterwards', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-install-pipe-'),
  );
  const wrapper = path.join(tmpDir, 'dud');
  const payloadFile = path.join(tmpDir, 'payload.bin');
  const hostPathFile = path.join(tmpDir, 'host-path.txt');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
stdin_mount=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-v" ]; then
    case "$2" in
      *:/tmp/dud-stdin:ro) stdin_mount="$2" ;;
    esac
    shift 2
    continue
  fi
  shift
done
host_path="\${stdin_mount%%:/tmp/dud-stdin:ro}"
printf '%s' "$host_path" > "${hostPathFile}"
cat "$host_path" > "${payloadFile}"
exit 7
`,
  );

  const installOutput = await runCommand(CLIENT_BIN, ['install']);
  assert.equal(installOutput.code, 0);
  await makeExecutable(wrapper, installOutput.stdout);

  const result = await runCommand(
    'sh',
    ['-c', `printf streamed-payload | "${wrapper}" upload`],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
      DUD_DROP_SECRET: 'top-secret',
      DUD_TEST_HOST_TTY: '1',
      DUD_TEST_STDOUT_TTY: '1',
      DUD_TEST_TTY_INPUT_PATH: '/dev/null',
    },
  );

  // The wrapper must forward the container's exit status even though it can no
  // longer exec into docker.
  assert.equal(result.code, 7);
  assert.equal(await readFile(payloadFile, 'utf8'), 'streamed-payload');

  const hostPath = await readFile(hostPathFile, 'utf8');
  assert.match(hostPath, /dud-wrapper-stdin-/);
  assert.equal(
    existsSync(hostPath),
    false,
    `wrapper left staged plaintext at ${hostPath}`,
  );
});

test('install wrapper removes the bind root after erase all and keeps dry-run read-only', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-install-erase-'),
  );
  const wrapper = path.join(tmpDir, 'dud');
  const dockerMock = path.join(tmpDir, 'docker');
  const dudHome = path.join(tmpDir, 'dud-home');
  const worldDir = path.join(dudHome, 'default');
  const configDir = path.join(worldDir, 'config');
  const stateDir = path.join(worldDir, 'state');

  await mkdir(configDir, { recursive: true });
  await mkdir(stateDir, { recursive: true });
  await writeFile(path.join(configDir, 'config.toml'), 'config', 'utf8');
  await writeFile(path.join(stateDir, 'delivery.json'), 'state', 'utf8');
  await makeExecutable(
    dockerMock,
    `#!/bin/sh
rm -rf "${configDir}" "${stateDir}"
`,
  );

  const installOutput = await runCommand(CLIENT_BIN, ['install']);
  assert.equal(installOutput.code, 0);
  await makeExecutable(wrapper, installOutput.stdout);

  const erased = await runCommand(wrapper, ['erase', 'all', '--yes'], {
    PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    DUD_HOME: dudHome,
  });
  assert.equal(erased.code, 0, erased.stderr);
  assert.equal(existsSync(worldDir), false);
  // The last world takes the root with it, so nothing named after DUD remains.
  assert.equal(existsSync(dudHome), false);

  const dryHome = path.join(tmpDir, 'dry-home');
  const dryRun = await runCommand(wrapper, ['erase', 'all', '--dry-run'], {
    PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    DUD_HOME: dryHome,
  });
  assert.equal(dryRun.code, 0, dryRun.stderr);
  assert.equal(existsSync(path.join(dryHome, 'default')), false);
});

// A profile other than the one being erased is a separate world under the same
// root, and erase all must leave it exactly where it was.
test('install wrapper keeps other worlds when one is erased', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-install-erase-profile-'),
  );
  const wrapper = path.join(tmpDir, 'dud');
  const dockerMock = path.join(tmpDir, 'docker');
  const dudHome = path.join(tmpDir, 'dud-home');
  const worldDir = path.join(dudHome, 'test');
  const otherWorld = path.join(dudHome, 'default');

  await mkdir(path.join(worldDir, 'config'), { recursive: true });
  await mkdir(path.join(otherWorld, 'config'), { recursive: true });
  await writeFile(path.join(otherWorld, 'config', 'seed'), 'keep', 'utf8');
  await makeExecutable(
    dockerMock,
    `#!/bin/sh
rm -rf "${worldDir}/config"
`,
  );

  const installOutput = await runCommand(CLIENT_BIN, ['install']);
  assert.equal(installOutput.code, 0);
  await makeExecutable(wrapper, installOutput.stdout);

  const erased = await runCommand(wrapper, ['erase', 'all', '--yes'], {
    PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    DUD_HOME: dudHome,
    DUD_PROFILE: 'test',
  });
  assert.equal(erased.code, 0, erased.stderr);
  assert.equal(existsSync(worldDir), false);
  assert.equal(existsSync(path.join(otherWorld, 'config', 'seed')), true);
});

test(
  'shell-init wrapper removes bind roots after erase all under zsh',
  { skip: commandExists('zsh') ? false : 'zsh is not installed' },
  async () => {
    const tmpDir = await mkdtemp(
      path.join(os.tmpdir(), 'dud-client-zsh-erase-'),
    );
    const dockerMock = path.join(tmpDir, 'docker');
    const dudHome = path.join(tmpDir, 'dud-home');
    const worldDir = path.join(dudHome, 'default');
    const configDir = path.join(worldDir, 'config');
    const stateDir = path.join(worldDir, 'state');

    await mkdir(configDir, { recursive: true });
    await mkdir(stateDir, { recursive: true });
    await writeFile(path.join(configDir, 'config.toml'), 'config', 'utf8');
    await writeFile(path.join(stateDir, 'delivery.json'), 'state', 'utf8');
    await makeExecutable(
      dockerMock,
      `#!/bin/sh
rm -rf "${configDir}" "${stateDir}"
`,
    );

    // `status` is a read-only alias for `$?` in zsh, so the wrapper must keep
    // its bookkeeping in its own namespace or the erase cleanup never runs.
    const erased = await runCommand(
      'zsh',
      ['-fc', `eval "$(${CLIENT_BIN} shell-init)"; dud erase all --yes`],
      {
        PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
        DUD_HOME: dudHome,
      },
    );

    assert.equal(erased.code, 0, erased.stderr);
    assert.doesNotMatch(erased.stderr, /read-only variable/);
    assert.equal(existsSync(worldDir), false);
    assert.equal(existsSync(dudHome), false);
  },
);

test('install wrapper binds the DUD_PROFILE world on both sides of the mount', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-install-profile-'),
  );
  const wrapper = path.join(tmpDir, 'dud');
  const dockerMock = path.join(tmpDir, 'docker');
  const logFile = path.join(tmpDir, 'docker.log');
  const dudHome = path.join(tmpDir, 'dud-home');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );
  const installOutput = await runCommand(CLIENT_BIN, ['install']);
  assert.equal(installOutput.code, 0);
  await makeExecutable(wrapper, installOutput.stdout);

  const env = {
    PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    DUD_HOME: dudHome,
  };

  const plain = await runCommand(wrapper, ['doctor'], env);
  assert.equal(plain.code, 0, plain.stderr);
  let args = await readFile(logFile, 'utf8');
  assert.match(args, new RegExp(`-v\n${dudHome}/default:/dud/default\n`));
  assert.match(args, /-e\nDUD_HOME=\/dud\n/);
  assert.match(args, /-e\nDUD_PROFILE=\n/);

  const profiled = await runCommand(wrapper, ['doctor'], {
    ...env,
    DUD_PROFILE: 'test',
  });
  assert.equal(profiled.code, 0, profiled.stderr);
  args = await readFile(logFile, 'utf8');
  // The container side carries the world name too, so the client's own lookup
  // lands exactly on the mount instead of an empty directory beside it. Only
  // that one world is mounted, so this container cannot reach any other.
  assert.match(args, new RegExp(`-v\n${dudHome}/test:/dud/test\n`));
  assert.doesNotMatch(args, new RegExp(`-v\n${dudHome}:/dud\n`));
  assert.match(args, /-e\nDUD_PROFILE=test\n/);
  assert.equal(existsSync(path.join(dudHome, 'test')), true);

  // The host picks the profile because the host builds the mount; a value left
  // in .env must not send the container looking somewhere unmounted.
  const workDir = path.join(tmpDir, 'work');
  await mkdir(workDir, { recursive: true });
  await writeFile(
    path.join(workDir, '.env'),
    'DUD_PROFILE=from-env\nDUD_HOME=/elsewhere\n',
    'utf8',
  );
  const fromEnvFile = await runCommand(wrapper, ['doctor'], env, {
    cwd: workDir,
  });
  assert.equal(fromEnvFile.code, 0, fromEnvFile.stderr);
  args = (await readFile(logFile, 'utf8')).split('\n');
  assert.ok(args.includes('--env-file'));
  assert.ok(
    args.lastIndexOf('DUD_PROFILE=') > args.indexOf('--env-file'),
    'the explicit empty DUD_PROFILE must follow --env-file',
  );
  assert.ok(
    args.lastIndexOf('DUD_HOME=/dud') > args.indexOf('--env-file'),
    'the pinned DUD_HOME must follow --env-file',
  );
  assert.equal(args.includes(`${dudHome}/from-env:/dud/from-env`), false);
});

test('shell-init function binds the DUD_PROFILE world', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-profile-'),
  );
  const dockerMock = path.join(tmpDir, 'docker');
  const logFile = path.join(tmpDir, 'docker.log');
  const dudHome = path.join(tmpDir, 'dud-home');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );

  const result = await runCommand(
    'bash',
    ['-c', `eval "$(${CLIENT_BIN} shell-init)"; dud doctor`],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
      DUD_HOME: dudHome,
      DUD_PROFILE: 'test',
    },
  );

  assert.equal(result.code, 0, result.stderr);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, new RegExp(`-v\n${dudHome}/test:/dud/test\n`));
  assert.match(args, /-e\nDUD_HOME=\/dud\n/);
  assert.match(args, /-e\nDUD_PROFILE=test\n/);
  assert.equal(existsSync(path.join(dudHome, 'default')), false);
});

test('wrappers refuse a DUD_PROFILE that would leave the DUD root', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-profile-refusal-'),
  );
  const wrapper = path.join(tmpDir, 'dud');
  const dockerMock = path.join(tmpDir, 'docker');
  const logFile = path.join(tmpDir, 'docker.log');
  const dudHome = path.join(tmpDir, 'dud-home');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );
  const installOutput = await runCommand(CLIENT_BIN, ['install']);
  assert.equal(installOutput.code, 0);
  await makeExecutable(wrapper, installOutput.stdout);

  const env = {
    PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    DUD_HOME: dudHome,
    DUD_PROFILE: '../escape',
  };

  const installed = await runCommand(wrapper, ['doctor'], env);
  assert.equal(installed.code, 1);
  assert.match(installed.stderr, /Refusing invalid DUD_PROFILE/);
  assert.equal(existsSync(logFile), false);

  const shellInit = await runCommand(
    'bash',
    ['-c', `eval "$(${CLIENT_BIN} shell-init)"; dud doctor`],
    env,
  );
  assert.equal(shellInit.code, 1);
  assert.match(shellInit.stderr, /Refusing invalid DUD_PROFILE/);
  assert.equal(existsSync(logFile), false);
  assert.equal(existsSync(path.join(dudHome, 'default')), false);
});

test('keygen command can generate post-quantum keys and a recipient file', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-keygen-'));
  const keyPath = path.join(tmpDir, 'key.txt');
  const recipientPath = path.join(tmpDir, 'recipient.txt');
  const ageKeygenMock = path.join(tmpDir, 'age-keygen-mock.sh');
  const keygenLog = path.join(tmpDir, 'age-keygen.log');

  await makeExecutable(
    ageKeygenMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${keygenLog}"
if [ "$1" = "--help" ]; then
  cat <<'EOF'
Usage:
    age-keygen [-pq] [-o OUTPUT]
    age-keygen -y [-o OUTPUT] [INPUT]
EOF
  exit 0
fi
if [ "$1" = "-y" ]; then
  printf '%s\n' 'age1pq1examplepublicrecipient'
  exit 0
fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s\n' 'AGE-SECRET-KEY-PQ-1EXAMPLE' > "$output"
printf '%s\n' 'Public key: age1pq1examplepublicrecipient' >&2
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['keygen', '--pq', '--out', keyPath, '-R', recipientPath],
    {
      DUD_AGE_KEYGEN_BIN: ageKeygenMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /Public key: age1pq1examplepublicrecipient/);
  assert.equal(
    await readFile(recipientPath, 'utf8'),
    'age1pq1examplepublicrecipient\n',
  );
  const keygenArgs = await readFile(keygenLog, 'utf8');
  assert.match(keygenArgs, /-pq/);
  assert.match(
    keygenArgs,
    new RegExp(keyPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
  assert.match(keygenArgs, /-y/);
});

test('keygen command reports a clear error when age-keygen lacks -pq support', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-keygen-no-pq-'),
  );
  const ageKeygenMock = path.join(tmpDir, 'age-keygen-mock.sh');

  await makeExecutable(
    ageKeygenMock,
    `#!/bin/sh
if [ "$1" = "--help" ]; then
  cat <<'EOF'
Usage:
    age-keygen [-o OUTPUT]
    age-keygen -y [-o OUTPUT] [INPUT]
EOF
  exit 0
fi
exit 1
`,
  );

  const result = await runCommand(CLIENT_BIN, ['keygen', '--pq'], {
    DUD_AGE_KEYGEN_BIN: ageKeygenMock,
  });

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /does not support -pq/);
});

test('keygen command can generate a key to stdout without --out', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-keygen-stdout-'),
  );
  const ageKeygenMock = path.join(tmpDir, 'age-keygen-mock.sh');
  const keygenLog = path.join(tmpDir, 'age-keygen.log');

  await makeExecutable(
    ageKeygenMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${keygenLog}"
printf '%s\n' '# public key: age1example'
printf '%s\n' 'AGE-SECRET-KEY-1EXAMPLE'
`,
  );

  const result = await runCommand(CLIENT_BIN, ['keygen'], {
    DUD_AGE_KEYGEN_BIN: ageKeygenMock,
  });

  assert.equal(result.code, 0);
  assert.match(result.stdout, /AGE-SECRET-KEY-1EXAMPLE/);
  assert.equal((await readFile(keygenLog, 'utf8')).trim(), '');
});

test('keygen command can convert an identity to a recipient file without --out', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-keygen-convert-file-'),
  );
  const keyPath = path.join(tmpDir, 'key.txt');
  const recipientPath = path.join(tmpDir, 'recipient.txt');
  const ageKeygenMock = path.join(tmpDir, 'age-keygen-mock.sh');
  const keygenLog = path.join(tmpDir, 'age-keygen.log');

  await writeFile(keyPath, 'AGE-SECRET-KEY-1EXAMPLE\n', 'utf8');

  await makeExecutable(
    ageKeygenMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${keygenLog}"
if [ "$1" = "-y" ]; then
  shift
  if [ "$1" = "-o" ]; then
    output="$2"
    input="$3"
    printf '%s\n' "age1converted-from-$input" > "$output"
    exit 0
  fi
fi
exit 1
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['keygen', '-R', recipientPath, keyPath],
    {
      DUD_AGE_KEYGEN_BIN: ageKeygenMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(result.stdout, '');
  assert.equal(
    await readFile(recipientPath, 'utf8'),
    `age1converted-from-${keyPath}\n`,
  );
  const keygenArgs = await readFile(keygenLog, 'utf8');
  assert.match(keygenArgs, /-y/);
  assert.match(keygenArgs, /-o/);
  assert.match(
    keygenArgs,
    new RegExp(recipientPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
});

test('keygen command can convert an identity to stdout', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-keygen-convert-stdout-'),
  );
  const keyPath = path.join(tmpDir, 'key.txt');
  const ageKeygenMock = path.join(tmpDir, 'age-keygen-mock.sh');
  const keygenLog = path.join(tmpDir, 'age-keygen.log');

  await writeFile(keyPath, 'AGE-SECRET-KEY-1EXAMPLE\n', 'utf8');

  await makeExecutable(
    ageKeygenMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${keygenLog}"
if [ "$1" = "-y" ]; then
  printf '%s\n' 'age1convertedstdout'
  exit 0
fi
exit 1
`,
  );

  const result = await runCommand(CLIENT_BIN, ['keygen', keyPath], {
    DUD_AGE_KEYGEN_BIN: ageKeygenMock,
  });

  assert.equal(result.code, 0);
  assert.equal(result.stdout, 'age1convertedstdout\n');
  assert.equal(result.stderr, '');
  const keygenArgs = await readFile(keygenLog, 'utf8');
  assert.match(keygenArgs, /-y/);
  assert.match(
    keygenArgs,
    new RegExp(keyPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
});

test('keygen --json reports the recipient and never the identity', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-keygen-json-'),
  );
  const keyPath = path.join(tmpDir, 'key.txt');
  const ageKeygenMock = path.join(tmpDir, 'age-keygen-mock.sh');

  await makeExecutable(
    ageKeygenMock,
    `#!/bin/sh
if [ "$1" = "-y" ]; then
  printf '%s\n' 'age1derivedrecipient'
  exit 0
fi
if [ "$1" = "-o" ]; then
  printf '%s\n' 'AGE-SECRET-KEY-1EXAMPLE' > "$2"
  exit 0
fi
exit 1
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['keygen', '--out', keyPath, '--json'],
    { DUD_AGE_KEYGEN_BIN: ageKeygenMock },
  );

  assert.equal(result.code, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.recipient, 'age1derivedrecipient');
  assert.equal(report.identity_file, keyPath);
  assert.equal(report.pq, false);
  // The identity stays in the file age-keygen wrote. A report that carried it
  // would put a private key into every log that captured stdout.
  assert.ok(!result.stdout.includes('AGE-SECRET-KEY'));
  assert.equal(await readFile(keyPath, 'utf8'), 'AGE-SECRET-KEY-1EXAMPLE\n');
});

test('keygen --json refuses to generate an identity onto stdout', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-keygen-json-stdout-'),
  );
  const ageKeygenMock = path.join(tmpDir, 'age-keygen-mock.sh');
  await makeExecutable(ageKeygenMock, '#!/bin/sh\nexit 1\n');

  const result = await runCommand(CLIENT_BIN, ['keygen', '--json'], {
    DUD_AGE_KEYGEN_BIN: ageKeygenMock,
  });

  assert.equal(result.code, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /keygen requires --out/);
});
