// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
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
import { execFileSync, spawn } from 'node:child_process';

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

async function makeExecutable(filePath, content) {
  await writeFile(filePath, content, 'utf8');
  await chmod(filePath, 0o755);
}

async function createVerboseCurlMock(tmpDir, responseBody = '{"ok":true}') {
  const logFile = path.join(tmpDir, 'curl.log');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s\n' '* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / id-ecPublicKey' >&2
printf '%s\n' '* ECH: result: status is succeeded, inner is dud.example.com, outer is cloudflare-ech.com' >&2
printf '%s\n' '* ALPN: server accepted http/1.1' >&2
printf '%s\n' '${responseBody}' > "$output"
`,
  );

  return { curlMock, logFile };
}

function createQrUploadToolPaths(tmpDir) {
  return {
    qrLog: path.join(tmpDir, 'qr.log'),
    ageMock: path.join(tmpDir, 'age-mock.sh'),
    curlMock: path.join(tmpDir, 'curl-mock.sh'),
    qrMock: path.join(tmpDir, 'qr-mock.sh'),
  };
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

test('test command enforces secure curl flags', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-test-'));
  const { curlMock, logFile } = await createVerboseCurlMock(tmpDir);

  const result = await runCommand(CLIENT_BIN, ['test'], {
    DUD_CURL_BIN: curlMock,
  });

  assert.equal(result.code, 0);
  assert.match(result.stdout, /Transport:/);
  assert.match(result.stdout, /Response:\n{"ok":true}/);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /--verbose/);
  assert.match(args, /--ech/);
  assert.match(args, /hard/);
  assert.match(args, /--doh-url/);
  assert.match(args, /cloudflare-dns.com/);
  assert.match(args, /--tlsv1.3/);
});

test('test command supports custom CA bundles and connect-to mappings', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-connect-to-'),
  );
  const { curlMock, logFile } = await createVerboseCurlMock(tmpDir);

  const result = await runCommand(CLIENT_BIN, ['test'], {
    DUD_CURL_BIN: curlMock,
    DUD_CA_BUNDLE: '/work/.dud-dev/caddy-data/pki/authorities/local/root.crt',
    DUD_CONNECT_TO: 'dud.local.test:443:caddy:443',
  });

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /--cacert/);
  assert.match(
    args,
    /\/work\/\.dud-dev\/caddy-data\/pki\/authorities\/local\/root\.crt/,
  );
  assert.match(args, /--connect-to/);
  assert.match(args, /dud\.local\.test:443:caddy:443/);
});

test('test command allows DUD_ECH_MODE=grease', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-grease-'));
  const { curlMock, logFile } = await createVerboseCurlMock(tmpDir);

  const result = await runCommand(CLIENT_BIN, ['test'], {
    DUD_CURL_BIN: curlMock,
    DUD_ECH_MODE: 'grease',
  });

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /--ech/);
  assert.match(args, /grease/);
});

test('test command can print TLS and ECH details', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-details-'));
  const { curlMock, logFile } = await createVerboseCurlMock(tmpDir);

  const result = await runCommand(CLIENT_BIN, ['test'], {
    DUD_CURL_BIN: curlMock,
  });

  assert.equal(result.code, 0);
  assert.match(result.stdout, /Transport:/);
  assert.match(
    result.stdout,
    /doh resolver: https:\/\/cloudflare-dns.com\/dns-query/,
  );
  assert.match(result.stdout, /ech mode: hard/);
  assert.match(
    result.stdout,
    /tls: TLSv1.3 \/ TLS_AES_256_GCM_SHA384 \/ X25519MLKEM768 \/ id-ecPublicKey/,
  );
  assert.match(result.stdout, /alpn: http\/1.1/);
  assert.match(result.stdout, /ech: succeeded/);
  assert.match(result.stdout, /inner sni: dud.example.com/);
  assert.match(result.stdout, /outer sni: cloudflare-ech.com/);
  assert.match(result.stdout, /Response:\n{"ok":true}/);

  const args = await readFile(logFile, 'utf8');
  assert.match(args, /--verbose/);
});

test('test command reports the ECH status from status-only trace lines', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-ech-status-'),
  );
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s\n' '* ECH: result: status is not attempted' >&2
printf '%s\n' '{"ok":true}' > "$output"
`,
  );

  const result = await runCommand(CLIENT_BIN, ['test'], {
    DUD_CURL_BIN: curlMock,
    DUD_ECH_MODE: 'grease',
  });

  assert.equal(result.code, 0);
  assert.match(result.stdout, /ech: not attempted/);
  assert.doesNotMatch(result.stdout, /ech: unavailable/);
});

test('exit codes from failing subprocesses are propagated', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-exit-code-'));
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' 'curl: (22) The requested URL returned error: 404' >&2
exit 22
`,
  );

  const result = await runCommand(CLIENT_BIN, ['flush'], {
    DUD_CURL_BIN: curlMock,
    DUD_SECRET_TOKEN: 'top-secret',
  });

  assert.equal(result.code, 22);
  assert.match(result.stderr, /curl: \(22\)/);
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
      DUD_SECRET_TOKEN: 'top-secret',
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

test('upload command encrypts locally with a passphrase and posts the encrypted file', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-upload-'));
  const filePath = path.join(tmpDir, 'plain.bin');
  const ageLog = path.join(tmpDir, 'age.log');
  const curlLog = path.join(tmpDir, 'curl.log');
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const { qrLog, ageMock, curlMock, qrMock } = createQrUploadToolPaths(tmpDir);

  await writeFile(filePath, 'plaintext', 'utf8');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":true}' > "$output"
`,
  );

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${qrLog}"
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['upload', '--file', filePath, '--ttl', '48h', '--delete-after-read'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /^Upload complete$/m);
  assert.match(result.stdout, /^ID: 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe$/m);
  assert.match(result.stdout, /^Expires: 2026-04-20T12:00:00.000Z$/m);
  assert.match(result.stdout, /^Delete after read: yes$/m);
  assert.match(
    result.stdout,
    /^Receive: dud receive --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe --url https:\/\/dud\.example\.com$/m,
  );
  assert.match(result.stdout, /\nQR Code:\n\[qr\]\n?$/);
  assert.match(await readFile(ageLog, 'utf8'), /--passphrase/);
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(curlArgs, /x-dud-ttl: 48h/);
  assert.match(curlArgs, /x-dud-delete-after-read: true/);
  assert.match(curlArgs, /x-dud-secret-token: top-secret/);
  assert.equal(await readFile(curlPayload, 'utf8'), 'plaintext');
  assert.equal(
    await readFile(qrLog, 'utf8'),
    '-t\nansiutf8\n3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe\n',
  );
});

test('upload command can encrypt to public recipients', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-recipient-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');
  const ageLog = path.join(tmpDir, 'age.log');
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await writeFile(filePath, 'plaintext', 'utf8');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  if [ "$1" = "-R" ]; then
    recipients_file="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cat "$recipients_file" > "${tmpDir}/recipients.txt"
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    [
      'upload',
      '--file',
      filePath,
      '-r',
      'age1examplepublickey0000000000000000000000000000000000000000000000',
      '--json',
    ],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  const ageArgs = await readFile(ageLog, 'utf8');
  assert.match(ageArgs, /--encrypt/);
  assert.match(ageArgs, /-R/);
  assert.doesNotMatch(ageArgs, /--passphrase/);
  assert.match(
    await readFile(path.join(tmpDir, 'recipients.txt'), 'utf8'),
    /age1examplepublickey0000000000000000000000000000000000000000000000/,
  );
  assert.equal(await readFile(curlPayload, 'utf8'), 'plaintext');
});

test('upload command accepts recipient file aliases', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-recipient-file-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');
  const recipientsPath = path.join(tmpDir, 'recipients.txt');
  const ageLog = path.join(tmpDir, 'age.log');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await writeFile(filePath, 'plaintext', 'utf8');
  await writeFile(
    recipientsPath,
    'age1examplepublickey0000000000000000000000000000000000000000000000\n',
    'utf8',
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  for (const flag of ['-R', '--recipient-file']) {
    const result = await runCommand(
      CLIENT_BIN,
      ['upload', '--file', filePath, flag, recipientsPath, '--json'],
      {
        DUD_CURL_BIN: curlMock,
        DUD_AGE_BIN: ageMock,
        DUD_SECRET_TOKEN: 'top-secret',
      },
    );

    assert.equal(result.code, 0, `expected success for ${flag}`);
    const ageArgs = await readFile(ageLog, 'utf8');
    assert.match(ageArgs, /-R/);
    assert.match(
      ageArgs,
      new RegExp(recipientsPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    );
  }
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
      DUD_SECRET_TOKEN: 'top-secret',
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
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /either --passphrase or recipient options/);
});

test('upload command can print raw JSON with --json', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-json-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await writeFile(filePath, 'plaintext', 'utf8');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['upload', '--file', filePath, '--json'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.equal(
    result.stdout,
    '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}\n',
  );
});

test('upload command can upload a literal message with -m', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-message-'),
  );
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['upload', '-m', 'hello from dud', '--json'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(curlPayload, 'utf8'), 'hello from dud');
});

test('upload command can read plaintext from stdin', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-stdin-'),
  );
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['upload', '--json'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
    { input: 'stdin plaintext' },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(curlPayload, 'utf8'), 'stdin plaintext');
});

test('upload command can bundle multiple files and directories', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-bundle-'),
  );
  const firstFile = path.join(tmpDir, 'alpha.txt');
  const secondDir = path.join(tmpDir, 'docs');
  const secondFile = path.join(secondDir, 'beta.txt');
  const curlPayload = path.join(tmpDir, 'payload.tar');
  const curlLog = path.join(tmpDir, 'curl.log');
  const { qrLog, ageMock, curlMock, qrMock } = createQrUploadToolPaths(tmpDir);

  await writeFile(firstFile, 'alpha payload', 'utf8');
  await mkdir(secondDir);
  await writeFile(secondFile, 'beta payload', 'utf8');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${qrLog}"
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['send', '--file', firstFile, '--file', secondDir],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.match(
    result.stdout,
    /^Receive: dud receive --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe --url https:\/\/dud\.example\.com --extract$/m,
  );
  const bundleEntries = execFileSync('tar', ['-tf', curlPayload], {
    encoding: 'utf8',
  })
    .trim()
    .split('\n');
  assert.deepEqual(bundleEntries.sort(), [
    'alpha.txt',
    'docs/',
    'docs/beta.txt',
  ]);
  assert.equal(
    await readFile(qrLog, 'utf8'),
    '-t\nansiutf8\n3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe\n',
  );
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
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /upload accepts only one source/);
});

test('upload command can suppress QR output with --no-qr', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-no-qr-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');
  const { qrLog, ageMock, curlMock, qrMock } = createQrUploadToolPaths(tmpDir);

  await writeFile(filePath, 'plaintext', 'utf8');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${qrLog}"
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['upload', '--file', filePath, '--no-qr'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /^Upload complete$/m);
  assert.match(result.stdout, /^ID: 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe$/m);
  assert.match(result.stdout, /^Delete after read: no$/m);
  assert.match(
    result.stdout,
    /^Receive: dud receive --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe --url https:\/\/dud\.example\.com$/m,
  );
  assert.doesNotMatch(result.stdout, /QR Code:/);
  await assert.rejects(readFile(qrLog, 'utf8'));
});

test('git push creates a full bundle and uploads it', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-git-push-'));
  const gitLog = path.join(tmpDir, 'git.log');
  const curlLog = path.join(tmpDir, 'curl.log');
  const curlPayload = path.join(tmpDir, 'payload.bundle');
  const gitMock = path.join(tmpDir, 'git-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const qrMock = path.join(tmpDir, 'qr-mock.sh');

  await makeExecutable(
    gitMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${gitLog}"
if [ "$1" = "rev-parse" ]; then
  printf '.git\n'
  exit 0
fi
if [ "$1" = "bundle" ] && [ "$2" = "create" ]; then
  printf 'bundle payload' > "$3"
  exit 0
fi
exit 1
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":true}' > "$output"
`,
  );

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    [
      'git',
      'push',
      '--ttl',
      '12h',
      '--delete-after-read',
      '-r',
      'age1examplepublickey0000000000000000000000000000000000000000000000',
      '--no-qr',
    ],
    {
      DUD_GIT_BIN: gitMock,
      DUD_AGE_BIN: ageMock,
      DUD_CURL_BIN: curlMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  const gitArgs = await readFile(gitLog, 'utf8');
  assert.match(gitArgs, /rev-parse\n--git-dir/);
  assert.match(
    gitArgs,
    /bundle\ncreate\n[^\n]*\/dud-git-push-bundle-[^\n]+\n--branches\n--tags/,
  );
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(curlArgs, /x-dud-ttl: 12h/);
  assert.match(curlArgs, /x-dud-delete-after-read: true/);
  assert.equal(await readFile(curlPayload, 'utf8'), 'bundle payload');
  assert.match(
    result.stdout,
    /^Receive: dud git fetch --id 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe --url https:\/\/dud\.example\.com$/m,
  );
});

test('git send is an alias for git push', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-git-send-alias-'),
  );
  const gitLog = path.join(tmpDir, 'git.log');
  const gitMock = path.join(tmpDir, 'git-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    gitMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${gitLog}"
if [ "$1" = "rev-parse" ]; then exit 0; fi
if [ "$1" = "bundle" ] && [ "$2" = "create" ]; then printf bundle > "$3"; exit 0; fi
exit 1
`,
  );
  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift 2; continue; fi
  input="$1"; shift
done
cp "$input" "$output"
`,
  );
  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then output="$2"; shift 2; continue; fi
  shift
done
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  const result = await runCommand(CLIENT_BIN, ['git', 'send', '--json'], {
    DUD_GIT_BIN: gitMock,
    DUD_AGE_BIN: ageMock,
    DUD_CURL_BIN: curlMock,
    DUD_SECRET_TOKEN: 'top-secret',
  });

  assert.equal(result.code, 0);
  assert.match(await readFile(gitLog, 'utf8'), /bundle\ncreate/);
});

test('git fetch downloads, verifies, and fetches remote-tracking refs', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-git-fetch-'));
  const identityPath = path.join(tmpDir, 'identity.txt');
  const gitLog = path.join(tmpDir, 'git.log');
  const ageLog = path.join(tmpDir, 'age.log');
  const gitMock = path.join(tmpDir, 'git-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await writeFile(identityPath, 'AGE-SECRET-KEY-1EXAMPLE\n', 'utf8');

  await makeExecutable(
    gitMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${gitLog}"
if [ "$1" = "rev-parse" ]; then
  printf '.git\n'
  exit 0
fi
if [ "$1" = "bundle" ] && [ "$2" = "verify" ]; then
  exit 0
fi
if [ "$1" = "ls-remote" ]; then
  printf 'abc123\trefs/heads/main\n'
  exit 0
fi
if [ "$1" = "fetch" ]; then
  exit 0
fi
exit 1
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'cipher bundle' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    [
      'git',
      'fetch',
      '--id',
      '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
      '--identity',
      identityPath,
      '--remote',
      'A',
    ],
    {
      DUD_GIT_BIN: gitMock,
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  const ageArgs = await readFile(ageLog, 'utf8');
  assert.match(ageArgs, /-i/);
  assert.match(
    ageArgs,
    new RegExp(identityPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
  const gitArgs = await readFile(gitLog, 'utf8');
  assert.match(gitArgs, /bundle\nverify\n[^\n]*\/dud-git-fetch-bundle-[^\n]+/);
  assert.match(
    gitArgs,
    /fetch\n[^\n]*\/dud-git-fetch-bundle-[^\n]+\n\+refs\/heads\/\*:refs\/remotes\/A\/\*/,
  );
  assert.match(result.stdout, /Fetched Git bundle into refs\/remotes\/A\/\*/);
  assert.match(result.stdout, /git merge --ff-only A\/main/);
});

test('git receive is an alias for git fetch with the default remote', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-git-receive-alias-'),
  );
  const gitLog = path.join(tmpDir, 'git.log');
  const gitMock = path.join(tmpDir, 'git-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    gitMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${gitLog}"
if [ "$1" = "rev-parse" ]; then exit 0; fi
if [ "$1" = "bundle" ] && [ "$2" = "verify" ]; then exit 0; fi
if [ "$1" = "ls-remote" ]; then printf 'abc123\trefs/heads/main\n'; exit 0; fi
if [ "$1" = "fetch" ]; then exit 0; fi
exit 1
`,
  );
  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift 2; continue; fi
  shift
done
printf bundle > "$output"
`,
  );
  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift 2; continue; fi
  input="$1"; shift
done
cp "$input" "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['git', 'receive', '--id', '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe'],
    {
      DUD_GIT_BIN: gitMock,
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.match(
    await readFile(gitLog, 'utf8'),
    /refs\/heads\/\*:refs\/remotes\/dud\/\*/,
  );
});

test('git command validates required arguments and subcommands', async () => {
  const missingId = await runCommand(CLIENT_BIN, ['git', 'fetch']);

  assert.notEqual(missingId.code, 0);
  assert.match(missingId.stderr, /git fetch requires --id/);

  const unknown = await runCommand(CLIENT_BIN, ['git', 'dance']);

  assert.notEqual(unknown.code, 0);
  assert.match(unknown.stderr, /Unknown git subcommand: dance/);
});

test('git push and fetch work with a real Git bundle', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-git-real-'));
  const sourceRepo = path.join(tmpDir, 'source');
  const targetRepo = path.join(tmpDir, 'target');
  const storedBundle = path.join(tmpDir, 'stored.bundle');
  const pushCurlMock = path.join(tmpDir, 'curl-push.sh');
  const fetchCurlMock = path.join(tmpDir, 'curl-fetch.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');

  await mkdir(sourceRepo);
  await mkdir(targetRepo);
  execFileSync('git', ['init', '-b', 'main'], { cwd: sourceRepo });
  execFileSync('git', ['config', 'user.email', 'dud@example.com'], {
    cwd: sourceRepo,
  });
  execFileSync('git', ['config', 'user.name', 'DUD Test'], {
    cwd: sourceRepo,
  });
  await writeFile(path.join(sourceRepo, 'README.md'), 'hello git\n', 'utf8');
  execFileSync('git', ['add', 'README.md'], { cwd: sourceRepo });
  execFileSync('git', ['commit', '-m', 'initial'], { cwd: sourceRepo });
  execFileSync('git', ['tag', 'v1'], { cwd: sourceRepo });
  execFileSync('git', ['init', '-b', 'main'], { cwd: targetRepo });

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    pushCurlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${storedBundle}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  await makeExecutable(
    fetchCurlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "${storedBundle}" "$output"
`,
  );

  const pushResult = await runCommand(
    CLIENT_BIN,
    ['git', 'push', '--json'],
    {
      DUD_CURL_BIN: pushCurlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
    { cwd: sourceRepo },
  );

  assert.equal(pushResult.code, 0);

  const fetchResult = await runCommand(
    CLIENT_BIN,
    [
      'git',
      'fetch',
      '--id',
      '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
      '--remote',
      'source',
    ],
    {
      DUD_CURL_BIN: fetchCurlMock,
      DUD_AGE_BIN: ageMock,
    },
    { cwd: targetRepo },
  );

  assert.equal(fetchResult.code, 0, fetchResult.stderr);
  assert.equal(
    execFileSync('git', ['rev-parse', '--verify', 'refs/remotes/source/main'], {
      cwd: targetRepo,
      encoding: 'utf8',
    }).trim().length,
    40,
  );
  assert.equal(
    execFileSync('git', ['rev-parse', '--verify', 'refs/tags/v1'], {
      cwd: targetRepo,
      encoding: 'utf8',
    }).trim().length,
    40,
  );
  assert.match(fetchResult.stdout, /git merge --ff-only source\/main/);
});

test('download command passes dashed IDs through to the API', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-download-'));
  const outDir = path.join(tmpDir, 'work');
  const outputPath = path.join(outDir, 'output.bin');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlLog = path.join(tmpDir, 'curl.log');

  await mkdir(outDir);

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'ciphertext' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    [
      'download',
      '--id',
      '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
      '--out',
      outputPath,
    ],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(outputPath, 'utf8'), 'ciphertext');
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(
    curlArgs,
    /\/v1\/files\/3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe/,
  );
});

test('download command still accepts raw IDs unchanged', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-download-raw-'),
  );
  const outDir = path.join(tmpDir, 'work');
  const outputPath = path.join(outDir, 'output.bin');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlLog = path.join(tmpDir, 'curl.log');

  await mkdir(outDir);

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'ciphertext' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  const rawId = '3df75d5c0c3b4f53ac1b8eeb23704fbe';
  const result = await runCommand(
    CLIENT_BIN,
    ['download', '--id', rawId, '--out', outputPath],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(outputPath, 'utf8'), 'ciphertext');
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(curlArgs, new RegExp(`/v1/files/${rawId}`));
});

test('download command can write decrypted plaintext to stdout', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-download-stdout-'),
  );
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'ciphertext' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
printf 'plain stdout' > "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    ['download', '--id', '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe', '--stdout'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(result.stdout, 'plain stdout');
});

test('receive command can extract a bundled archive', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-download-extract-'),
  );
  const archivePath = path.join(tmpDir, 'bundle.tar');
  const archiveRoot = path.join(tmpDir, 'bundle-root');
  const nestedDir = path.join(archiveRoot, 'docs');
  const extractDir = path.join(tmpDir, 'extracted');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');

  await mkdir(archiveRoot);
  await mkdir(nestedDir);
  await writeFile(path.join(archiveRoot, 'alpha.txt'), 'alpha payload', 'utf8');
  await writeFile(path.join(nestedDir, 'beta.txt'), 'beta payload', 'utf8');
  execFileSync(
    'tar',
    ['-cf', archivePath, '-C', archiveRoot, 'alpha.txt', 'docs'],
    { encoding: 'utf8' },
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "${archivePath}" "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    [
      'receive',
      '--id',
      '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
      '--extract',
      '--out-dir',
      extractDir,
    ],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.match(
    result.stdout,
    new RegExp(
      `Extracted bundle to ${extractDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`,
    ),
  );
  assert.equal(
    await readFile(path.join(extractDir, 'alpha.txt'), 'utf8'),
    'alpha payload',
  );
  assert.equal(
    await readFile(path.join(extractDir, 'docs', 'beta.txt'), 'utf8'),
    'beta payload',
  );
});

test('download command can decrypt with an explicit identity file', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-download-identity-'),
  );
  const outDir = path.join(tmpDir, 'work');
  const outputPath = path.join(outDir, 'output.bin');
  const identityPath = path.join(tmpDir, 'key.txt');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const ageLog = path.join(tmpDir, 'age.log');

  await mkdir(outDir);
  await writeFile(identityPath, 'AGE-SECRET-KEY-1EXAMPLE', 'utf8');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'ciphertext' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
printf 'plain with identity' > "$output"
`,
  );

  const result = await runCommand(
    CLIENT_BIN,
    [
      'download',
      '--id',
      '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
      '-i',
      identityPath,
      '--out',
      outputPath,
    ],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(outputPath, 'utf8'), 'plain with identity');
  const ageArgs = await readFile(ageLog, 'utf8');
  assert.match(ageArgs, /--decrypt/);
  assert.match(ageArgs, /-i/);
  assert.match(
    ageArgs,
    new RegExp(identityPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
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

test('interactive upload can collect typed text and upload it', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-upload-'),
  );
  const interactiveScript = CLIENT_BIN;
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const qrMock = path.join(tmpDir, 'qr-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
    { input: '2\n\n2\n\n\n\nmenu payload' },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(curlPayload, 'utf8'), 'menu payload');
  assert.match(result.stdout, /Upload source:/);
  assert.equal(
    (
      result.stderr.match(
        /Enter plaintext, then press Ctrl-D when finished\./g,
      ) ?? []
    ).length,
    1,
  );
});

test('interactive upload can use a recipient file with a file source', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-upload-recipient-file-'),
  );
  const interactiveScript = CLIENT_BIN;
  const filePath = path.join(tmpDir, 'plain.bin');
  const recipientPath = path.join(tmpDir, 'recipient.txt');
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const ageLog = path.join(tmpDir, 'age.log');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const qrMock = path.join(tmpDir, 'qr-mock.sh');

  await writeFile(filePath, 'plaintext', 'utf8');
  await writeFile(recipientPath, 'age1recipientexample\n', 'utf8');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
    {
      input: `2\n\n1\n${filePath}\n3\n${recipientPath}\n15m\ny\n`,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(curlPayload, 'utf8'), 'plaintext');
  const ageArgs = await readFile(ageLog, 'utf8');
  assert.match(ageArgs, /-R/);
  assert.match(
    ageArgs,
    new RegExp(recipientPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
  assert.match(result.stdout, /Recipient file:/);
});

test('interactive download can write decrypted output to stdout', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-download-'),
  );
  const interactiveScript = CLIENT_BIN;
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'ciphertext' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
printf 'interactive stdout' > "$output"
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
    { input: '3\n\n3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe\n2\n\n' },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /Download output:/);
  assert.match(result.stdout, /interactive stdout$/);
});

test('interactive download can use an identity file', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-download-identity-'),
  );
  const interactiveScript = CLIENT_BIN;
  const identityPath = path.join(tmpDir, 'identity.txt');
  const outputPath = path.join(tmpDir, 'output.txt');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const ageLog = path.join(tmpDir, 'age.log');

  await writeFile(identityPath, 'AGE-SECRET-KEY-1EXAMPLE\n', 'utf8');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'ciphertext' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
printf 'interactive identity output' > "$output"
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
    {
      input: `3\n\n3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe\n1\n${outputPath}\n${identityPath}\n`,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(
    await readFile(outputPath, 'utf8'),
    'interactive identity output',
  );
  assert.match(result.stdout, /Identity file/);
  const ageArgs = await readFile(ageLog, 'utf8');
  assert.match(ageArgs, /-i/);
  assert.match(
    ageArgs,
    new RegExp(identityPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  );
});

test('interactive download can extract a bundle into a directory', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-download-extract-'),
  );
  const interactiveScript = CLIENT_BIN;
  const archivePath = path.join(tmpDir, 'bundle.tar');
  const archiveRoot = path.join(tmpDir, 'bundle-root');
  const nestedDir = path.join(archiveRoot, 'docs');
  const extractDir = path.join(tmpDir, 'output-dir');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');

  await mkdir(archiveRoot);
  await mkdir(nestedDir);
  await writeFile(path.join(archiveRoot, 'alpha.txt'), 'alpha payload', 'utf8');
  await writeFile(path.join(nestedDir, 'beta.txt'), 'beta payload', 'utf8');
  execFileSync(
    'tar',
    ['-cf', archivePath, '-C', archiveRoot, 'alpha.txt', 'docs'],
    { encoding: 'utf8' },
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "${archivePath}" "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
    {
      input: `3\n\n3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe\n3\n${extractDir}\n\n`,
    },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /extract bundle/);
  assert.equal(
    await readFile(path.join(extractDir, 'alpha.txt'), 'utf8'),
    'alpha payload',
  );
  assert.equal(
    await readFile(path.join(extractDir, 'docs', 'beta.txt'), 'utf8'),
    'beta payload',
  );
});

test('interactive git push can collect recipient settings', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-git-push-'),
  );
  const interactiveScript = CLIENT_BIN;
  const recipientPath = path.join(tmpDir, 'recipient.txt');
  const gitLog = path.join(tmpDir, 'git.log');
  const curlLog = path.join(tmpDir, 'curl.log');
  const curlPayload = path.join(tmpDir, 'payload.bundle');
  const gitMock = path.join(tmpDir, 'git-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const qrMock = path.join(tmpDir, 'qr-mock.sh');

  await writeFile(recipientPath, 'age1interactivegitrecipient\n', 'utf8');

  await makeExecutable(
    gitMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${gitLog}"
if [ "$1" = "rev-parse" ]; then exit 0; fi
if [ "$1" = "bundle" ] && [ "$2" = "create" ]; then printf git-bundle > "$3"; exit 0; fi
exit 1
`,
  );
  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift 2; continue; fi
  input="$1"; shift
done
cp "$input" "$output"
`,
  );
  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then payload="$2"; shift 2; continue; fi
  if [ "$1" = "--output" ]; then output="$2"; shift 2; continue; fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":true}' > "$output"
`,
  );
  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_GIT_BIN: gitMock,
      DUD_AGE_BIN: ageMock,
      DUD_CURL_BIN: curlMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
    { input: `5\n1\n\n3\n${recipientPath}\n15m\ny\nn\n` },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(curlPayload, 'utf8'), 'git-bundle');
  assert.match(result.stdout, /Git mode:/);
  assert.match(result.stdout, /Show QR code/);
  assert.match(await readFile(gitLog, 'utf8'), /bundle\ncreate/);
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(curlArgs, /x-dud-ttl: 15m/);
  assert.match(curlArgs, /x-dud-delete-after-read: true/);
  assert.doesNotMatch(result.stdout, /QR Code:/);
});

test('interactive git fetch can collect identity and remote settings', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-git-fetch-'),
  );
  const interactiveScript = CLIENT_BIN;
  const identityPath = path.join(tmpDir, 'identity.txt');
  const gitLog = path.join(tmpDir, 'git.log');
  const ageLog = path.join(tmpDir, 'age.log');
  const gitMock = path.join(tmpDir, 'git-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await writeFile(identityPath, 'AGE-SECRET-KEY-1EXAMPLE\n', 'utf8');

  await makeExecutable(
    gitMock,
    `#!/bin/sh
printf '%s\n' "$@" >> "${gitLog}"
if [ "$1" = "rev-parse" ]; then exit 0; fi
if [ "$1" = "bundle" ] && [ "$2" = "verify" ]; then exit 0; fi
if [ "$1" = "ls-remote" ]; then printf 'abc123\trefs/heads/main\n'; exit 0; fi
if [ "$1" = "fetch" ]; then exit 0; fi
exit 1
`,
  );
  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift 2; continue; fi
  shift
done
printf bundle > "$output"
`,
  );
  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift 2; continue; fi
  input="$1"; shift
done
cp "$input" "$output"
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_GIT_BIN: gitMock,
      DUD_AGE_BIN: ageMock,
      DUD_CURL_BIN: curlMock,
    },
    {
      input: `5\n2\n\n3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe\n${identityPath}\nB\n`,
    },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /Git mode:/);
  assert.match(result.stdout, /Remote name/);
  assert.match(await readFile(ageLog, 'utf8'), /-i/);
  assert.match(
    await readFile(gitLog, 'utf8'),
    /refs\/heads\/\*:refs\/remotes\/B\/\*/,
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
    { input: `4\n2\n${keyPath}\n${recipientPath}\n` },
  );

  assert.equal(result.code, 0);
  assert.equal(
    await readFile(recipientPath, 'utf8'),
    'age1interactiveconverted\n',
  );
  assert.match(result.stdout, /Keygen mode:/);
});

test('flush command posts the secret token header', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-flush-'));
  const logFile = path.join(tmpDir, 'curl.log');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
printf '{"ok":true,"deletedCount":2}\n'
`,
  );

  const result = await runCommand(CLIENT_BIN, ['flush'], {
    DUD_CURL_BIN: curlMock,
    DUD_SECRET_TOKEN: 'top-secret',
  });

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /x-dud-secret-token: top-secret/);
  assert.match(result.stdout, /deletedCount/);
});

test('install command prints a TTY-aware wrapper', async () => {
  const result = await runCommand(CLIENT_BIN, ['install']);

  assert.equal(result.code, 0);
  assert.match(result.stdout, /dud_docker_env_args\(\)/);
  assert.match(result.stdout, /if \[ -r \.env \]; then/);
  assert.match(result.stdout, /--env-file/);
  assert.match(
    result.stdout,
    /DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN DUD_CA_BUNDLE DUD_CONNECT_TO/,
  );
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
  assert.match(result.stdout, /^dud\(\) \{/m);
  assert.match(result.stdout, /if \[ -r \.env \]; then/);
  assert.match(result.stdout, /--env-file/);
  assert.match(
    result.stdout,
    /DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN DUD_CA_BUNDLE DUD_CONNECT_TO/,
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
      DUD_SECRET_TOKEN: 'top-secret',
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
  assert.match(args, /-e\nDUD_SECRET_TOKEN=top-secret/);
  assert.match(
    args,
    /-e\nDUD_CA_BUNDLE=\/work\/\.dud-dev\/caddy-data\/pki\/authorities\/local\/root\.crt/,
  );
  assert.match(args, /-e\nDUD_CONNECT_TO=dud\.local\.test:443:caddy:443/);
});

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
      DUD_SECRET_TOKEN: 'top-secret',
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
